#!/usr/bin/env python3
"""Generic CLI wrapper that streams output transparently and emits NeuroSwarm events.

Wraps any AI agent CLI or worker command (codex, claude, opencode, gemini, custom
scripts) without altering stdout, stderr, or the child exit code:
- Streams stdout and stderr in real time.
- Detects HTTP 429 / provider rate-limit errors in output and reports metadata.http_status=429.
- Emits normalized tool_error events on non-zero exit (feeding LOOP_SUSPECTED).
- Emits success events on exit 0 (interrupting stall streaks) unless --errors-only is set.
- Redacts secrets locally before transmission and fails open if NeuroSwarm is unreachable.

Usage:
  SWARMCONTROL_TOKEN=... python3 integrations/cli_wrapper.py \
      --harness codex --agent-name worker-1 --task-id task-42 -- <cmd> [args...]
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, BinaryIO

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR.parent) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR.parent))

from integrations.client import (  # noqa: E402
    EmitResult,
    SwarmEventClient,
    detect_rate_limit,
    extract_http_status,
    load_config,
    normalize_error_signature,
)

MAX_BUFFERED_LINES = 30
MAX_LINE_CAPTURE_CHARS = 512
DEFAULT_MAX_429_EVENTS = 10


def _split_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split wrapper flags from wrapped command at the first '--' separator."""
    if "--" in argv:
        idx = argv.index("--")
        return argv[:idx], argv[idx + 1 :]
    return argv, []


def _pump_stream(
    src: BinaryIO,
    dst: BinaryIO,
    tail: collections.deque[str],
    rate_limit_lines: list[str],
    lock: threading.Lock,
    max_429: int,
) -> None:
    """Forward raw bytes from child pipe to parent stream while scanning lines."""
    try:
        for raw_line in iter(src.readline, b""):
            try:
                dst.write(raw_line)
                dst.flush()
            except OSError:
                pass
            text = raw_line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            clipped = text[:MAX_LINE_CAPTURE_CHARS]
            with lock:
                tail.append(clipped)
                if len(rate_limit_lines) < max_429 and detect_rate_limit(clipped):
                    rate_limit_lines.append(clipped)
    finally:
        try:
            src.close()
        except OSError:
            pass


def _pick_error_line(stderr_tail: list[str], stdout_tail: list[str]) -> str:
    """Choose the most informative final line from stderr (falling back to stdout)."""
    for lines in (stderr_tail, stdout_tail):
        for line in reversed(lines):
            stripped = line.strip()
            if stripped:
                return stripped
    return ""


def run_wrapped_command(
    command: list[str],
    *,
    client: SwarmEventClient,
    harness: str = "cli",
    agent_name: str = "worker",
    task_id: str | None = None,
    errors_only: bool = False,
    max_429_events: int = DEFAULT_MAX_429_EVENTS,
    dry_run: bool = False,
    verbose: bool = False,
) -> tuple[int, list[EmitResult]]:
    """Run command, stream I/O transparently, emit structured events, return (exit_code, results)."""
    if not command:
        raise ValueError("No command provided to wrap")

    prog = Path(command[0]).name or command[0]
    resolved_task = (task_id or os.environ.get("SWARMCONTROL_TASK_ID") or f"cli-{prog}")[:128]
    t0 = time.monotonic()

    stderr_tail: collections.deque[str] = collections.deque(maxlen=MAX_BUFFERED_LINES)
    stdout_tail: collections.deque[str] = collections.deque(maxlen=MAX_BUFFERED_LINES)
    rate_limit_lines: list[str] = []
    lock = threading.Lock()

    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        dur_ms = round((time.monotonic() - t0) * 1000.0, 1)
        print(f"[swarmcontrol-wrap] failed to start '{command[0]}': {exc}", file=sys.stderr)
        sig = normalize_error_signature(str(exc))
        res = client.emit(
            harness=harness,
            agent_name=agent_name,
            event_type="tool_error",
            severity="ERROR",
            message=f"Command '{prog}' failed to start: {sig}",
            metadata={
                "source": "cli-wrapper",
                "task_id": resolved_task,
                "command": prog[:64],
                "exit_code": 127,
                "duration_ms": dur_ms,
            },
            dry_run=dry_run,
        )
        return 127, [res]

    prev_sigint = signal.getsignal(signal.SIGINT)
    prev_sigterm = signal.getsignal(signal.SIGTERM)

    def _forward_signal(signum: int, _frame: Any) -> None:
        if proc.poll() is None:
            try:
                proc.send_signal(signum)
            except OSError:
                pass

    installed_handlers = False
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, _forward_signal)
        signal.signal(signal.SIGTERM, _forward_signal)
        installed_handlers = True

    t_out = threading.Thread(
        target=_pump_stream,
        args=(proc.stdout, sys.stdout.buffer, stdout_tail, rate_limit_lines, lock, max_429_events),
        daemon=True,
    )
    t_err = threading.Thread(
        target=_pump_stream,
        args=(proc.stderr, sys.stderr.buffer, stderr_tail, rate_limit_lines, lock, max_429_events),
        daemon=True,
    )
    t_out.start()
    t_err.start()

    try:
        raw_rc = proc.wait()
    finally:
        t_out.join(timeout=2.0)
        t_err.join(timeout=2.0)
        if installed_handlers:
            signal.signal(signal.SIGINT, prev_sigint)
            signal.signal(signal.SIGTERM, prev_sigterm)

    rc = 128 + abs(raw_rc) if raw_rc < 0 else raw_rc
    dur_ms = round((time.monotonic() - t0) * 1000.0, 1)

    base_meta: dict[str, Any] = {
        "source": "cli-wrapper",
        "task_id": resolved_task,
        "command": prog[:64],
        "exit_code": rc,
        "duration_ms": dur_ms,
    }
    results: list[EmitResult] = []

    if rc != 0:
        if rate_limit_lines:
            # Emit earlier internal retry 429s before the terminal tool_error
            for line in rate_limit_lines[:-1]:
                sig = normalize_error_signature(line)
                results.append(
                    client.emit(
                        harness=harness,
                        agent_name=agent_name,
                        event_type="retry",
                        severity="WARNING",
                        message=f"Command '{prog}' rate-limited: {sig}",
                        metadata={**base_meta, "http_status": 429},
                        dry_run=dry_run,
                    )
                )
            final_sig = normalize_error_signature(rate_limit_lines[-1])
            results.append(
                client.emit(
                    harness=harness,
                    agent_name=agent_name,
                    event_type="tool_error",
                    severity="WARNING",
                    message=f"Command '{prog}' failed (exit {rc}): {final_sig}",
                    metadata={**base_meta, "http_status": 429},
                    dry_run=dry_run,
                )
            )
        else:
            last_line = _pick_error_line(list(stderr_tail), list(stdout_tail))
            combined = "\n".join(list(stderr_tail) + list(stdout_tail))
            http_status = extract_http_status(combined)
            meta = dict(base_meta)
            if http_status is not None:
                meta["http_status"] = http_status
            sig = normalize_error_signature(last_line)
            msg = f"Command '{prog}' failed (exit {rc}): {sig}" if sig else f"Command '{prog}' failed (exit {rc})"
            results.append(
                client.emit(
                    harness=harness,
                    agent_name=agent_name,
                    event_type="tool_error",
                    severity="WARNING",
                    message=msg,
                    metadata=meta,
                    dry_run=dry_run,
                )
            )
    else:
        for line in rate_limit_lines:
            sig = normalize_error_signature(line)
            results.append(
                client.emit(
                    harness=harness,
                    agent_name=agent_name,
                    event_type="rate_limit",
                    severity="WARNING",
                    message=f"Command '{prog}' encountered rate limit: {sig}",
                    metadata={**base_meta, "http_status": 429, "recovered": True},
                    dry_run=dry_run,
                )
            )
        if not errors_only:
            results.append(
                client.emit(
                    harness=harness,
                    agent_name=agent_name,
                    event_type="success",
                    severity="INFO",
                    message=f"Command '{prog}' succeeded",
                    metadata={**base_meta, "progress": True},
                    dry_run=dry_run,
                )
            )

    if verbose:
        for r in results:
            status = "ok" if r.ok else f"error={r.error}"
            print(f"[swarmcontrol-wrap] emit {r.payload['event_type']}: {status}", file=sys.stderr)

    return rc, results


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    wrapper_argv, cmd_after_sep = _split_argv(raw_argv)

    parser = argparse.ArgumentParser(
        description="Wrap any CLI command and emit structured failure/429/recovery events to NeuroSwarm."
    )
    parser.add_argument("--server", default=None, help="NeuroSwarm server URL (default: SWARMCONTROL_SERVER)")
    parser.add_argument("--host-id", default=None, help="Host ID (default: SWARMCONTROL_HOST_ID or hostname)")
    parser.add_argument("--env-file", default=None, help="Path to agent.env")
    parser.add_argument("--harness", default=os.environ.get("SWARMCONTROL_HARNESS", "cli"), help="Harness name")
    parser.add_argument("--agent-name", default=os.environ.get("SWARMCONTROL_AGENT_NAME", "worker"), help="Agent name")
    parser.add_argument("--task-id", default=None, help="Task ID for loop guardrail scoping")
    parser.add_argument("--timeout", type=float, default=None, help="HTTP timeout in seconds")
    parser.add_argument("--errors-only", action="store_true", help="Do not emit success events on exit 0")
    parser.add_argument("--max-429-events", type=int, default=DEFAULT_MAX_429_EVENTS, help="Cap 429 events per command")
    parser.add_argument("--dry-run", action="store_true", help="Print emitted payloads to stderr without sending")
    parser.add_argument("--strict", action="store_true", help="Return non-zero if telemetry delivery fails")
    parser.add_argument("--verbose", action="store_true", help="Log delivery diagnostics to stderr")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to execute (prefer separating with --)")

    args = parser.parse_args(wrapper_argv)
    command = cmd_after_sep or list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.print_usage(sys.stderr)
        print("ERROR: provide a command after '--', e.g.: cli_wrapper.py -- codex ...", file=sys.stderr)
        return 2

    cfg = load_config(
        server=args.server,
        host_id=args.host_id,
        timeout=args.timeout,
        env_file=args.env_file,
    )
    client = SwarmEventClient(cfg)
    rc, results = run_wrapped_command(
        command,
        client=client,
        harness=args.harness,
        agent_name=args.agent_name,
        task_id=args.task_id,
        errors_only=args.errors_only,
        max_429_events=max(1, args.max_429_events),
        dry_run=args.dry_run,
        verbose=args.verbose,
    )

    if args.dry_run:
        print(json.dumps([r.payload for r in results], indent=2), file=sys.stderr)
        return rc

    if args.strict and any(not r.ok for r in results):
        for r in results:
            if not r.ok:
                print(f"[swarmcontrol-wrap] strict telemetry error: {r.error}", file=sys.stderr)
        return rc if rc != 0 else 1

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
