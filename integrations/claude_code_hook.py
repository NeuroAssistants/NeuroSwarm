#!/usr/bin/env python3
"""Claude Code hook emitter for NeuroSwarm (POST /api/v1/ingest/event).

Reads Claude Code hook JSON from stdin and translates tool failures, rate-limit
(HTTP 429) responses, and tool recoveries into structured NeuroSwarm events so
LOOP_SUSPECTED and QUOTA_EXHAUSTION_BURST guardrails trigger in real workloads.

Design rules:
- Never prints to stdout during normal hook execution (preserves Claude Code's
  hook JSON protocol).
- Fail-open (exits 0) by default so NeuroSwarm outages never break Claude Code.
- Never requires SWARMCONTROL_TOKEN on argv (reads env or agent.env).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

# Support direct script execution (`python3 integrations/claude_code_hook.py`)
# as well as package import (`python3 -m integrations.claude_code_hook`).
_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR.parent) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR.parent))

from integrations.client import (  # noqa: E402
    SwarmEventClient,
    detect_rate_limit,
    extract_http_status,
    load_config,
    normalize_error_signature,
)


def _extract_text(value: Any) -> str:
    """Extract human-readable error/message text from a string, dict, or list."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("error", "stderr", "message", "content", "detail", "stdout", "output"):
            if key in value and value[key]:
                extracted = _extract_text(value[key])
                if extracted:
                    return extracted
        try:
            return json.dumps(value, ensure_ascii=False)[:600]
        except Exception:
            return str(value)[:600]
    if isinstance(value, list):
        parts = [_extract_text(item) for item in value]
        return " ".join(p for p in parts if p).strip()
    return str(value).strip()


def _extract_explicit_status(payload: dict[str, Any]) -> int | None:
    """Look for structured numeric HTTP status fields in Claude Code hook payloads."""
    containers: list[Any] = [payload]
    for key in ("error", "tool_response", "metadata"):
        if isinstance(payload.get(key), dict):
            containers.append(payload[key])
    for obj in containers:
        if not isinstance(obj, dict):
            continue
        for key in ("http_status", "status_code", "statusCode", "status"):
            val = obj.get(key)
            if isinstance(val, int) and 400 <= val <= 599:
                return val
            if isinstance(val, str) and val.isdigit():
                code = int(val)
                if 400 <= code <= 599:
                    return code
    return None


def _is_post_tool_error(payload: dict[str, Any]) -> tuple[bool, str]:
    """Detect whether a PostToolUse payload carries a tool failure."""
    if payload.get("error"):
        return True, _extract_text(payload["error"])
    resp = payload.get("tool_response")
    if isinstance(resp, dict):
        if resp.get("interrupted") is True:
            return False, ""
        if resp.get("is_error") is True or resp.get("isError") is True:
            return True, _extract_text(resp)
        for code_key in ("exit_code", "exitCode", "returncode"):
            code = resp.get(code_key)
            if isinstance(code, int) and code != 0:
                err_txt = _extract_text(resp.get("stderr") or resp.get("error") or resp)
                return True, err_txt or f"exit code {code}"
        if resp.get("error"):
            return True, _extract_text(resp["error"])
    return False, ""


def _resolve_task_id(payload: dict[str, Any], override: str | None) -> str:
    for candidate in (
        override,
        os.environ.get("SWARMCONTROL_TASK_ID"),
        payload.get("task_id"),
        payload.get("agent_id"),
        payload.get("session_id"),
    ):
        if candidate and str(candidate).strip():
            return str(candidate).strip()[:128]
    return "default"


def _resolve_agent_name(payload: dict[str, Any], override: str | None) -> str:
    for candidate in (
        override,
        os.environ.get("SWARMCONTROL_AGENT_NAME"),
        payload.get("agent_name"),
        payload.get("agent_type"),
        payload.get("agent_id"),
    ):
        if candidate and str(candidate).strip():
            return str(candidate).strip()[:128]
    session_id = str(payload.get("session_id") or "").strip()
    if session_id:
        return f"claude-{session_id[:12]}"
    cwd = str(payload.get("cwd") or "").strip()
    if cwd:
        base = Path(cwd).name
        if base:
            return f"claude-{base[:48]}"
    return "claude-code"


def translate_hook_payload(
    payload: dict[str, Any],
    *,
    harness: str = "claude-code",
    agent_name: str | None = None,
    task_id: str | None = None,
    fallback_event: str | None = None,
) -> dict[str, Any] | None:
    """Map a Claude Code hook JSON object to SwarmEventClient.emit() kwargs."""
    hook_event = str(payload.get("hook_event_name") or fallback_event or "").strip()
    resolved_task = _resolve_task_id(payload, task_id)
    resolved_agent = _resolve_agent_name(payload, agent_name)
    tool_name = str(payload.get("tool_name") or "unknown").strip()[:64]

    base_meta: dict[str, Any] = {
        "source": "claude-code-hook",
        "task_id": resolved_task,
    }
    if hook_event:
        base_meta["hook_event"] = hook_event[:64]
    if payload.get("session_id"):
        base_meta["session_id"] = str(payload["session_id"])[:128]
    if payload.get("cwd"):
        base_meta["cwd"] = str(payload["cwd"])[:256]

    # 1. Explicit tool failure hook
    if hook_event == "PostToolUseFailure":
        base_meta["tool_name"] = tool_name
        if payload.get("is_interrupt") is True:
            base_meta["interrupted"] = True
            return {
                "harness": harness,
                "agent_name": resolved_agent,
                "event_type": "info",
                "severity": "INFO",
                "message": f"Tool {tool_name} interrupted by user",
                "metadata": base_meta,
            }

        raw_err = _extract_text(payload.get("error")) or _extract_text(payload.get("tool_response"))
        http_status = _extract_explicit_status(payload) or extract_http_status(raw_err)
        if http_status is not None:
            base_meta["http_status"] = http_status
        sig = normalize_error_signature(raw_err)
        msg = f"Tool {tool_name} failed: {sig}" if sig else f"Tool {tool_name} failed"
        return {
            "harness": harness,
            "agent_name": resolved_agent,
            "event_type": "tool_error",
            "severity": "WARNING",
            "message": msg,
            "metadata": base_meta,
        }

    # 2. PostToolUse (handles both recovery/success and embedded tool errors)
    if hook_event == "PostToolUse":
        base_meta["tool_name"] = tool_name
        is_err, err_text = _is_post_tool_error(payload)
        if is_err:
            http_status = _extract_explicit_status(payload) or extract_http_status(err_text)
            if http_status is not None:
                base_meta["http_status"] = http_status
            sig = normalize_error_signature(err_text)
            msg = f"Tool {tool_name} failed: {sig}" if sig else f"Tool {tool_name} failed"
            return {
                "harness": harness,
                "agent_name": resolved_agent,
                "event_type": "tool_error",
                "severity": "WARNING",
                "message": msg,
                "metadata": base_meta,
            }
        base_meta["progress"] = True
        return {
            "harness": harness,
            "agent_name": resolved_agent,
            "event_type": "success",
            "severity": "INFO",
            "message": f"Tool {tool_name} succeeded",
            "metadata": base_meta,
        }

    # 3. Notification hook (capture rate-limit / quota warnings)
    if hook_event == "Notification":
        raw_text = " ".join(
            p
            for p in (
                _extract_text(payload.get("title")),
                _extract_text(payload.get("message")),
            )
            if p
        ).strip()
        if payload.get("notification_type"):
            base_meta["notification_type"] = str(payload["notification_type"])[:64]
        http_status = _extract_explicit_status(payload) or extract_http_status(raw_text)
        if http_status == 429 or detect_rate_limit(raw_text):
            base_meta["http_status"] = 429
            sig = normalize_error_signature(raw_text) or "Rate limit notification"
            return {
                "harness": harness,
                "agent_name": resolved_agent,
                "event_type": "rate_limit",
                "severity": "WARNING",
                "message": sig,
                "metadata": base_meta,
            }
        if not raw_text:
            return None
        return {
            "harness": harness,
            "agent_name": resolved_agent,
            "event_type": "info",
            "severity": "INFO",
            "message": normalize_error_signature(raw_text),
            "metadata": base_meta,
        }

    # 4. Stop / SubagentStop checkpoints
    if hook_event in {"Stop", "SubagentStop"}:
        raw_text = (
            _extract_text(payload.get("error"))
            or _extract_text(payload.get("last_assistant_message"))
            or _extract_text(payload.get("reason"))
        )
        http_status = _extract_explicit_status(payload) or extract_http_status(raw_text)
        if http_status == 429 or detect_rate_limit(raw_text):
            base_meta["http_status"] = 429
            return {
                "harness": harness,
                "agent_name": resolved_agent,
                "event_type": "rate_limit",
                "severity": "WARNING",
                "message": normalize_error_signature(raw_text) or f"{hook_event}: HTTP 429 rate limit",
                "metadata": base_meta,
            }
        return {
            "harness": harness,
            "agent_name": resolved_agent,
            "event_type": "info",
            "severity": "INFO",
            "message": f"Claude Code {hook_event} checkpoint",
            "metadata": base_meta,
        }

    # 5. Generic fallback for any custom/unknown hook event
    raw_err = _extract_text(payload.get("error"))
    if raw_err:
        base_meta["tool_name"] = tool_name
        http_status = _extract_explicit_status(payload) or extract_http_status(raw_err)
        if http_status is not None:
            base_meta["http_status"] = http_status
        return {
            "harness": harness,
            "agent_name": resolved_agent,
            "event_type": "tool_error",
            "severity": "WARNING",
            "message": f"Tool {tool_name} failed: {normalize_error_signature(raw_err)}",
            "metadata": base_meta,
        }
    return None


def render_claude_settings(script_path: Path | None = None) -> dict[str, Any]:
    """Return a ready-to-merge ~/.claude/settings.json hooks snippet."""
    resolved = str((script_path or Path(__file__).resolve()).resolve())
    cmd = f"python3 {resolved}"
    entry = [{"matcher": ".*", "hooks": [{"type": "command", "command": cmd, "timeout": 5}]}]
    simple = [{"hooks": [{"type": "command", "command": cmd, "timeout": 5}]}]
    return {
        "hooks": {
            "PostToolUseFailure": entry,
            "PostToolUse": entry,
            "Notification": simple,
            "SubagentStop": simple,
        }
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Claude Code hook emitter for NeuroSwarm (reads hook JSON from stdin)."
    )
    parser.add_argument("--server", default=None, help="NeuroSwarm server URL (default: SWARMCONTROL_SERVER)")
    parser.add_argument("--host-id", default=None, help="Host ID (default: SWARMCONTROL_HOST_ID or hostname)")
    parser.add_argument("--env-file", default=None, help="Path to agent.env (default: ~/.local/share/swarmcontrol/agent.env)")
    parser.add_argument("--harness", default="claude-code", help="Harness identifier (default: claude-code)")
    parser.add_argument("--agent-name", default=None, help="Override agent name")
    parser.add_argument("--task-id", default=None, help="Override metadata.task_id")
    parser.add_argument("--event", default=None, help="Fallback hook_event_name if missing in stdin JSON")
    parser.add_argument("--timeout", type=float, default=None, help="HTTP timeout in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Print event JSON to stdout without sending")
    parser.add_argument("--print-settings", action="store_true", help="Print ~/.claude/settings.json snippet and exit")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if stdin is invalid or delivery fails")
    parser.add_argument("--verbose", action="store_true", help="Log diagnostic messages to stderr")
    args = parser.parse_args(argv)

    if args.print_settings:
        print(json.dumps(render_claude_settings(), indent=2))
        return 0

    raw_stdin = sys.stdin.read().strip()
    if not raw_stdin:
        if args.verbose or args.strict:
            print("[swarmcontrol-claude-hook] empty stdin payload", file=sys.stderr)
        return 2 if args.strict else 0

    try:
        hook_payload = json.loads(raw_stdin)
    except json.JSONDecodeError as exc:
        if args.verbose or args.strict:
            print(f"[swarmcontrol-claude-hook] invalid JSON on stdin: {exc}", file=sys.stderr)
        return 2 if args.strict else 0

    if not isinstance(hook_payload, dict):
        if args.verbose or args.strict:
            print("[swarmcontrol-claude-hook] expected JSON object on stdin", file=sys.stderr)
        return 2 if args.strict else 0

    event_kwargs = translate_hook_payload(
        hook_payload,
        harness=args.harness,
        agent_name=args.agent_name,
        task_id=args.task_id,
        fallback_event=args.event,
    )
    if event_kwargs is None:
        return 0

    cfg = load_config(
        server=args.server,
        host_id=args.host_id,
        timeout=args.timeout,
        env_file=args.env_file,
    )
    client = SwarmEventClient(cfg)
    result = client.emit(**event_kwargs, dry_run=args.dry_run)

    if args.dry_run:
        print(json.dumps(result.payload, indent=2))
        return 0

    if not result.ok:
        if args.verbose or args.strict:
            print(f"[swarmcontrol-claude-hook] emit failed: {result.error}", file=sys.stderr)
        return 1 if args.strict else 0

    if args.verbose:
        print(f"[swarmcontrol-claude-hook] emitted {event_kwargs['event_type']} -> {result.response}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
