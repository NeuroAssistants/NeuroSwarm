#!/usr/bin/env python3
"""NeuroSwarm Lite Agent — passive, cross-platform telemetry & opt-in activity shipper."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import signal
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from activity_shipper import (  # noqa: E402
    _load_activity_core,
    chunk_activity_payload,
    collect_incremental_activity,
    collect_remote_activity_payload,
    parse_activity_roots,
    redact_local_text,
)
from detector import collect_host_snapshot, detect_os_platform  # noqa: E402


AGENT_VERSION = "0.3.0"
DEFAULT_MAX_REJECT_RETRIES = 3
MAX_PENDING_CHUNKS = 20
MAX_PENDING_BYTES = 4 * 1024 * 1024


class RejectedStepsError(RuntimeError):
    """Raised when the console refuses to commit offsets because steps were rejected."""

    def __init__(self, status_code: int, response: dict | None = None):
        resp = dict(response or {})
        self.status_code = status_code
        self.response = resp
        self.steps_rejected = int(resp.get("steps_rejected") or 0)
        self.clock_skew_sec = float(resp.get("clock_skew_sec") or 0.0)
        self.warnings = list(resp.get("warnings") or [])
        super().__init__(
            f"Server rejected {self.steps_rejected} step(s) (HTTP {status_code}, warnings={self.warnings})"
        )


def redact_local(text: str) -> str:
    return redact_local_text(text, max_len=500)


def post_json(url: str, token: str, payload: dict, timeout: int = 8) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": f"NeuroSwarm-Agent/{AGENT_VERSION}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw else {"ok": True}
    except urllib.error.HTTPError as exc:
        if exc.code == 422:
            raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            try:
                parsed = json.loads(raw) if raw else {}
            except ValueError:
                parsed = {"ok": False, "error": raw}
            raise RejectedStepsError(422, parsed if isinstance(parsed, dict) else {}) from exc
        raise


def build_harness_transition_events(snap: dict, prev_state: dict[str, tuple[str, int]]) -> list[dict]:
    """Emit OMi/SCOM transition events when a detected runtime starts or stops."""
    events: list[dict] = []
    for h in snap.get("harnesses") or []:
        hid = str(h.get("id") or "")
        hstatus = str(h.get("status") or "not_found")
        hpcount = int(h.get("process_count") or 0)
        if not hid:
            continue
        old = prev_state.get(hid)
        if old is not None and old[0] != hstatus and (old[0] == "running" or hstatus == "running"):
            ev_type = "harness_started" if hstatus == "running" else "harness_stopped"
            ev_msg = (
                f"Service Monitor: {h.get('name', hid)} active ({hpcount} process(es))"
                if hstatus == "running"
                else f"Service Monitor: {h.get('name', hid)} stopped (exit 0)"
            )
            events.append(
                {
                    "host_id": snap["host_id"],
                    "harness": hid,
                    "agent_name": "service-monitor",
                    "event_type": ev_type,
                    "severity": "INFO",
                    "message": ev_msg,
                    "metadata": {"previous_status": old[0], "new_status": hstatus, "process_count": hpcount},
                }
            )
        prev_state[hid] = (hstatus, hpcount)
    return events


def set_low_priority() -> None:
    """Keep observer strictly non-intrusive to running agent workloads."""
    try:
        os.nice(15)
    except (AttributeError, OSError):
        pass


def _write_json_atomic(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp_path, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _state_paths(state_dir: Path) -> tuple[Path, Path]:
    return state_dir / "capture_offsets.json", state_dir / "pending_activity_queue.json"


def _default_state() -> dict:
    return {
        "offsets": {},
        "skipped_srcs": {},
        "last_metrics": None,
        "last_error": "",
        "last_ship_ok_at": 0.0,
        "last_clock_skew_sec": 0.0,
        "last_rejected_steps": 0,
        "last_warnings": [],
        "last_capture_reader": "",
    }


def load_capture_state(state_dir: Path) -> dict:
    offsets_file, _ = _state_paths(state_dir)
    if not offsets_file.is_file():
        return _default_state()
    try:
        raw = json.loads(offsets_file.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            raw_skips = raw.get("skipped_srcs")
            skipped_srcs = (
                {str(k): int(v or 0) for k, v in raw_skips.items() if isinstance(k, str)}
                if isinstance(raw_skips, dict)
                else {}
            )
            return {
                "offsets": raw.get("offsets") if isinstance(raw.get("offsets"), dict) else {},
                "skipped_srcs": skipped_srcs,
                "last_metrics": raw.get("last_metrics") if isinstance(raw.get("last_metrics"), dict) else None,
                "last_error": str(raw.get("last_error") or ""),
                "last_ship_ok_at": float(raw.get("last_ship_ok_at") or 0.0),
                "last_clock_skew_sec": float(raw.get("last_clock_skew_sec") or 0.0),
                "last_rejected_steps": int(raw.get("last_rejected_steps") or 0),
                "last_warnings": list(raw.get("last_warnings") or []),
                "last_capture_reader": str(raw.get("last_capture_reader") or ""),
            }
    except (OSError, ValueError, TypeError):
        pass
    return _default_state()


def save_capture_state(state_dir: Path, state: dict) -> None:
    offsets_file, _ = _state_paths(state_dir)
    _write_json_atomic(offsets_file, state)


def load_pending_queue(state_dir: Path) -> list[dict]:
    _, queue_file = _state_paths(state_dir)
    if not queue_file.is_file():
        return []
    try:
        raw = json.loads(queue_file.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, dict) and isinstance(item.get("chunks"), list)]
    except (OSError, ValueError):
        pass
    return []


def save_pending_queue(state_dir: Path, queue: list[dict]) -> None:
    _, queue_file = _state_paths(state_dir)
    trimmed = list(queue)
    while trimmed and (
        sum(len(e.get("chunks") or []) for e in trimmed) > MAX_PENDING_CHUNKS
        or len(json.dumps(trimmed).encode("utf-8")) > MAX_PENDING_BYTES
    ):
        trimmed.pop(0)
    if not trimmed:
        try:
            queue_file.unlink(missing_ok=True)
        except OSError:
            pass
        return
    _write_json_atomic(queue_file, trimmed)


def _extract_gap_file_key(chunks: list[dict]) -> str:
    for chunk in chunks:
        for sess in chunk.get("sessions") or []:
            for st in sess.get("capture_steps") or sess.get("steps") or []:
                src = st.get("src")
                if isinstance(src, str) and ":" in src:
                    return src.split(":", 1)[0]
    return ""


def _post_with_commit_check(poster, endpoint: str, token: str, chunk: dict) -> dict:
    resp = poster(endpoint, token, chunk)
    if isinstance(resp, dict) and (resp.get("commit_offsets") is False or int(resp.get("steps_rejected") or 0) > 0):
        raise RejectedStepsError(200, resp)
    return resp


def _emit_rejected_gap(poster, endpoint: str, token: str, base_chunk: dict, fk: str, attempts: int, rejected_n: int) -> None:
    gap_payload = {
        "schema_version": base_chunk.get("schema_version", "1.0"),
        "host_id": base_chunk["host_id"],
        "hostname": base_chunk.get("hostname", base_chunk["host_id"]),
        "os_name": base_chunk.get("os_name", "unknown"),
        "arch": base_chunk.get("arch", "unknown"),
        "collected_at": time.time(),
        "activity_enabled": bool(base_chunk.get("activity_enabled", True)),
        "activity_roots": list(base_chunk.get("activity_roots") or []),
        "harnesses": [],
        "sessions": [],
        "workspaces": [],
        "map_update": False,
        "capture_gaps": [
            {
                "file": fk,
                "reason": f"skipped permanently rejected steps after {attempts} attempt(s) ({rejected_n} step(s))",
            }
        ],
    }
    try:
        poster(endpoint, token, gap_payload)
    except Exception:
        pass


def _record_skipped_srcs(skipped: dict[str, int], chunks: list[dict], target_offsets: dict) -> dict[str, int]:
    """Remember poisoned step src keys alongside file inode so 256 KiB overlap does not re-send them."""
    updated = dict(skipped)
    for chunk in chunks:
        for sess in chunk.get("sessions") or []:
            for st in (sess.get("capture_steps") or []) + (sess.get("steps") or []):
                src = st.get("src") if isinstance(st, dict) else None
                if isinstance(src, str) and ":" in src:
                    fk = src.split(":", 1)[0]
                    ino = int(((target_offsets.get(fk) or {}) if isinstance(target_offsets.get(fk), dict) else {}).get("inode") or 0)
                    updated[src] = ino
    if len(updated) > 500:
        keep_keys = list(updated.keys())[-500:]
        updated = {k: updated[k] for k in keep_keys}
    return updated


def _filter_skipped_payload(payload: dict, skipped: dict[str, int], offsets: dict) -> tuple[dict, dict[str, int]]:
    """Strip previously skipped poisoned src keys still inside overlap unless the file rotated or changed inode."""
    if not skipped:
        return payload, skipped
    gap_fks = {
        str(g.get("file") or "")
        for g in (payload.get("capture_gaps") or [])
        if isinstance(g, dict) and g.get("file")
    }
    cleaned_skips = dict(skipped)
    for src in list(cleaned_skips.keys()):
        fk = src.split(":", 1)[0]
        cur_state = offsets.get(fk) if isinstance(offsets.get(fk), dict) else None
        cur_ino = int((cur_state or {}).get("inode") or 0)
        if fk in gap_fks or (cur_state is not None and cur_ino != cleaned_skips[src]):
            cleaned_skips.pop(src, None)
    if not cleaned_skips:
        return payload, cleaned_skips

    def _keep(st: dict) -> bool:
        src = st.get("src") if isinstance(st, dict) else None
        return not (isinstance(src, str) and src in cleaned_skips)

    new_sessions = []
    for sess in payload.get("sessions") or []:
        s_copy = dict(sess)
        if isinstance(s_copy.get("capture_steps"), list):
            s_copy["capture_steps"] = [st for st in s_copy["capture_steps"] if _keep(st)]
        if isinstance(s_copy.get("steps"), list):
            s_copy["steps"] = [st for st in s_copy["steps"] if _keep(st)]
        la = s_copy.get("latest_action")
        if isinstance(la, dict) and not _keep(la):
            s_copy["latest_action"] = s_copy["steps"][-1] if s_copy.get("steps") else None
        new_sessions.append(s_copy)
    return {**payload, "sessions": new_sessions}, cleaned_skips


def ship_activity_once(
    server: str,
    token: str,
    raw_roots: str | list[str] | None,
    host_id: str | None,
    state_dir: Path,
    home_dir: Path | None = None,
    ceiling: int | None = None,
    poster=post_json,
    use_core: bool | None = None,
    max_reject_retries: int | None = None,
) -> dict:
    """Drain any queued chunks and ship one incremental scan; commit offsets only after HTTP 2xx with commit_offsets."""
    endpoint = f"{server.rstrip('/')}/api/v1/ingest/activity"
    state = load_capture_state(state_dir)
    offsets = dict(state.get("offsets") or {})
    skipped_srcs = dict(state.get("skipped_srcs") or {})
    queue = load_pending_queue(state_dir)
    reject_cap = max(
        1,
        int(
            max_reject_retries
            if max_reject_retries is not None
            else os.environ.get("SWARMCONTROL_MAX_REJECT_RETRIES", DEFAULT_MAX_REJECT_RETRIES)
        ),
    )

    chunks_sent = 0
    steps_persisted = 0
    last_resp: dict = {}

    while queue:
        entry = queue[0]
        chunks = list(entry.get("chunks") or [])
        skip_poison = False
        for idx, chunk in enumerate(chunks):
            try:
                resp = _post_with_commit_check(poster, endpoint, token, chunk)
            except RejectedStepsError as exc:
                retries = int(entry.get("reject_retries") or 0) + 1
                entry["reject_retries"] = retries
                entry["chunks"] = chunks[idx:]
                if retries >= reject_cap:
                    fk = _extract_gap_file_key(chunks[idx:])
                    _emit_rejected_gap(poster, endpoint, token, chunk, fk, retries, exc.steps_rejected)
                    queue.pop(0)
                    offsets = dict(entry.get("target_offsets") or offsets)
                    skipped_srcs = _record_skipped_srcs(skipped_srcs, [chunk], offsets)
                    state = {
                        "offsets": offsets,
                        "skipped_srcs": skipped_srcs,
                        "last_metrics": entry.get("metrics") or state.get("last_metrics"),
                        "last_error": str(exc),
                        "last_ship_ok_at": time.time(),
                        "last_clock_skew_sec": exc.clock_skew_sec,
                        "last_rejected_steps": exc.steps_rejected,
                        "last_warnings": exc.warnings,
                        "last_capture_reader": str(chunk.get("capture_reader") or state.get("last_capture_reader") or ""),
                    }
                    save_pending_queue(state_dir, queue)
                    save_capture_state(state_dir, state)
                    skip_poison = True
                    break
                save_pending_queue(state_dir, queue)
                save_capture_state(
                    state_dir,
                    {
                        **state,
                        "skipped_srcs": skipped_srcs,
                        "last_error": str(exc),
                        "last_clock_skew_sec": exc.clock_skew_sec,
                        "last_rejected_steps": exc.steps_rejected,
                        "last_warnings": exc.warnings,
                    },
                )
                raise
            except Exception as exc:
                entry["chunks"] = chunks[idx:]
                save_pending_queue(state_dir, queue)
                save_capture_state(state_dir, {**state, "last_error": str(exc)})
                raise
            chunks_sent += 1
            steps_persisted += int(resp.get("steps_persisted") or 0)
            last_resp = resp
        if skip_poison:
            continue
        queue.pop(0)
        offsets = dict(entry.get("target_offsets") or offsets)
        state = {
            "offsets": offsets,
            "skipped_srcs": skipped_srcs,
            "last_metrics": entry.get("metrics") or state.get("last_metrics"),
            "last_error": "",
            "last_ship_ok_at": time.time(),
            "last_clock_skew_sec": float(last_resp.get("clock_skew_sec") or 0.0),
            "last_rejected_steps": 0,
            "last_warnings": list(last_resp.get("warnings") or []),
            "last_capture_reader": str(last_resp.get("capture_reader") or state.get("last_capture_reader") or ""),
        }
        save_pending_queue(state_dir, queue)
        save_capture_state(state_dir, state)

    payload, next_offsets, has_backlog = collect_incremental_activity(
        raw_roots=raw_roots,
        host_id=host_id,
        home_dir=home_dir,
        offsets=offsets,
        ceiling=ceiling,
        use_core=use_core,
    )
    if payload is None:
        return {
            "ok": True,
            "activity_enabled": False,
            "chunks_sent": chunks_sent,
            "steps_persisted": steps_persisted,
            "has_backlog": False,
        }

    payload, skipped_srcs = _filter_skipped_payload(payload, skipped_srcs, next_offsets)
    chunks = chunk_activity_payload(payload)
    for idx, chunk in enumerate(chunks):
        try:
            resp = _post_with_commit_check(poster, endpoint, token, chunk)
        except RejectedStepsError as exc:
            if reject_cap <= 1:
                fk = _extract_gap_file_key(chunks[idx:])
                _emit_rejected_gap(poster, endpoint, token, chunk, fk, 1, exc.steps_rejected)
                skipped_srcs = _record_skipped_srcs(skipped_srcs, chunks[idx:], next_offsets)
                save_capture_state(
                    state_dir,
                    {
                        "offsets": next_offsets,
                        "skipped_srcs": skipped_srcs,
                        "last_metrics": payload.get("capture_metrics"),
                        "last_error": str(exc),
                        "last_ship_ok_at": time.time(),
                        "last_clock_skew_sec": exc.clock_skew_sec,
                        "last_rejected_steps": exc.steps_rejected,
                        "last_warnings": exc.warnings,
                        "last_capture_reader": str(payload.get("capture_reader") or ""),
                    },
                )
                return {
                    "ok": False,
                    "activity_enabled": True,
                    "chunks_sent": chunks_sent,
                    "steps_persisted": steps_persisted,
                    "has_backlog": has_backlog,
                    "skipped_rejected": True,
                    "capture_reader": payload.get("capture_reader") or "unknown",
                    "warnings": exc.warnings,
                }
            queue.append(
                {
                    "chunks": chunks[idx:],
                    "target_offsets": next_offsets,
                    "metrics": payload.get("capture_metrics"),
                    "queued_at": time.time(),
                    "reject_retries": 1,
                }
            )
            save_pending_queue(state_dir, queue)
            save_capture_state(
                state_dir,
                {
                    **state,
                    "skipped_srcs": skipped_srcs,
                    "last_error": str(exc),
                    "last_clock_skew_sec": exc.clock_skew_sec,
                    "last_rejected_steps": exc.steps_rejected,
                    "last_warnings": exc.warnings,
                    "last_capture_reader": str(payload.get("capture_reader") or state.get("last_capture_reader") or ""),
                },
            )
            raise
        except Exception as exc:
            queue.append(
                {
                    "chunks": chunks[idx:],
                    "target_offsets": next_offsets,
                    "metrics": payload.get("capture_metrics"),
                    "queued_at": time.time(),
                }
            )
            save_pending_queue(state_dir, queue)
            save_capture_state(
                state_dir,
                {
                    **state,
                    "skipped_srcs": skipped_srcs,
                    "last_error": str(exc),
                    "last_capture_reader": str(payload.get("capture_reader") or state.get("last_capture_reader") or ""),
                },
            )
            raise
        chunks_sent += 1
        steps_persisted += int(resp.get("steps_persisted") or 0)
        last_resp = resp

    save_capture_state(
        state_dir,
        {
            "offsets": next_offsets,
            "skipped_srcs": skipped_srcs,
            "last_metrics": payload.get("capture_metrics"),
            "last_error": "",
            "last_ship_ok_at": time.time(),
            "last_clock_skew_sec": float(last_resp.get("clock_skew_sec") or 0.0),
            "last_rejected_steps": 0,
            "last_warnings": list(last_resp.get("warnings") or []),
            "last_capture_reader": str(payload.get("capture_reader") or ""),
        },
    )
    return {
        "ok": True,
        "activity_enabled": True,
        "chunks_sent": chunks_sent,
        "steps_persisted": steps_persisted,
        "has_backlog": has_backlog,
        "capture_reader": payload.get("capture_reader") or "unknown",
        "capture_metrics": payload.get("capture_metrics"),
        "warnings": list(last_resp.get("warnings") or []),
        "last_response": last_resp,
    }


def build_diagnose_report(
    raw_roots: str | list[str] | None,
    host_id: str | None,
    state_dir: Path,
    home_dir: Path | None = None,
) -> dict:
    """Return non-mutating diagnostics about local incremental capture state and pending backlog."""
    state = load_capture_state(state_dir)
    queue = load_pending_queue(state_dir)
    roots = parse_activity_roots(raw_roots)
    core_mod = _load_activity_core()
    resolved_host = (
        host_id
        or os.environ.get("SWARMCONTROL_HOST_ID")
        or (os.uname().nodename if hasattr(os, "uname") else platform.node())
    )
    capture_reader = "core" if core_mod is not None else "fallback"
    fallback_reason = "" if core_mod is not None else "activity_core_missing"

    dry_scan = None
    dry_scan_error = ""
    if roots:
        try:
            payload, _, has_backlog = collect_incremental_activity(
                raw_roots=raw_roots,
                host_id=resolved_host,
                home_dir=home_dir,
                offsets=state.get("offsets") or {},
            )
            if payload is not None:
                capture_reader = payload.get("capture_reader") or capture_reader
                fallback_reason = payload.get("fallback_reason") or fallback_reason
                dry_scan = {
                    "sessions": len(payload.get("sessions") or []),
                    "has_backlog": has_backlog,
                    "metrics": payload.get("capture_metrics"),
                    "gaps": len(payload.get("capture_gaps") or []),
                }
        except Exception as exc:
            dry_scan_error = str(exc)

    out = {
        "host_id": resolved_host,
        "os_name": detect_os_platform(),
        "arch": platform.machine() or "unknown",
        "agent_version": AGENT_VERSION,
        "state_dir": str(state_dir),
        "activity_core_loaded": core_mod is not None,
        "capture_reader": capture_reader,
        "last_capture_reader": state.get("last_capture_reader") or "",
        "fallback_reason": fallback_reason,
        "activity_roots": [str(r) for r in roots],
        "offsets_count": len(state.get("offsets") or {}),
        "pending_queue_batches": len(queue),
        "pending_queue_chunks": sum(len(e.get("chunks") or []) for e in queue),
        "last_metrics": state.get("last_metrics"),
        "last_clock_skew_sec": state.get("last_clock_skew_sec") or 0.0,
        "last_rejected_steps": state.get("last_rejected_steps") or 0,
        "last_warnings": state.get("last_warnings") or [],
        "last_error": state.get("last_error") or "",
        "last_ship_ok_at": state.get("last_ship_ok_at") or 0.0,
        "share_commands": os.environ.get("SWARMCONTROL_SHARE_COMMANDS") == "1",
        "share_command_output": os.environ.get("SWARMCONTROL_SHARE_COMMAND_OUTPUT") == "1",
        "share_file_previews": os.environ.get("SWARMCONTROL_SHARE_FILE_PREVIEWS") == "1",
        "dry_scan": dry_scan,
    }
    if dry_scan_error:
        out["dry_scan_error"] = dry_scan_error
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="NeuroSwarm Lite Agent (passive read-only observer)")
    parser.add_argument("--server", default=os.environ.get("SWARMCONTROL_SERVER", "http://127.0.0.1:8790"))
    parser.add_argument("--token", default=os.environ.get("SWARMCONTROL_TOKEN", ""))
    parser.add_argument("--host-id", default=os.environ.get("SWARMCONTROL_HOST_ID", ""))
    parser.add_argument("--interval", type=int, default=int(os.environ.get("SWARMCONTROL_INTERVAL", "15")))
    parser.add_argument(
        "--activity-roots",
        default=os.environ.get("SWARMCONTROL_ACTIVITY_ROOTS", ""),
        help="Opt-in folder roots for redacted session/plan/file activity shipping (colon/comma separated)",
    )
    parser.add_argument(
        "--agent-labels",
        default=os.environ.get("SWARMCONTROL_AGENT_LABELS", ""),
        help="Optional folder=Name mappings for agent attribution in activity snapshots",
    )
    parser.add_argument(
        "--share-commands",
        action="store_true",
        default=os.environ.get("SWARMCONTROL_SHARE_COMMANDS") == "1",
        help="Opt-in to include locally-redacted command lines (<=160 chars) in activity snapshots",
    )
    parser.add_argument(
        "--share-command-output",
        action="store_true",
        default=os.environ.get("SWARMCONTROL_SHARE_COMMAND_OUTPUT") == "1",
        help="Opt-in to include bounded, locally-redacted command outputs (<=4096 chars) in incremental capture",
    )
    parser.add_argument(
        "--share-file-previews",
        action="store_true",
        default=os.environ.get("SWARMCONTROL_SHARE_FILE_PREVIEWS") == "1",
        help="Opt-in to include inert raster image previews (PNG/JPEG/GIF/WebP <=160 KiB) and redacted text excerpts for confirmed file reads",
    )
    default_state_dir = (
        Path(os.environ["LOCALAPPDATA"]) / "SwarmControl" / "state"
        if os.name == "nt" and os.environ.get("LOCALAPPDATA")
        else Path.home() / ".local" / "state" / "swarmcontrol"
    )
    parser.add_argument(
        "--state-dir",
        default=os.environ.get("SWARMCONTROL_STATE_DIR") or str(default_state_dir),
        help="Directory for atomic capture_offsets.json and bounded pending retry queue",
    )
    parser.add_argument(
        "--diagnose",
        action="store_true",
        help="Print read-only incremental capture status, offsets count, and queue summary as JSON",
    )
    parser.add_argument("--once", action="store_true", help="Send a single heartbeat (and activity if roots set) and exit")
    parser.add_argument("--dry-run", action="store_true", help="Print heartbeat snapshot JSON without sending")
    parser.add_argument(
        "--preview-activity",
        action="store_true",
        help="Print locally-redacted activity payload JSON for --activity-roots without sending",
    )
    parser.add_argument("--emit-event", action="store_true", help="Send a single structured event and exit")
    parser.add_argument("--harness", default="generic")
    parser.add_argument("--agent-name", default="worker")
    parser.add_argument("--event-type", default="info")
    parser.add_argument("--severity", default="INFO")
    parser.add_argument("--message", default="")
    args = parser.parse_args()

    set_low_priority()
    server = args.server.rstrip("/")

    if args.activity_roots:
        os.environ["SWARMCONTROL_ACTIVITY_ROOTS"] = args.activity_roots
    if args.agent_labels:
        os.environ["SWARMCONTROL_AGENT_LABELS"] = args.agent_labels
    if args.share_commands:
        os.environ["SWARMCONTROL_SHARE_COMMANDS"] = "1"
    if args.share_command_output:
        os.environ["SWARMCONTROL_SHARE_COMMAND_OUTPUT"] = "1"
    if args.share_file_previews:
        os.environ["SWARMCONTROL_SHARE_FILE_PREVIEWS"] = "1"

    state_dir_path = Path(args.state_dir or str(default_state_dir))

    if args.diagnose:
        report = build_diagnose_report(
            raw_roots=args.activity_roots,
            host_id=args.host_id or None,
            state_dir=state_dir_path,
        )
        print(json.dumps(report, indent=2))
        return 0

    if args.preview_activity:
        act_payload = collect_remote_activity_payload(
            raw_roots=args.activity_roots,
            host_id=args.host_id or None,
        )
        print(
            json.dumps(
                act_payload
                or {
                    "activity_shipping": "disabled",
                    "reason": "No valid directories configured in --activity-roots / SWARMCONTROL_ACTIVITY_ROOTS",
                },
                indent=2,
            )
        )
        return 0

    if args.dry_run:
        snap = collect_host_snapshot(agent_version=AGENT_VERSION, host_id=args.host_id or None)
        print(json.dumps(snap, indent=2))
        return 0

    if not args.token:
        print(
            "ERROR: SWARMCONTROL_TOKEN (preferred) or --token is required (or use --dry-run / --preview-activity).",
            file=sys.stderr,
        )
        return 2

    if server.startswith("http://") and not re.match(r"^http://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$", server):
        print(
            f"[swarmcontrol-agent] WARNING: {server} is not HTTPS; the token travels in clear text.",
            file=sys.stderr,
            flush=True,
        )

    if args.emit_event:
        snap = collect_host_snapshot(agent_version=AGENT_VERSION, host_id=args.host_id or None)
        ev_payload = {
            "host_id": snap["host_id"],
            "harness": args.harness,
            "agent_name": args.agent_name,
            "event_type": args.event_type,
            "severity": args.severity,
            "message": redact_local(args.message),
            "metadata": {"source": "cli-hook"},
        }
        res = post_json(f"{server}/api/v1/ingest/event", args.token, ev_payload)
        print(json.dumps(res))
        return 0

    stop = False
    prev_harness_state: dict[str, tuple[str, int]] = {}

    def _handle_sig(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _handle_sig)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_sig)

    while not stop:
        snap = collect_host_snapshot(agent_version=AGENT_VERSION, host_id=args.host_id or None)
        snap["capture_reader"] = "core" if _load_activity_core() is not None else "fallback"
        if snap["capture_reader"] == "fallback":
            snap["fallback_reason"] = "activity_core_missing"
        try:
            res = post_json(f"{server}/api/v1/ingest/heartbeat", args.token, snap)
            for transition_ev in build_harness_transition_events(snap, prev_harness_state):
                try:
                    post_json(f"{server}/api/v1/ingest/event", args.token, transition_ev)
                except Exception:
                    pass
            if args.activity_roots:
                try:
                    ship_res = ship_activity_once(
                        server=server,
                        token=args.token,
                        raw_roots=args.activity_roots,
                        host_id=snap["host_id"],
                        state_dir=state_dir_path,
                    )
                    if ship_res.get("activity_enabled"):
                        res["activity_ingested"] = ship_res.get("last_response") or ship_res
                except urllib.error.HTTPError as act_err:
                    # Server may not have /api/v1/ingest/activity wired yet; fail-open so heartbeats continue
                    res["activity_warning"] = f"HTTP {act_err.code}"
                    print(f"[swarmcontrol-agent] activity HTTP {act_err.code}: {act_err}", file=sys.stderr, flush=True)
                except Exception as act_exc:
                    res["activity_warning"] = str(act_exc)
                    print(f"[swarmcontrol-agent] activity warning: {act_exc}", file=sys.stderr, flush=True)
            if args.once:
                print(json.dumps(res))
                return 0
        except urllib.error.URLError as exc:
            print(f"[swarmcontrol-agent] heartbeat error: {exc}", file=sys.stderr, flush=True)
            if args.once:
                return 1
        except Exception as exc:
            print(f"[swarmcontrol-agent] unexpected error: {exc}", file=sys.stderr, flush=True)
            if args.once:
                return 1

        sleep_for = max(5, args.interval)
        for _ in range(sleep_for):
            if stop:
                break
            time.sleep(1)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
