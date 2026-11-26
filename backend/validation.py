"""Strict input sanitation for agent telemetry (heartbeats and events).

Every value that reaches SQLite, the guardrail engine or the web console passes
through here first. Unknown keys are dropped, strings are length-capped, numbers
must be finite and inside plausible bounds, and list sizes are capped so a single
compromised token cannot bloat the database or break the console renderer.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

HOST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
WORKSPACE_LABEL_RE = re.compile(r"[A-Za-z0-9._-]{1,64}(?:/[A-Za-z0-9._-]{1,64}){0,3}")
MAX_HARNESSES = 32
MAX_PROCESSES = 200
MAX_EVIDENCE = 8
MAX_EVENT_METADATA_BYTES = 8 * 1024
ALLOWED_SEVERITIES = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class ValidationError(ValueError):
    """Raised when a telemetry payload is malformed; message is safe to return to clients."""


def _text(value: Any, max_len: int, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        raise ValidationError("Expected a scalar value")
    text = str(value)
    # Strip control characters except tab; keeps logs and the console sane.
    text = "".join(ch for ch in text if ch == "\t" or ord(ch) >= 32)
    return text[:max_len] if text else default


def _num(value: Any, name: str, lo: float, hi: float, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise ValidationError(f"{name} must be a number")
    try:
        num = float(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{name} must be a number") from None
    if not math.isfinite(num):
        raise ValidationError(f"{name} must be finite")
    return min(max(num, lo), hi)


def _int(value: Any, name: str, lo: int, hi: int, default: int = 0) -> int:
    return int(_num(value, name, lo, hi, default))


def validate_host_id(value: Any) -> str:
    if not isinstance(value, str) or not HOST_ID_RE.match(value):
        raise ValidationError(
            "host_id is required: 1-128 chars, letters, digits and . _ : @ - (must start alphanumeric)"
        )
    return value


def _clean_harness(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValidationError("harnesses must be a list of objects")
    evidence = raw.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
    out: dict[str, Any] = {
        "id": _text(raw.get("id"), 64, "unknown"),
        "name": _text(raw.get("name"), 64, "unknown"),
        "status": _text(raw.get("status"), 16, "installed").lower(),
        "process_count": _int(raw.get("process_count"), "process_count", 0, 100_000),
        "cpu_pct": _num(raw.get("cpu_pct"), "cpu_pct", 0.0, 100_000.0),
        "rss_mb": _num(raw.get("rss_mb"), "rss_mb", 0.0, 1e9),
        "evidence": [_text(e, 256) for e in evidence[:MAX_EVIDENCE]],
    }
    if raw.get("workspace_agents") is not None:
        out["workspace_agents"] = _int(raw.get("workspace_agents"), "workspace_agents", 0, 1_000_000)
    return out


def _clean_process(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValidationError("processes must be a list of objects")
    proc = {
        "pid": _int(raw.get("pid"), "pid", 0, 2**31 - 1),
        "user": _text(raw.get("user"), 64),
        "comm": _text(raw.get("comm"), 64, "unknown"),
        "cpu_pct": _num(raw.get("cpu_pct"), "cpu_pct", 0.0, 100_000.0),
        "rss_mb": _num(raw.get("rss_mb"), "rss_mb", 0.0, 1e9),
        "uptime_sec": _int(raw.get("uptime_sec"), "uptime_sec", 0, 10**10),
        "harness": _text(raw.get("harness"), 64),
    }
    # A workspace is a short relative label chosen by the agent (e.g. "projects/api"),
    # never an absolute path: 1-4 segments of letters, digits, dot, dash or underscore.
    workspace = raw.get("workspace")
    if isinstance(workspace, str) and WORKSPACE_LABEL_RE.fullmatch(workspace) and ".." not in workspace.split("/"):
        proc["workspace"] = workspace
    return proc


def sanitize_heartbeat(body: dict[str, Any]) -> dict[str, Any]:
    host_id = validate_host_id(body.get("host_id"))
    harnesses = body.get("harnesses", [])
    processes = body.get("processes", [])
    if not isinstance(harnesses, list) or not isinstance(processes, list):
        raise ValidationError("harnesses and processes must be lists")
    if len(harnesses) > MAX_HARNESSES:
        raise ValidationError(f"Too many harnesses (max {MAX_HARNESSES})")
    if len(processes) > MAX_PROCESSES:
        raise ValidationError(f"Too many processes (max {MAX_PROCESSES})")
    return {
        "host_id": host_id,
        "hostname": _text(body.get("hostname"), 253, host_id),
        "os_name": _text(body.get("os_name"), 32, "unknown"),
        "arch": _text(body.get("arch"), 32, "unknown"),
        "agent_version": _text(body.get("agent_version"), 32, "unknown"),
        "cpu_count": _int(body.get("cpu_count"), "cpu_count", 1, 4096, 1),
        "load_1m": _num(body.get("load_1m"), "load_1m", 0.0, 1e6),
        "mem_total_mb": _num(body.get("mem_total_mb"), "mem_total_mb", 0.0, 1e9),
        "mem_used_mb": _num(body.get("mem_used_mb"), "mem_used_mb", 0.0, 1e9),
        "agent_rss_mb": _num(body.get("agent_rss_mb"), "agent_rss_mb", 0.0, 1e6),
        "scan_duration_ms": _num(body.get("scan_duration_ms"), "scan_duration_ms", 0.0, 1e7),
        "harnesses": [_clean_harness(h) for h in harnesses],
        "processes": [_clean_process(p) for p in processes],
    }


def sanitize_event(body: dict[str, Any]) -> dict[str, Any]:
    host_id = validate_host_id(body.get("host_id"))
    metadata = body.get("metadata", {})
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, dict):
        raise ValidationError("metadata must be a JSON object")
    try:
        encoded = json.dumps(metadata, allow_nan=False)
    except ValueError:
        raise ValidationError("metadata must not contain NaN or Infinity") from None
    if len(encoded.encode("utf-8")) > MAX_EVENT_METADATA_BYTES:
        raise ValidationError(f"metadata too large (max {MAX_EVENT_METADATA_BYTES} bytes)")
    event_type = _text(body.get("event_type"), 64, "info")
    if event_type in {"agent_message", "decision", "blocker", "memory_saved"}:
        # These reports carry explicitly shared prose only. Unknown metadata can contain private runtime traces.
        fields = {"workspace": 192, "method": 160, "mission_id": 96, "task_id": 96, "to_agent": 64, "reason": 500}
        clean = {k: _text(metadata[k], limit) for k, limit in fields.items() if isinstance(metadata.get(k), str)}
        if isinstance(metadata.get("files"), list):
            clean["files"] = [_text(path, 320) for path in metadata["files"][:12] if isinstance(path, str)]
        metadata = clean
    severity = _text(body.get("severity"), 16, "INFO").upper()
    if severity not in ALLOWED_SEVERITIES:
        severity = "INFO"
    return {
        "host_id": host_id,
        "harness": _text(body.get("harness"), 64, "unknown"),
        "agent_name": _text(body.get("agent_name"), 128, "unknown"),
        "event_type": event_type,
        "severity": severity,
        "message": _text(body.get("message"), 1000),
        "metadata": metadata,
    }
