"""Remote Activity Ingestion, Sanitization & Multi-Host Tenant Aggregation.

See REMOTE-CONTRACT.md for the observer protocol.
Provides drop-in helpers for backend/server.py and backend/db.py without modifying
those files directly:
- ensure_remote_activity_table(db)
- sanitize_activity_payload(body)
- ingest_remote_activity(db, body)
- build_tenant_activity_map(db, local_fallback=None)
"""

from __future__ import annotations

import datetime
import hashlib
import json
import math
import re
import time
from collections import Counter
from typing import Any

import step_journal
from activity_inspector import mask_evidence_paths
from event_evidence import SOURCE_POSITION as SRC_RE
from validation import ValidationError, validate_host_id

MAX_ACTIVITY_SESSIONS = 200
MAX_ACTIVITY_WORKSPACES = 30
MAX_ACTIVITY_HARNESSES = 32
MAX_ACTIVITY_STEPS = 20
MAX_CAPTURE_STEPS_PER_SESSION = 2000
MAX_CAPTURE_STEPS_TOTAL = 2000
MAX_CAPTURE_GAPS = 100
MAX_ACTIVITY_PLAN_ITEMS = 20
MAX_ACTIVITY_FILES = 25
STEP_RETENTION_SEC = step_journal.RETENTION

SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{4,64}$")

CATEGORY_LABEL = {
    "file_edit": "Edit files",
    "shell": "Run commands",
    "shell_exec": "Run commands",
    "file_read": "Read files",
    "web": "Browse & search",
    "web_research": "Browse & search",
    "coordination": "Coordinate work",
    "visual": "Generate visuals",
    "visual_asset": "Generate visuals",
    "plan": "Plan work",
    "think": "Reason",
    "other": "Other tools",
}

# Reuse step classification constants from step_journal rather than duplicating mappings
CANONICAL_CATEGORY = step_journal.CANONICAL_CATEGORY
JOURNAL_ACTIONS = step_journal.ACTIONS
SAFE_SHELL_LABELS = step_journal.COMMANDS
PROGRAM_RE = step_journal.PROGRAM_RE
SENSITIVE_DIRS = {".vault", "vault", "agent-api-keys", ".farm-connector", ".beszel-access", ".ssh", ".gnupg"}
SENSITIVE_FILE_RE = re.compile(
    r"(?i)(?:^\.env(?:\.|$)|auth\.json$|credentials?\.json$|operator-password$|server-password$|\.pw$|"
    r"admin_credentials|id_rsa|id_ed25519|ssh_ed25519|\.(?:pem|key|p12|pfx|kdbx)$|^cookies(?:\.|$)|"
    r"(?:^|[._-])(?:secret|secrets|passwd|password|credential|credentials|api[_-]?key)(?:$|[._-])|"
    r"(?:^|[._-])token\.(?:txt|json|env|key|secret)$|oauth-token$)"
)

SERVER_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("swarmcontrol_token", re.compile(r"\bsc_(?:live|tok|ro)_[A-Za-z0-9_-]{8,}")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{25,}")),
    ("xai_key", re.compile(r"\bxai-[A-Za-z0-9_-]{20,}")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{20,}")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{20,}")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("url_credentials", re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)")),
]

INLINE_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pass|secret|api[_-]?key|token|admin[_-]?pass|session[_-]?secret)"
    r"(\s*[:=]\s*)(['\"]?)([^\s'\",;]{6,})"
)

CLI_SECRET_RE = re.compile(
    r"(?i)((?:^|\s)(?:-u|-p|--user|--password|--passwd|--pass|--token|--secret|--api[-_]?key|--auth|--header|-H)\s+)"
    r"(?:\"[^\"]*\"|'[^']*'|\S+)"
)


def is_sensitive_path(path_str: str) -> bool:
    parts = [p for p in re.split(r"[\\/]+", str(path_str or "").strip()) if p]
    if not parts:
        return False
    if any(part.lower() in SENSITIVE_DIRS for part in parts):
        return True
    return bool(SENSITIVE_FILE_RE.search(parts[-1]))


def _redact_str(value: Any, max_len: int = 240, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        raise ValidationError("Expected a scalar string value")
    text = "".join(ch for ch in str(value) if ch == "\t" or ord(ch) >= 32).strip()
    if not text:
        return default
    for name, pat in SERVER_SECRET_PATTERNS:
        text = pat.sub(f"[redacted:{name}]", text)
    text = INLINE_SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", text)
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def _redact_command(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        raise ValidationError("Expected a scalar string value")
    text = "".join(ch for ch in str(value) if ch == "\t" or ord(ch) >= 32).strip()
    if not text:
        return ""
    text = CLI_SECRET_RE.sub(r"\1[redacted]", text)
    text = _redact_str(text, 4000)
    text = mask_evidence_paths(text)
    return text if len(text) <= 160 else text[:159].rstrip() + "…"


def _command_form(program: Any, raw: Any) -> str | None:
    if not isinstance(raw, str) or not isinstance(program, str):
        return None
    words = raw.split()
    for form in COMMAND_FORMS.get(program, ()):
        expected = [program, *form.split()]
        if words[: len(expected)] == expected:
            return " ".join(expected)
    return None


def _num(value: Any, lo: float, hi: float, default: float = 0.0) -> float:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise ValidationError("Expected numeric value")
    try:
        n = float(value)
    except (TypeError, ValueError):
        raise ValidationError("Expected numeric value") from None
    if not math.isfinite(n):
        raise ValidationError("Numeric value must be finite")
    return min(max(n, lo), hi)


def _int(value: Any, lo: int, hi: int, default: int = 0) -> int:
    return int(_num(value, lo, hi, default))


def _clean_path_list(items: Any, limit: int = MAX_ACTIVITY_FILES) -> list[str]:
    if not isinstance(items, list):
        return []
    out: list[str] = []
    for raw in items[:limit]:
        s = _redact_str(raw, 320)
        if s and not is_sensitive_path(s) and s not in out:
            out.append(s)
    return out


def _clean_step(raw: Any, *, capture=False) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    step: dict[str, Any] = {
        "tool": _redact_str(raw.get("tool"), 64, "tool"),
        "category": _redact_str(raw.get("category"), 32, "other"),
        "label": _redact_str(raw.get("label"), 160, "Run step"),
    }
    if raw.get("time"):
        step["time"] = _redact_str(raw.get("time"), 40)
    if raw.get("status"):
        step["status"] = _redact_str(raw.get("status"), 24)
    if capture and isinstance(raw.get("cwd"), str):
        step["cwd"] = _redact_str(raw["cwd"], 320)
    if capture:
        native_ref = raw.get("native_call_ref")
        if isinstance(native_ref, str) and re.fullmatch(r"[0-9a-f]{64}", native_ref):
            step["native_call_ref"] = native_ref
        for field in ("command_input", "command_output", "exit_code", "output_truncated", "image_previews", "text_previews"):
            if field in raw:
                step[field] = raw[field]
        for field in ("output_reason", "files_reason"):  # why evidence is missing (fixed vocabulary)
            if raw.get(field) in step_journal.REASONS:
                step[field] = raw[field]
        web = step_journal._web_resource(raw.get("web_resource"))  # allowlisted, bounded, redacted
        if web:
            step["web_resource"] = web
        commit_id = raw.get("git_commit")
        if isinstance(commit_id, str) and re.fullmatch(r"[0-9a-f]{7,40}", commit_id):
            step["git_commit"] = commit_id  # only the ID a session's own `git commit` printed
    files = _clean_path_list(raw.get("files"), 12)
    if files:
        step["files"] = files
    if raw.get("file_basis"):
        step["file_basis"] = _redact_str(raw.get("file_basis"), 24)
    if raw.get("file_count") is not None:
        step["file_count"] = _int(raw.get("file_count"), 0, 100_000)
    raw_prog = raw.get("program")
    if isinstance(raw_prog, str) and raw_prog.strip():
        prog = _redact_str(raw_prog, 40)
        if prog == raw_prog.strip() and PROGRAM_RE.fullmatch(prog) and not is_sensitive_path(prog):
            step["program"] = prog
    elif raw_prog is not None and isinstance(raw_prog, (dict, list)):
        raise ValidationError("Expected a scalar string value")
    if raw.get("command"):
        cmd = _redact_command(raw.get("command"))
        if cmd:
            step["command"] = cmd
    raw_src = raw.get("src")
    if isinstance(raw_src, str) and raw_src.strip():
        src_val = raw_src.strip()
        if SRC_RE.fullmatch(src_val):
            step["src"] = src_val
    elif raw_src is not None and isinstance(raw_src, (dict, list)):
        raise ValidationError("Expected a scalar string value")
    raw_tid = raw.get("task_id")
    if isinstance(raw_tid, str) and raw_tid.strip():
        tid = raw_tid.strip()
        if len(tid) <= 96 and re.fullmatch(r"[\w][\w.:-]{0,95}", tid, re.ASCII) and _redact_str(tid, 96) == tid:
            step["task_id"] = tid
    elif raw_tid is not None and isinstance(raw_tid, (dict, list)):
        raise ValidationError("Expected a scalar string value")
    return step


def _clean_plan_item(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    status = _redact_str(raw.get("status"), 24, "pending").lower()
    if status not in {"completed", "in_progress", "pending"}:
        status = "completed" if raw.get("done") else "pending"
    item: dict[str, Any] = {
        "status": status,
        "text": _redact_str(raw.get("text"), 160),
    }
    named = _clean_path_list(raw.get("named_files"), 8)
    if named:
        item["named_files"] = named
    return item


def _clean_session(raw: Any, host_id: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValidationError("sessions must be a list of objects")
    how_raw = raw.get("how") if isinstance(raw.get("how"), dict) else (raw.get("how_tools") or {})
    how: dict[str, int] = {}
    if isinstance(how_raw, dict):
        for k, v in list(how_raw.items())[:16]:
            key = _redact_str(k, 32)
            if key:
                how[key] = _int(v, 0, 1_000_000)

    steps_raw = raw.get("steps") if isinstance(raw.get("steps"), list) else []
    steps = [s for s in (_clean_step(x) for x in steps_raw[:MAX_ACTIVITY_STEPS]) if s]
    cap_raw = raw.get("capture_steps")
    capture_steps = None
    if isinstance(cap_raw, list):
        capture_steps = [s for s in (_clean_step(x, capture=True) for x in cap_raw[:MAX_CAPTURE_STEPS_PER_SESSION]) if s]

    plan_raw = raw.get("plan") if isinstance(raw.get("plan"), list) else (raw.get("plan_items") or [])
    plan = [p for p in (_clean_plan_item(x) for x in plan_raw[:MAX_ACTIVITY_PLAN_ITEMS]) if p and p.get("text")]

    files_edited = _clean_path_list(raw.get("files_edited") or raw.get("edited_files") or raw.get("touched_files"), 16)
    files_read = _clean_path_list(raw.get("files_read"), 12)
    files_delivered = _clean_path_list(raw.get("files_delivered"), 12)

    latest_raw = raw.get("latest_action")
    latest_action = _clean_step(latest_raw) if isinstance(latest_raw, dict) else (steps[-1] if steps else None)
    latest_work_raw = raw.get("latest_work")
    substantive_cats = {"file_edit", "file_read", "shell", "shell_exec", "web", "web_research", "visual", "visual_asset"}
    substantive_steps = [s for s in steps if s.get("category") in substantive_cats]
    latest_work = (
        _clean_step(latest_work_raw)
        if isinstance(latest_work_raw, dict)
        else (substantive_steps[-1] if substantive_steps else latest_action)
    )

    agent_name = _redact_str(raw.get("agent_name"), 80, "Agent")
    agent_id = _redact_str(raw.get("agent_id"), 80, agent_name.lower().replace(" ", "-"))
    harness = _redact_str(raw.get("harness"), 48, "generic")
    harness_name = _redact_str(raw.get("harness_name"), 64, harness)

    session: dict[str, Any] = {
        "session_id": _redact_str(raw.get("session_id"), 96, f"{harness}:{host_id}"),
        "host_id": host_id,
        "harness": harness,
        "harness_name": harness_name,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "owner_basis": _redact_str(raw.get("owner_basis"), 32, "workspace"),
        "workspace": _redact_str(raw.get("workspace"), 320, ""),
        "model": _redact_str(raw.get("model"), 80, ""),
        "tokens_used": _int(raw.get("tokens_used"), 0, 10**12),
        "updated_at": _num(raw.get("updated_at"), 0.0, 1e12, time.time()),
        "status": "active" if _redact_str(raw.get("status"), 16, "idle").lower() == "active" else "idle",
        "what_done": _redact_str(
            raw.get("what_done"), 240, "No written summary in the latest part of this session."
        ),
        "plan": plan,
        "how": how,
        "steps": steps,
        "files_edited": files_edited,
        "files_read": files_read,
        "files_delivered": files_delivered,
    }
    for field in ("legacy_session_id", "parent_session"):  # previous 12-char session keys; sub-agent parent
        value = _redact_str(raw.get(field), 96)
        if value:
            session[field] = value
    if raw.get("current_folder"):
        cf = _redact_str(raw.get("current_folder"), 320)
        if cf and not is_sensitive_path(cf):
            session["current_folder"] = cf
    if raw.get("provider"):
        session["provider"] = _redact_str(raw.get("provider"), 32)
    if raw.get("provider_label"):
        session["provider_label"] = _redact_str(raw.get("provider_label"), 48)
    if raw.get("provider_basis"):
        session["provider_basis"] = _redact_str(raw.get("provider_basis"), 24)
    raw_stid = raw.get("task_id")
    if isinstance(raw_stid, str) and raw_stid.strip():
        stid = raw_stid.strip()
        if len(stid) <= 96 and re.fullmatch(r"[\w][\w.:-]{0,95}", stid, re.ASCII) and _redact_str(stid, 96) == stid:
            session["task_id"] = stid
    elif raw_stid is not None and isinstance(raw_stid, (dict, list)):
        raise ValidationError("Expected a scalar string value")
    if latest_action:
        session["latest_action"] = latest_action
    if latest_work:
        session["latest_work"] = latest_work
    if capture_steps is not None:
        session["capture_steps"] = capture_steps
    return session


def _clean_workspace(raw: Any, host_id: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValidationError("workspaces must be a list of objects")
    folders_raw = raw.get("folders") if isinstance(raw.get("folders"), list) else []
    folders = []
    for f in folders_raw[:12]:
        if isinstance(f, dict) and f.get("name"):
            folders.append({"name": _redact_str(f.get("name"), 80), "files": _int(f.get("files"), 0, 1_000_000)})
        elif isinstance(f, str):
            folders.append({"name": _redact_str(f, 80), "files": 0})

    recent_raw = raw.get("recent_files") if isinstance(raw.get("recent_files"), list) else []
    recent_files = []
    for rf in recent_raw[:15]:
        if not isinstance(rf, dict):
            continue
        edited_by = _clean_path_list(rf.get("edited_by"), 6)
        recent_files.append(
            {
                "path": _redact_str(rf.get("path"), 320),
                "rel_path": _redact_str(rf.get("rel_path"), 200),
                "size_kb": _num(rf.get("size_kb"), 0.0, 1e9),
                "mtime": _num(rf.get("mtime"), 0.0, 1e12),
                "category": _redact_str(rf.get("category"), 24, "other"),
                "edited_by": edited_by,
            }
        )

    label = _redact_str(raw.get("label") or raw.get("name"), 120, "workspace")
    return {
        "id": _redact_str(raw.get("id"), 120, f"ws:{host_id}:{label}"),
        "host_id": host_id,
        "label": label,
        "kind": _redact_str(raw.get("kind"), 32, "workspace"),
        "agent_id": _redact_str(raw.get("agent_id"), 80, ""),
        "path": _redact_str(raw.get("path"), 320, ""),
        "file_count": _int(raw.get("file_count"), 0, 10_000_000),
        "truncated": bool(raw.get("truncated", False)),
        "last_modified": _num(raw.get("last_modified"), 0.0, 1e12, time.time()),
        "folders": folders,
        "recent_files": recent_files,
    }


def _clean_harness(raw: Any, host_id: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValidationError("harnesses must be a list of objects")
    ev = _clean_path_list(raw.get("evidence"), 8)
    return {
        "id": _redact_str(raw.get("id"), 64, "unknown"),
        "host_id": host_id,
        "name": _redact_str(raw.get("name"), 64, "unknown"),
        "version": _redact_str(raw.get("version"), 40, ""),
        "status": _redact_str(raw.get("status"), 16, "installed").lower(),
        "process_count": _int(raw.get("process_count"), 0, 100_000),
        "cpu_pct": _num(raw.get("cpu_pct"), 0.0, 100_000.0),
        "rss_mb": _num(raw.get("rss_mb"), 0.0, 1e9),
        "evidence": ev,
    }


def sanitize_activity_payload(body: dict[str, Any]) -> dict[str, Any]:
    """Validate and sanitize a remote host's POST /api/v1/ingest/activity payload."""
    if not isinstance(body, dict):
        raise ValidationError("Activity payload must be a JSON object")
    host_id = validate_host_id(body.get("host_id"))
    sessions_raw = body.get("sessions", [])
    workspaces_raw = body.get("workspaces", [])
    harnesses_raw = body.get("harnesses", [])
    if not isinstance(sessions_raw, list) or not isinstance(workspaces_raw, list) or not isinstance(harnesses_raw, list):
        raise ValidationError("sessions, workspaces and harnesses must be lists")
    if len(sessions_raw) > MAX_ACTIVITY_SESSIONS:
        raise ValidationError(f"Too many sessions (max {MAX_ACTIVITY_SESSIONS})")
    if len(workspaces_raw) > MAX_ACTIVITY_WORKSPACES:
        raise ValidationError(f"Too many workspaces (max {MAX_ACTIVITY_WORKSPACES})")
    if len(harnesses_raw) > MAX_ACTIVITY_HARNESSES:
        raise ValidationError(f"Too many harnesses (max {MAX_ACTIVITY_HARNESSES})")

    sessions = [_clean_session(s, host_id) for s in sessions_raw]
    workspaces = [_clean_workspace(w, host_id) for w in workspaces_raw]
    harnesses = [_clean_harness(h, host_id) for h in harnesses_raw]
    roots = _clean_path_list(body.get("activity_roots"), 16)

    total_capture_steps = sum(len(s.get("capture_steps") or []) for s in sessions)
    if total_capture_steps > MAX_CAPTURE_STEPS_TOTAL:
        raise ValidationError(f"Too many capture_steps across sessions (max {MAX_CAPTURE_STEPS_TOTAL})")

    gaps_raw = body.get("capture_gaps")
    capture_gaps: list[dict[str, str]] = []
    if isinstance(gaps_raw, list):
        for g in gaps_raw[:MAX_CAPTURE_GAPS]:
            if isinstance(g, dict):
                fk = _redact_str(g.get("file") or g.get("file_key"), 40)
                reason = _redact_str(g.get("reason"), 64, "log rotated")
                capture_gaps.append({"file": fk, "reason": reason})

    legacy_raw = body.get("capture_legacy_until")
    capture_legacy_until: dict[str, int] | None = None
    if isinstance(legacy_raw, dict):
        capture_legacy_until = {}
        for k, v in list(legacy_raw.items())[:500]:
            ks = _redact_str(k, 64)
            if ks and SAFE_KEY_RE.fullmatch(ks):
                capture_legacy_until[ks] = _int(v, 0, 10**12)

    metrics_raw = body.get("capture_metrics")
    capture_metrics: dict[str, Any] | None = None
    if isinstance(metrics_raw, dict):
        capture_metrics = {
            "steps_seen": _int(metrics_raw.get("steps_seen"), 0, 1_000_000),
            "pending": _int(metrics_raw.get("pending"), 0, 1_000_000),
            "files_read": _int(metrics_raw.get("files_read"), 0, 1_000_000),
            "bytes_read": _int(metrics_raw.get("bytes_read"), 0, 10**12),
            "backlog_files": _int(metrics_raw.get("backlog_files"), 0, 1_000_000),
            "ms": _num(metrics_raw.get("ms"), 0.0, 1e7, 0.0) if metrics_raw.get("ms") is not None else None,
        }

    # Line survival measurements: commit IDs, paths inside the shared folders and line counts only (no contents).
    survival_raw = body.get("line_survival")
    line_survival_items: list[dict[str, Any]] | None = None
    if isinstance(survival_raw, list):
        line_survival_items = []
        for item in survival_raw[:300]:
            if not isinstance(item, dict):
                continue
            paths = _clean_path_list([item.get("path")], 1)
            sha, head = str(item.get("sha") or ""), str(item.get("head") or "")
            if not paths or not re.fullmatch(r"[0-9a-f]{40}", sha) or not re.fullmatch(r"[0-9a-f]{40}", head):
                continue
            line_survival_items.append({
                "sha": sha, "head": head, "path": paths[0], "exists": bool(item.get("exists")),
                "added": _int(item.get("added"), 0, 1_000_000), "surviving": _int(item.get("surviving"), 0, 1_000_000),
                "commit_time": _num(item.get("commit_time"), 0.0, 1e12, 0.0),
                "prev_time": _num(item.get("prev_time"), 0.0, 1e12, 0.0),
                "measured_at": _num(item.get("measured_at"), 0.0, 1e12, time.time()),
                # Line numbers at HEAD (pairs of ints) and the path inside the repository; checked again on storage.
                **({"ranges": [[int(a), int(b)] for a, b in item["ranges"][:100]]}
                   if isinstance(item.get("ranges"), list) and all(
                       isinstance(p, list) and len(p) == 2 and all(type(n) is int for n in p) for p in item["ranges"][:100])
                   else {}),
                "ranges_truncated": item.get("ranges_truncated") is True,
                "too_large": item.get("too_large") is True,
                **({"repo_path": _redact_str(item["repo_path"], 320)} if isinstance(item.get("repo_path"), str) else {}),
            })

    raw_reader = str(body.get("capture_reader") or "").strip().lower()
    capture_reader = raw_reader if raw_reader in {"core", "fallback"} else ""
    fallback_reason = _redact_str(body.get("fallback_reason"), 96) if capture_reader == "fallback" else ""
    collected_at_provided = body.get("collected_at") is not None and body.get("collected_at") != ""

    out = {
        "schema_version": _redact_str(body.get("schema_version"), 16, "1.0"),
        "host_id": host_id,
        "hostname": _redact_str(body.get("hostname"), 253, host_id),
        "os_name": _redact_str(body.get("os_name"), 32, "unknown"),
        "arch": _redact_str(body.get("arch"), 32, "unknown"),
        "collected_at": _num(body.get("collected_at"), 0.0, 1e12, time.time()),
        "collected_at_provided": collected_at_provided,
        "scan_ms": _num(body.get("scan_ms"), 0.0, 1e7, 0.0),
        "activity_enabled": bool(body.get("activity_enabled", bool(roots))),
        "activity_roots": roots,
        "harnesses": harnesses,
        "sessions": sessions,
        "workspaces": workspaces,
        "map_update": bool(body.get("map_update", True)),
    }
    if capture_reader:
        out["capture_reader"] = capture_reader
    if fallback_reason:
        out["fallback_reason"] = fallback_reason
    if capture_gaps:
        out["capture_gaps"] = capture_gaps
    if capture_legacy_until is not None:
        out["capture_legacy_until"] = capture_legacy_until
    if capture_metrics is not None:
        out["capture_metrics"] = capture_metrics
    # Where the observer looked for each runtime's records (labels only; no path outside the home folder).
    sources_raw = body.get("sources")
    if isinstance(sources_raw, list):
        sources = []
        for item in sources_raw[:12]:
            if not isinstance(item, dict):
                continue
            status = _redact_str(item.get("status"), 80)
            if not re.fullmatch(r"found|not found|no permission|unsupported format \([\w.-]{1,40}\)(; reading [\w.-]{1,40})?", status):
                continue
            sources.append({"runtime": _redact_str(item.get("runtime"), 40, "runtime"),
                            "location": _redact_str(item.get("location"), 120), "status": status,
                            "origin": _redact_str(item.get("origin"), 40, "default")})
        out["sources"] = sources
    if line_survival_items is not None:
        out["line_survival"] = line_survival_items
    return out


_REMOTE_TABLES_SQL = (
    """
    CREATE TABLE IF NOT EXISTS host_activity (
        host_id TEXT PRIMARY KEY,
        hostname TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        updated_at REAL NOT NULL
    )
    """,
)


def ensure_remote_activity_table(db: Any) -> None:
    """Ensure the tenant database has host_activity and unified journal tables."""
    for stmt in _REMOTE_TABLES_SQL:
        db.execute(stmt)
    step_journal.ensure_journal_tables(db)


def _strip_capture_for_map(cleaned: dict[str, Any]) -> dict[str, Any]:
    """Keep host_activity focused on the live overview map without unbounded capture batches."""
    map_sessions = [
        {k: v for k, v in s.items() if k != "capture_steps"}
        for s in cleaned.get("sessions", [])
    ]
    omit = {
        "sessions",
        "capture_gaps",
        "capture_metrics",
        "capture_legacy_until",
        "line_survival",
        "map_update",
        "collected_at_provided",
        "fallback_reason",
    }
    return {
        **{k: v for k, v in cleaned.items() if k not in omit},
        "sessions": map_sessions,
    }


def inspect_heartbeat_telemetry(conn: Any, host_id: str, body: dict[str, Any], now: float) -> dict[str, Any]:
    """Detect remote clock skew and fallback reader state from heartbeat metadata."""
    out: dict[str, Any] = {"server_time": now}
    warnings: list[str] = []

    raw_ts = body.get("collected_at")
    if isinstance(raw_ts, (int, float)) and not isinstance(raw_ts, bool) and math.isfinite(raw_ts):
        if raw_ts > 946684800.0:
            skew = float(raw_ts) - now
            if abs(skew) > step_journal.FUTURE_GRACE_SEC:
                out["clock_skew_sec"] = round(skew, 1)
                if skew > step_journal.FUTURE_GRACE_SEC:
                    warnings.append(f"clock_skew:+{round(skew, 1)}s")
                    step_journal.ensure_journal_tables(conn)
                    step_journal.maybe_emit_host_warning(
                        conn,
                        host_id,
                        "clock_skew",
                        f"Remote host clock on {host_id} ahead by {round(skew, 1)}s",
                        {"skew_sec": round(skew, 1), "source": "heartbeat"},
                        now,
                    )

    reader = str(body.get("capture_reader") or "").strip().lower()
    if reader == "fallback":
        reason = _redact_str(body.get("fallback_reason"), 64, "activity_core_missing")
        warnings.append(f"reader_fallback:{reason}")
        step_journal.ensure_journal_tables(conn)
        step_journal.maybe_emit_host_warning(
            conn,
            host_id,
            "reader_fallback",
            f"Remote host {host_id} using fallback reader ({reason})",
            {"capture_reader": "fallback", "reason": reason, "source": "heartbeat"},
            now,
        )

    if warnings:
        out["warnings"] = warnings
    return out


def ingest_remote_activity(db: Any, body: dict[str, Any]) -> dict[str, Any]:
    """Validate, sanitize, and upsert a host's activity snapshot into the tenant's SQLite DB."""
    cleaned = sanitize_activity_payload(body)
    now = time.time()
    meta: dict[str, Any] = {}
    with db.transaction() as conn:
        ensure_remote_activity_table(conn)
        if cleaned.get("map_update", True):
            map_payload = _strip_capture_for_map(cleaned)
            conn.execute(
                """
                INSERT INTO host_activity(host_id, hostname, payload_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(host_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (cleaned["host_id"], cleaned["hostname"], json.dumps(map_payload), now),
            )
        counts = step_journal.persist_steps(
            conn,
            cleaned,
            now=now,
            activity_roots=cleaned.get("activity_roots") or [],
            activity_enabled=bool(cleaned.get("activity_enabled")),
            capture_gaps=cleaned.get("capture_gaps") or None,
            capture_metrics=cleaned.get("capture_metrics"),
            legacy_until_map=cleaned.get("capture_legacy_until"),
            allow_command=True,
            remote_clock_check=True,
            capture_reader=cleaned.get("capture_reader") or None,
            fallback_reason=cleaned.get("fallback_reason") or "",
            meta_out=meta,
        )
    steps_rejected = counts.get("rejected_future", 0) + counts.get("rejected_invalid_time", 0)
    steps_expired = counts.get("rejected_expired", 0)
    commit_offsets = steps_rejected == 0
    warnings: list[str] = []
    if meta.get("skew_applied"):
        warnings.append(f"clock_skew:+{meta.get('clock_skew_sec', 0.0)}s")
    if steps_rejected > 0:
        warnings.append(f"steps_rejected:{steps_rejected}")
    if steps_expired > 0:
        warnings.append(f"steps_expired:{steps_expired}")
    if cleaned.get("capture_reader") == "fallback":
        warnings.append(f"reader_fallback:{cleaned.get('fallback_reason') or 'activity_core_missing'}")
    return {
        "ok": commit_offsets,
        "host_id": cleaned["host_id"],
        "server_time": now,
        "sessions_ingested": len(cleaned["sessions"]),
        "workspaces_ingested": len(cleaned["workspaces"]),
        "harnesses_ingested": len(cleaned["harnesses"]),
        "steps_persisted": counts.get("inserted", 0),
        "steps_duplicates": counts.get("duplicates", 0),
        "steps_pending": counts.get("pending", 0),
        "steps_rejected": steps_rejected,
        "steps_expired": steps_expired,
        "steps_clock_adjusted": counts.get("clock_adjusted", 0),
        "clock_skew_sec": meta.get("clock_skew_sec", 0.0),
        "capture_gaps": counts.get("gaps", 0),
        "capture_reader": cleaned.get("capture_reader") or "unknown",
        "commit_offsets": commit_offsets,
        "warnings": warnings,
    }


def build_tenant_activity_map(db: Any, local_fallback: dict[str, Any] | None = None,
                              local_snapshot: dict[str, Any] | None = None) -> dict[str, Any]:
    """Aggregate all remote host_activity snapshots for the current tenant into GET /api/v1/activity format.

    `local_snapshot` is the console machine's own collection (local roots or adapters). It is merged with the remote
    observers instead of being replaced by them, so connecting a first remote machine does not hide local agents. A
    remote observer that reports the same host ID wins over the local collection for that host."""
    ensure_remote_activity_table(db)
    rows = [dict(r) for r in db.query_all("SELECT host_id, hostname, payload_json, updated_at FROM host_activity ORDER BY updated_at DESC")]
    if rows and isinstance(local_snapshot, dict) and (local_snapshot.get("sessions") or local_snapshot.get("hosts")):
        local_host = ((local_snapshot.get("hosts") or [{}])[0] or {})
        local_id = local_host.get("host_id") or local_snapshot.get("host_id") or local_snapshot.get("host") or "local"
        if local_id not in {r["host_id"] for r in rows}:
            rows.append({"host_id": local_id, "hostname": local_host.get("hostname") or local_id,
                         "payload_json": json.dumps({**local_snapshot, "hostname": local_host.get("hostname") or local_id,
                                                     "activity_roots": local_host.get("activity_roots", local_snapshot.get("activity_roots") or []),
                                                     "activity_enabled": local_host.get("activity_enabled", local_snapshot.get("activity_enabled", True)),
                                                     "sources": local_host.get("sources", local_snapshot.get("sources") or []),
                                                     "capture_reader": "console"}),
                         "updated_at": float(local_snapshot.get("collected_at") or time.time())})
    if not rows:
        if local_fallback is not None:
            return local_fallback
        return {
            "host": "no-hosts-reporting",
            "hosts": [],
            "collected_at": time.time(),
            "scan_ms": 0.0,
            "summary": {
                "harnesses_installed": 0,
                "harnesses_running": 0,
                "agents": 0,
                "agents_active": 0,
                "sessions": 0,
                "files_edited": 0,
                "workspaces": 0,
                "how": {},
            },
            "harnesses": [],
            "agents": [],
            "sessions": [],
            "workspaces": [],
            "category_labels": CATEGORY_LABEL,
        }

    all_harnesses: list[dict[str, Any]] = []
    all_sessions: list[dict[str, Any]] = []
    all_workspaces: list[dict[str, Any]] = []
    hosts_meta: list[dict[str, Any]] = []
    total_scan_ms = 0.0
    latest_collected = 0.0

    for r in rows:
        try:
            snap = json.loads(r["payload_json"] or "{}")
        except Exception:
            continue
        hid = r["host_id"]
        hosts_meta.append(
            {
                "host_id": hid,
                "hostname": snap.get("hostname") or hid,
                "os_name": snap.get("os_name", "unknown"),
                "arch": snap.get("arch", "unknown"),
                "activity_roots": snap.get("activity_roots") or [],
                "activity_enabled": bool(snap.get("activity_enabled", bool(snap.get("activity_roots")))),
                "capture_reader": snap.get("capture_reader") or "unknown",
                "sources": snap.get("sources") if isinstance(snap.get("sources"), list) else [],
                "updated_at": r["updated_at"],
            }
        )
        total_scan_ms += float(snap.get("scan_ms") or 0.0)
        latest_collected = max(latest_collected, float(snap.get("collected_at") or r["updated_at"] or 0.0))
        all_harnesses.extend(snap.get("harnesses") or [])
        all_sessions.extend(snap.get("sessions") or [])
        all_workspaces.extend(snap.get("workspaces") or [])

    all_sessions.sort(key=lambda s: float(s.get("updated_at") or 0.0), reverse=True)
    all_workspaces.sort(key=lambda w: float(w.get("last_modified") or 0.0), reverse=True)

    editors: dict[str, list[str]] = {}
    for s in all_sessions:
        for p in s.get("files_edited") or []:
            editors.setdefault(p, [])
            tag = f"{s.get('agent_name', 'Agent')} · {s.get('harness_name', s.get('harness', ''))}"
            if tag not in editors[p]:
                editors[p].append(tag)

    for w in all_workspaces:
        for f in w.get("recent_files") or []:
            if not f.get("edited_by"):
                f["edited_by"] = editors.get(f.get("path", ""), [])

    agents: dict[str, dict[str, Any]] = {}
    for s in all_sessions:
        key = f"{s.get('host_id', '')}:{s.get('agent_id') or s.get('agent_name') or s.get('harness')}"
        a = agents.setdefault(
            key,
            {
                "agent_id": s.get("agent_id") or s.get("agent_name") or "agent",
                "name": s.get("agent_name") or "Agent",
                "host_id": s.get("host_id") or "",
                "harnesses": [],
                "provider": s.get("provider", ""),
                "provider_label": s.get("provider_label", ""),
                "provider_basis": s.get("provider_basis", ""),
                "workspace": s.get("workspace", ""),
                "status": "idle",
                "last_active": 0.0,
                "sessions": 0,
                "files_edited": 0,
            },
        )
        hname = s.get("harness_name") or s.get("harness") or ""
        if hname and hname not in a["harnesses"]:
            a["harnesses"].append(hname)
        a["sessions"] += 1
        a["files_edited"] += len(s.get("files_edited") or [])
        a["last_active"] = max(a["last_active"], float(s.get("updated_at") or 0.0))
        if s.get("status") == "active":
            a["status"] = "active"
        if not a.get("provider") and s.get("provider"):
            a["provider"] = s["provider"]
            a["provider_label"] = s.get("provider_label", "")
            a["provider_basis"] = s.get("provider_basis", "")

    how: Counter[str] = Counter()
    for s in all_sessions:
        for k, v in (s.get("how") or {}).items():
            how[k] += int(v)

    host_title = hosts_meta[0]["hostname"] if len(hosts_meta) == 1 else f"{len(hosts_meta)} hosts"
    return {
        "host": host_title,
        "hosts": hosts_meta,
        "collected_at": latest_collected or time.time(),
        "scan_ms": round(total_scan_ms, 1),
        "summary": {
            "harnesses_installed": len(all_harnesses),
            "harnesses_running": sum(1 for h in all_harnesses if h.get("status") == "running"),
            "agents": len(agents),
            "agents_active": sum(1 for a in agents.values() if a.get("status") == "active"),
            "sessions": len(all_sessions),
            "files_edited": len(editors),
            "workspaces": len(all_workspaces),
            "how": {CATEGORY_LABEL.get(k, k): v for k, v in how.most_common()},
        },
        "harnesses": all_harnesses,
        "agents": sorted(agents.values(), key=lambda a: a["last_active"], reverse=True),
        "sessions": all_sessions[:30],
        "workspaces": all_workspaces[:24],
        "category_labels": CATEGORY_LABEL,
    }
