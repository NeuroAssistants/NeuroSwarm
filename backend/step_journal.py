"""Unified step normalization, deduplication, and incremental journal persistence.

Used by both the local background work journal (`backend/work_journal.py`) and
remote HTTP activity ingestion (`backend/remote_activity.py`) so local and
remote collection share identical projection, privacy filtering, and dedup keys.
"""

from __future__ import annotations

import collections
import datetime
import hashlib
import json
import math
import os
import re
import time
from pathlib import Path
from typing import Any

import event_evidence
from activity_inspector import (
    CMD_KIND,
    NONTERMINAL,
    PROGRAM_RE,
    is_sensitive_path,
    redact,
)

ACTIONS: dict[str, str] = {
    "file_edit": "File edit",
    "file_read": "File read",
    "shell": "Shell command",
    "coordination": "Coordination",
    "plan": "Plan update",
    "web": "Web request",
    "visual": "Visual task",
}

CANONICAL_CATEGORY: dict[str, str] = {
    "shell_exec": "shell",
    "web_research": "web",
    "visual_asset": "visual",
}

COMMANDS: set[str] = {label for _, label in CMD_KIND} | {"List or search files"}

COMMAND_FORMS: dict[str, tuple[str, ...]] = {
    "git": ("diff", "status", "log", "show", "add", "commit", "rev-parse"),
    "python": ("-m unittest discover", "-m unittest", "-m pytest", "-m compileall"),
    "python3": ("-m unittest discover", "-m unittest", "-m pytest", "-m compileall"),
    "rg": ("--files",),
    "go": ("test", "build", "fmt"),
    "cargo": ("test", "check", "build"),
    "npm": ("test", "run build", "run lint"),
}

RETENTION = 7 * 86400
FUTURE_GRACE_SEC = 60.0
MAX_FUTURE_SKEW_SEC = 24 * 3600.0
WARNING_COOLDOWN_SEC = 3600.0


def command_form(program: Any, raw: Any) -> str | None:
    """Keep a known command form without persisting free-text command arguments."""
    if not isinstance(raw, str) or not isinstance(program, str):
        return None
    words = raw.split()
    for form in COMMAND_FORMS.get(program, ()):
        expected = [program, *form.split()]
        if words[: len(expected)] == expected:
            return " ".join(expected)
    return None


def position_key(host: str, src: str) -> str:
    """Return the deterministic position-based digest for a step source offset."""
    return hashlib.sha256(json.dumps(["src", host, src]).encode("utf-8")).hexdigest()


def content_key(identity: tuple[Any, ...], occurrence: int) -> str:
    """Return the content-based digest used before incremental capture offsets exist."""
    return hashlib.sha256(json.dumps([identity, occurrence]).encode("utf-8")).hexdigest()


def legacy_remote_v1_key(
    host_id: str,
    session_id: str,
    harness: str,
    agent_name: str,
    timestamp: float,
    category: str,
    tool: str,
    rel_files: list[str],
    program: str,
    outcome: str,
    occurrence: int,
) -> str:
    """Return the pre-Paso-8 remote content digest for zero-duplicate upgrades."""
    base_identity = (
        "remote_v1",
        host_id,
        session_id,
        harness,
        agent_name,
        round(timestamp, 3),
        category,
        tool,
        tuple(rel_files),
        program,
        outcome,
    )
    return hashlib.sha256(
        json.dumps([base_identity, occurrence], separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def step_severity(outcome: Any) -> str:
    """Map a step outcome string to INFO, WARNING, or ERROR."""
    low = str(outcome or "").lower()
    if "err" in low or "fail" in low:
        return "ERROR"
    if "warn" in low:
        return "WARNING"
    return "INFO"


def parse_raw_ts(raw_time: Any) -> float | None:
    """Parse an ISO 8601 timestamp string into UTC epoch seconds, or None if invalid."""
    if not isinstance(raw_time, str) or not raw_time.strip():
        return None
    text = raw_time.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    try:
        ts = dt.timestamp()
    except (OverflowError, OSError, ValueError):
        return None
    if not math.isfinite(ts):
        return None
    return ts


def parse_step_ts(raw_time: Any, now: float, retention: int = RETENTION) -> float | None:
    """Parse an ISO timestamp within the retention window into UTC epoch seconds."""
    ts = parse_raw_ts(raw_time)
    if ts is None or not (now - retention <= ts <= now + FUTURE_GRACE_SEC):
        return None
    return ts


def detect_forward_clock_skew(snapshot: dict[str, Any], now: float) -> tuple[float, bool]:
    """Detect forward remote clock skew when a batch contains future step timestamps.

    Never shifts backward or queued delayed batches (where no step is in the future),
    nor old agents that omitted `collected_at` (`collected_at_provided == False`).
    """
    if not snapshot.get("collected_at_provided", True):
        return 0.0, False

    future_deltas: list[float] = []
    for session in snapshot.get("sessions", []):
        steps = session.get("capture_steps") if session.get("capture_steps") is not None else session.get("steps", [])
        for step in steps:
            if not isinstance(step, dict):
                continue
            raw_cat = str(step.get("category") or "")
            if CANONICAL_CATEGORY.get(raw_cat, raw_cat) not in ACTIONS:
                continue
            if str(step.get("status") or "").lower() in NONTERMINAL:
                continue
            ts = parse_raw_ts(step.get("time"))
            if ts is not None and ts > now + FUTURE_GRACE_SEC:
                future_deltas.append(ts - now)

    if not future_deltas:
        return 0.0, False

    raw_collected = snapshot.get("collected_at")
    host_skew = 0.0
    if isinstance(raw_collected, (int, float)) and not isinstance(raw_collected, bool):
        if math.isfinite(raw_collected) and raw_collected > 946684800.0:
            diff = float(raw_collected) - now
            if FUTURE_GRACE_SEC < diff <= MAX_FUTURE_SKEW_SEC:
                host_skew = diff

    bounded = [d for d in future_deltas if d <= MAX_FUTURE_SKEW_SEC]
    if not bounded and host_skew <= FUTURE_GRACE_SEC:
        return 0.0, False

    max_bounded = max(bounded, default=0.0)
    if host_skew > FUTURE_GRACE_SEC:
        skew = host_skew
        if max_bounded - skew > FUTURE_GRACE_SEC:
            skew = min(max_bounded, MAX_FUTURE_SKEW_SEC)
    else:
        skew = min(max_bounded, MAX_FUTURE_SKEW_SEC)
    return (skew, skew > FUTURE_GRACE_SEC)


def norm_abs_path(raw: Any) -> str:
    """Normalize POSIX or Windows absolute paths safely without resolving remote symlinks."""
    s = str(raw or "").strip().strip('"').strip("'")
    if s.startswith("file://"):
        s = s[7:]
    if not s or "\0" in s or any(ord(c) < 32 for c in s):
        return ""
    s = re.sub(r"/+", "/", s.replace("\\", "/"))
    if s != "/" and not re.fullmatch(r"[A-Za-z]:/", s):
        s = s.rstrip("/")
    if not (s.startswith("/") or re.match(r"^[A-Za-z]:/", s)):
        return ""
    if ".." in s.split("/"):
        return ""
    return s


def _cmp_key(norm: str) -> str:
    return (norm[0].lower() + norm[1:]) if re.match(r"^[A-Za-z]:/", norm) else norm


def build_root_index(raw_roots: list[str]) -> list[tuple[str, str, str]]:
    """Order approved roots deepest-first and assign disambiguated display labels."""
    norms: list[str] = []
    for raw in raw_roots:
        nr = norm_abs_path(raw)
        if nr and not is_sensitive_path(nr) and nr not in norms:
            norms.append(nr)
    norms.sort(key=lambda r: (len(r.split("/")), len(r)), reverse=True)
    base_counts = collections.Counter(r.rsplit("/", 1)[-1] or r for r in norms)
    index: list[tuple[str, str, str]] = []
    for nr in norms:
        base = nr.rsplit("/", 1)[-1] or nr
        label = base if base_counts[base] == 1 else f"{base}-{hashlib.sha256(nr.encode()).hexdigest()[:6]}"
        index.append((_cmp_key(nr), nr, label))
    return index


def _match_root(norm_path: str, root_index: list[tuple[str, str, str]]) -> tuple[str, str, str] | None:
    if not norm_path:
        return None
    cmp_p = _cmp_key(norm_path)
    for cmp_r, norm_r, label in root_index:
        if cmp_r == "/" and cmp_p.startswith("/"):
            return cmp_r, norm_r, label
        if cmp_r.endswith("/") and cmp_p.startswith(cmp_r):
            return cmp_r, norm_r, label
        if cmp_p == cmp_r or cmp_p.startswith(cmp_r + "/"):
            return cmp_r, norm_r, label
    return None



def recorded_path(raw, cwd):
    """Anchor a relative file only to its recorded working directory."""
    if not isinstance(raw, str) or len(raw) > 1024 or raw.startswith(("\\", "//")):
        return ""
    absolute = norm_abs_path(raw)
    if absolute:
        return absolute
    if not cwd or not raw.strip() or re.match(r"^(?:[A-Za-z][\w+.-]*:|~)", raw):
        return ""
    parts = raw.replace("\\", "/").split("/")
    if ".." in parts or any(ord(c) < 32 for c in raw):
        return ""
    return norm_abs_path(cwd.rstrip("/") + "/" + "/".join(p for p in parts if p and p != "."))


def journal_files(paths: list[Any], project: Path, extra_scope: Any, cwd: str = "") -> tuple[list[str], list[str], set[str]]:
    """Resolve and privacy-filter local file paths against primary project and Scope roots."""
    primary: list[str] = []
    additional: list[str] = []
    labels: set[str] = set()
    base = norm_abs_path(cwd)
    try:
        if base and not (Path(base).resolve().is_relative_to(project) or (extra_scope and extra_scope.contains(base))):
            base = ""
    except (OSError, ValueError, RuntimeError):
        base = ""
    for raw in paths:
        try:
            path = recorded_path(raw, base)
            if not path or not Path(path).is_absolute():
                continue
            absolute = Path(path).resolve()
            root = project
            if not absolute.is_relative_to(project):
                root = extra_scope.root_of(absolute) if extra_scope else None
            if root is None:
                continue
            rel_path = absolute.relative_to(root)
        except (OSError, ValueError, RuntimeError):
            continue
        rel = rel_path.as_posix()
        if (
            not rel_path.parts
            or any(p.startswith(".") for p in rel_path.parts)
            or is_sensitive_path(rel)
            or redact(rel, 240) != rel
        ):
            continue
        if root == project:
            if rel not in primary:
                primary.append(rel)
        else:
            root_id = extra_scope.identity(root)[0]
            if root_id.startswith(".") or redact(root_id, 64) != root_id:
                continue
            display = f"{root_id}/{rel}"
            if display not in additional:
                additional.append(display)
                labels.add(root_id)
    return primary, additional, labels


def resolve_step_files(
    paths: list[Any],
    root_index: list[tuple[str, str, str]],
    session_workspace: str,
) -> tuple[list[str], list[str], set[str], str]:
    """Resolve cross-platform file paths against an indexed list of approved roots."""
    ws_norm = norm_abs_path(session_workspace)
    ws_match = _match_root(ws_norm, root_index)
    ws_cmp = ws_match[0] if ws_match else ""
    ws_label = ws_match[2] if ws_match else ""

    primary: list[str] = []
    additional: list[str] = []
    extra_roots: set[str] = set()

    for raw in paths:
        norm_p = recorded_path(raw, ws_norm if ws_match else "")
        if not norm_p or is_sensitive_path(norm_p):
            continue
        matched = _match_root(norm_p, root_index)
        if not matched:
            continue
        cmp_r, norm_r, label = matched
        rel = norm_p[len(norm_r) :].lstrip("/")
        parts = [pt for pt in rel.split("/") if pt]
        if not parts or any(pt.startswith(".") or pt == ".." for pt in parts):
            continue
        rel_clean = "/".join(parts)
        if is_sensitive_path(rel_clean) or redact(rel_clean, 240) != rel_clean:
            continue
        if (ws_match and cmp_r == ws_cmp) or (not ws_match and len(root_index) == 1):
            if rel_clean not in primary:
                primary.append(rel_clean)
        else:
            if label.startswith(".") or redact(label, 64) != label:
                continue
            display = f"{label}/{rel_clean}"
            if display not in additional:
                additional.append(display)
                extra_roots.add(label)

    base_label = ws_label if (primary or ws_cmp) else (root_index[0][2] if len(root_index) == 1 else "Agent workspace")
    if not ws_cmp and not primary:
        base_label = "Agent workspace"
    return primary, additional, extra_roots, base_label


def ensure_journal_tables(db: Any) -> None:
    """Create unified journal tables and migrate legacy remote dedup digests if present."""
    event_evidence.ensure_tables(db)
    db.execute("CREATE TABLE IF NOT EXISTS observed_step_keys (digest TEXT PRIMARY KEY, ts REAL NOT NULL)")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS capture_offsets (
            file_key TEXT PRIMARY KEY,
            inode INTEGER NOT NULL,
            offset INTEGER NOT NULL,
            legacy_until INTEGER NOT NULL,
            updated REAL NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS capture_metrics (
            ts REAL NOT NULL,
            sessions INTEGER,
            steps_seen INTEGER,
            inserted INTEGER,
            duplicates INTEGER,
            pending INTEGER,
            gaps INTEGER,
            files_read INTEGER,
            bytes_read INTEGER,
            backlog_files INTEGER,
            ms REAL
        )
        """
    )
    has_legacy = (
        db.query_one("SELECT 1 FROM sqlite_master WHERE type='table' AND name='remote_observed_step_keys'")
        if hasattr(db, "query_one")
        else db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='remote_observed_step_keys'").fetchone()
    )
    if has_legacy:
        db.execute(
            "INSERT OR IGNORE INTO observed_step_keys(digest, ts) SELECT digest, ts FROM remote_observed_step_keys"
        )
        db.execute("DELETE FROM remote_observed_step_keys")


def _clean_program(raw_prog: Any) -> str:
    if isinstance(raw_prog, str):
        prog = raw_prog.strip()
        if (
            prog
            and PROGRAM_RE.fullmatch(prog)
            and redact(prog, 40) == prog
            and not is_sensitive_path(prog)
        ):
            return prog
    return ""


def project_rows(
    snapshot: dict[str, Any],
    *,
    now: float,
    agents: set[str] | None = None,
    project: Path | None = None,
    extra_scope: Any = None,
    activity_roots: list[str] | None = None,
    activity_enabled: bool = True,
    capture: Any = None,
    legacy_until_map: dict[str, int] | None = None,
    allow_command: bool | None = None,
    skipped: collections.Counter[str] | None = None,
    clock_skew_sec: float = 0.0,
    evidence_by_key: dict | None = None,
):
    """Yield (key, legacy_keys, timestamp, event_tuple) for either local or remote snapshots."""
    share_cmd = (os.getenv("SWARMCONTROL_SHARE_COMMANDS") == "1") if allow_command is None else bool(allow_command)
    global_roots = list(activity_roots or [])

    for session in snapshot.get("sessions", []):
        agent = session.get("agent_name") or "Agent"
        if agents is not None and agent not in agents:
            continue
        workspace_str = str(session.get("workspace") or "")
        host_id = session.get("host_id") or snapshot.get("host_id") or snapshot.get("host") or "local"
        harness = session.get("harness") or "generic"
        session_id = session.get("session_id") or f"{harness}:{host_id}"
        # Keys stored before full session ids were computed with the 12-character form.
        legacy_session_id = session.get("legacy_session_id") or session_id

        root_index: list[tuple[str, str, str]] = []
        if project is None:
            session_roots = list(global_roots)
            if not session_roots and activity_enabled and workspace_str:
                session_roots = [workspace_str]
            root_index = build_root_index(session_roots)

        if project is not None:
            try:
                scoped = bool(workspace_str and (Path(workspace_str).resolve().is_relative_to(project)
                                                  or (extra_scope and extra_scope.contains(workspace_str))))
            except (ValueError, OSError, RuntimeError):
                scoped = False
        else:
            scoped = bool(activity_enabled and global_roots and _match_root(norm_abs_path(workspace_str), root_index))
        seen: collections.Counter[tuple[Any, ...]] = collections.Counter()
        legacy_seen: collections.Counter[tuple[Any, ...]] = collections.Counter()
        steps = session.get("capture_steps") if session.get("capture_steps") is not None else session.get("steps", [])

        for step in steps:
            raw_cat = str(step.get("category") or "")
            category = CANONICAL_CATEGORY.get(raw_cat, raw_cat)
            if category not in ACTIONS:
                continue
            status_val = str(step.get("status") or "").lower()
            if status_val in NONTERMINAL:
                if skipped is not None:
                    skipped["pending"] += 1
                continue
            raw_ts = parse_raw_ts(step.get("time"))
            if raw_ts is None:
                if skipped is not None:
                    skipped["rejected_invalid_time"] += 1
                continue
            adjusted = clock_skew_sec > 0.0
            timestamp = raw_ts - clock_skew_sec if adjusted else raw_ts
            if timestamp > now + FUTURE_GRACE_SEC:
                if skipped is not None:
                    skipped["rejected_future"] += 1
                continue
            if timestamp < now - RETENTION:
                if skipped is not None:
                    skipped["rejected_expired"] += 1
                continue
            if adjusted and skipped is not None:
                skipped["clock_adjusted"] += 1

            step_cwd = step.get("cwd") or workspace_str
            if project is not None:
                scope = Path(workspace_str) if workspace_str else Path("")
                files, extra_files, extra_roots = journal_files(step.get("files") or [], project, extra_scope, step_cwd)
                ws_base_label = project.name if files or (workspace_str and scope == project) else "Agent workspace"
            else:
                files, extra_files, extra_roots, ws_base_label = resolve_step_files(
                    step.get("files") or [], root_index, step_cwd
                )

            all_files = (files + extra_files)[:12]
            action = step["label"] if category == "shell" and step.get("label") in COMMANDS else ACTIONS[category]
            outcome = step.get("status") or "recorded"
            program = _clean_program(step.get("program"))
            tool = redact(step.get("tool") or "tool", 48)

            summary = action + (" · " + ", ".join(files[:3]) if files else "")
            if program:
                summary += " · " + program

            context: dict[str, Any] = {
                "session": session_id,
                "agent": agent,
                "runtime": harness,
                "tool": tool,
                "action": category,
                "files": files,
                "workspace": ws_base_label,
                "basis": (step.get("file_basis") or "recorded") if files else "session record",
                "outcome": outcome,
            }
            if program:
                context["program"] = program

            metadata = json.dumps(dict(context, session=legacy_session_id), sort_keys=True, ensure_ascii=False)
            identity = (host_id, timestamp, metadata, summary)
            seen[identity] += 1
            c_key = content_key(identity, seen[identity])

            if extra_files:
                context["files"] = all_files
                labels = ([ws_base_label] if files and ws_base_label != "Agent workspace" else []) + sorted(extra_roots)
                if not labels and project is not None and files:
                    labels = [project.name]
                context["workspace"] = ", ".join(labels) if labels else "Agent workspace"
                context["basis"] = step.get("file_basis") or ("recorded" if all_files else "session record")
                summary = action + " · " + ", ".join(context["files"][:3])
                if program:
                    summary += " · " + program

            legacy_sig = (
                "remote_v1",
                host_id,
                legacy_session_id,
                harness,
                agent,
                round(timestamp, 3),
                category,
                tool,
                tuple(all_files[:8]),
                program,
                outcome,
            )
            legacy_seen[legacy_sig] += 1
            r_v1_key = legacy_remote_v1_key(
                host_id,
                legacy_session_id,
                harness,
                agent,
                timestamp,
                category,
                tool,
                all_files[:8],
                program,
                outcome,
                legacy_seen[legacy_sig],
            )

            if program and share_cmd:
                cmd_op = command_form(program, step.get("command"))
                if cmd_op:
                    context["command"] = cmd_op
            raw_tid = step.get("task_id") if step.get("task_id") is not None else session.get("task_id")
            if isinstance(raw_tid, str):
                tid = raw_tid.strip()
                if tid and len(tid) <= 96 and re.fullmatch(r"[\w][\w.:-]{0,95}", tid, re.ASCII) and redact(tid, 96) == tid:
                    context["task_id"] = tid
            parent = redact(session.get("parent_session") or "", 96)
            if parent and parent != session_id:  # a sub-agent's step names the session that launched it
                context["parent_session"] = parent

            final_metadata = json.dumps(context, sort_keys=True, ensure_ascii=False)
            key = c_key
            legacy: list[str] = []

            src = step.get("src")
            if isinstance(src, str) and src.count(":") == 2:
                file_key, pos_str, _ = src.split(":", 2)
                try:
                    pos = int(pos_str)
                except ValueError:
                    pos = -1
                known = True  # the reader said which bytes predate it (local scan, or a remote legacy map)
                if capture is not None:
                    limit = capture.legacy_until(file_key)
                elif isinstance(legacy_until_map, dict):
                    limit = int(legacy_until_map.get(file_key, 0) or 0)
                else:
                    limit, known = pos + 1, False
                if pos < 0 or pos < limit:
                    legacy = [c_key, r_v1_key]
                    if known and 0 <= pos < limit:
                        # Older journal rows may omit the program and use an abbreviated session ID.
                        # _claim_near matches those rows within the same recorded second.
                        legacy.append(("near", host_id, agent, legacy_session_id, category, timestamp))
                key = position_key(host_id, src)
            else:
                legacy = [r_v1_key]

            if (scoped and evidence_by_key is not None and
                    any(k in step for k in ("command_input", "command_output", "exit_code", "image_previews", "text_previews"))):
                shared_paths = []
                previews = [(field, item) for field in ("image_previews", "text_previews")
                            if isinstance(step.get(field), list) for item in step[field][:2]]
                if (previews and category in ("file_edit", "file_read", "visual")
                        and context["basis"] in ("confirmed", "recorded")
                        and str(outcome).lower() in ("completed", "success", "recorded")):
                    for field, item in previews:
                        if not isinstance(item, dict) or item.get("path") not in (step.get("files") or []):
                            continue
                        if project is not None:
                            primary, extra, _ = journal_files([item["path"]], project, extra_scope, step_cwd)
                        else:
                            primary, extra, _, _ = resolve_step_files([item["path"]], root_index, step_cwd)
                        display = primary or extra
                        if display and display[0] in all_files:
                            shared_paths.append((field, item, display[0]))
                evidence_by_key.setdefault(key, (step, shared_paths))
            severity = step_severity(outcome)
            yield key, legacy, timestamp, (
                host_id,
                harness,
                agent,
                "observed_step",
                severity,
                summary,
                final_metadata,
                timestamp,
            )


NEAR_SEC = 1.0  # an upgraded journal's step and a row stored by an older journal: same second (±1 s)


def _claim_near(conn: Any, sig: tuple[Any, ...], claimed: set[int]) -> bool:
    """Claim one stored row of an older journal for this step: same host, agent, 12-character session, action and
    time ±1 s, ignoring program and files (older formats differ there). Each stored row is claimed at most once, and
    rows inserted by this scan are never claimed, so two real actions in the same second are both kept."""
    _, host, agent, session, category, ts = sig
    rows = conn.execute(
        "SELECT id, metadata_json FROM events WHERE host_id=? AND created_at BETWEEN ? AND ? "
        "AND event_type='observed_step' AND agent_name=? ORDER BY abs(created_at - ?), id",
        (host, ts - NEAR_SEC, ts + NEAR_SEC, agent, ts),
    ).fetchall()
    for row_id, raw in rows:
        if row_id in claimed:
            continue
        try:
            meta = json.loads(raw or "{}")
        except ValueError:
            continue
        if isinstance(meta, dict) and meta.get("session") == session and meta.get("action") == category:
            claimed.add(row_id)
            return True
    return False


def maybe_emit_host_warning(
    conn: Any,
    host_id: str,
    event_type: str,
    message: str,
    metadata: dict[str, Any],
    now: float,
    cooldown: float = WARNING_COOLDOWN_SEC,
) -> bool:
    """Emit at most one WARNING event per (host_id, event_type) per cooldown window."""
    cutoff = now - cooldown
    has_rejected = int(metadata.get("rejected_future", 0) or 0) + int(metadata.get("rejected_invalid_time", 0) or 0) > 0
    rows = conn.execute(
        "SELECT metadata_json FROM events WHERE host_id=? AND event_type=? AND severity='WARNING' AND created_at>=?",
        (host_id, event_type, cutoff),
    ).fetchall()
    if rows:
        if not has_rejected:
            return False
        for (raw_meta,) in rows:
            try:
                parsed = json.loads(raw_meta or "{}")
            except ValueError:
                parsed = {}
            if int(parsed.get("rejected_future", 0) or 0) + int(parsed.get("rejected_invalid_time", 0) or 0) > 0:
                return False
    conn.execute(
        """INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at)
           VALUES(?,?,?,?,?,?,?,?)""",
        (host_id, "journal", "work-journal", event_type, "WARNING", message, json.dumps(metadata, sort_keys=True), now),
    )
    return True


def persist_steps(
    conn: Any,
    snapshot: dict[str, Any],
    *,
    now: float,
    agents: set[str] | None = None,
    project: Path | None = None,
    extra_scope: Any = None,
    activity_roots: list[str] | None = None,
    activity_enabled: bool = True,
    capture: Any = None,
    capture_gaps: list[dict[str, Any]] | None = None,
    capture_metrics: dict[str, Any] | None = None,
    legacy_until_map: dict[str, int] | None = None,
    allow_command: bool | None = None,
    started: float | None = None,
    remote_clock_check: bool = False,
    capture_reader: str | None = None,
    fallback_reason: str = "",
    meta_out: dict[str, Any] | None = None,
) -> dict[str, int]:
    """Persist new observed steps, capture gaps, offsets, and scan metrics inside the caller's transaction."""
    counts: collections.Counter[str] = collections.Counter()
    ensure_journal_tables(conn)
    conn.execute("DELETE FROM observed_step_keys WHERE ts < ?", (now - RETENTION,))
    conn.execute(
        "DELETE FROM events WHERE event_type IN ('observed_step','capture_gap','clock_skew','reader_fallback') AND created_at < ?",
        (now - RETENTION,),
    )

    clock_skew_sec, skew_applied = (
        detect_forward_clock_skew(snapshot, now) if remote_clock_check else (0.0, False)
    )
    if meta_out is not None:
        meta_out["clock_skew_sec"] = round(clock_skew_sec, 1)
        meta_out["skew_applied"] = skew_applied

    # The journal also runs as an independent process. Old resource DBs remain writable
    # during an upgrade. Only post-migration journal writes can supply incident context.
    columns = {r[1] for r in conn.execute("PRAGMA table_info(events)")}
    insert_step = ("INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at"
                   + (",journaled) VALUES(?,?,?,?,?,?,?,?,1)" if "journaled" in columns else ") VALUES(?,?,?,?,?,?,?,?)"))
    rows: list[tuple[Any, ...]] = []
    evidence_by_key = {}
    for key, legacy, stamp, event in project_rows(
        snapshot,
        now=now,
        agents=agents,
        project=project,
        extra_scope=extra_scope,
        activity_roots=activity_roots,
        activity_enabled=activity_enabled,
        capture=capture,
        legacy_until_map=legacy_until_map,
        allow_command=allow_command,
        skipped=counts,
        clock_skew_sec=clock_skew_sec,
        evidence_by_key=evidence_by_key,
    ):
        counts["seen"] += 1
        rows.append((key, legacy, stamp, event))
    # Pass 1: steps already stored under an exact key. Each also claims its stored row, so pass 2 cannot match a
    # different step to it.
    claimed: set[int] = set()
    pending: list[tuple[Any, ...]] = []
    for key, legacy, stamp, event in rows:
        if conn.execute("SELECT 1 FROM observed_step_keys WHERE digest=?", (key,)).fetchone():
            counts["duplicates"] += 1
            continue
        exact = [k for k in legacy if isinstance(k, str)]
        near = [k for k in legacy if isinstance(k, tuple)]
        if any(conn.execute("SELECT 1 FROM observed_step_keys WHERE digest=?", (k,)).fetchone() for k in exact):
            counts["duplicates"] += 1
            conn.execute("INSERT OR IGNORE INTO observed_step_keys(digest, ts) VALUES (?,?)", (key, stamp))
            for sig in near:
                _claim_near(conn, sig, claimed)
            continue
        pending.append((key, near, stamp, event))
    # Pass 2, in scan order: rows of older journals matched by moment, then new actions.
    for key, near, stamp, event in pending:
        if any(_claim_near(conn, sig, claimed) for sig in near):
            counts["duplicates"] += 1
            counts["legacy_near"] += 1
            conn.execute("INSERT OR IGNORE INTO observed_step_keys(digest, ts) VALUES (?,?)", (key, stamp))
            continue
        if conn.execute("INSERT OR IGNORE INTO observed_step_keys(digest, ts) VALUES (?,?)", (key, stamp)).rowcount:
            cur = conn.execute(insert_step, event)
            if getattr(cur, "lastrowid", None):
                claimed.add(int(cur.lastrowid))
                if key in evidence_by_key:
                    step, shared_paths = evidence_by_key[key]
                    event_evidence.store(conn, cur.lastrowid, step, shared_paths, stamp)
            counts["inserted"] += 1
        else:
            counts["duplicates"] += 1

    host = snapshot.get("host_id") or snapshot.get("host") or "local"

    if capture is not None:
        for file_key, state in capture.read.items():
            conn.execute(
                """INSERT INTO capture_offsets VALUES (?,?,?,?,?) ON CONFLICT(file_key) DO UPDATE SET
                   inode=excluded.inode, offset=excluded.offset, legacy_until=excluded.legacy_until,
                   updated=excluded.updated""",
                (file_key, state["inode"], state["offset"], state["legacy_until"], now),
            )
        conn.execute("DELETE FROM capture_offsets WHERE updated < ?", (now - RETENTION,))
        gaps = list(capture.gaps)
        for gap in gaps:
            conn.execute(
                """INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (
                    host,
                    "journal",
                    "work-journal",
                    "capture_gap",
                    "WARNING",
                    f"Capture gap: {gap['reason']}; actions in that span may be missing",
                    json.dumps({"reason": gap["reason"], "file_key": gap.get("file", gap.get("file_key", ""))}),
                    now,
                ),
            )
        counts["gaps"] = len(gaps)
        conn.execute("DELETE FROM capture_metrics WHERE ts < ?", (now - RETENTION,))
        conn.execute(
            "INSERT INTO capture_metrics VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                now,
                sum(1 for s in snapshot.get("sessions", []) if s.get("capture_steps")),
                counts["seen"],
                counts["inserted"],
                counts["duplicates"],
                counts["pending"],
                counts["gaps"],
                capture.files_read,
                capture.bytes_read,
                len(capture.backlog),
                round((time.perf_counter() - started) * 1000, 1) if started else None,
            ),
        )
    elif capture_gaps or capture_metrics is not None or (
        remote_clock_check and (counts["rejected_future"] + counts["rejected_invalid_time"]) > 0
    ):
        gaps = list(capture_gaps or [])
        for gap in gaps:
            reason = redact(gap.get("reason") or "log rotated", 64)
            fk = redact(gap.get("file") or gap.get("file_key") or "", 40)
            conn.execute(
                """INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (
                    host,
                    "journal",
                    "work-journal",
                    "capture_gap",
                    "WARNING",
                    f"Capture gap: {reason}; actions in that span may be missing",
                    json.dumps({"reason": reason, "file_key": fk}),
                    now,
                ),
            )
        counts["gaps"] = len(gaps)
        rejected_total = counts["rejected_future"] + counts["rejected_invalid_time"]
        metrics = capture_metrics or {}
        conn.execute("DELETE FROM capture_metrics WHERE ts < ?", (now - RETENTION,))
        conn.execute(
            "INSERT INTO capture_metrics VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                now,
                sum(1 for s in snapshot.get("sessions", []) if s.get("capture_steps")),
                max(counts["seen"] + rejected_total, int(metrics.get("steps_seen", 0) or 0)),
                counts["inserted"],
                counts["duplicates"],
                max(counts["pending"], int(metrics.get("pending", 0) or 0)),
                counts["gaps"] + (1 if rejected_total > 0 else 0),
                int(metrics.get("files_read", 0) or 0),
                int(metrics.get("bytes_read", 0) or 0),
                int(metrics.get("backlog_files", 0) or 0),
                float(metrics["ms"]) if metrics.get("ms") is not None else None,
            ),
        )

    if remote_clock_check:
        rejected_total = counts["rejected_future"] + counts["rejected_invalid_time"]
        if skew_applied or rejected_total > 0:
            if rejected_total > 0:
                msg = (
                    f"Remote host clock/timestamp error on {host}: "
                    f"{rejected_total} step(s) rejected (skew={round(clock_skew_sec, 1)}s)"
                )
            else:
                msg = (
                    f"Remote host clock on {host} ahead by {round(clock_skew_sec, 1)}s; "
                    f"{counts['clock_adjusted']} step timestamp(s) normalized"
                )
            maybe_emit_host_warning(
                conn,
                host,
                "clock_skew",
                msg,
                {
                    "skew_sec": round(clock_skew_sec, 1),
                    "adjusted": counts["clock_adjusted"],
                    "rejected_future": counts["rejected_future"],
                    "rejected_invalid_time": counts["rejected_invalid_time"],
                },
                now,
            )

    if capture_reader == "fallback":
        reason_clean = redact(fallback_reason or "activity_core_missing", 64)
        maybe_emit_host_warning(
            conn,
            host,
            "reader_fallback",
            f"Remote host {host} using fallback reader ({reason_clean})",
            {"capture_reader": "fallback", "reason": reason_clean},
            now,
        )

    return dict(counts)
