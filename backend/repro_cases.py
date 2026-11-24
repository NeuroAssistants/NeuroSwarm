"""Reproducible test cases converted from failed agent sessions and manual run comparisons.

Security invariant: telemetry text (commands, outputs, messages, paths) is strictly
treated as inert redacted data and is NEVER automatically executed on the server.
"""
from __future__ import annotations

import difflib
import json
import re
import secrets
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

from activity_inspector import evidence_text, is_sensitive_path, mask_evidence_paths, protected_command, redact
from event_evidence import work_summary
from identity import IdentityError
from validation import ValidationError

EXECUTION_MODE = "manual_only"
SAFETY_NOTICE = (
    "Commands and outputs captured from agent telemetry are redacted data only and are never "
    "executed automatically by NeuroSwarm. Run verified commands manually in your local environment."
)
FAILED_EVENT_TYPES = {
    "test_failed",
    "tool_error",
    "command_failed",
    "session_failed",
    "build_failed",
    "run_failed",
    "error",
}
NON_REPRO_EVENT_TYPES = {"host_stale", "quota_429", "rate_limit", "permission_request", "permission_granted", "permission_denied"}
FAILED_OUTCOMES = {"error", "failed", "failure", "timeout", "timed_out", "crashed"}
REVISION_KEYS = ("revision", "git_revision", "git_commit", "commit", "commit_sha", "head_sha", "sha")
REVISION_RE = re.compile(r"^[A-Za-z0-9._/@:+-]{1,80}$")
RUN_STATUSES = {"passed", "failed", "inconclusive"}
MAX_DIFF_LINES = 80


def ensure_tables(conn) -> None:
    """Create tenant-local repro case tables, indexes, and cleanup trigger idempotently."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS repro_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_key TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            source_event_id INTEGER,
            host_id TEXT NOT NULL,
            harness TEXT NOT NULL,
            agent_name TEXT NOT NULL,
            session_id TEXT NOT NULL,
            workspace TEXT NOT NULL DEFAULT '',
            revision TEXT,
            revision_source TEXT,
            program TEXT NOT NULL DEFAULT '',
            command_input TEXT,
            expected_result TEXT,
            observed_outcome TEXT NOT NULL DEFAULT '',
            observed_exit_code INTEGER,
            observed_output TEXT,
            observed_output_truncated INTEGER NOT NULL DEFAULT 0,
            files_json TEXT NOT NULL DEFAULT '[]',
            context_json TEXT NOT NULL DEFAULT '{}',
            created_by TEXT NOT NULL,
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS repro_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES repro_cases(id) ON DELETE CASCADE,
            run_number INTEGER NOT NULL,
            status TEXT NOT NULL,
            revision TEXT,
            command_used TEXT,
            exit_code INTEGER,
            observed_output TEXT,
            observed_output_truncated INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            recorded_by TEXT NOT NULL,
            recorded_at REAL NOT NULL,
            UNIQUE(case_id, run_number)
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_repro_cases_updated ON repro_cases(updated_at DESC, id DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_repro_cases_session ON repro_cases(host_id, session_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_repro_cases_event ON repro_cases(source_event_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_repro_runs_case ON repro_runs(case_id, run_number ASC)")
    conn.execute(
        """CREATE TRIGGER IF NOT EXISTS delete_repro_case_runs AFTER DELETE ON repro_cases BEGIN
            DELETE FROM repro_runs WHERE case_id = OLD.id;
        END"""
    )


def _table_exists(db, name: str) -> bool:
    row = db.query_one("SELECT 1 AS present FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return bool(row)


def _parse_metadata(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def _redact_text(value: Any, limit: int) -> tuple[str | None, bool]:
    if not isinstance(value, str):
        return None, False
    cleaned, truncated = evidence_text(value, limit)
    if cleaned is None:
        return None, False
    return cleaned, bool(truncated)


def _redact_line(value: Any, limit: int = 200) -> str:
    if not isinstance(value, str):
        return ""
    cleaned, _ = evidence_text(value, max(limit * 2, 512))
    if not cleaned:
        return ""
    collapsed = re.sub(r"\s+", " ", cleaned).strip()
    collapsed = mask_evidence_paths(redact(collapsed, max(limit * 2, 512)))
    if len(collapsed) > limit:
        return collapsed[: limit - 1].rstrip() + "…"
    return collapsed


def _validate_int32(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not -(2**31) <= value < 2**31:
        raise ValidationError(f"{field} must be a 32-bit integer or null")
    return value


def _safe_int32(value: Any) -> int | None:
    if type(value) is int and -(2**31) <= value < 2**31:
        return value
    return None


def _clean_revision(value: Any, *, strict: bool = False) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        if strict:
            raise ValidationError("revision must be a string or null")
        return None
    trimmed = value.strip()
    if not trimmed:
        return None
    if (
        len(trimmed) > 80
        or trimmed.startswith("-")
        or ".." in trimmed
        or not REVISION_RE.fullmatch(trimmed)
        or redact(trimmed, 120) != trimmed
        or is_sensitive_path(trimmed)
    ):
        if strict:
            raise ValidationError("revision must be 1-80 git ref/commit characters without secrets or '..'")
        return None
    return trimmed


def _extract_event_revision(metadata: dict[str, Any]) -> str | None:
    for key in REVISION_KEYS:
        candidate = _clean_revision(metadata.get(key), strict=False)
        if candidate:
            return candidate
    return None


def _sanitize_workspace(raw: Any) -> str:
    if not isinstance(raw, str) or not raw.strip():
        return ""
    s = raw.strip().replace("\\", "/")
    if is_sensitive_path(s):
        return ""
    if s.startswith("/") or re.match(r"^[A-Za-z]:/", s):
        s = Path(s.rstrip("/")).name or ""
    if not s or is_sensitive_path(s):
        return ""
    return _redact_line(s, 120)


def _sanitize_files(raw: Any, extra: Any = None) -> list[str]:
    out: list[str] = []
    for source in (raw, extra):
        if not isinstance(source, list):
            continue
        for item in source:
            if not isinstance(item, str):
                continue
            path = item.strip().replace("\\", "/")
            if not path or len(path) > 320:
                continue
            if path.startswith(("/", "~")) or ":" in path or any(ord(c) < 32 for c in path):
                continue
            parts = path.split("/")
            if any(not p or p in {".", ".."} or p.startswith(".") for p in parts):
                continue
            if is_sensitive_path(path):
                continue
            cleaned = _redact_line(path, 240)
            if cleaned and "[redacted" not in cleaned and cleaned not in out:
                out.append(cleaned)
            if len(out) >= 12:
                return out
    return out


def _event_link(org_id: int, event_id: int | None) -> str:
    if not event_id:
        return ""
    return f"/live?event={quote(f'event:{event_id}', safe='')}&org={org_id}"


def _session_id_for_row(row: dict[str, Any], meta: dict[str, Any], work: dict[str, Any]) -> str:
    sid = work.get("session") or (meta.get("session") if isinstance(meta.get("session"), str) else "")
    if sid:
        return _redact_line(sid, 128)
    return f"event:{row['id']}"


def _is_failed_row(row: dict[str, Any], meta: dict[str, Any], work: dict[str, Any]) -> bool:
    etype = str(row.get("event_type") or "").strip().lower()
    severity = str(row.get("severity") or "").strip().upper()
    outcome = str(work.get("outcome") or meta.get("outcome") or "").strip().lower()
    exit_code = _safe_int32(row.get("exit_code"))
    if exit_code is None:
        exit_code = _safe_int32(meta.get("exit_code"))

    if etype in NON_REPRO_EVENT_TYPES:
        return False
    if exit_code is not None and exit_code != 0:
        return True
    if etype == "observed_step":
        return severity in {"ERROR", "CRITICAL"} or outcome in FAILED_OUTCOMES
    if etype in FAILED_EVENT_TYPES:
        return True
    return severity in {"ERROR", "CRITICAL"}


def _raw_command_and_output(row: dict[str, Any], meta: dict[str, Any]) -> tuple[str | None, str | None, int | None, bool, str | None]:
    raw_cmd = row.get("command_input")
    if not isinstance(raw_cmd, str) or not raw_cmd.strip():
        raw_cmd = meta.get("command_input") if isinstance(meta.get("command_input"), str) else meta.get("command")
    raw_cmd_str = raw_cmd if isinstance(raw_cmd, str) and raw_cmd.strip() else None

    cmd_redacted, _ = _redact_text(raw_cmd_str, 1024)
    if isinstance(cmd_redacted, str) and not cmd_redacted.strip():
        cmd_redacted = None

    suppressed_reason: str | None = None
    if protected_command(raw_cmd_str) or protected_command(cmd_redacted):
        out_redacted = None
        out_truncated = False
        suppressed_reason = "protected_command"
    else:
        raw_out = row.get("command_output")
        if not isinstance(raw_out, str) or not raw_out.strip():
            raw_out = (
                meta.get("observed_output")
                if isinstance(meta.get("observed_output"), str)
                else meta.get("command_output")
                if isinstance(meta.get("command_output"), str)
                else meta.get("output")
            )
        out_redacted, out_truncated = _redact_text(raw_out, 4096)
        if out_redacted == "":
            out_redacted = None
        out_truncated = bool(out_truncated or row.get("output_truncated"))

    exit_code = _safe_int32(row.get("exit_code"))
    if exit_code is None:
        exit_code = _safe_int32(meta.get("exit_code"))

    return cmd_redacted, out_redacted, exit_code, out_truncated, suppressed_reason


def _collect_session_context(db, org_id: int, anchor_row: dict[str, Any], meta: dict[str, Any], work: dict[str, Any]) -> dict[str, Any]:
    session_id = _session_id_for_row(anchor_row, meta, work)
    host_id = str(anchor_row.get("host_id") or "")
    has_real_session = bool(work.get("session") or (isinstance(meta.get("session"), str) and meta.get("session").strip()))

    recent_steps: list[dict[str, Any]] = []
    agg_files: list[str] = _sanitize_files(work.get("files"), meta.get("files"))
    revision = _extract_event_revision(meta)

    if has_real_session:
        peer_rows = db.query_all(
            """SELECT e.id, e.event_type, e.severity, e.message, e.metadata_json, e.created_at, x.exit_code
               FROM events e LEFT JOIN event_execution x ON x.event_id = e.id
               WHERE e.host_id = ? AND e.id <= ?
               ORDER BY e.id DESC LIMIT 40""",
            (host_id, anchor_row["id"]),
        )
        matched_rows: list[tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = []
        for prow in peer_rows:
            pmeta = _parse_metadata(prow.get("metadata_json"))
            pwork = work_summary(pmeta) if prow.get("event_type") == "observed_step" else {}
            psid = _session_id_for_row(prow, pmeta, pwork)
            if psid != session_id:
                continue
            matched_rows.append((prow, pmeta, pwork))
            if not revision:
                revision = _extract_event_revision(pmeta)
            for path in _sanitize_files(pwork.get("files"), pmeta.get("files")):
                if path not in agg_files and len(agg_files) < 12:
                    agg_files.append(path)
        for prow, pmeta, pwork in reversed(matched_rows[:5]):
            recent_steps.append(
                {
                    "event_id": prow["id"],
                    "tool": _redact_line(pwork.get("tool") or pmeta.get("tool") or prow.get("event_type") or "", 48),
                    "outcome": _redact_line(pwork.get("outcome") or pmeta.get("outcome") or prow.get("severity") or "", 32),
                    "summary": _redact_line(prow.get("message") or "", 180),
                    "exit_code": _safe_int32(prow.get("exit_code")) if prow.get("exit_code") is not None else _safe_int32(pmeta.get("exit_code")),
                    "created_at": prow["created_at"],
                }
            )
    else:
        recent_steps.append(
            {
                "event_id": anchor_row["id"],
                "tool": _redact_line(meta.get("tool") or anchor_row.get("event_type") or "", 48),
                "outcome": _redact_line(meta.get("outcome") or anchor_row.get("severity") or "", 32),
                "summary": _redact_line(anchor_row.get("message") or "", 180),
                "exit_code": _safe_int32(anchor_row.get("exit_code")) if anchor_row.get("exit_code") is not None else _safe_int32(meta.get("exit_code")),
                "created_at": anchor_row["created_at"],
            }
        )

    cmd_redacted, out_redacted, exit_code, out_truncated, suppressed_reason = _raw_command_and_output(anchor_row, meta)
    expected_raw = meta.get("expected_result") if isinstance(meta.get("expected_result"), str) else meta.get("expected")
    expected_redacted, _ = _redact_text(expected_raw, 1024)
    if isinstance(expected_redacted, str) and not expected_redacted.strip():
        expected_redacted = None

    workspace = _sanitize_workspace(work.get("workspace") or meta.get("workspace") or "")
    program = _redact_line(work.get("program") or meta.get("program") or "", 48)
    outcome = _redact_line(work.get("outcome") or meta.get("outcome") or anchor_row.get("severity") or "failed", 32).lower() or "failed"
    summary = _redact_line(anchor_row.get("message") or "", 240)
    default_title = summary or (f"Failed {program}" if program else f"Failed session {session_id}")
    if len(default_title) > 120:
        default_title = default_title[:119].rstrip() + "…"

    return {
        "source_event_id": anchor_row["id"],
        "event_link": _event_link(org_id, anchor_row["id"]),
        "host_id": _redact_line(host_id, 128),
        "harness": _redact_line(work.get("runtime") or anchor_row.get("harness") or "unknown", 64),
        "agent_name": _redact_line(work.get("agent") or anchor_row.get("agent_name") or "Agent", 80),
        "session_id": session_id,
        "workspace": workspace,
        "revision": revision,
        "revision_source": "event_metadata" if revision else None,
        "program": program,
        "command_input": cmd_redacted,
        "expected_result": expected_redacted,
        "observed_outcome": outcome,
        "observed_exit_code": exit_code,
        "observed_output": out_redacted,
        "observed_output_truncated": out_truncated,
        "output_suppressed_reason": suppressed_reason,
        "files": agg_files,
        "failure_summary": summary,
        "suggested_title": default_title,
        "recent_steps": recent_steps,
        "failed_at": anchor_row["created_at"],
    }


def list_failed_sessions(db, org_id: int, limit: int = 20) -> list[dict[str, Any]]:
    """Discover failed sessions from recent ingested events without executing any telemetry."""
    rows = db.query_all(
        """SELECT e.id, e.host_id, e.harness, e.agent_name, e.event_type, e.severity,
                  e.message, e.metadata_json, e.created_at,
                  x.command_input, x.command_output, x.exit_code, x.output_truncated
           FROM events e
           LEFT JOIN event_execution x ON x.event_id = e.id
           ORDER BY e.created_at DESC, e.id DESC
           LIMIT 400"""
    )

    existing_by_event: dict[int, int] = {}
    existing_by_session: dict[tuple[str, str], int] = {}
    if _table_exists(db, "repro_cases"):
        for crow in db.query_all("SELECT id, source_event_id, host_id, session_id FROM repro_cases ORDER BY id DESC"):
            if crow["source_event_id"] is not None and crow["source_event_id"] not in existing_by_event:
                existing_by_event[int(crow["source_event_id"])] = int(crow["id"])
            key = (str(crow["host_id"]), str(crow["session_id"]))
            if key not in existing_by_session:
                existing_by_session[key] = int(crow["id"])

    seen_sessions: set[tuple[str, str]] = set()
    candidates: list[dict[str, Any]] = []
    for row in rows:
        meta = _parse_metadata(row.get("metadata_json"))
        work = work_summary(meta) if row.get("event_type") == "observed_step" else {}
        if not _is_failed_row(row, meta, work):
            continue
        session_id = _session_id_for_row(row, meta, work)
        dedup_key = (str(row.get("host_id") or ""), session_id)
        if dedup_key in seen_sessions:
            continue
        seen_sessions.add(dedup_key)
        ctx = _collect_session_context(db, org_id, row, meta, work)
        existing_id = existing_by_event.get(int(row["id"])) or existing_by_session.get(dedup_key)
        ctx["existing_case_id"] = existing_id
        ctx["has_command"] = ctx["command_input"] is not None
        ctx["has_output"] = ctx["observed_output"] is not None
        ctx["has_revision"] = ctx["revision"] is not None
        candidates.append(ctx)
        if len(candidates) >= limit:
            break
    return candidates


def compare_run(baseline: dict[str, Any], run: dict[str, Any]) -> dict[str, Any]:
    """Deterministically compare a manual verification run against the baseline failure."""
    status = str(run.get("status") or "").lower()
    b_code = baseline.get("exit_code")
    r_code = run.get("exit_code")
    b_rev = baseline.get("revision")
    r_rev = run.get("revision")
    b_cmd = baseline.get("command_input")
    r_cmd = run.get("command_used")
    b_out = baseline.get("observed_output")
    r_out = run.get("observed_output")

    exit_differs = b_code is not None and r_code is not None and b_code != r_code
    out_norm_b = (b_out or "").strip() if isinstance(b_out, str) else ""
    out_norm_r = (r_out or "").strip() if isinstance(r_out, str) else ""
    out_differs = bool(out_norm_b and out_norm_r and out_norm_b != out_norm_r)

    if status == "inconclusive":
        verdict = "inconclusive"
        verdict_label = "Inconclusive"
        summary = "Run marked inconclusive by the operator."
    elif status == "passed":
        if r_code is not None and r_code != 0:
            verdict = "inconclusive"
            verdict_label = "Inconclusive"
            summary = f"Marked passed, but recorded non-zero exit code {r_code}."
        else:
            verdict = "fixed"
            verdict_label = "Fixed"
            summary = "Verification run passed against the baseline failure."
    else:
        if exit_differs or out_differs:
            verdict = "changed_failure"
            verdict_label = "Changed failure"
            summary = "Run still failed, but exit code or observed output changed from baseline."
        else:
            verdict = "still_failing"
            verdict_label = "Still failing"
            summary = "Run reproduced the failure with matching exit/output characteristics."

    diff_lines: list[str] = []
    diff_truncated = False
    if out_norm_b or out_norm_r:
        raw_diff = list(
            difflib.unified_diff(
                (b_out or "").splitlines(),
                (r_out or "").splitlines(),
                fromfile="baseline",
                tofile=f"run-{run.get('run_number', '?')}",
                lineterm="",
                n=2,
            )
        )
        if len(raw_diff) > MAX_DIFF_LINES:
            diff_lines = raw_diff[:MAX_DIFF_LINES]
            diff_truncated = True
        else:
            diff_lines = raw_diff

    return {
        "verdict": verdict,
        "verdict_label": verdict_label,
        "summary": summary,
        "exit_code_baseline": b_code,
        "exit_code_run": r_code,
        "exit_code_changed": (b_code != r_code) if (b_code is not None and r_code is not None) else None,
        "revision_baseline": b_rev,
        "revision_run": r_rev,
        "revision_changed": (b_rev != r_rev) if (b_rev is not None and r_rev is not None) else None,
        "command_changed": (b_cmd != r_cmd) if (b_cmd and r_cmd) else None,
        "output_changed": (out_norm_b != out_norm_r) if (isinstance(b_out, str) and isinstance(r_out, str)) else None,
        "diff_lines": diff_lines,
        "diff_truncated": diff_truncated,
    }


def _present_run(row: dict[str, Any], baseline: dict[str, Any], previous: dict[str, Any] | None) -> dict[str, Any]:
    run_obj = {
        "id": row["id"],
        "case_id": row["case_id"],
        "run_number": row["run_number"],
        "status": row["status"],
        "revision": row["revision"],
        "command_used": row["command_used"],
        "exit_code": row["exit_code"],
        "observed_output": row["observed_output"],
        "observed_output_truncated": bool(row["observed_output_truncated"]),
        "notes": row["notes"],
        "recorded_by": row["recorded_by"],
        "recorded_at": row["recorded_at"],
    }
    run_obj["comparison"] = compare_run(baseline, run_obj)
    if previous is not None:
        prev_out = (previous.get("observed_output") or "").strip()
        cur_out = (run_obj.get("observed_output") or "").strip()
        run_obj["vs_previous"] = {
            "previous_run_number": previous["run_number"],
            "status_changed": previous["status"] != run_obj["status"],
            "exit_code_changed": (
                previous["exit_code"] != run_obj["exit_code"]
                if previous["exit_code"] is not None and run_obj["exit_code"] is not None
                else None
            ),
            "output_changed": (
                prev_out != cur_out
                if previous.get("observed_output") is not None and run_obj.get("observed_output") is not None
                else None
            ),
        }
    else:
        run_obj["vs_previous"] = None
    return run_obj


def _present_case(db, org_id: int, row: dict[str, Any], runs_rows: list[dict[str, Any]], *, can_write: bool, role: str) -> dict[str, Any]:
    try:
        files = json.loads(row.get("files_json") or "[]")
    except (TypeError, ValueError):
        files = []
    ctx = _parse_metadata(row.get("context_json"))
    baseline = {
        "status": "failed",
        "revision": row["revision"],
        "command_input": row["command_input"],
        "expected_result": row["expected_result"],
        "observed_outcome": row["observed_outcome"],
        "exit_code": row["observed_exit_code"],
        "observed_output": row["observed_output"],
        "observed_output_truncated": bool(row["observed_output_truncated"]),
    }
    runs: list[dict[str, Any]] = []
    prev_run: dict[str, Any] | None = None
    for rrow in runs_rows:
        presented = _present_run(rrow, baseline, prev_run)
        runs.append(presented)
        prev_run = presented

    latest_run = runs[-1] if runs else None
    latest_comp = latest_run["comparison"] if latest_run else None
    return {
        "id": row["id"],
        "case_key": row["case_key"],
        "organization": org_id,
        "role": role,
        "can_write": can_write,
        "execution_mode": EXECUTION_MODE,
        "safety_notice": SAFETY_NOTICE,
        "title": row["title"],
        "source_event_id": row["source_event_id"],
        "event_link": _event_link(org_id, row["source_event_id"]),
        "host_id": row["host_id"],
        "harness": row["harness"],
        "agent_name": row["agent_name"],
        "session_id": row["session_id"],
        "workspace": row["workspace"],
        "revision": row["revision"],
        "revision_source": row["revision_source"],
        "program": row["program"],
        "command_input": row["command_input"],
        "expected_result": row["expected_result"],
        "observed_outcome": row["observed_outcome"],
        "observed_exit_code": row["observed_exit_code"],
        "observed_output": row["observed_output"],
        "observed_output_truncated": bool(row["observed_output_truncated"]),
        "files": files if isinstance(files, list) else [],
        "context": ctx,
        "baseline": baseline,
        "runs": runs,
        "run_count": len(runs),
        "latest_run": latest_run,
        "latest_comparison": latest_comp,
        "latest_verdict": latest_comp["verdict"] if latest_comp else "baseline_only",
        "latest_verdict_label": latest_comp["verdict_label"] if latest_comp else "Baseline failed",
        "export_urls": {
            "json": f"/api/v1/repro-cases/{row['id']}/export?format=json&organization_id={org_id}",
            "markdown": f"/api/v1/repro-cases/{row['id']}/export?format=markdown&organization_id={org_id}",
        },
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_overview(db, org_id: int, *, can_write: bool, role: str) -> dict[str, Any]:
    """List failed session candidates and saved reproducible test cases for an organization."""
    failed_sessions = list_failed_sessions(db, org_id)
    cases: list[dict[str, Any]] = []
    if _table_exists(db, "repro_cases"):
        case_rows = db.query_all("SELECT * FROM repro_cases ORDER BY updated_at DESC, id DESC LIMIT 100")
        runs_by_case: dict[int, list[dict[str, Any]]] = {}
        if case_rows and _table_exists(db, "repro_runs"):
            case_ids = [int(c["id"]) for c in case_rows]
            marks = ",".join("?" for _ in case_ids)
            for rrow in db.query_all(
                f"SELECT * FROM repro_runs WHERE case_id IN ({marks}) ORDER BY run_number ASC",
                tuple(case_ids),
            ):
                runs_by_case.setdefault(int(rrow["case_id"]), []).append(rrow)
        for crow in case_rows:
            cases.append(_present_case(db, org_id, crow, runs_by_case.get(int(crow["id"]), []), can_write=can_write, role=role))

    fixed_count = sum(1 for c in cases if c["latest_verdict"] == "fixed")
    failing_count = sum(1 for c in cases if c["latest_verdict"] in {"still_failing", "changed_failure"})
    baseline_only = sum(1 for c in cases if c["latest_verdict"] == "baseline_only")
    return {
        "organization": org_id,
        "role": role,
        "can_write": can_write,
        "execution_mode": EXECUTION_MODE,
        "safety_notice": SAFETY_NOTICE,
        "generated_at": time.time(),
        "counts": {
            "failed_sessions": len(failed_sessions),
            "cases": len(cases),
            "fixed": fixed_count,
            "still_failing": failing_count,
            "baseline_only": baseline_only,
        },
        "failed_sessions": failed_sessions,
        "cases": cases,
    }


def get_case(db, org_id: int, case_id: int, *, can_write: bool, role: str) -> dict[str, Any] | None:
    """Return full details and run comparisons for a single repro case in the active organization."""
    if not _table_exists(db, "repro_cases"):
        return None
    row = db.query_one("SELECT * FROM repro_cases WHERE id = ?", (case_id,))
    if row is None:
        return None
    runs = (
        db.query_all("SELECT * FROM repro_runs WHERE case_id = ? ORDER BY run_number ASC", (case_id,))
        if _table_exists(db, "repro_runs")
        else []
    )
    return _present_case(db, org_id, row, runs, can_write=can_write, role=role)


def _optional_str_field(body: dict[str, Any], key: str, max_len: int) -> str | None:
    if key not in body or body[key] is None:
        return None
    val = body[key]
    if not isinstance(val, str):
        raise ValidationError(f"{key} must be a string or null")
    if len(val) > max_len * 4:
        raise ValidationError(f"{key} exceeds maximum allowed length")
    return val


def create_case(db, org_id: int, actor: str, body: dict[str, Any], *, role: str = "operator") -> dict[str, Any]:
    """Convert a failed session event into a saved minimal redacted reproducible test case."""
    ensure_tables(db._conn)

    raw_event_id = body.get("source_event_id")
    raw_session_id = body.get("session_id")
    if raw_event_id is None and not (isinstance(raw_session_id, str) and raw_session_id.strip()):
        raise ValidationError("Provide source_event_id or session_id to convert")

    if raw_event_id is not None:
        if type(raw_event_id) is not int or not 0 < raw_event_id < 2**63:
            raise ValidationError("source_event_id must be a positive integer")
        anchor = db.query_one(
            """SELECT e.id, e.host_id, e.harness, e.agent_name, e.event_type, e.severity,
                      e.message, e.metadata_json, e.created_at,
                      x.command_input, x.command_output, x.exit_code, x.output_truncated
               FROM events e
               LEFT JOIN event_execution x ON x.event_id = e.id
               WHERE e.id = ?""",
            (raw_event_id,),
        )
        if anchor is None:
            raise IdentityError(404, "Source event not found")
        meta = _parse_metadata(anchor.get("metadata_json"))
        work = work_summary(meta) if anchor.get("event_type") == "observed_step" else {}
        if isinstance(raw_session_id, str) and raw_session_id.strip():
            actual_sid = _session_id_for_row(anchor, meta, work)
            if actual_sid != raw_session_id.strip():
                raise ValidationError("source_event_id does not belong to the requested session_id")
    else:
        if not isinstance(raw_session_id, str) or len(raw_session_id.strip()) > 256:
            raise ValidationError("Invalid session_id")
        target_sid = raw_session_id.strip()
        rows = db.query_all(
            """SELECT e.id, e.host_id, e.harness, e.agent_name, e.event_type, e.severity,
                      e.message, e.metadata_json, e.created_at,
                      x.command_input, x.command_output, x.exit_code, x.output_truncated
               FROM events e
               LEFT JOIN event_execution x ON x.event_id = e.id
               ORDER BY e.created_at DESC, e.id DESC
               LIMIT 400"""
        )
        anchor = None
        meta = {}
        work = {}
        for cand in rows:
            cmeta = _parse_metadata(cand.get("metadata_json"))
            cwork = work_summary(cmeta) if cand.get("event_type") == "observed_step" else {}
            if _session_id_for_row(cand, cmeta, cwork) == target_sid and _is_failed_row(cand, cmeta, cwork):
                anchor = cand
                meta = cmeta
                work = cwork
                break
        if anchor is None:
            raise IdentityError(404, "Failed session not found")

    ctx = _collect_session_context(db, org_id, anchor, meta, work)

    title_raw = _optional_str_field(body, "title", 180)
    title = _redact_line(title_raw, 180) if isinstance(title_raw, str) and title_raw.strip() else ctx["suggested_title"]
    if not title:
        title = f"Failed session {ctx['session_id']}"

    expected_raw = _optional_str_field(body, "expected_result", 1024)
    if expected_raw is not None:
        expected_result, _ = _redact_text(expected_raw, 1024)
        expected_result = expected_result if expected_result and expected_result.strip() else None
    else:
        expected_result = ctx["expected_result"]

    notes_raw = _optional_str_field(body, "notes", 1024)
    operator_notes, _ = _redact_text(notes_raw, 1024) if notes_raw else (None, False)
    if operator_notes == "":
        operator_notes = None

    rev_raw = _optional_str_field(body, "revision", 80)
    if rev_raw is not None and rev_raw.strip():
        revision = _clean_revision(rev_raw, strict=True)
        revision_source = "operator"
    else:
        revision = ctx["revision"]
        revision_source = ctx["revision_source"]

    cmd_override = _optional_str_field(body, "command_input", 1024)
    command_input = ctx["command_input"]
    suppressed_reason = ctx["output_suppressed_reason"]
    if cmd_override is not None:
        red_cmd, _ = _redact_text(cmd_override, 1024)
        command_input = red_cmd if red_cmd and red_cmd.strip() else None
        if protected_command(cmd_override) or protected_command(command_input):
            suppressed_reason = "protected_command"

    out_override = _optional_str_field(body, "observed_output", 4096)
    if suppressed_reason:
        observed_output = None
        observed_output_truncated = False
    elif out_override is not None:
        observed_output, observed_output_truncated = _redact_text(out_override, 4096)
        if observed_output == "":
            observed_output = None
    else:
        observed_output = ctx["observed_output"]
        observed_output_truncated = ctx["observed_output_truncated"]

    if "exit_code" in body and body["exit_code"] is not None:
        observed_exit_code = _validate_int32(body["exit_code"], "exit_code")
    else:
        observed_exit_code = ctx["observed_exit_code"]

    context_payload = {
        "failure_summary": ctx["failure_summary"],
        "recent_steps": ctx["recent_steps"],
        "operator_notes": operator_notes,
        "output_suppressed_reason": suppressed_reason,
        "execution_mode": EXECUTION_MODE,
    }
    now = time.time()
    case_key = f"rc-{ctx['source_event_id']}-{secrets.token_hex(4)}"
    case_id = db.execute(
        """INSERT INTO repro_cases (
               case_key, title, source_event_id, host_id, harness, agent_name, session_id, workspace,
               revision, revision_source, program, command_input, expected_result, observed_outcome,
               observed_exit_code, observed_output, observed_output_truncated, files_json, context_json,
               created_by, created_at, updated_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            case_key,
            title,
            ctx["source_event_id"],
            ctx["host_id"],
            ctx["harness"],
            ctx["agent_name"],
            ctx["session_id"],
            ctx["workspace"],
            revision,
            revision_source,
            ctx["program"],
            command_input,
            expected_result,
            ctx["observed_outcome"],
            observed_exit_code,
            observed_output,
            int(bool(observed_output_truncated)),
            json.dumps(ctx["files"]),
            json.dumps(context_payload),
            actor[:128],
            now,
            now,
        ),
    )
    db.append_audit(
        db._conn,
        actor,
        "repro_case_create",
        f"repro_case:{case_id}",
        json.dumps({"case_key": case_key, "source_event_id": ctx["source_event_id"], "session_id": ctx["session_id"]}),
    )
    created = get_case(db, org_id, case_id, can_write=True, role=role)
    assert created is not None
    return created


def record_run(db, org_id: int, case_id: int, actor: str, body: dict[str, Any], *, role: str = "operator") -> dict[str, Any] | None:
    """Record a manual reproduction run against a saved repro case and compare it to baseline."""
    ensure_tables(db._conn)
    case_row = db.query_one("SELECT * FROM repro_cases WHERE id = ?", (case_id,))
    if case_row is None:
        return None

    raw_status = body.get("status")
    if not isinstance(raw_status, str) or raw_status.strip().lower() not in RUN_STATUSES:
        raise ValidationError("status must be passed, failed, or inconclusive")
    status = raw_status.strip().lower()

    exit_code = _validate_int32(body.get("exit_code"), "exit_code")
    rev_raw = _optional_str_field(body, "revision", 80)
    revision = _clean_revision(rev_raw, strict=True) if rev_raw and rev_raw.strip() else None

    cmd_raw = _optional_str_field(body, "command_used", 1024)
    command_used, _ = _redact_text(cmd_raw, 1024) if cmd_raw else (None, False)
    if command_used == "":
        command_used = None

    out_raw = _optional_str_field(body, "observed_output", 4096)
    if protected_command(cmd_raw) or protected_command(command_used) or (not command_used and protected_command(case_row["command_input"])):
        observed_output, observed_output_truncated = None, False
    elif out_raw is not None:
        observed_output, observed_output_truncated = _redact_text(out_raw, 4096)
        if observed_output == "":
            observed_output = None
    else:
        observed_output, observed_output_truncated = None, False

    notes_raw = _optional_str_field(body, "notes", 1024)
    notes, _ = _redact_text(notes_raw, 1024) if notes_raw else (None, False)
    if notes == "":
        notes = None

    last = db.query_one("SELECT COALESCE(MAX(run_number), 0) AS max_n FROM repro_runs WHERE case_id = ?", (case_id,))
    run_number = int(last["max_n"] if last else 0) + 1
    now = time.time()
    run_id = db.execute(
        """INSERT INTO repro_runs (
               case_id, run_number, status, revision, command_used, exit_code,
               observed_output, observed_output_truncated, notes, recorded_by, recorded_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            case_id,
            run_number,
            status,
            revision,
            command_used,
            exit_code,
            observed_output,
            int(bool(observed_output_truncated)),
            notes,
            actor[:128],
            now,
        ),
    )
    db.execute("UPDATE repro_cases SET updated_at = ? WHERE id = ?", (now, case_id))
    db.append_audit(
        db._conn,
        actor,
        "repro_run_record",
        f"repro_case:{case_id}",
        json.dumps({"run_id": run_id, "run_number": run_number, "status": status, "exit_code": exit_code}),
    )

    updated = get_case(db, org_id, case_id, can_write=True, role=role)
    assert updated is not None
    new_run = next((r for r in updated["runs"] if r["id"] == run_id), updated["runs"][-1])
    return {"case": updated, "run": new_run, "comparison": new_run["comparison"]}


def _fence_block(text: str, lang: str = "text") -> str:
    ticks = "~" * 3
    while ticks in text:
        ticks += "~"
    return f"{ticks}{lang}\n{text}\n{ticks}"


def export_case(db, org_id: int, case_id: int, fmt: str = "json", *, can_write: bool = False, role: str = "viewer") -> tuple[bytes, str, str] | None:
    """Export a minimal, redacted, manual-only reproducible bundle as JSON or Markdown."""
    case = get_case(db, org_id, case_id, can_write=can_write, role=role)
    if case is None:
        return None

    clean_fmt = (fmt or "json").strip().lower()
    if clean_fmt not in {"json", "markdown", "md"}:
        raise ValidationError("format must be json or markdown")

    bundle = {
        "schema_version": "1.0",
        "execution_mode": EXECUTION_MODE,
        "safety_notice": SAFETY_NOTICE,
        "case_id": case["id"],
        "case_key": case["case_key"],
        "title": case["title"],
        "created_at": case["created_at"],
        "created_by": case["created_by"],
        "context": {
            "host_id": case["host_id"],
            "harness": case["harness"],
            "agent_name": case["agent_name"],
            "session_id": case["session_id"],
            "workspace": case["workspace"] or None,
            "source_event_id": case["source_event_id"],
            "files": case["files"],
            "failure_summary": case["context"].get("failure_summary"),
            "recent_steps": case["context"].get("recent_steps", []),
            "operator_notes": case["context"].get("operator_notes"),
        },
        "revision": case["revision"],
        "revision_source": case["revision_source"],
        "command": case["command_input"],
        "expected_result": case["expected_result"],
        "observed": {
            "outcome": case["observed_outcome"],
            "exit_code": case["observed_exit_code"],
            "output": case["observed_output"],
            "output_truncated": case["observed_output_truncated"],
            "output_suppressed_reason": case["context"].get("output_suppressed_reason"),
        },
        "runs": [
            {
                "run_number": r["run_number"],
                "status": r["status"],
                "revision": r["revision"],
                "command_used": r["command_used"],
                "exit_code": r["exit_code"],
                "observed_output": r["observed_output"],
                "notes": r["notes"],
                "recorded_by": r["recorded_by"],
                "recorded_at": r["recorded_at"],
                "comparison": r["comparison"],
            }
            for r in case["runs"]
        ],
    }

    if clean_fmt == "json":
        payload = json.dumps(bundle, indent=2, ensure_ascii=False).encode("utf-8")
        return payload, "application/json; charset=utf-8", f"repro-case-{case_id}.json"

    lines = [
        f"# Reproducible Case #{case['id']}: {case['title']}",
        "",
        f"> **Execution mode:** `{EXECUTION_MODE}` — {SAFETY_NOTICE}",
        "",
        "## Context",
        f"- **Case key:** `{case['case_key']}`",
        f"- **Host / Runtime / Agent:** `{case['host_id']}` / `{case['harness']}` / `{case['agent_name']}`",
        f"- **Session:** `{case['session_id']}`",
        f"- **Workspace:** `{case['workspace'] or 'Not recorded'}`",
        f"- **Revision:** `{case['revision'] or 'Not recorded'}`",
        f"- **Files:** {', '.join(f'`{f}`' for f in case['files']) if case['files'] else 'None recorded'}",
        "",
        "## Command (run manually)",
        _fence_block(case["command_input"] or "Not recorded in captured telemetry.", "sh"),
        "",
        "## Expected result",
        _fence_block(case["expected_result"] or "Not recorded.", "text"),
        "",
        "## Baseline observed result",
        f"- **Outcome:** `{case['observed_outcome']}`",
        f"- **Exit code:** `{case['observed_exit_code'] if case['observed_exit_code'] is not None else 'Not recorded'}`",
        _fence_block(case["observed_output"] or "Not recorded.", "text"),
        "",
        "## Verification runs",
    ]
    if not case["runs"]:
        lines.append("No verification runs recorded yet.")
    else:
        for run in case["runs"]:
            comp = run["comparison"]
            lines.extend(
                [
                    f"### Run #{run['run_number']} — {comp['verdict_label']} (`{run['status']}`)",
                    f"- **Revision:** `{run['revision'] or 'Not recorded'}`",
                    f"- **Exit code:** `{run['exit_code'] if run['exit_code'] is not None else 'Not recorded'}`",
                    f"- **Summary:** {comp['summary']}",
                    _fence_block(run["observed_output"] or "No output recorded.", "text"),
                ]
            )
            if comp["diff_lines"]:
                lines.append("Diff vs baseline:")
                lines.append(_fence_block("\n".join(comp["diff_lines"]), "diff"))
            lines.append("")
    return "\n".join(lines).encode("utf-8"), "text/markdown; charset=utf-8", f"repro-case-{case_id}.md"
