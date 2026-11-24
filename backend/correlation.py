"""Explicit correlation between assignments/tasks, sessions, observed steps, and confirmed files.

Implements LINK-CONTRACT v1:
- Uses ONLY explicit relationships (`metadata.task_id` on observed steps, or unambiguous
  orchestrator turn→session links).
- Never infers a link from agent names, titles, or nearby timestamps.
- Reports `status: "unknown"` with an explicit reason whenever evidence is missing or ambiguous.
- Strictly tenant-scoped to the active organization's database.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

IDENTIFIER_RE = re.compile(r"[\w][\w.:-]{0,95}", re.ASCII)


def clean_task_id(raw: Any) -> str:
    """Validate an explicit task/assignment identifier, returning '' if absent or invalid."""
    if not isinstance(raw, str):
        return ""
    val = raw.strip()
    if not val or len(val) > 96 or not IDENTIFIER_RE.fullmatch(val):
        return ""
    return val


def _parse_json(raw: Any) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def _is_confirmed_file_step(meta: dict[str, Any]) -> bool:
    files = meta.get("files")
    if not isinstance(files, list) or not files:
        return False
    basis = str(meta.get("basis") or "").strip().lower()
    action = str(meta.get("action") or "").strip().lower()
    if basis == "mentioned":
        return False
    return basis == "confirmed" or action == "file_edit"


def _step_summary(row: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    files = [str(f) for f in (meta.get("files") or []) if isinstance(f, str) and f.strip()]
    return {
        "event_id": int(row["id"]),
        "key": f"event:{int(row['id'])}",
        "ts": float(row["created_at"] or 0.0),
        "action": str(meta.get("action") or "other"),
        "message": str(row.get("message") or ""),
        "program": str(meta.get("program") or ""),
        "file": files[0] if files else "",
        "file_basis": str(meta.get("basis") or ""),
    }


def _build_linked_entry(
    task_id: str,
    change_id: str,
    basis: str,
    reason: str,
    matched_rows: list[tuple[dict[str, Any], dict[str, Any]]],
    fallback_session: str = "",
    fallback_runtime: str = "",
) -> dict[str, Any]:
    # matched_rows is ordered newest-first (created_at DESC, id DESC)
    latest_row, latest_meta = matched_rows[0]
    session_id = str(latest_meta.get("session") or fallback_session or "")
    host_id = str(latest_row.get("host_id") or "")
    agent = str(latest_meta.get("agent") or latest_row.get("agent_name") or "")
    runtime = str(latest_meta.get("runtime") or latest_row.get("harness") or fallback_runtime or "")

    confirmed_files: list[str] = []
    confirmed_file_event_id: int | None = None
    for row, meta in matched_rows:
        if not _is_confirmed_file_step(meta):
            continue
        if confirmed_file_event_id is None:
            confirmed_file_event_id = int(row["id"])
        for f in meta.get("files") or []:
            if isinstance(f, str) and f.strip() and f not in confirmed_files:
                confirmed_files.append(f)
                if len(confirmed_files) >= 12:
                    break
        if len(confirmed_files) >= 12:
            break

    return {
        "task_id": task_id,
        "change_id": change_id,
        "status": "linked",
        "basis": basis,
        "reason": reason,
        "session_id": session_id,
        "host_id": host_id,
        "agent": agent,
        "runtime": runtime,
        "step_count": len(matched_rows),
        "last_step": _step_summary(latest_row, latest_meta),
        "confirmed_file": confirmed_files[0] if confirmed_files else "",
        "confirmed_files": confirmed_files,
        "confirmed_file_event_id": confirmed_file_event_id,
    }


def _build_unknown_entry(
    task_id: str,
    change_id: str,
    basis: str,
    reason: str,
    *,
    session_id: str = "",
    runtime: str = "",
    host_id: str = "",
    agent: str = "",
) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "change_id": change_id,
        "status": "unknown",
        "basis": basis,
        "reason": reason,
        "session_id": session_id,
        "host_id": host_id,
        "agent": agent,
        "runtime": runtime,
        "step_count": 0,
        "last_step": None,
        "confirmed_file": "",
        "confirmed_files": [],
        "confirmed_file_event_id": None,
    }


def resolve_links(
    db: Any,
    org_id: int,
    collaboration_data: dict[str, Any] | None = None,
    reports: list[dict[str, Any]] | None = None,
    openbot_turn_links: dict[str, dict[str, Any]] | None = None,
    *,
    filter_task_id: str = "",
    filter_session: str = "",
    now: float | None = None,
) -> dict[str, Any]:
    """Build tenant-scoped explicit correlation maps (`by_task` and `by_session`)."""
    now_ts = float(now if now is not None else time.time())
    turn_links = openbot_turn_links if isinstance(openbot_turn_links, dict) else {}

    # 1. Collect all known assignments from collaboration + work reports
    tasks_meta: dict[str, dict[str, str]] = {}
    for ch in (collaboration_data or {}).get("changes") or []:
        if not isinstance(ch, dict):
            continue
        ch_id = clean_task_id(ch.get("id"))
        for t in ch.get("tasks") or []:
            if not isinstance(t, dict):
                continue
            tid = clean_task_id(t.get("id"))
            if not tid:
                continue
            tasks_meta[tid] = {
                "task_id": tid,
                "change_id": ch_id,
                "title": str(t.get("title") or "Assigned task")[:160],
                "agent": str(t.get("agent") or ""),
                "status": str(t.get("status") or "unknown"),
            }

    for rep in reports or []:
        if not isinstance(rep, dict):
            continue
        meta = rep.get("metadata") if isinstance(rep.get("metadata"), dict) else {}
        tid = clean_task_id(meta.get("task_id"))
        if not tid or tid in tasks_meta:
            continue
        tasks_meta[tid] = {
            "task_id": tid,
            "change_id": "",
            "title": str(rep.get("message") or "Work report")[:160],
            "agent": str(rep.get("agent_name") or ""),
            "status": str(rep.get("event_type") or "recorded"),
        }

    # 2. Load recent observed_step rows from THIS tenant's database only
    step_rows = db.query_all(
        """SELECT id, host_id, harness, agent_name, message, metadata_json, created_at
             FROM events
            WHERE event_type = 'observed_step'
            ORDER BY created_at DESC, id DESC
            LIMIT 2500"""
    )

    by_explicit_task: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}
    by_session_rows: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = {}

    for row in step_rows:
        meta = _parse_json(row.get("metadata_json"))
        step_tid = clean_task_id(meta.get("task_id"))
        if step_tid:
            by_explicit_task.setdefault(step_tid, []).append((row, meta))
            if step_tid not in tasks_meta:
                tasks_meta[step_tid] = {
                    "task_id": step_tid,
                    "change_id": "",
                    "title": str(row.get("message") or "Task step")[:160],
                    "agent": str(meta.get("agent") or row.get("agent_name") or ""),
                    "status": "recorded",
                }
        sid = str(meta.get("session") or "").strip()
        if sid:
            by_session_rows.setdefault(sid, []).append((row, meta))

    if filter_task_id:
        ft = clean_task_id(filter_task_id)
        if ft and ft not in tasks_meta:
            tasks_meta[ft] = {"task_id": ft, "change_id": "", "title": "Requested task", "agent": "", "status": "unknown"}

    # 3. Resolve each assignment strictly via explicit evidence
    by_task: dict[str, dict[str, Any]] = {}
    by_session: dict[str, list[dict[str, Any]]] = {}

    for tid, tinfo in tasks_meta.items():
        ch_id = tinfo["change_id"]
        explicit_rows = by_explicit_task.get(tid) or []
        if explicit_rows:
            entry = _build_linked_entry(
                tid,
                ch_id,
                "explicit_task_id",
                f"Explicit task_id recorded on {len(explicit_rows)} observed step(s).",
                explicit_rows,
            )
        else:
            tlink = turn_links.get(tid)
            if isinstance(tlink, dict) and tlink.get("session_id"):
                if tlink.get("ambiguous"):
                    entry = _build_unknown_entry(
                        tid,
                        ch_id,
                        "ambiguous_concurrent_turn",
                        "Concurrent assignments share this session without per-step task_id.",
                    )
                else:
                    sid = str(tlink["session_id"])
                    rt = str(tlink.get("runtime") or "")
                    start_ts = float(tlink.get("started_at") or 0.0)
                    end_ts = float(tlink.get("completed_at") or now_ts)
                    candidates = by_session_rows.get(sid) or []
                    matched = []
                    for row, meta in candidates:
                        other_tid = clean_task_id(meta.get("task_id"))
                        if other_tid and other_tid != tid:
                            continue
                        ts = float(row.get("created_at") or 0.0)
                        if start_ts > 0 and not (start_ts - 1.0 <= ts <= end_ts + 2.0):
                            continue
                        matched.append((row, meta))
                    if matched:
                        entry = _build_linked_entry(
                            tid,
                            ch_id,
                            "explicit_turn_session",
                            f"Orchestrator turn linked to session {sid} ({len(matched)} step(s)).",
                            matched,
                            fallback_session=sid,
                            fallback_runtime=rt,
                        )
                    else:
                        entry = _build_unknown_entry(
                            tid,
                            ch_id,
                            "session_recorded_no_steps",
                            f"Orchestrator recorded session {sid}, but no confirmed step or file was captured for this turn.",
                            session_id=sid,
                            runtime=rt,
                            agent=tinfo["agent"],
                        )
            else:
                entry = _build_unknown_entry(
                    tid,
                    ch_id,
                    "none",
                    "No explicit session or step link recorded for this assignment.",
                    agent=tinfo["agent"],
                )

        by_task[tid] = entry
        if entry["status"] == "linked" and entry["session_id"]:
            by_session.setdefault(entry["session_id"], []).append(
                {
                    "task_id": tid,
                    "change_id": ch_id,
                    "title": tinfo["title"],
                    "agent": tinfo["agent"] or entry["agent"],
                    "status": tinfo["status"],
                    "basis": entry["basis"],
                    "confirmed_file": entry["confirmed_file"],
                }
            )

    if filter_task_id:
        ft = clean_task_id(filter_task_id)
        by_task = {ft: by_task[ft]} if ft in by_task else {}
    if filter_session:
        fs = filter_session.strip()[:256]
        by_session = {fs: by_session[fs]} if fs in by_session else {}

    return {
        "version": "1",
        "organization": int(org_id),
        "by_task": by_task,
        "by_session": by_session,
    }
