"""Needs attention evaluator: explicit permissions, failed tests, exhausted quotas,
resolutions, age, exact event links, and heartbeat-only No signal hosts.

Every item in `items` and `resolved` comes strictly from persisted tenant records
in `events`, `event_execution`, and `incident_cases`. Missing heartbeats are kept
in a separate `no_signal` list computed strictly from `hosts.last_seen_at` without
inferring a cause.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import urlencode

import event_evidence
import incidents

DEFAULT_WINDOW_SEC = 24 * 3600
MAX_EVENTS_SCAN = 2500
MAX_RESOLVED_ITEMS = 15

PERMISSION_EVENT_TYPES = {
    "permission_request",
    "permission_needed",
    "approval_request",
    "approval_needed",
    "awaiting_permission",
    "awaiting_approval",
}
PERMISSION_OUTCOMES = {
    "awaiting_permission",
    "awaiting_approval",
    "needs_permission",
    "needs_approval",
    "permission_required",
    "approval_required",
    "blocked_permission",
}
PERMISSION_RESOLVED_EVENT_TYPES = {
    "permission_granted",
    "permission_denied",
    "permission_resolved",
    "approval_granted",
    "approval_denied",
    "approval_resolved",
}
PERMISSION_RESOLVED_OUTCOMES = {
    "permission_granted",
    "permission_denied",
    "permission_resolved",
    "approval_granted",
    "approval_denied",
    "approval_resolved",
    "approved",
    "denied",
}

TEST_PROGRAMS = {"pytest", "unittest", "jest", "vitest", "mocha", "rspec", "phpunit", "ctest"}
TEST_CMD_RE = re.compile(
    r"(?i)\b(?:pytest|unittest|npm\s+(?:run\s+)?test|pnpm\s+test|yarn\s+test|"
    r"go\s+test|cargo\s+test|vitest|jest|mocha|mvn\s+test|gradle\s+test|"
    r"dotnet\s+test|rspec|phpunit|ctest)\b"
)

QUOTA_EVENT_TYPES = {"quota_429", "rate_limit", "quota_exhausted", "rate_limit_exceeded"}
QUOTA_OUTCOMES = {"quota_exhausted", "rate_limited", "rate_limit_exceeded", "quota_exceeded"}
QUOTA_RESOLVED_EVENT_TYPES = {"quota_recovered", "rate_limit_cleared", "quota_restored"}
QUOTA_MESSAGE_RE = re.compile(
    r"(?i)\b(?:HTTP(?:/\d+(?:\.\d+)?)?\s+(?:status\s+)?429\b|"
    r"429\s+too\s+many\s+requests\b|"
    r"quota\s+(?:exceeded|exhausted)\b|"
    r"rate[\s_-]?limit(?:ed|\s+exceeded|\s+reached)?\b|"
    r"insufficient_quota\b|"
    r"usage\s+limit\s+reached\b|"
    r"credit\s+balance\s+is\s+too\s+low\b)"
)

SUBSTANTIVE_ACTIONS = {"file_edit", "shell", "file_read", "web", "visual"}
ERROR_OUTCOME_TOKENS = ("fail", "err", "error", "denied", "blocked", "timeout")
PASS_OUTCOMES = {"completed", "passed", "ok", "success", "succeeded", "done", "recorded"}

CATEGORY_PRIORITY = {"permission": 0, "quota_exhausted": 1, "failed_test": 2}


def _parse_json(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def _clean_str(val: Any, max_len: int = 240) -> str:
    if not isinstance(val, str):
        return ""
    return val.strip()[:max_len]


def _int_or_none(val: Any) -> int | None:
    if isinstance(val, bool) or val is None:
        return None
    if isinstance(val, int):
        return val
    if isinstance(val, str) and re.fullmatch(r"-?[0-9]{1,6}", val.strip()):
        return int(val.strip())
    return None


def _fmt_age(seconds: int) -> str:
    s = max(0, int(seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    hours = s // 3600
    mins = (s % 3600) // 60
    if hours < 24:
        return f"{hours}h {mins}m" if mins else f"{hours}h"
    days = hours // 24
    rem_h = hours % 24
    return f"{days}d {rem_h}h" if rem_h else f"{days}d"


def _event_link(
    event_id: int,
    *,
    event_type: str = "",
    host_id: str = "",
    session: str = "",
    agent: str = "",
    runtime: str = "",
) -> str:
    params: list[tuple[str, str]] = [("event", f"event:{int(event_id)}")]
    if host_id:
        params.append(("host", host_id))
    # Only observed_step rows carry sessionId in /live and match /api/v1/live-records?session=...
    if event_type == "observed_step" and session and host_id and agent and runtime:
        params.extend([("session", session), ("agent", agent), ("runtime", runtime)])
    params.append(("from", "/#needs-attention"))
    return "/live?" + urlencode(params)


def _incident_link(incident_id: int, org_id: int) -> str:
    return "/live?" + urlencode(
        [("incident", str(int(incident_id))), ("organization", str(int(org_id))), ("from", "/#needs-attention")]
    )


def _session_map_link(session: str) -> str:
    if not session:
        return ""
    return "/?" + urlencode([("am_view", "sessions"), ("am_session", session)]) + "#activity"


def _normalize_row(row: dict[str, Any]) -> dict[str, Any]:
    meta = _parse_json(row.get("metadata_json"))
    work = event_evidence.work_summary(meta)
    event_type = _clean_str(row.get("event_type"), 64).lower()
    severity = _clean_str(row.get("severity"), 16).upper()
    message = _clean_str(row.get("message"), 400)
    host_id = _clean_str(row.get("host_id"), 128)
    row_harness = _clean_str(row.get("harness"), 64)
    row_agent = _clean_str(row.get("agent_name"), 128)
    harness = _clean_str(work.get("runtime") or row_harness, 64)
    agent = _clean_str(work.get("agent") or row_agent, 128)
    work_session = _clean_str(work.get("session"), 256)
    session = _clean_str(work_session or meta.get("session") or meta.get("session_id"), 256)
    workspace = _clean_str(work.get("workspace") or meta.get("workspace"), 256)
    action = _clean_str(work.get("action") or meta.get("action"), 64).lower()
    tool = _clean_str(work.get("tool") or meta.get("tool"), 64)
    program = _clean_str(work.get("program") or meta.get("program"), 64).lower()
    outcome = _clean_str(work.get("outcome") or meta.get("outcome") or meta.get("status"), 64).lower()
    command_input = _clean_str(row.get("command_input") or meta.get("command_input") or meta.get("command"), 300)
    command_output = _clean_str(row.get("command_output") or meta.get("command_output"), 1200)
    exit_code = _int_or_none(row.get("exit_code"))
    if exit_code is None:
        exit_code = _int_or_none(meta.get("exit_code"))
    files = work.get("files") if isinstance(work.get("files"), list) else []

    return {
        "id": int(row["id"]),
        "created_at": float(row["created_at"]),
        "host_id": host_id,
        "harness": harness,
        "agent": agent,
        "row_harness": row_harness,
        "row_agent": row_agent,
        "work_session": work_session,
        "session": session,
        "workspace": workspace,
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "action": action,
        "tool": tool,
        "program": program,
        "outcome": outcome,
        "command_input": command_input,
        "command_output": command_output,
        "exit_code": exit_code,
        "files": files,
        "meta": meta,
    }


def _scope_key(ev: dict[str, Any]) -> tuple[str, ...]:
    if ev["session"]:
        return ("session", ev["host_id"], ev["session"])
    return ("agent", ev["host_id"], ev["harness"], ev["agent"])


def _is_test_command(ev: dict[str, Any]) -> bool:
    if ev["event_type"] in {"test_failed", "test_passed", "test_result"}:
        return True
    if ev["program"] in TEST_PROGRAMS:
        return True
    if ev["message"].lower().startswith("run tests"):
        return True
    for text in (ev["command_input"], ev["message"], _clean_str(ev["meta"].get("command_form"), 120)):
        if text and TEST_CMD_RE.search(text):
            return True
    return False


def _is_permission_request(ev: dict[str, Any]) -> bool:
    meta = ev["meta"]
    if ev["event_type"] in PERMISSION_EVENT_TYPES:
        return True
    if ev["outcome"] in PERMISSION_OUTCOMES:
        return True
    waiting_for = _clean_str(meta.get("waiting_for"), 64).lower()
    if waiting_for in {"permission", "approval"}:
        return True
    if meta.get("permission_required") is True or meta.get("approval_required") is True:
        return True
    return False


def _is_permission_resolution(ev: dict[str, Any], trigger: dict[str, Any]) -> str | None:
    if ev["event_type"] in PERMISSION_RESOLVED_EVENT_TYPES:
        if "denied" in ev["event_type"]:
            return "Permission denied"
        if "granted" in ev["event_type"]:
            return "Permission granted"
        return "Permission resolved"
    if ev["outcome"] in PERMISSION_RESOLVED_OUTCOMES:
        if "denied" in ev["outcome"]:
            return "Permission denied"
        if "granted" in ev["outcome"] or ev["outcome"] == "approved":
            return "Permission granted"
        return "Permission resolved"
    if (
        trigger["session"]
        and ev["session"] == trigger["session"]
        and ev["event_type"] == "observed_step"
        and ev["action"] in SUBSTANTIVE_ACTIONS
        and not _is_permission_request(ev)
        and not _is_quota_signal(ev)
        and ev["outcome"] not in PERMISSION_OUTCOMES
        and not any(tok in ev["outcome"] for tok in ERROR_OUTCOME_TOKENS)
    ):
        return "Session continued after permission prompt"
    return None


def _is_failed_test(ev: dict[str, Any]) -> bool:
    if not _is_test_command(ev):
        return False
    meta = ev["meta"]
    if ev["event_type"] == "test_failed":
        return True
    if ev["event_type"] == "test_result":
        if meta.get("passed") is False:
            return True
        if ev["exit_code"] is not None and ev["exit_code"] != 0:
            return True
        if any(tok in ev["outcome"] for tok in ("fail", "err")):
            return True
        return False
    if ev["event_type"] == "observed_step" and ev["action"] == "shell":
        if ev["exit_code"] is not None and ev["exit_code"] != 0:
            return True
        if any(tok in ev["outcome"] for tok in ("fail", "err")):
            return True
        if ev["severity"] in {"ERROR", "CRITICAL"}:
            return True
    return False


def _is_passed_test(ev: dict[str, Any], trigger: dict[str, Any]) -> str | None:
    if not _is_test_command(ev):
        return None
    if trigger["workspace"] and ev["workspace"] and trigger["workspace"] != ev["workspace"]:
        return None
    meta = ev["meta"]
    if ev["event_type"] == "test_passed":
        return "Tests passed"
    if ev["event_type"] == "test_result":
        if meta.get("passed") is True or ev["exit_code"] == 0 or ev["outcome"] in PASS_OUTCOMES:
            if not _is_failed_test(ev):
                return "Tests passed"
        return None
    if ev["event_type"] == "observed_step" and ev["action"] == "shell":
        if ev["exit_code"] == 0 and not any(tok in ev["outcome"] for tok in ("fail", "err")):
            return "Tests passed (exit 0)"
        if ev["exit_code"] is None and ev["outcome"] in PASS_OUTCOMES and ev["severity"] not in {"ERROR", "CRITICAL"}:
            return "Tests passed"
    return None


def _is_quota_signal(ev: dict[str, Any]) -> bool:
    meta = ev["meta"]
    if ev["event_type"] in QUOTA_EVENT_TYPES:
        return True
    if ev["outcome"] in QUOTA_OUTCOMES:
        return True
    if meta.get("http_status") in (429, "429"):
        return True
    err_code = _clean_str(meta.get("error_code"), 64).lower()
    if err_code in {"429", "rate_limit_exceeded", "insufficient_quota", "quota_exceeded"}:
        return True
    if ev["message"] and QUOTA_MESSAGE_RE.search(ev["message"]):
        return True
    if ev["command_output"] and (ev["exit_code"] not in (None, 0) or ev["severity"] in {"ERROR", "WARNING", "CRITICAL"} or any(tok in ev["outcome"] for tok in ("fail", "err"))):
        if QUOTA_MESSAGE_RE.search(ev["command_output"]):
            return True
    return False


def _is_quota_resolution(ev: dict[str, Any], trigger: dict[str, Any]) -> str | None:
    if ev["event_type"] in QUOTA_RESOLVED_EVENT_TYPES or ev["outcome"] in {"quota_recovered", "rate_limit_cleared"}:
        return "Quota recovered"
    if _is_quota_signal(ev):
        return None
    if ev["event_type"] == "observed_step" and ev["action"] in SUBSTANTIVE_ACTIONS:
        if (ev["exit_code"] in (None, 0)) and not any(tok in ev["outcome"] for tok in ERROR_OUTCOME_TOKENS) and ev["outcome"] not in PERMISSION_OUTCOMES:
            return "Subsequent step completed"
    if ev["event_type"] in {"work_done", "test_passed"}:
        return "Subsequent work completed"
    if ev["event_type"] == "tool_call" and ev["severity"] not in {"ERROR", "CRITICAL"} and ev["meta"].get("progress") is not False:
        return "Subsequent tool call succeeded"
    return None


def _item_payload(
    category: str,
    trigger: dict[str, Any],
    *,
    now: float,
    org_id: int,
    resolved: dict[str, Any] | None = None,
) -> dict[str, Any]:
    since = trigger["created_at"]
    age_seconds = max(0, int(now - since))
    link = _event_link(
        trigger["id"],
        event_type=trigger["event_type"],
        host_id=trigger["host_id"],
        session=trigger["work_session"],
        agent=trigger["row_agent"],
        runtime=trigger["row_harness"],
    )

    if category == "permission":
        label = "Permission required"
        req_detail = _clean_str(trigger["meta"].get("permission") or trigger["meta"].get("requested_action") or trigger["message"], 220)
        title = req_detail or "Explicit permission requested"
        basis = "Explicit permission signal in recorded event"
    elif category == "failed_test":
        label = "Failed test"
        prog = trigger["program"] or "tests"
        code_txt = f"exit {trigger['exit_code']}" if trigger["exit_code"] is not None else trigger["outcome"] or "failed"
        title = f"Test run failed ({prog} · {code_txt})"
        basis = trigger["command_input"] or trigger["message"] or f"Recorded test failure ({code_txt})"
    else:
        label = "Quota exhausted"
        title = trigger["message"] or "Provider quota or rate limit reached"
        retry_after = _int_or_none(trigger["meta"].get("retry_after_sec"))
        basis = f"HTTP 429 / quota limit recorded (retry after {retry_after}s)" if retry_after else "Explicit quota or HTTP 429 limit recorded"

    payload: dict[str, Any] = {
        "id": f"{category}:event:{trigger['id']}",
        "category": category,
        "category_label": label,
        "status": "resolved" if resolved else "active",
        "title": title[:220],
        "detail": basis[:260],
        "host_id": trigger["host_id"],
        "agent": trigger["agent"] or "unknown",
        "runtime": trigger["harness"] or "unknown",
        "session": trigger["session"],
        "workspace": trigger["workspace"],
        "program": trigger["program"],
        "exit_code": trigger["exit_code"],
        "files": trigger["files"],
        "event_id": trigger["id"],
        "event_key": f"event:{trigger['id']}",
        "organization": int(org_id),
        "since": since,
        "age_seconds": age_seconds,
        "link": link,
        "session_map_link": _session_map_link(trigger["session"]),
    }

    if resolved:
        res_ev = resolved["event"]
        payload.update(
            {
                "resolved_at": res_ev["created_at"],
                "resolved_age_seconds": max(0, int(now - res_ev["created_at"])),
                "resolution_reason": resolved["reason"],
                "resolved_by_event_id": res_ev["id"],
                "resolved_link": _event_link(
                    res_ev["id"],
                    event_type=res_ev["event_type"],
                    host_id=res_ev["host_id"],
                    session=res_ev["work_session"],
                    agent=res_ev["row_agent"],
                    runtime=res_ev["row_harness"],
                ),
            }
        )
    return payload


def build_needs_attention(
    db: Any,
    org_id: int,
    *,
    stale_host_sec: int = 90,
    window_sec: int = DEFAULT_WINDOW_SEC,
    now: float | None = None,
) -> dict[str, Any]:
    """Compute active Needs attention items, recent resolutions, and No signal hosts."""
    now_ts = float(now if now is not None else time.time())
    cutoff = now_ts - max(60, int(window_sec))

    rows = db.query_all(
        """
        SELECT e.id, e.host_id, e.harness, e.agent_name, e.event_type, e.severity,
               e.message, e.metadata_json, e.created_at,
               x.command_input, x.command_output, x.exit_code
        FROM events e
        LEFT JOIN event_execution x ON x.event_id = e.id
        WHERE e.created_at >= ?
        ORDER BY e.created_at ASC, e.id ASC
        LIMIT ?
        """,
        (cutoff, MAX_EVENTS_SCAN),
    )
    events = [_normalize_row(r) for r in rows]

    # Track per-(scope, category) open condition and resolutions chronologically.
    open_state: dict[tuple[tuple[str, ...], str], dict[str, Any]] = {}
    resolved_records: list[dict[str, Any]] = []

    for ev in events:
        scope = _scope_key(ev)

        # 1. Check whether this event resolves any currently open condition in this scope.
        for cat, resolver in (
            ("permission", _is_permission_resolution),
            ("failed_test", _is_passed_test),
            ("quota_exhausted", _is_quota_resolution),
        ):
            key = (scope, cat)
            if key in open_state:
                reason = resolver(ev, open_state[key])
                if reason:
                    resolved_records.append(
                        {
                            "category": cat,
                            "trigger": open_state.pop(key),
                            "resolved": {"event": ev, "reason": reason},
                        }
                    )

        # 2. Check whether this event opens (or refreshes) a Needs attention condition.
        if _is_permission_request(ev):
            open_state[(scope, "permission")] = ev
        if _is_failed_test(ev):
            open_state[(scope, "failed_test")] = ev
        if _is_quota_signal(ev):
            open_state[(scope, "quota_exhausted")] = ev

    active_items = [
        _item_payload(cat, trig, now=now_ts, org_id=org_id)
        for (_, cat), trig in open_state.items()
    ]

    # Include active QUOTA_EXHAUSTION_BURST incidents if no active quota event covers that host.
    quota_hosts = {it["host_id"] for it in active_items if it["category"] == "quota_exhausted"}
    active_incidents = db.query_all(
        f"""
        SELECT id, host_id, rule_code, severity, title, summary, evidence_json, status, created_at, updated_at
        FROM incident_cases
        WHERE {incidents.ACTIVE}
        ORDER BY updated_at DESC
        """
    )
    stale_incident_by_host: dict[str, int] = {}
    for inc in active_incidents:
        if inc["rule_code"] == "STALE_HOST_HEARTBEAT":
            stale_incident_by_host.setdefault(inc["host_id"], int(inc["id"]))
        elif inc["rule_code"] == "QUOTA_EXHAUSTION_BURST" and inc["host_id"] not in quota_hosts:
            ev_meta = _parse_json(inc.get("evidence_json"))
            ev_id = _int_or_none(ev_meta.get("event_id"))
            since = float(inc["created_at"])
            active_items.append(
                {
                    "id": f"quota_exhausted:incident:{inc['id']}",
                    "category": "quota_exhausted",
                    "category_label": "Quota exhausted",
                    "status": "active",
                    "title": _clean_str(inc["title"], 220) or f"Provider quota burst on {inc['host_id']}",
                    "detail": _clean_str(inc["summary"], 260),
                    "host_id": _clean_str(inc["host_id"], 128),
                    "agent": "multiple agents",
                    "runtime": "guardrail",
                    "session": "",
                    "workspace": "",
                    "program": "",
                    "exit_code": None,
                    "files": [],
                    "event_id": ev_id,
                    "event_key": f"event:{ev_id}" if ev_id else "",
                    "incident_id": int(inc["id"]),
                    "organization": int(org_id),
                    "since": since,
                    "age_seconds": max(0, int(now_ts - since)),
                    "link": _event_link(ev_id, host_id=inc["host_id"]) if ev_id else _incident_link(int(inc["id"]), org_id),
                    "incident_link": _incident_link(int(inc["id"]), org_id),
                    "session_map_link": "",
                }
            )

    active_items.sort(key=lambda it: (CATEGORY_PRIORITY.get(it["category"], 9), -float(it["since"])))

    resolved_items = [
        _item_payload(rec["category"], rec["trigger"], now=now_ts, org_id=org_id, resolved=rec["resolved"])
        for rec in reversed(resolved_records[-MAX_RESOLVED_ITEMS:])
    ]

    # Separate heartbeat-only No signal list — NEVER infer a cause from missing telemetry.
    hosts = db.query_all(
        "SELECT host_id, hostname, os_name, arch, status, last_seen_at, first_seen_at FROM hosts ORDER BY last_seen_at ASC"
    )
    no_signal: list[dict[str, Any]] = []
    threshold = max(1, int(stale_host_sec))
    for h in hosts:
        last_seen = float(h["last_seen_at"])
        age_sec = max(0, int(now_ts - last_seen))
        if age_sec >= threshold:
            hid = _clean_str(h["host_id"], 128)
            hname = _clean_str(h["hostname"], 128) or hid
            inc_id = stale_incident_by_host.get(hid)
            link = (
                _incident_link(inc_id, org_id)
                if inc_id
                else "/live?" + urlencode([("host", hid), ("from", "/#needs-attention")])
            )
            no_signal.append(
                {
                    "id": f"no_signal:{hid}",
                    "host_id": hid,
                    "hostname": hname,
                    "os_name": _clean_str(h.get("os_name"), 64),
                    "arch": _clean_str(h.get("arch"), 32),
                    "status": "no_signal",
                    "cause_inferred": False,
                    "last_seen_at": last_seen,
                    "age_seconds": age_sec,
                    "threshold_seconds": threshold,
                    "incident_id": inc_id,
                    "summary": (
                        f"No heartbeat received from {hname} for {_fmt_age(age_sec)} "
                        f"(threshold {threshold}s). Cause is not inferred from missing telemetry."
                    ),
                    "link": link,
                }
            )

    counts = {
        "total": len(active_items),
        "permission": sum(1 for it in active_items if it["category"] == "permission"),
        "failed_test": sum(1 for it in active_items if it["category"] == "failed_test"),
        "quota_exhausted": sum(1 for it in active_items if it["category"] == "quota_exhausted"),
        "no_signal": len(no_signal),
        "resolved": len(resolved_items),
    }

    return {
        "organization": int(org_id),
        "generated_at": now_ts,
        "stale_host_seconds": threshold,
        "counts": counts,
        "items": active_items,
        "no_signal": no_signal,
        "resolved": resolved_items,
    }
