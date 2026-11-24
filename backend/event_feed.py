"""Real-time event and alert feed for the full-screen event console (EVENT-FEED-CONTRACT v1).

One call returns everything new or changed since the client's cursor, so a console left open
never skips records between refreshes, however many arrive (the client keeps reading while
`more` is true). Events are append-only (id order). Alerts change state (OPEN → ACKED →
RESOLVED); every change bumps `updated_at`, and alerts touched in the last GRACE seconds are
re-sent so two writes with the same timestamp cannot be lost. Clients upsert by `key`.

Pure functions over a tenant database (`query_all`); the route only passes the tenant's db.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

FEED_VERSION = "1"
GRACE = 2.0
DEFAULT_LIMIT = 500
MAX_LIMIT = 1000
INITIAL_WINDOW = 500
SEVERITY_ORDER = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]
CURSOR_RE = re.compile(r"1\.e(\d{1,19})\.a(\d{1,13}(?:\.\d{1,17})?)\.i(\d{1,19})\.([pc])")


class FeedError(ValueError):
    """Bad cursor or parameter; message is safe to return as HTTP 400."""


def _json(raw: Any, cap: int = 4096) -> Any:
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if len(json.dumps(value)) <= cap else {"note": "metadata too large to show"}


def _sev(value: Any) -> str:
    s = str(value or "").upper()
    return s if s in SEVERITY_ORDER else "INFO"


def _event(r: dict[str, Any]) -> dict[str, Any]:
    return {"key": f"event:{r['id']}", "kind": "event", "id": r["id"], "ts": r["created_at"],
            "created_at": r["created_at"], "updated_at": r["created_at"], "severity": _sev(r["severity"]),
            "state": "RECORDED", "host_id": r["host_id"], "harness": r["harness"], "agent": r["agent_name"],
            "source": r["event_type"], "title": r["message"], "summary": "", "acked_by": None, "acked_at": None,
            "details": _json(r.get("metadata_json"))}


def _alert(r: dict[str, Any]) -> dict[str, Any]:
    return {"key": f"alert:{r['id']}", "kind": "alert", "id": r["id"], "ts": r["updated_at"],
            "created_at": r["created_at"], "updated_at": r["updated_at"], "severity": _sev(r["severity"]),
            "state": str(r["status"] or "OPEN").upper(), "host_id": r["host_id"], "harness": "", "agent": "",
            "source": r["rule_code"], "title": r["title"], "summary": r["summary"], "acked_by": r.get("acked_by"),
            "acked_at": r.get("acked_at"), "details": _json(r.get("evidence_json")), "owner": r["owner"],
            "occurrence_count": r["occurrence_count"], "count_is_minimum": bool(r["count_is_minimum"]),
            "previous_id": r["previous_id"], "resolved_at": r["resolved_at"], "resolved_by": r["resolved_by"]}


def parse_cursor(raw: str | None) -> tuple[int, float, int, str] | None:
    """(last event id, last alert updated_at, last alert id, mode). Mode p = paging (exact), c = caught up."""
    if not raw:
        return None
    m = CURSOR_RE.fullmatch(raw)
    if not m:
        raise FeedError("invalid cursor")
    return int(m.group(1)), float(m.group(2)), int(m.group(3)), m.group(4)


def make_cursor(event_id: int, alert_ts: float, alert_id: int = 0, mode: str = "c") -> str:
    ts = repr(float(alert_ts))  # exact round-trip, so `updated_at = ts` matches the stored REAL
    return f"1.e{int(event_id)}.a{ts}.i{int(alert_id)}.{mode}"


def counts(db: Any, now: float | None = None) -> dict[str, Any]:
    """Totals for the status bar: alerts by state and severity, events of the last 24 h by severity."""
    now = now or time.time()
    by_state = {r["status"]: r["n"] for r in db.query_all("SELECT status, COUNT(*) AS n FROM incident_cases GROUP BY status")}
    open_sev = {r["severity"]: r["n"] for r in db.query_all(
        "SELECT severity, COUNT(*) AS n FROM incident_cases WHERE status = 'OPEN' GROUP BY severity")}
    ev_sev = {r["severity"]: r["n"] for r in db.query_all(
        "SELECT severity, COUNT(*) AS n FROM events WHERE created_at >= ? GROUP BY severity", (now - 86400,))}
    norm = lambda d: {s: sum(v for k, v in d.items() if _sev(k) == s) for s in SEVERITY_ORDER}  # noqa: E731
    return {"alerts": {"OPEN": by_state.get("OPEN", 0), "ACKED": by_state.get("ACKED", 0),
                       "RESOLVED": by_state.get("RESOLVED", 0)},
            "open_alerts_by_severity": norm(open_sev), "events_24h_by_severity": norm(ev_sev)}


def feed(db: Any, cursor: str | None = None, limit: int | str | None = None) -> dict[str, Any]:
    """Records new or changed since `cursor` (oldest first), or the latest window when there is no cursor."""
    try:
        limit = max(1, min(MAX_LIMIT, int(limit or DEFAULT_LIMIT)))
    except (TypeError, ValueError):
        raise FeedError("invalid limit") from None
    since = parse_cursor(cursor)
    now = time.time()
    if since is None:
        # First read: the newest window of each kind, plus a cursor at the current end of both.
        events = db.query_all("SELECT * FROM events ORDER BY id DESC LIMIT ?", (INITIAL_WINDOW,))
        alerts = db.query_all("SELECT * FROM incident_cases ORDER BY updated_at DESC, id DESC LIMIT ?", (INITIAL_WINDOW,))
        # Advance only over rows returned here. A concurrent insert after the
        # window query must still be delivered on the next poll.
        top = events[0]["id"] if events else 0
        a_top = float(alerts[0]["updated_at"]) if alerts else 0.0
        records = [_event(r) for r in events] + [_alert(r) for r in alerts]
        records.sort(key=lambda x: (x["ts"], x["key"]))
        return {"version": FEED_VERSION, "reset": True, "cursor": make_cursor(top, a_top, 0, "c"), "more": False,
                "records": records, "counts": counts(db, now), "server_time": now}
    e_since, a_since, a_id, mode = since
    events = db.query_all("SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?", (e_since, limit + 1))
    more_e = len(events) > limit
    events = events[:limit]
    if mode == "p":  # mid-page: continue exactly after the last alert sent
        alerts = db.query_all("SELECT * FROM incident_cases WHERE updated_at > ? OR (updated_at = ? AND id > ?) "
                              "ORDER BY updated_at ASC, id ASC LIMIT ?", (a_since, a_since, a_id, limit + 1))
    else:  # caught up: re-send the last GRACE seconds so same-timestamp writes are never lost
        alerts = db.query_all("SELECT * FROM incident_cases WHERE updated_at > ? ORDER BY updated_at ASC, id ASC LIMIT ?",
                              (a_since - GRACE, limit + 1))
    more_a = len(alerts) > limit
    alerts = alerts[:limit]
    e_next = events[-1]["id"] if events else e_since
    if more_a:
        a_next, a_next_id, a_mode = float(alerts[-1]["updated_at"]), int(alerts[-1]["id"]), "p"
    else:
        last = max(alerts, key=lambda a: (a["updated_at"], a["id"])) if alerts else None
        a_next = max(a_since, float(last["updated_at"])) if last else a_since
        a_next_id, a_mode = (int(last["id"]) if last else a_id), "c"
    records = [_event(r) for r in events] + [_alert(r) for r in alerts]
    records.sort(key=lambda x: (x["ts"], x["key"]))
    return {"version": FEED_VERSION, "reset": False, "cursor": make_cursor(e_next, a_next, a_next_id, a_mode),
            "more": bool(more_e or more_a), "records": records, "counts": counts(db, now), "server_time": now}
