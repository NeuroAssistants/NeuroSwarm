"""Tenant-local incident episodes. Callers supply only the authenticated organization's database."""
from __future__ import annotations

from itertools import groupby
import json
import math
import re
import time

from activity_inspector import is_sensitive_path, redact
from remote_activity import CLI_SECRET_RE


PAGE_SIZE = 50
ACTIVE = "status IN ('OPEN','ACKED')"
_LOCAL_CREDENTIAL = re.compile(r"\b(?:sc_ro_[\w-]{8,}|s2\.[A-Za-z0-9_-]{32,})")
_PRIVATE_PATH = re.compile(r"""(?<![\w.<])(?:/(?!/)[\w.-]+(?:/[\w.+-]+)+|[A-Za-z]:[\\/][^\s"'<>]+)""")
_NUMERIC_EVIDENCE = (
    "mem_used_mb", "mem_total_mb", "hot_count", "count", "affected_agents", "process_count",
    "age_seconds", "event_id", "max_cpu_pct", "max_rss_mb", "threshold", "last_heartbeat_at",
)


def _object(raw):
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _display_text(value, limit):
    text = redact(value, limit + 256)
    text = _LOCAL_CREDENTIAL.sub("[redacted]", text)
    text = CLI_SECRET_RE.sub(r"\1[redacted]", text)
    return _PRIVATE_PATH.sub("[private path]", text)[:limit]


def _label(value):
    if (isinstance(value, str) and re.fullmatch(r"[\w.@:+ -]{1,128}", value)
            and _display_text(value, 128) == value and not is_sensitive_path(value)):
        return value
    return ""


def _numbers(data, keys):
    return {k: data[k] for k in keys if type(data.get(k)) in (int, float)
            and abs(data[k]) <= 1e18 and math.isfinite(data[k])}


def signal_evidence(data):
    """Keep measured values and identifiers, never free-text log samples or a process command line."""
    safe = _numbers(data, _NUMERIC_EVIDENCE)
    for key in ("agent_name", "harness"):
        if value := _label(data.get(key)):
            safe[key] = value
    if isinstance(data.get("process"), dict):
        proc = data["process"]
        safe["process"] = _numbers(proc, ("pid", "cpu_pct", "rss_mb", "uptime_sec"))
        for key in ("comm", "harness"):
            if value := _label(proc.get(key)):
                safe["process"][key] = value
    if isinstance(data.get("patterns"), list):
        safe["patterns"] = [p for p in data["patterns"][:16] if isinstance(p, str) and re.fullmatch(r"[a-z_]{1,40}", p)]
    return safe


def _last_step(db, host, now):
    row = db.query_one(
        """SELECT id,created_at,harness,agent_name,metadata_json FROM events
           WHERE journaled=1 AND host_id=? AND created_at<=? ORDER BY created_at DESC,id DESC LIMIT 1""",
        (host, now),
    )
    if row is None:
        return None
    meta = _object(row["metadata_json"])
    # Only the journal can set the journaled column. Its files are pre-filtered against shared roots.
    files = meta.get("files") if meta.get("basis") == "confirmed" else []
    confirmed = []
    for path in files if isinstance(files, list) else ():
        if (isinstance(path, str) and 0 < len(path) <= 240 and ":" not in path and "\\" not in path
                and all(part and not part.startswith(".") for part in path.split("/"))
                and not is_sensitive_path(path) and _display_text(path, 240) == path):
            confirmed.append(path)
    return {"event_id": row["id"], "at": row["created_at"], "agent": _label(row["agent_name"]),
            "runtime": _label(row["harness"]), "session": _label(meta.get("session")),
            "action": _label(meta.get("action")), "tool": _label(meta.get("tool")),
            "confirmed_files": confirmed[:12], "basis": "last_observed_on_host"}


def _entry(conn, case_id, kind, actor, at, data):
    conn.execute("INSERT INTO incident_history(alert_id,kind,actor,at,data_json) VALUES(?,?,?,?,?)",
                 (case_id, kind, actor, at, json.dumps(data, ensure_ascii=False)))


def migrate(conn):
    """Upgrade resource schema 1 in its existing transaction. Keep physical legacy rows and audit IDs."""
    # Preserve the exact original rows locally, including older evidence fields with
    # unknown shapes. The HTTP API never reads this migration archive.
    conn.execute("CREATE TABLE incident_v1_snapshots AS SELECT * FROM alerts")
    conn.execute("CREATE UNIQUE INDEX idx_incident_v1_snapshot ON incident_v1_snapshots(id)")
    for definition in (
        "owner TEXT", "occurrence_count INTEGER NOT NULL DEFAULT 1", "count_is_minimum INTEGER NOT NULL DEFAULT 0",
        "last_seen_at REAL", "last_step_json TEXT", "resolved_by TEXT", "resolved_at REAL", "resolution TEXT",
        "previous_id INTEGER REFERENCES alerts(id)", "merged_into INTEGER REFERENCES alerts(id)",
    ):
        conn.execute("ALTER TABLE alerts ADD COLUMN " + definition)
    conn.execute("ALTER TABLE events ADD COLUMN journaled INTEGER NOT NULL DEFAULT 0")
    conn.execute("""CREATE INDEX idx_incident_steps ON events(host_id,created_at DESC,id DESC) WHERE journaled=1""")
    conn.execute("""CREATE TABLE incident_history(
        id INTEGER PRIMARY KEY, alert_id INTEGER NOT NULL REFERENCES alerts(id), kind TEXT NOT NULL,
        actor TEXT, at REAL NOT NULL, data_json TEXT NOT NULL)""")
    conn.execute("CREATE INDEX idx_incident_history ON incident_history(alert_id,id DESC)")
    conn.execute("CREATE VIEW incident_cases AS SELECT * FROM alerts WHERE merged_into IS NULL")
    # Stream the immutable archive while updating canonical rows in the original table.
    rows = conn.execute("SELECT * FROM incident_v1_snapshots ORDER BY host_id,rule_code,created_at,id")
    for _, group in groupby(rows, key=lambda r: (r["host_id"], r["rule_code"])):
        episode = []
        closed_at = None
        previous = None
        for row in group:
            if closed_at is not None and row["created_at"] >= closed_at:
                previous = _import_episode(conn, episode, previous)
                episode = []
                closed_at = None
            episode.append(row)
            if row["status"] == "RESOLVED":
                closed_at = row["updated_at"]
        _import_episode(conn, episode, previous)
    conn.execute("""CREATE UNIQUE INDEX idx_single_active_case ON alerts(host_id,rule_code)
                    WHERE merged_into IS NULL AND status IN ('OPEN','ACKED')""")
    conn.execute("""CREATE INDEX idx_case_recurrence ON alerts(host_id,rule_code,resolved_at DESC,id DESC)
                    WHERE merged_into IS NULL AND status='RESOLVED'""")


def _import_episode(conn, rows, previous):
    case_id = rows[0]["id"]
    latest = max(rows, key=lambda r: (r["updated_at"], r["id"]))
    acknowledged = []
    resolved = None
    entries = []
    observed = []
    for row in rows:
        evidence = signal_evidence(_object(row["evidence_json"]))
        # On closed/acked v1 rows updated_at can describe an operator action, not a signal.
        observed.append(row["updated_at"] if row["status"] == "OPEN" else row["created_at"])
        entries.append((row["updated_at"], "legacy_snapshot", None, {
            "source_id": row["id"], "status": row["status"], "created_at": row["created_at"], "evidence": evidence}))
        auto = row["rule_code"] == "STALE_HOST_HEARTBEAT" and row["status"] == "RESOLVED" and row["acked_by"] == "system"
        if row["acked_at"] is not None and not auto:
            acknowledged.append(row)
            entries.append((row["acked_at"], "acknowledged", row["acked_by"], {"source_id": row["id"]}))
        if row["status"] == "RESOLVED":
            resolved = row
            entries.append((row["updated_at"], "resolved", "system" if auto else None,
                            {"reason": "heartbeat_resumed" if auto else "legacy_resolution", "source_id": row["id"]}))
        if row["id"] != case_id:
            conn.execute("UPDATE alerts SET merged_into=? WHERE id=?", (case_id, row["id"]))
    for at, kind, actor, data in sorted(entries, key=lambda e: e[0]):
        _entry(conn, case_id, kind, actor, at, data)
    first_ack = min(acknowledged, key=lambda r: (r["acked_at"], r["id"])) if acknowledged else None
    status = "ACKED" if any(r["status"] == "ACKED" for r in rows) else "OPEN"
    resolver = reason = resolved_at = None
    if resolved is not None:
        status = "RESOLVED"
        resolved_at = resolved["updated_at"]
        if resolved["rule_code"] == "STALE_HOST_HEARTBEAT" and resolved["acked_by"] == "system":
            resolver, reason = "system", "heartbeat_resumed"
        else:
            reason = "legacy_resolution"
    owner = first_ack["acked_by"] if first_ack else None
    conn.execute("""UPDATE alerts SET occurrence_count=?, count_is_minimum=1, owner=?, acked_by=?, acked_at=?,
                    previous_id=?, status=?, resolved_by=?, resolved_at=?, resolution=?, last_seen_at=?,
                    updated_at=?, title=?, summary=?, severity=?, evidence_json=? WHERE id=?""",
                 (len(rows), owner, owner, first_ack["acked_at"] if first_ack else None, previous, status,
                  resolver, resolved_at, reason, max(observed), latest["updated_at"], _display_text(latest["title"], 512),
                  _display_text(latest["summary"], 1000), latest["severity"], json.dumps(signal_evidence(_object(latest["evidence_json"]))), case_id))
    return case_id


def observe(db, host, rule, severity, title, summary, evidence):
    with db.transaction() as conn:
        now = time.time()
        active = db.query_one(f"SELECT id FROM incident_cases WHERE host_id=? AND rule_code=? AND {ACTIVE}", (host, rule))
        step = _last_step(db, host, now)
        safe = signal_evidence(evidence)
        values = (severity, _display_text(title, 512), _display_text(summary, 1000), json.dumps(safe), now, now,
                  json.dumps(step) if step else None)
        if active:
            case_id = active["id"]
            conn.execute("""UPDATE alerts SET severity=?,title=?,summary=?,evidence_json=?,updated_at=?,last_seen_at=?,
                            last_step_json=coalesce(?,last_step_json), occurrence_count=occurrence_count+1 WHERE id=?""",
                         (*values, case_id))
            kind = "repeated"
        else:
            previous = db.query_one("""SELECT id FROM incident_cases WHERE host_id=? AND rule_code=? AND status='RESOLVED'
                                       ORDER BY resolved_at DESC,id DESC LIMIT 1""", (host, rule))
            case_id = conn.execute("""INSERT INTO alerts(severity,title,summary,evidence_json,updated_at,last_seen_at,
                                    last_step_json,host_id,rule_code,created_at,previous_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                                   (*values, host, rule, now, previous["id"] if previous else None)).lastrowid
            kind = "opened"
        _entry(conn, case_id, kind, None, now, {"evidence": safe, "last_step": step})
        return case_id


def find_case(db, ident):
    return db.query_one("SELECT * FROM alerts WHERE id=(SELECT coalesce(merged_into,id) FROM alerts WHERE id=?)", (ident,))


def acknowledge(db, row, actor):
    if row["status"] == "ACKED":
        return
    now = time.time()
    db.execute("UPDATE alerts SET status='ACKED',owner=coalesce(owner,?),acked_by=?,acked_at=?,updated_at=? WHERE id=?",
               (actor, actor, now, now, row["id"]))
    _entry(db, row["id"], "acknowledged", actor, now, {"owner": row["owner"] or actor})
    db.log_audit(actor, "ALERT_ACKED", f"alert:{row['id']}", f"Acknowledged {row['rule_code']} on {row['host_id']}")


def assign(db, row, actor, owner):
    if owner == row["owner"]:
        return
    now = time.time()
    db.execute("UPDATE alerts SET owner=?,updated_at=? WHERE id=?", (owner, now, row["id"]))
    _entry(db, row["id"], "assigned", actor, now, {"owner": owner, "previous_owner": row["owner"]})
    db.log_audit(actor, "ALERT_ASSIGNED", f"alert:{row['id']}", f"Owner: {owner or 'unassigned'}")


def resolve(db, row, actor, reason, evidence):
    if row["status"] == "RESOLVED":
        return
    now = time.time()
    step = _last_step(db, row["host_id"], now)
    db.execute("""UPDATE alerts SET status='RESOLVED',resolved_by=?,resolved_at=?,resolution=?,updated_at=?,
                  last_step_json=coalesce(?,last_step_json) WHERE id=?""",
               (actor, now, reason, now, json.dumps(step) if step else None, row["id"]))
    _entry(db, row["id"], "resolved", actor, now, {"reason": reason, "evidence": signal_evidence(evidence),
                                                   "last_step": step})
    db.log_audit(actor, "ALERT_RESOLVED" if reason == "operator_verified" else "ALERT_AUTO_RESOLVED",
                 f"alert:{row['id']}", reason)


def present(row):
    result = dict(row)
    result["evidence"] = _object(result.pop("evidence_json"))
    result["last_step"] = _object(result.pop("last_step_json")) or None
    result["count_is_minimum"] = bool(result["count_is_minimum"])
    result.pop("merged_into")
    return result


def detail(db, ident, before):
    with db.transaction(write=False):
        row = find_case(db, ident)
        if not row:
            return None
        sql = "SELECT id,kind,actor,at,data_json FROM incident_history WHERE alert_id=?"
        args = [row["id"]]
        if before is not None:
            sql += " AND id<?"
            args.append(before)
        history = db.query_all(sql + " ORDER BY id DESC LIMIT ?", (*args, PAGE_SIZE + 1))
        page = history[:PAGE_SIZE]
        for entry in page:
            entry["data"] = _object(entry.pop("data_json"))
        return {"alert": present(row), "history": page, "next_before": page[-1]["id"] if len(history) > PAGE_SIZE else None}
