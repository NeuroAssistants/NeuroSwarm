"""Tenant-local joins between an edit, a named test run and their native tool calls."""
import json
import re
import time

from activity_inspector import redact
from correlation import clean_task_id
from validation import ValidationError


DIGEST = re.compile(r"[0-9a-f]{64}")
MAX_EDITS = 32


def ensure_tables(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS verification_calls(
        event_id INTEGER PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
        host TEXT NOT NULL, session TEXT NOT NULL, ref TEXT NOT NULL,
        stream TEXT, byte_pos INTEGER, ordinal INTEGER)""")
    conn.execute("CREATE INDEX IF NOT EXISTS verification_calls_ref ON verification_calls(host,session,ref)")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS delete_verification_call AFTER DELETE ON events BEGIN
        DELETE FROM verification_calls WHERE event_id=OLD.id; END""")
    conn.execute("""CREATE TABLE IF NOT EXISTS verification_receipts(
        host TEXT NOT NULL, session TEXT NOT NULL, ref TEXT NOT NULL, role TEXT NOT NULL,
        task TEXT NOT NULL, actor TEXT NOT NULL, revision TEXT NOT NULL, result TEXT NOT NULL,
        edits TEXT NOT NULL, received REAL NOT NULL, PRIMARY KEY(host,session,ref))""")
    conn.execute("""CREATE INDEX IF NOT EXISTS verification_receipts_context
        ON verification_receipts(host,session,task,actor,revision,role)""")
    conn.execute("CREATE INDEX IF NOT EXISTS verification_receipts_age ON verification_receipts(received)")


def receive(conn, host, data):
    session, task, actor = (data.get(key) for key in ("session_id", "task_id", "actor"))
    if any(not isinstance(v, str) or not v or clean_task_id(v) != v or redact(v, 96) != v
           for v in (session, task, actor)):
        raise ValidationError("Explicit session_id, task_id and actor are required")
    ref, revision = data.get("call_ref"), data.get("revision")
    if not all(isinstance(v, str) and DIGEST.fullmatch(v) for v in (ref, revision)):
        raise ValidationError("Expected full SHA-256 call and revision identifiers")
    role, result, edits = data.get("role"), data.get("result", ""), data.get("edits", [])
    if not isinstance(edits, list) or len(edits) > MAX_EDITS or any(
            not isinstance(v, str) or not DIGEST.fullmatch(v) or v == ref for v in edits):
        raise ValidationError("Invalid edit references")
    if not ((role == "edit" and not edits and result == "") or
            (role == "test" and edits and result in ("passed", "failed"))):
        raise ValidationError("Expected a completed edit or a test result with explicit edit references")
    key = (host, session, ref)
    fields = (role, task, actor, revision, result, json.dumps(sorted(set(edits))))
    old = conn.execute("SELECT role,task,actor,revision,result,edits FROM verification_receipts "
                       "WHERE host=? AND session=? AND ref=?", key).fetchone()
    if old and tuple(old) != fields:
        raise ValidationError("This tool call already has a different receipt")
    if old is None:
        conn.execute("INSERT INTO verification_receipts VALUES(?,?,?,?,?,?,?,?,?,?)", (*key, *fields, time.time()))
    return {"ok": True}


def for_edit(db, event_id, work):
    missing = {"status": "not_recorded", "tests": []}
    if not work.get("files") or work.get("basis") != "confirmed":
        return missing
    # Native ids can arrive before or after hook receipts. A repeated native id in
    # one host/session is ambiguous. Never pick one row by time or arrival order.
    rows = db.query_all("""
        SELECT run.id AS event_id, run.created_at AS ts, json_extract(run.metadata_json,'$.program') AS program,
               t.task, t.actor, t.revision, t.result, x.exit_code
        FROM verification_calls a JOIN events edit ON edit.id=a.event_id
        JOIN verification_receipts e ON (e.host,e.session,e.ref)=(a.host,a.session,a.ref) AND e.role='edit'
        JOIN verification_receipts t ON (t.host,t.session,t.task,t.actor,t.revision) =
            (e.host,e.session,e.task,e.actor,e.revision) AND t.role='test'
        JOIN verification_calls b ON (b.host,b.session,b.ref)=(t.host,t.session,t.ref)
        JOIN events run ON run.id=b.event_id AND run.harness=edit.harness AND run.agent_name=edit.agent_name
        LEFT JOIN event_execution x ON x.event_id=run.id
        WHERE a.event_id=? AND e.task=coalesce(json_extract(edit.metadata_json,'$.task_id'),e.task)
          AND t.task=coalesce(json_extract(run.metadata_json,'$.task_id'),t.task)
          AND json_extract(run.metadata_json,'$.action')='shell'
          AND run.created_at >= edit.created_at
          AND CASE WHEN a.stream=b.stream THEN (b.byte_pos,b.ordinal)>(a.byte_pos,a.ordinal)
                   ELSE run.created_at>edit.created_at END
          AND NOT (coalesce(json_extract(run.metadata_json,'$.outcome'),'') IN ('error','failed')
                   AND t.result='passed')
          AND coalesce(json_extract(edit.metadata_json,'$.outcome'),'') NOT IN ('error','failed')
          AND e.ref IN (SELECT value FROM json_each(t.edits))
          AND NOT EXISTS (SELECT 1 FROM verification_calls dup WHERE
              (dup.host,dup.session,dup.ref)=(a.host,a.session,a.ref) AND dup.event_id!=a.event_id)
          AND NOT EXISTS (SELECT 1 FROM verification_calls dup WHERE
              (dup.host,dup.session,dup.ref)=(b.host,b.session,b.ref) AND dup.event_id!=b.event_id)
          AND (x.exit_code IS NULL OR (x.exit_code=0)=(t.result='passed'))
        ORDER BY run.created_at DESC,run.id DESC LIMIT 10""", (event_id,))
    if not rows:
        return missing
    return {"status": "recorded", "basis": "explicit_edit_ref", "task_id": rows[0]["task"],
            "actor": rows[0]["actor"], "revision": rows[0]["revision"],
            "tests": [{"event_id": r["event_id"], "ts": r["ts"], "result": r["result"],
                       "exit_code": r["exit_code"], "program": r["program"]}
                      for r in rows]}
