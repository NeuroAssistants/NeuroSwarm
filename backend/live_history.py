"""Tenant-local, keyset-paginated display history for the operations console."""
import json
import math

from event_evidence import work_summary
from correlation import clean_task_id
from validation import ValidationError
from work_journal import command_form

ROWS = """
SELECT * FROM (
  SELECT 'Event' AS kind,id,created_at AS ts,host_id,severity,message,event_type AS source,
         agent_name AS detail,'' AS status,harness AS runtime,agent_name AS agent,metadata_json AS extra
    FROM events
  UNION ALL
  SELECT 'Alert',id,updated_at,host_id,severity,title,rule_code,summary,status,'','',
         json_object('owner',owner,'occurrence_count',occurrence_count,'count_is_minimum',count_is_minimum,
                     'previous_id',previous_id,'acked_by',acked_by,'acked_at',acked_at,
                     'resolved_by',resolved_by,'resolved_at',resolved_at,'created_at',created_at)
    FROM incident_cases
)"""


def history(db, organization, query):
    where = ""
    args = ()
    if "before" in query:
        try:
            ts, kind, ident = query["before"][0].split("|")
            args = (float(ts), kind, int(ident))
            if not math.isfinite(args[0]) or args[1] not in {"Event","Alert"} or not 1 <= args[2] <= 2**63 - 1:
                raise ValueError
        except (ValueError, IndexError):
            raise ValidationError("Invalid history cursor")
        where = " WHERE (ts,kind,id) < (?,?,?)"
    if "session" in query:
        for field in ("session", "host", "agent", "runtime"):
            if not query.get(field) or len(query[field][0]) > 256:
                raise ValidationError("Invalid session filter")
        where += (" AND " if where else " WHERE ") + """source='observed_step' AND host_id=? AND agent=?
            AND runtime=? AND json_extract(extra,'$.session')=?"""
        args += tuple(query[k][0] for k in ("host", "agent", "runtime", "session"))
    if "task_id" in query:
        tid = clean_task_id((query.get("task_id") or [""])[0])
        if not tid:
            raise ValidationError("Invalid task_id filter")
        where += (" AND " if where else " WHERE ") + "source='observed_step' AND json_extract(extra,'$.task_id')=?"
        args += (tid,)
    rows = db.query_all(ROWS + where + " ORDER BY ts DESC,kind DESC,id DESC LIMIT 251", args)
    page = rows[:250]
    for row in page:
        raw = row.pop("extra")
        if row["kind"] == "Alert":
            row.update(json.loads(raw))
            row["count_is_minimum"] = bool(row["count_is_minimum"])
        elif row["source"] == "observed_step" and raw:
            metadata = json.loads(raw)
            if isinstance(metadata, dict):
                row["work"] = work_summary(metadata)
                operation = command_form(metadata.get("program"), metadata.get("command"))
                if operation:
                    row["work"]["command"] = operation
    last = page[-1] if page else None
    cursor = f"{last['ts']}|{last['kind']}|{last['id']}" if last and len(rows)>250 else None
    return {"organization": organization, "records": page, "next": cursor}
