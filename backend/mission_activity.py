"""Recent mission evidence from enrolled reporters and the explicitly shared OpenBot channel."""
import json
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from adapters.openbot_collaboration import IDENTIFIER, STATES, _agent_name, _epoch, _summary

# Public posts only. Provider transcripts, plans and attachments never supply message text.
CHANNEL_EVENTS = """
WITH recent AS (
    SELECT message_id, message_json, sequence FROM projection_channel_messages
    WHERE channel_id = :channel ORDER BY sequence DESC LIMIT 1500
)
SELECT m.message_id, json_extract(m.message_json, '$.author.name') AS agent,
       json_extract(m.message_json, '$.message.createdAt') AS stamp,
       substr(json_extract(m.message_json, '$.message.text'), 1, 2001) AS body,
       json_extract(m.message_json, '$.message.replyToMessageId') AS reply,
       CASE WHEN json_extract(parent.message_json, '$.author.kind') = 'agent'
            THEN json_extract(parent.message_json, '$.author.name') END AS recipient,
       CASE WHEN json_extract(parent.message_json,'$.author.kind')='agent'
          AND coalesce(json_extract(parent.message_json,'$.superseded'),0)=0
          AND (parent.message_id GLOB 'channel-reply-*' OR parent.message_id GLOB 'channel-result-*'
              OR (parent.message_id GLOB 'msg_*' AND json_extract(parent.message_json,'$.message.itemType') IN ('commentary','final_answer')))
          THEN substr(json_extract(parent.message_json,'$.message.text'),1,2001) END AS parent_body,
       t.task_id, r.task_id AS root, json_extract(r.task_json,'$.requestMessageId') AS request, substr(json_extract(r.task_json, '$.instruction'),1,2001) AS objective,
       substr(json_extract(t.task_json, '$.instruction'),1,2001) AS task,
       json_extract(t.task_json, '$.state') AS state,
       json_extract(owner.agent_json, '$.name') AS owner
FROM recent m
JOIN projection_channel_tasks t ON t.channel_id = :channel AND t.task_id = json_extract(m.message_json,'$.taskId')
JOIN projection_channel_tasks r ON r.channel_id = :channel AND r.task_id = json_extract(t.task_json,'$.rootTaskId')
    AND r.task_id = json_extract(r.task_json,'$.rootTaskId')
LEFT JOIN projection_channel_messages parent ON parent.channel_id = :channel
    AND parent.message_id = json_extract(m.message_json,'$.message.replyToMessageId')
LEFT JOIN projection_agents owner ON owner.agent_id = json_extract(t.task_json,'$.ownerAgentId')
WHERE json_extract(m.message_json,'$.author.kind') = 'agent'
    AND json_extract(m.message_json,'$.message.status') = 'completed'
    AND coalesce(json_extract(m.message_json,'$.superseded'),0) = 0
    AND (m.message_id GLOB 'channel-reply-*' OR (m.message_id GLOB 'channel-result-*' AND EXISTS (
           SELECT 1 FROM projection_channel_assignments a WHERE a.channel_id=:channel AND a.task_id=t.task_id
           AND m.message_id='channel-result-' || a.assignment_id || '-revision-' || json_extract(a.assignment_json,'$.taskRevision')
           AND json_extract(a.assignment_json,'$.taskRevision')=json_extract(t.task_json,'$.revision')
           AND json_extract(a.assignment_json,'$.agentId')=json_extract(m.message_json,'$.author.id')
           AND json_extract(t.task_json,'$.ownerAgentId')=json_extract(m.message_json,'$.author.id')))
         OR (m.message_id GLOB 'msg_*' AND json_extract(m.message_json,'$.message.itemType') IN ('commentary','final_answer')))
ORDER BY m.sequence DESC LIMIT 240
"""

MEMORIES = """
SELECT m.memory_id, substr(m.text,1,2001) AS body, m.updated_at, a.task_id,
       json_extract(t.task_json,'$.rootTaskId') AS mission, json_extract(owner.agent_json,'$.name') AS agent
FROM projection_channel_memories m
JOIN projection_channel_assignments a ON a.channel_id=m.channel_id
    AND json_extract(a.assignment_json,'$.turnId')=m.source_turn_id
JOIN projection_channel_tasks t ON t.task_id=a.task_id AND t.channel_id=m.channel_id
LEFT JOIN projection_agents owner ON owner.agent_id=json_extract(a.assignment_json,'$.agentId')
WHERE m.channel_id=? AND m.source_turn_id IS NOT NULL AND m.source_turn_id!=''
ORDER BY m.last_event_sequence DESC LIMIT 50
"""

def identifier(value):
    return value if isinstance(value, str) and IDENTIFIER.fullmatch(value) else ""


def channel_missions(conn, channel):
    missions = {}
    roots = {}
    for row in conn.execute(CHANNEL_EVENTS, {"channel": channel}):
        mid = identifier(row["request"]) or identifier(row["root"])
        roots[row["root"]] = mid
        if not mid or not identifier(row["task_id"]):
            continue
        item = missions.setdefault(mid, {"id": mid, "source": "Shared channel",
            "title": _summary(row["objective"], 160) or "Assigned mission", "events": []})
        key = row["message_id"]
        kind = "Reply" if row["reply"] else "Result" if key.startswith("channel-result-") else "Update"
        # Accept explicit public labels only; never classify an inferred intention.
        if kind == "Update":
            label = (row["body"] or "").partition(":")[0].strip("* ").casefold()
            kind = {"decision": "Decision", "decisión": "Decision", "blocker": "Blocker",
                    "bloqueo": "Blocker", "problema": "Problem", "problem": "Problem"}.get(label, kind)
        item["events"].append({"kind": kind, "agent": _agent_name(row["agent"]),
            "to": _agent_name(row["recipient"]) if row["recipient"] else "",
            "time": _epoch(row["stamp"]), "text": _summary(row["body"], 360),
            "id": key, "reply": row["reply"] or "", "parent_text": _summary(row["parent_body"], 240), "task_id": row["task_id"],
            "task": _summary(row["task"], 120), "owner": _agent_name(row["owner"]),
            "state": row["state"] if row["state"] in STATES else ""})
    if conn.execute("SELECT 1 FROM sqlite_master WHERE name='projection_channel_memories'").fetchone():
        for row in conn.execute(MEMORIES, (channel,)):
            mission = missions.get(roots.get(row["mission"]))
            if mission:
                mission["events"].append({"kind": "Shared memory saved", "id": row["memory_id"],
                    "agent": _agent_name(row["agent"]), "time": _epoch(row["updated_at"]),
                    "text": _summary(row["body"], 240), "task_id": row["task_id"]})
    return list(missions.values())


def shared_updates(org):
    channel = identifier(os.environ.get("SWARMCONTROL_OPENBOT_CHANNEL_ID"))
    if org != 1 or not channel or os.environ.get("SWARMCONTROL_SHARE_MISSION_UPDATES") != "1":
        return [], "disabled"
    config = os.environ.get("SWARMCONTROL_OPENBOT_CONFIG") or Path.home() / ".config/OpenBot"
    uri = (Path(config).expanduser() / "openbot.db").absolute().as_uri() + "?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=0.2)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA trusted_schema=OFF")
            deadline = time.monotonic() + 1.5
            conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
            conn.execute("BEGIN")
            return channel_missions(conn, channel), "connected"
    except (sqlite3.Error, OSError, ValueError):
        return [], "unavailable"


REPORTS = """SELECT id, event_type, host_id, agent_name, message, metadata_json, created_at
 FROM events WHERE event_type IN ('plan','task_plan','work_started','work_done','decision','blocker','memory_saved','agent_message')
 ORDER BY created_at DESC, id DESC LIMIT 240"""


def activity(db, org):
    missions, status = shared_updates(org)
    reported = {}
    for row in db.query_all(REPORTS):
        data = json.loads(row["metadata_json"])
        if not isinstance(data, dict):
            continue
        tid = identifier(data.get("task_id"))
        mid = identifier(data.get("mission_id")) or tid
        if not mid:
            continue
        mission = reported.setdefault(mid, {"id": mid, "title": mid, "source": "Reported events", "events": []})
        mission["events"].append({"id": "event:" + str(row["id"]), "event_id": row["id"],
            "time": row["created_at"], "kind": row["event_type"].replace("_"," ").capitalize(),
            "agent": _agent_name(row["agent_name"]), "to": _agent_name(data["to_agent"]) if data.get("to_agent") else "",
            "text": _summary(row["message"], 360), "reason": _summary(data.get("reason"), 360),
            "host": row["host_id"], "task_id": tid})
    missions.extend(reported.values())
    for mission in missions:
        mission["events"].sort(key=lambda e: e["time"], reverse=True)
    missions.sort(key=lambda m: m["events"][0]["time"], reverse=True)
    return {"organization": org, "shared_channel": status, "missions": missions}
