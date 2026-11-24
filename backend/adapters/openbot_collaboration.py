"""Read a single explicitly shared OpenBot task tree projection for the legacy tenant."""

from __future__ import annotations

from collections import defaultdict, deque
from contextlib import closing
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import sqlite3
import time
import unicodedata

from remote_activity import SERVER_SECRET_PATTERNS


MAX_CHANGES = 12
MAX_TASKS = 48
MAX_SOURCE_TEXT = 2000
RECENT_MESSAGES = 512
IDENTIFIER = re.compile(r"[\w][\w.:-]{0,95}", re.ASCII)
STATES = {"queued", "running", "waiting", "completed", "failed", "cancelled", "paused", "blocked", "interrupted"}
TERMINAL = {"completed", "failed", "cancelled", "interrupted"}

# Return the coordinator as a task, too. Keep each parent/child link inside a single
# channel AND root, even if the projection is incomplete during an OpenBot upgrade.
TASKS = """
WITH delegated AS (
    SELECT DISTINCT json_extract(task_json, '$.rootTaskId') AS id
      FROM projection_channel_tasks
     WHERE channel_id = :channel AND json_type(task_json, '$.parentTaskId') = 'text'
), roots AS (
    SELECT t.task_id
      FROM projection_channel_tasks t
      JOIN delegated d ON d.id = t.task_id
      LEFT JOIN projection_channel_messages req
        ON req.channel_id = t.channel_id AND req.message_id = json_extract(t.task_json, '$.requestMessageId')
     WHERE t.channel_id = :channel AND json_extract(t.task_json, '$.parentTaskId') IS NULL
       AND json_extract(t.task_json, '$.rootTaskId') = t.task_id
     ORDER BY json_extract(t.task_json, '$.state') IN ('completed','failed','cancelled','interrupted'),
              req.sequence DESC, t.rowid DESC
     LIMIT :changes
), ranked AS (
    SELECT t.task_id, r.task_id AS root_id,
           row_number() OVER (PARTITION BY r.task_id ORDER BY t.task_id != r.task_id, t.rowid) AS position
      FROM projection_channel_tasks t JOIN roots r ON r.task_id = json_extract(t.task_json, '$.rootTaskId')
     WHERE t.channel_id = :channel
)
SELECT t.task_id, ranked.root_id, json_extract(t.task_json, '$.parentTaskId') AS parent_id,
       json_extract(t.task_json, '$.state') AS state,
       CASE WHEN json_type(t.task_json, '$.instruction') = 'text'
            THEN substr(json_extract(t.task_json, '$.instruction'), 1, :text_size) END AS instruction,
       CASE WHEN json_type(t.task_json, '$.expectedResult') = 'text'
            THEN substr(json_extract(t.task_json, '$.expectedResult'), 1, :text_size) END AS objective,
       CASE WHEN json_type(a.agent_json, '$.name') = 'text'
            THEN substr(json_extract(a.agent_json, '$.name'), 1, 96) END AS agent,
       json_extract(t.task_json, '$.updatedAt') AS updated,
       json_extract(req.message_json, '$.message.createdAt') AS requested
  FROM ranked JOIN projection_channel_tasks t ON t.task_id = ranked.task_id AND t.channel_id = :channel
  LEFT JOIN projection_agents a ON a.agent_id = json_extract(t.task_json, '$.ownerAgentId')
  LEFT JOIN projection_channel_messages req
    ON req.channel_id = t.channel_id AND req.message_id = json_extract(t.task_json, '$.requestMessageId')
 WHERE ranked.position <= :tasks ORDER BY ranked.root_id, ranked.position
"""

# Only a formal result of an assignment of this revision can supply a result body.
# Ordinary channel posts, plans, attachments and turn transcripts are never selected as text.
RESULTS = """
SELECT a.task_id, substr(json_extract(m.message_json, '$.message.text'), 1, ?) AS result,
       json_extract(m.message_json, '$.message.createdAt') AS reported
  FROM projection_channel_assignments a
  JOIN projection_channel_tasks t ON t.channel_id = a.channel_id AND t.task_id = a.task_id
  JOIN projection_channel_messages m ON m.channel_id = a.channel_id
       AND m.message_id = 'channel-result-' || a.assignment_id || '-revision-' || json_extract(a.assignment_json, '$.taskRevision')
 WHERE a.channel_id = ? AND a.task_id IN ({ids})
   AND json_extract(t.task_json, '$.revision') = json_extract(a.assignment_json, '$.taskRevision')
   AND json_extract(m.message_json, '$.taskId') = t.task_id
   AND json_extract(m.message_json, '$.author.kind') = 'agent'
   AND json_extract(m.message_json, '$.author.id') = json_extract(t.task_json, '$.ownerAgentId')
   AND json_extract(m.message_json, '$.author.id') = json_extract(a.assignment_json, '$.agentId')
   AND json_extract(m.message_json, '$.message.status') = 'completed'
   AND json_type(m.message_json, '$.message.text') = 'text'
   AND coalesce(json_extract(m.message_json, '$.superseded'), 0) = 0
 ORDER BY m.sequence DESC
"""

# OpenBot's task projection currently has no update clock. Read only timestamps
# and task identifiers from recent messages; never infer a state from the clock.
TIMES = """
SELECT json_extract(message_json, '$.taskId') AS task_id,
       json_extract(message_json, '$.message.createdAt') AS recorded
  FROM (SELECT message_json FROM projection_channel_messages
         WHERE channel_id = ? ORDER BY sequence DESC LIMIT ?)
 WHERE coalesce(json_extract(message_json, '$.superseded'), 0) = 0
   AND json_extract(message_json, '$.taskId') IN ({ids})
"""

# Cut off the rest of the source on encountering credentials, quoted conversations,
# code fences or markup. A missing safe sentence is preferable to a partial secret.
PRIVATE = re.compile(
    r"""(?<!\w)["'«“]|"""
    r"```|~~~|-----BEGIN|</?[a-z][\w.-]*(?:\s|/?>)|^\s*(?:>|\$\s|(?:user|usuario|assistant|asistente|system|tool|prompt|transcript)\s*:)"
    r"|\b(?:bearer|authorization|passwords?|passphrases?|passwd|contraseñas?|claves?|cookies?|credentials?|credenciales?"
    r"|private[_ -]?key|api[_ -]?keys?|secrets?|secretos?|tokens?|otp|totp|pin)\b"
    r"|\b(?:sc_(?:ro|tok|inv|live|session)_|sk-|gh[pousr]_|github_pat_|xox[baprs]-|AIza|AKIA|ssh-(?:rsa|ed25519))"
    r"|\b[\w.-]+\s*=|\b(?:pass|pwd|code|código|key)\s*[:=]|\botpauth:",
    re.I | re.M,
)
PRIVATE_LOCATION = re.compile(
    r"[/\\~@]|\b[a-z0-9_-]+\.(?:[a-z]{2,}|\d{1,3})\b|\b\d{1,3}(?:\.\d{1,3}){3}\b"
    r"|(?<![\w.])\.[a-z_][\w-]*|\b(?:localhost|id_rsa|id_ed25519)\b", re.I
)
MACHINE_TEXT = re.compile(
    r"[{}`<>|=]|(?<!\S)--[a-z]|\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b|\b\d{6,}\b"
    r"|\b(?=[\w.-]{12,}\b)(?=[\w.-]*\d)(?=[\w.-]*[a-zA-Z])[\w.-]+\b"
    r"|[A-Za-z0-9_+=]{28,}|\b(?:sudo|curl|powershell|wget)\b", re.I
)
SALUTATION = re.compile(r"^(?:(?:muy bien|excelente(?: trabajo)?|muchas gracias|gracias|genial|great work|thanks|please|por\s*favor)\b[\s,!:.]*)+", re.I)
GENERIC = {"complete the requested work and report the result", "tarea asignada", "assigned task"}
SECRET_MARKERS = (PRIVATE, *(pattern for _, pattern in SERVER_SECRET_PATTERNS))


def _complete_prefix(value):
    end = max(value.rfind(mark) for mark in ".!?;\n")
    return value[:end + 1]


def _summary(value, limit):
    if not isinstance(value, str):
        return ""
    # SQL supplies one extra character to identify a cut record. Never display a
    # cut-through word from a path, credential or code fragment.
    if len(value) > MAX_SOURCE_TEXT:
        value = _complete_prefix(value[:MAX_SOURCE_TEXT])
    value = unicodedata.normalize("NFKC", value)
    value = "".join(c if c == "\n" or not unicodedata.category(c).startswith("C") else " " for c in value)
    matches = (pattern.search(value) for pattern in SECRET_MARKERS)
    cutoff = min((match.start() for match in matches if match), default=len(value))
    if cutoff < len(value):
        # The value can precede its label ("… is the password"). Drop the entire
        # containing sentence and everything after it, including continuation lines.
        value = _complete_prefix(value[:cutoff])
    # Omit code spans and Markdown links, including their labels and destinations.
    value = re.sub(r"`[^`\n]*`|!?\[[^\]\n]*\]\([^\n)]*\)", "\n", value)
    parts = re.split(r"\n|(?<=[.!?;])\s+", value)
    for part in parts:
        part = " ".join(part.replace("**", "").split()).strip(" \t-#*:;")
        part = SALUTATION.sub("", part)
        # A request can open with context then repeat the actual request politely.
        if re.search(r"\bpor\s*favor\b", part, re.I):
            part = re.split(r"\bpor\s*favor\b", part, flags=re.I)[-1].strip()
        if PRIVATE_LOCATION.search(part) or MACHINE_TEXT.search(part):
            # A safe leading objective can precede a comma and an internal technical detail.
            part = part.partition(",")[0]
        part = re.sub(r"\s+(?:en|de|desde|con|para|in|at|from|with)\s*[:,]?$", "", part, flags=re.I)
        if (len(re.findall(r"[^\W\d_]+", part)) < 2 or part.lower().strip(".!") in GENERIC
                or PRIVATE_LOCATION.search(part) or MACHINE_TEXT.search(part)):
            continue
        if len(part) > limit:
            part = part[:limit - 1].rsplit(" ", 1)[0].rstrip(",;:") + "…"
        return part[0].upper() + part[1:]
    return ""


def _agent_name(name):
    if (not isinstance(name, str) or not re.fullmatch(r"[\w][\w .'’\-]{0,63}", name)
            or PRIVATE.search(name) or PRIVATE_LOCATION.search(name) or MACHINE_TEXT.search(name)
            or any(pattern.search(name) for _, pattern in SERVER_SECRET_PATTERNS)):
        return "Agent"
    return name


def _epoch(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value) if 0 <= value < 253402300800 else 0
    if isinstance(value, str):
        try:
            date = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if date.tzinfo:
                return max(0, int(date.astimezone(timezone.utc).timestamp()))
        except (ValueError, OverflowError, OSError):
            pass
    return 0


def _changes(conn, channel):
    params = {"channel": channel, "changes": MAX_CHANGES, "tasks": MAX_TASKS, "text_size": MAX_SOURCE_TEXT + 1}
    rows = conn.execute(TASKS, params).fetchall()
    tasks = {}
    children = defaultdict(list)
    roots = []
    family = {}
    for row in rows:
        task_id = row["task_id"]
        if (not isinstance(task_id, str) or not IDENTIFIER.fullmatch(task_id) or PRIVATE.search(task_id)
                or any(pattern.search(task_id) for _, pattern in SERVER_SECRET_PATTERNS)):
            continue
        parent = row["parent_id"]
        if task_id == row["root_id"] and parent is None:
            roots.append(task_id)
        elif not isinstance(parent, str):
            continue
        else:
            children[parent].append(task_id)
        family[task_id] = row["root_id"]
        tasks[task_id] = {
            "id": task_id, "parent_id": parent, "agent": _agent_name(row["agent"]),
            "title": _summary(row["instruction"], 160) or _summary(row["objective"], 160) or "Assigned work",
            "status": row["state"] if row["state"] in STATES else "unknown",
            "result": "", "updated_at": max(_epoch(row["requested"]), _epoch(row["updated"])),
        }
    if not tasks:
        return []
    ids = ",".join("?" for _ in tasks)
    for row in conn.execute(TIMES.format(ids=ids), (channel, RECENT_MESSAGES, *tasks)):
        task = tasks[row["task_id"]]
        task["updated_at"] = max(task["updated_at"], _epoch(row["recorded"]))
    for row in conn.execute(RESULTS.format(ids=ids), (MAX_SOURCE_TEXT + 1, channel, *tasks)):
        task = tasks[row["task_id"]]
        if not task["result"]:
            task["result"] = _summary(row["result"], 180) or "Result recorded"
            task["updated_at"] = max(task["updated_at"], _epoch(row["reported"]))

    changes = []
    for root_id in roots:
        root = tasks[root_id]
        connected = []
        pending = deque([root_id])
        while pending:
            task_id = pending.popleft()
            task = tasks[task_id]
            task["updated_at"] = task["updated_at"] or None
            connected.append(task)
            # Each task has one parent. Cycles and orphans cannot be reached from this root.
            pending.extend(child for child in children[task_id] if family[child] == root_id)
        if len(connected) > 1:
            changes.append({
                "id": root_id, "title": root["title"], "status": root["status"],
                "updated_at": max(t["updated_at"] or 0 for t in connected) or None, "tasks": connected,
            })
    return sorted(changes, key=lambda c: (c["status"] in TERMINAL, -(c["updated_at"] or 0), c["id"]))


def collaboration(org_id):
    if org_id != 1:
        return {"changes": []}
    channel = os.environ.get("SWARMCONTROL_OPENBOT_CHANNEL_ID", "").strip()
    if not IDENTIFIER.fullmatch(channel):
        return {"changes": []}
    try:
        config = os.environ.get("SWARMCONTROL_OPENBOT_CONFIG") or Path.home() / ".config/OpenBot"
        db = (Path(config).expanduser() / "openbot.db").absolute()
        with closing(sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=0.2)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("PRAGMA temp_store=MEMORY")
            deadline = time.monotonic() + 0.5
            conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
            conn.execute("BEGIN")
            return {"changes": _changes(conn, channel)}
    except (sqlite3.Error, OSError, ValueError, RuntimeError):
        # Optional source. Do not disclose source paths, channel IDs or SQL errors to tenants.
        return {"changes": []}


_TURN_SESSION_QUERY = """
SELECT a.task_id,
       json_extract(a.assignment_json, '$.turnId') AS turn_id,
       t.started_at, t.completed_at,
       ps.provider, ps.external_session_id
  FROM projection_channel_assignments a
  JOIN projection_turns t ON t.turn_id = json_extract(a.assignment_json, '$.turnId')
  JOIN projection_provider_sessions ps ON ps.id = t.provider_session_id
 WHERE a.channel_id = ?
   AND a.task_id IN ({ids})
   AND json_type(a.assignment_json, '$.turnId') = 'text'
 ORDER BY a.rowid DESC
"""


def _canonical_session_id(provider, ext_id):
    p = str(provider or "").strip().lower()
    e = str(ext_id or "").strip()
    if not p or not e or not IDENTIFIER.fullmatch(p):
        return ""
    if p == "claude-code":
        p = "claude"
    return f"{p}:{e[:12]}"


def task_session_links(org_id, task_ids):
    """Read explicit turn->provider_session links for Org 1 tasks (read-only, never heuristic).

    If two tasks overlap the same session_id window, both are marked `ambiguous: True`
    so callers never misattribute steps across concurrent tasks.
    """
    if org_id != 1:
        return {}
    clean_ids = [t for t in (task_ids or []) if isinstance(t, str) and IDENTIFIER.fullmatch(t)]
    if not clean_ids:
        return {}
    channel = os.environ.get("SWARMCONTROL_OPENBOT_CHANNEL_ID", "").strip()
    if not IDENTIFIER.fullmatch(channel):
        return {}
    try:
        config = os.environ.get("SWARMCONTROL_OPENBOT_CONFIG") or Path.home() / ".config/OpenBot"
        db = (Path(config).expanduser() / "openbot.db").absolute()
        with closing(sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=0.2)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("PRAGMA temp_store=MEMORY")
            deadline = time.monotonic() + 0.5
            conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
            conn.execute("BEGIN")
            tables = {
                r["name"]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name IN ('projection_channel_assignments', 'projection_turns', 'projection_provider_sessions')"
                ).fetchall()
            }
            if len(tables) < 3:
                return {}
            placeholders = ",".join("?" for _ in clean_ids)
            rows = conn.execute(_TURN_SESSION_QUERY.format(ids=placeholders), (channel, *clean_ids)).fetchall()
    except (sqlite3.Error, OSError, ValueError, RuntimeError):
        return {}

    now_ts = time.time()
    by_task = {}
    windows_by_session = defaultdict(list)
    for row in rows:
        tid = row["task_id"]
        if tid in by_task:
            continue  # latest turn per task
        sid = _canonical_session_id(row["provider"], row["external_session_id"])
        if not sid:
            continue
        start_ts = _epoch(row["started_at"])
        end_ts = _epoch(row["completed_at"])
        entry = {
            "session_id": sid,
            "runtime": str(row["provider"] or "").strip().lower(),
            "turn_id": str(row["turn_id"] or "")[:96],
            "started_at": start_ts,
            "completed_at": end_ts,
            "ambiguous": False,
        }
        by_task[tid] = entry
        windows_by_session[sid].append((tid, start_ts, end_ts or now_ts))

    # Flag concurrent overlapping turns on the same session so callers never guess.
    for sid, wins in windows_by_session.items():
        if len(wins) < 2:
            continue
        for i in range(len(wins)):
            tid_a, s_a, e_a = wins[i]
            for j in range(i + 1, len(wins)):
                tid_b, s_b, e_b = wins[j]
                if s_a <= 0 or s_b <= 0 or (s_a <= e_b and s_b <= e_a):
                    by_task[tid_a]["ambiguous"] = True
                    by_task[tid_b]["ambiguous"] = True
    return by_task
