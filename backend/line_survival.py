"""Which lines an agent's edit added are still in the code, from explicit Git evidence only.

Evidence chain (nothing is attributed from file text):
  1. The session's own `git commit` printed the commit ID ("[branch abc1234] message"); the collector stores only that
     ID on the command's event (`git_commit`).
  2. The collector measures, on the machine that has the repository and only inside shared folders, how many lines each
     recent commit added to each file (`git log --numstat`) and how many of those lines `git blame -M HEAD` still assigns
     to that commit. It sends numbers, never file contents (`line_survival` in the activity payload).
  3. An edit event is linked to the first commit recorded by the same session after the edit that changed the same file.
     The link is refused when another session edited that file before the commit, or when an earlier commit to the file
     came after the edit (the edit may already be in that one).

Files are joined by a stable key, "<shared folder label>/<path in that folder>", computed with the journal's own path
projection, so a file outside the shared folders or a protected file never gets a key.
"""
from __future__ import annotations

import json
import re
from typing import Any

SHA = re.compile(r"[0-9a-f]{40}")
SHORT_SHA = re.compile(r"[0-9a-f]{7,40}")
MAX_ITEMS = 300
MAX_COMMITS_PER_SESSION = 50

STATUS_TEXT = {
    "attributed": "Lines added by this session's commit",
    "not_shared": "Line tracking is not shared by this machine",
    "no_commit": "No commit recorded by this session after the edit",
    "not_in_commit": "The session's commits after this edit do not change this file on the checked-out branch",
    "earlier_commit": "An earlier commit to this file came after the edit, so the edit may already be in it",
    "other_session": "Another session also edited this file before the commit, so its lines cannot be told apart",
    "not_tracked": "This edit was recorded without a file in a shared Git folder",
}


def ensure_tables(conn: Any) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS line_survival (
        host_id TEXT NOT NULL, sha TEXT NOT NULL, path TEXT NOT NULL,
        added INTEGER NOT NULL, surviving INTEGER NOT NULL, exists_at_head INTEGER NOT NULL,
        commit_time REAL NOT NULL, prev_time REAL NOT NULL, head TEXT NOT NULL, measured_at REAL NOT NULL,
        PRIMARY KEY (host_id, sha, path))""")


def canonical_keys(paths: list[Any], *, project: Any = None, extra_scope: Any = None, root_index: Any = None,
                   cwd: str = "") -> list[str]:
    """"<folder label>/<relative path>" for each path inside a shared folder, using the journal's own projection."""
    import step_journal  # local import: step_journal imports this module

    keys: list[str] = []
    if project is not None:
        primary, extra, _ = step_journal.journal_files(paths, project, extra_scope, cwd)
        keys = [f"{project.name}/{p}" for p in primary] + list(extra)
    elif root_index:
        primary, extra, _, label = step_journal.resolve_step_files(paths, root_index, cwd)
        if label in ("", "Agent workspace"):  # no matched workspace: primary paths exist only with a single folder
            label = root_index[0][2] if len(root_index) == 1 else ""
        keys = ([f"{label}/{p}" for p in primary] if label else []) + list(extra)
    return [k for k in dict.fromkeys(keys) if len(k) <= 320][:12]


def store(conn: Any, host_id: str, items: Any, now: float, resolve) -> int:
    """Upsert one host's measurements. `resolve(abs_path)` returns the file's key or None (outside shared folders)."""
    if not isinstance(items, list):
        return 0
    ensure_tables(conn)
    stored = 0
    for item in items[:MAX_ITEMS]:
        if not isinstance(item, dict):
            continue
        sha, head = str(item.get("sha") or ""), str(item.get("head") or "")
        if not SHA.fullmatch(sha) or not SHA.fullmatch(head):
            continue
        try:
            added, surviving = int(item["added"]), int(item["surviving"])
            commit_time, prev_time = float(item["commit_time"]), float(item.get("prev_time") or 0)
            measured_at = float(item.get("measured_at") or now)
        except (KeyError, TypeError, ValueError):
            continue
        if not (0 < added <= 1_000_000 and 0 <= surviving <= 1_000_000) or measured_at > now + 300:
            continue
        key = resolve(item.get("path"))
        if not key:
            continue
        conn.execute(
            """INSERT INTO line_survival VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(host_id, sha, path) DO UPDATE SET
               added=excluded.added, surviving=excluded.surviving, exists_at_head=excluded.exists_at_head,
               commit_time=excluded.commit_time, prev_time=excluded.prev_time, head=excluded.head,
               measured_at=excluded.measured_at WHERE excluded.measured_at >= line_survival.measured_at""",
            (host_id, sha, key, added, min(surviving, added), 1 if item.get("exists") else 0, commit_time, prev_time,
             head, measured_at),
        )
        stored += 1
    return stored


def prune(conn: Any, cutoff: float) -> None:
    ensure_tables(conn)
    conn.execute("DELETE FROM line_survival WHERE measured_at < ?", (cutoff,))


def _meta(raw: Any) -> dict[str, Any]:
    try:
        value = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def detail(db: Any, org: int, event_id: int) -> dict[str, Any] | None:
    """Line survival for one edit event of this organization's database, or None when the event does not exist."""
    with db.transaction(write=False) as conn:
        ensure_tables(conn)
        row = conn.execute("SELECT id, host_id, created_at, metadata_json FROM events WHERE id=? AND event_type='observed_step'",
                           (event_id,)).fetchone()
        if row is None:
            return None
        _, host, edited_at, raw = tuple(row)
        meta = _meta(raw)
        out: dict[str, Any] = {"event_id": event_id, "organization": org, "session": meta.get("session"), "files": []}
        if meta.get("action") != "file_edit":
            out["applies"] = False
            return out
        out["applies"] = True
        keys = [k for k in meta.get("line_keys") or [] if isinstance(k, str)][:12]
        session = meta.get("session")
        shared = conn.execute("SELECT 1 FROM line_survival WHERE host_id=? LIMIT 1", (host,)).fetchone() is not None
        commits = [] if not isinstance(session, str) else conn.execute(
            """SELECT id, created_at, json_extract(metadata_json,'$.git_commit') FROM events
               WHERE host_id=? AND event_type='observed_step' AND json_extract(metadata_json,'$.session')=?
                 AND json_extract(metadata_json,'$.git_commit') IS NOT NULL AND created_at >= ?
               ORDER BY created_at, id LIMIT ?""", (host, session, edited_at - 1, MAX_COMMITS_PER_SESSION)).fetchall()
        if not keys:
            out["files"] = [{"file": f, "status": "not_tracked", "reason": STATUS_TEXT["not_tracked"]}
                            for f in (meta.get("files") or [])[:12] if isinstance(f, str)]
            return out
        for key in keys:
            entry: dict[str, Any] = {"file": key.split("/", 1)[1] if "/" in key else key, "folder": key.split("/", 1)[0]}
            found = None
            for cid, ctime, short in commits:
                if not isinstance(short, str) or not SHORT_SHA.fullmatch(short):
                    continue
                rows = conn.execute("SELECT * FROM line_survival WHERE host_id=? AND path=? AND sha LIKE ?",
                                    (host, key, short + "%")).fetchall()
                if len({r["sha"] if hasattr(r, "keys") else r[1] for r in rows}) == 1:
                    found = (cid, ctime, rows[0])
                    break
            if found is None:
                status = "not_shared" if not shared else ("not_in_commit" if commits else "no_commit")
            else:
                cid, ctime, m = found
                m = dict(m) if hasattr(m, "keys") else dict(zip(
                    ("host_id", "sha", "path", "added", "surviving", "exists_at_head", "commit_time", "prev_time", "head",
                     "measured_at"), m))
                others = conn.execute(
                    """SELECT COUNT(*) FROM events WHERE host_id=? AND event_type='observed_step' AND id<>?
                         AND json_extract(metadata_json,'$.action')='file_edit'
                         AND COALESCE(json_extract(metadata_json,'$.session'),'')<>?
                         AND created_at > ? AND created_at <= ?
                         AND EXISTS (SELECT 1 FROM json_each(json_extract(metadata_json,'$.line_keys')) WHERE value=?)""",
                    (host, event_id, session, m["prev_time"], ctime, key)).fetchone()[0]
                same = conn.execute(
                    """SELECT COUNT(*) FROM events WHERE host_id=? AND event_type='observed_step'
                         AND json_extract(metadata_json,'$.action')='file_edit'
                         AND json_extract(metadata_json,'$.session')=? AND created_at > ? AND created_at <= ?
                         AND EXISTS (SELECT 1 FROM json_each(json_extract(metadata_json,'$.line_keys')) WHERE value=?)""",
                    (host, session, m["prev_time"], ctime, key)).fetchone()[0]
                entry.update(commit=m["sha"][:12], commit_event_id=cid)
                if m["prev_time"] >= edited_at:
                    status = "earlier_commit"
                elif others:
                    status = "other_session"
                else:
                    status = "attributed"
                    entry.update(added=m["added"], surviving=m["surviving"],
                                 changed_or_removed=max(0, m["added"] - m["surviving"]),
                                 file_exists=bool(m["exists_at_head"]), head=m["head"][:12],
                                 measured_at=m["measured_at"], edits_in_commit=max(1, same))
            entry.update(status=status, reason=STATUS_TEXT[status])
            out["files"].append(entry)
        return out
