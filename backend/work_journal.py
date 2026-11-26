"""Record every observed action of explicitly selected local agents (incremental capture).

Each scan reads the agent logs from the byte offset where the previous scan stopped (activity_inspector.Capture),
so bursts are not lost to the map's "last 10 steps" view. Steps are keyed by their exact source position; for
bytes written before this version, the previous content key is still honoured, so an upgrade does not duplicate.
Events, read offsets, capture gaps and scan metrics are written in one transaction: if anything fails, nothing
advances and the next scan re-reads the same bytes. Unfinished steps (running/pending) wait until they finish.
"""
import os
from pathlib import Path
import sqlite3
import sys
import time

import capture_settings
from activity_inspector import Capture, Scope, collect_activity
from step_journal import (
    ACTIONS,
    COMMAND_FORMS,
    COMMANDS,
    RETENTION,
    command_form,
    ensure_journal_tables as _tables,
    journal_files,
    persist_steps,
    position_key as _position_key,
    project_rows,
)


def journal_rows(snapshot, agents, project, now, extra_scope=None, capture=None, skipped=None):
    """Yield (key, legacy_keys, timestamp, event). `key` is the position key when the step has a source position,
    else the content key; `legacy_keys` are content keys that also count as "already stored" (upgrade path)."""
    return project_rows(
        snapshot,
        now=now,
        agents=agents,
        project=project,
        extra_scope=extra_scope,
        capture=capture,
        skipped=skipped,
    )


def load_offsets(db):
    _tables(db)
    return {
        k: {"inode": i, "offset": o, "legacy_until": legacy}
        for k, i, o, legacy in db.execute("SELECT file_key, inode, offset, legacy_until FROM capture_offsets")
    }


def record(db, snapshot, agents, project, now, extra_scope=None, capture=None, started=None):
    """Store new actions. With `capture`, also persist read offsets, gaps and scan metrics in the same transaction."""
    with db:
        return persist_steps(
            db,
            snapshot,
            now=now,
            agents=agents,
            project=project,
            extra_scope=extra_scope,
            capture=capture,
            started=started,
        )


def capture_once(db, agents, project, now=None, extra_scope=None, scope=None):
    """One incremental scan: read what was appended since the stored offsets and store it atomically."""
    started = time.perf_counter()
    capture = Capture(load_offsets(db))
    snapshot = collect_activity(scope, capture)
    result = record(db, snapshot, agents, project, now or time.time(), extra_scope, capture, started)
    # What this journal may share for its host (issue #11): switches and a folder count, never a path.
    host_id = snapshot.get("host_id")
    if host_id:
        folders = 1 + len(getattr(extra_scope, "roots", []) or [])
        with db:
            capture_settings.store(db, host_id, "journal", capture_settings.local_settings(folders), now)
    return result


def main():
    agents = set(filter(None, os.environ["SWARMCONTROL_JOURNAL_AGENTS"].split(",")))
    project = Path(os.environ["SWARMCONTROL_JOURNAL_PROJECT"]).resolve(strict=True)
    extra_scope = Scope([p for p in os.getenv("SWARMCONTROL_JOURNAL_ROOTS", "").split(os.pathsep) if p])
    uri = Path(os.environ["SWARMCONTROL_DB"]).resolve(strict=True).as_uri() + "?mode=rw"
    with sqlite3.connect(uri, uri=True, timeout=5) as db:
        delay = 5
        while True:
            try:
                capture_once(db, agents, project, time.time(), extra_scope)
                delay = 5
            except sqlite3.Error as exc:  # e.g. database locked: nothing was committed, so nothing is lost
                print(f"[work-journal] scan not stored ({type(exc).__name__}); retrying", file=sys.stderr, flush=True)
                delay = min(delay * 2, 60)
            time.sleep(delay)


if __name__ == "__main__":
    main()
