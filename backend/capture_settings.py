"""What each collector on a host may share, as it last reported it (issue #11).

Two collectors can record a host's activity: the remote observer (reported with every heartbeat) and a local activity
journal running next to the console. Each reports only on/off switches and a folder count: never a path, a command or a
value. A collector that predates this report has no row, and the console shows its settings as Unknown.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

SOURCES = ("observer", "journal")
SWITCHES = {  # reported key -> environment variable that turns it on
    "commands": "SWARMCONTROL_SHARE_COMMANDS",
    "command_output": "SWARMCONTROL_SHARE_COMMAND_OUTPUT",
    "file_previews": "SWARMCONTROL_SHARE_FILE_PREVIEWS",
    "line_survival": "SWARMCONTROL_SHARE_LINE_SURVIVAL",
}


def local_settings(shared_folders: int) -> dict[str, Any]:
    """This process's own settings, read from its environment."""
    out: dict[str, Any] = {key: os.environ.get(var) == "1" for key, var in SWITCHES.items()}
    out["activity"] = shared_folders > 0
    out["shared_folders"] = max(0, int(shared_folders))
    return out


def clean(raw: Any) -> dict[str, Any] | None:
    """Only the known switches as booleans and a bounded folder count; anything else is dropped."""
    if not isinstance(raw, dict):
        return None
    out: dict[str, Any] = {}
    for key in (*SWITCHES, "activity"):
        if isinstance(raw.get(key), bool):
            out[key] = raw[key]
    count = raw.get("shared_folders")
    if type(count) is int and 0 <= count <= 10_000:
        out["shared_folders"] = count
    return out or None


def ensure_tables(conn: Any) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS capture_settings (
        host_id TEXT NOT NULL, source TEXT NOT NULL, settings_json TEXT NOT NULL, reported_at REAL NOT NULL,
        PRIMARY KEY (host_id, source))""")


def store(conn: Any, host_id: str, source: str, raw: Any, now: float | None = None) -> bool:
    settings = clean(raw)
    if source not in SOURCES or not settings or not isinstance(host_id, str) or not host_id:
        return False
    ensure_tables(conn)
    conn.execute("""INSERT INTO capture_settings VALUES (?,?,?,?) ON CONFLICT(host_id, source) DO UPDATE SET
                    settings_json=excluded.settings_json, reported_at=excluded.reported_at""",
                 (host_id, source, json.dumps(settings, sort_keys=True), float(now or time.time())))
    return True


def by_host(db: Any) -> dict[str, list[dict[str, Any]]]:
    """host_id -> [{source, reported_at, settings}] for the hosts API."""
    with db.transaction(write=False) as conn:  # a read: the table appears with the first report
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='capture_settings'").fetchone() is None:
            return {}
        rows = conn.execute("SELECT host_id, source, settings_json, reported_at FROM capture_settings "
                            "ORDER BY host_id, source").fetchall()
    out: dict[str, list[dict[str, Any]]] = {}
    for host_id, source, raw, reported_at in (tuple(r) for r in rows):
        try:
            settings = clean(json.loads(raw)) or {}
        except (TypeError, ValueError):
            settings = {}
        out.setdefault(host_id, []).append({"source": source, "reported_at": reported_at, "settings": settings})
    return out
