"""Optional OpenBot adapter for the activity inspector (read-only, non-critical).

Enabled only with SWARMCONTROL_ACTIVITY_ADAPTERS=openbot. It contributes:
  roots()            OpenBot agent workspaces (<root>/Agents/*) and shared folders (<root>/Shared/*)
  labels()           agent display names read from OpenBot's own database (no names in code)
  runtime_versions() versions of CLIs managed by OpenBot
Settings:
  SWARMCONTROL_OPENBOT_ROOT    OpenBot data folder (default: ~/OpenBot)
  SWARMCONTROL_OPENBOT_CONFIG  OpenBot config folder (default: ~/.config/OpenBot)
  SWARMCONTROL_OPENBOT_SHARED  optional comma list of shared folder names to include (default: all)
If OpenBot is absent or its schema changes, every function returns empty results.
"""
from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path

HARNESSES = [("openbot", "OpenBot", ["openbot", "cua-driver"], None)]
TOOL_PREFIXES = ["mcp_openbot_browser_", "mcp_openbot_"]  # single-underscore MCP names used by some CLIs
AGENT_DIR = re.compile(r"agent-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _root() -> Path:
    return Path(os.environ.get("SWARMCONTROL_OPENBOT_ROOT") or Path.home() / "OpenBot")


def _config() -> Path:
    return Path(os.environ.get("SWARMCONTROL_OPENBOT_CONFIG") or Path.home() / ".config/OpenBot")


def roots() -> list[Path]:
    out: list[Path] = []
    wanted = {s.strip() for s in os.environ.get("SWARMCONTROL_OPENBOT_SHARED", "").split(",") if s.strip()}
    for kind in ("Agents", "Shared"):
        base = _root() / kind
        try:
            entries = sorted(e for e in base.iterdir() if e.is_dir() and not e.is_symlink() and not e.name.startswith("."))
        except OSError:
            continue
        for e in entries:
            if kind == "Agents" and not AGENT_DIR.fullmatch(e.name):
                continue
            if kind == "Shared" and wanted and e.name not in wanted:
                continue
            out.append(e)
    return out


def labels() -> dict[str, str]:
    """Absolute agent folder -> agent name, from OpenBot's database (opened read-only)."""
    db = _config() / "openbot.db"
    if not db.is_file():
        return {}
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
        try:
            rows = conn.execute("SELECT agent_id, json_extract(agent_json, '$.name') FROM projection_agents").fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return {}
    base = _root() / "Agents"
    return {str(base / aid): str(name)[:64] for aid, name in rows
            if isinstance(aid, str) and AGENT_DIR.fullmatch(aid) and isinstance(name, str) and name.strip()}


def runtime_versions(home: Path) -> dict[str, list[str]]:
    base = _config() / "provider-runtimes"
    out: dict[str, list[str]] = {}
    try:
        for rt in base.iterdir():
            if rt.is_dir() and not rt.name.startswith("."):
                out[rt.name] = sorted({v.name for v in rt.glob("*/*") if v.is_dir()})
    except OSError:
        pass
    return out
