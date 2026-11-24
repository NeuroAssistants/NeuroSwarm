"""Work board data for the console: detected runtimes and an optional watched project folder.

Portable: no team names, agent ids or host-application paths. Session timelines live in the
Activity map (activity_inspector / remote activity); reports come from the database.
  SWARMCONTROL_WORKBOARD_ROOT  optional folder whose source files are compared between reads
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from activity_inspector import harnesses
from workspace_activity import WorkspaceActivity

_WATCH: WorkspaceActivity | None = None
_WATCH_ROOT: Path | None = None


def _watch() -> WorkspaceActivity | None:
    global _WATCH, _WATCH_ROOT
    raw = os.environ.get("SWARMCONTROL_WORKBOARD_ROOT", "").strip()
    root = Path(raw).expanduser() if raw else None
    if root is None or not root.is_dir():
        _WATCH, _WATCH_ROOT = None, None
    elif root != _WATCH_ROOT:
        _WATCH, _WATCH_ROOT = WorkspaceActivity(root), root
    return _WATCH


def managed_runtimes() -> list[dict[str, Any]]:
    """Agent runtimes found on this host, with the evidence that found them."""
    return [{"name": h["name"], "version": h["version"], "status": h["status"],
             "binary": " · ".join(h.get("evidence") or [])} for h in harnesses()]


def work_board() -> dict[str, Any]:
    watch = _watch()
    board: dict[str, Any] = {"project": _WATCH_ROOT.name if watch else "", "runtimes": managed_runtimes(),
                             "sessions": [], "files": [], "workspace_activity": None}
    if watch:
        sample = watch.sample()
        board["files"] = sample.pop("files")
        board["workspace_activity"] = sample
    return board
