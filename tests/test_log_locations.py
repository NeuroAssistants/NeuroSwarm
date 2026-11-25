"""Agent records outside their default folders: each runtime's own variable, other Antigravity variants, newer Codex
state files, and the per-machine "sources" report that explains an empty map without revealing private paths."""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(Path(__file__).resolve().parent)]
import activity_inspector as ai  # noqa: E402
import remote_activity  # noqa: E402
from test_capture_incremental import CaptureHarness  # noqa: E402

CLEAN_ENV = {"CODEX_HOME": "", "CLAUDE_CONFIG_DIR": "", "XDG_DATA_HOME": ""}


class LogLocationTests(CaptureHarness):
    def setUp(self):
        super().setUp()
        p = patch.dict(os.environ, CLEAN_ENV)
        p.start()
        self.addCleanup(p.stop)
        self.elsewhere = Path(self.tmp.name) / "elsewhere"

    def sessions(self):
        return {s["harness"]: s for s in ai.collect_activity(self.scope)["sessions"]}

    def sources(self):
        return {s["runtime"]: s for s in ai.collect_activity(self.scope)["sources"]}

    def move(self, rel: str, dest: Path) -> Path:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(self.home / rel), str(dest))
        return dest

    def test_default_locations_are_reported_as_found(self):
        self.claude(1)
        self.codex(1)
        self.antigravity(1)
        self.opencode(1)
        self.assertEqual(set(self.sessions()), {"claude-code", "codex", "antigravity", "opencode"})
        src = self.sources()
        self.assertEqual({k: v["status"] for k, v in src.items()},
                         {"Codex CLI": "found", "Claude Code": "found", "OpenCode": "found", "Gemini / Antigravity": "found"})
        self.assertEqual(src["Claude Code"]["location"], "~/.claude/projects")
        self.assertEqual(src["Codex CLI"]["origin"], "default")

    def test_codex_home_moves_codex(self):
        self.codex(2)
        moved = self.move(".codex", self.elsewhere / "codex-profile")
        with sqlite3.connect(moved / "state_5.sqlite") as c:   # the thread points at the moved rollout
            c.execute("UPDATE threads SET rollout_path=?", (str(moved / "rollout.jsonl"),))
        self.assertNotIn("codex", self.sessions(), "without the variable the default folder is empty")
        self.assertEqual(self.sources()["Codex CLI"]["status"], "not found")
        with patch.dict(os.environ, {"CODEX_HOME": str(moved)}):
            self.assertIn("codex", self.sessions())
            src = self.sources()["Codex CLI"]
        self.assertEqual((src["status"], src["origin"], src["location"]), ("found", "CODEX_HOME", "set by CODEX_HOME"))

    def test_newest_readable_codex_state_is_used_and_an_unknown_one_is_reported(self):
        self.codex(1)
        home = self.home / ".codex"
        shutil.copy(home / "state_5.sqlite", home / "state_6.sqlite")
        with sqlite3.connect(home / "state_6.sqlite") as c:
            c.execute("UPDATE threads SET id='t6'")
        with sqlite3.connect(home / "state_7.sqlite") as c:       # a future format the reader does not know
            c.execute("CREATE TABLE threads (thread_key TEXT)")
        db, status = ai.codex_state_db()
        self.assertEqual(db.name, "state_6.sqlite")
        self.assertEqual(status, "unsupported format (state_7.sqlite); reading state_6.sqlite")
        self.assertEqual(self.sessions()["codex"]["session_id"], "codex:t6")
        (home / "state_6.sqlite").unlink()
        (home / "state_5.sqlite").unlink()
        self.assertEqual(ai.codex_state_db(), (None, "unsupported format (state_7.sqlite)"))
        self.assertNotIn("codex", self.sessions(), "an unknown format is not guessed at")

    def test_claude_config_dir_moves_claude_code_including_tasks(self):
        self.claude(2)
        moved = self.move(".claude", self.elsewhere / "claude-profile")
        self.assertNotIn("claude-code", self.sessions())
        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(moved)}):
            self.assertIn("claude-code", self.sessions())
            self.assertEqual(self.sources()["Claude Code"]["origin"], "CLAUDE_CONFIG_DIR")

    def test_xdg_data_home_moves_opencode(self):
        self.opencode(2)
        data = self.elsewhere / "xdg-data"
        self.move(".local/share/opencode", data / "opencode")
        self.assertNotIn("opencode", self.sessions())
        with patch.dict(os.environ, {"XDG_DATA_HOME": str(data)}):
            self.assertIn("opencode", self.sessions())
            self.assertEqual(self.sources()["OpenCode"]["status"], "found")

    def test_every_antigravity_variant_is_read(self):
        self.antigravity(2)
        self.move(".gemini/antigravity-acp", self.home / ".gemini/antigravity-cli")
        s = self.sessions()
        self.assertIn("antigravity", s, "the CLI variant keeps the same layout")
        self.assertEqual(s["antigravity"]["agent_name"], "ag-team", "the workspace still comes from its own metadata")
        locations = [x["location"] for x in ai.collect_activity(self.scope)["sources"] if x["runtime"] == "Gemini / Antigravity"]
        self.assertEqual(locations, ["~/.gemini/antigravity-cli"])

    def test_sources_never_reveal_a_path_outside_the_home_folder(self):
        self.claude(1)
        moved = self.move(".claude", self.elsewhere / "private-profile-name")
        with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(moved)}):
            snap = ai.collect_activity(self.scope)
        blob = json.dumps(snap["sources"]) + json.dumps(snap["hosts"])
        self.assertNotIn("private-profile-name", blob)
        self.assertNotIn(str(self.elsewhere), blob)
        self.assertEqual(snap["hosts"][0]["sources"], snap["sources"])

    def test_remote_ingest_keeps_valid_sources_for_the_map_only(self):
        self.claude(1)
        snap = ai.collect_activity(self.scope)
        body = {"host_id": "box-1", "activity_enabled": True, "activity_roots": [str(self.roots["claude-team"])],
                "sessions": [], "sources": snap["sources"] + [
                    {"runtime": "Evil", "location": "/etc", "status": "<script>found</script>"},
                    {"runtime": "Codex CLI", "location": "~/.codex", "status": "unsupported format (state_9.sqlite)"}]}
        cleaned = remote_activity.sanitize_activity_payload(body)
        statuses = [x["status"] for x in cleaned["sources"]]
        self.assertNotIn("<script>found</script>", statuses)
        self.assertIn("unsupported format (state_9.sqlite)", statuses)
        self.assertEqual(len(cleaned["sources"]), len(snap["sources"]) + 1)
        self.assertIn("sources", remote_activity._strip_capture_for_map(cleaned))


if __name__ == "__main__":
    unittest.main()
