"""Live event files and command evidence for agents whose session starts outside the shared folders.

Real layout reproduced: each agent's session starts in its own folder (not shared), and its commands run inside a
shared project copy (`cwd` of the command) or name shared files (`tail -n 20 logs/app.log`, `python3 tools/run.py`).
The event must list those files and keep the command's input and output when output sharing is on. A command that
runs and reads only inside the agent's own folder shares nothing.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from .test_capture_incremental import append, stamp
except ImportError:
    from test_capture_incremental import append, stamp

import activity_inspector as ai
import event_evidence
import work_journal as wj
from db import Database

SHARE = {"SWARMCONTROL_SHARE_COMMANDS": "1", "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "1", "SWARMCONTROL_SHARE_FILE_PREVIEWS": "1"}


class StepScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = Path(self.tmp.name)
        self.home = t / "home"
        self.agent_dir = t / "Agents" / "agent-one"            # where the session starts: not shared with the journal
        self.shared = t / "Shared" / "team"                     # the shared folder
        self.project = self.shared / "product"                  # journal project
        self.copy = self.shared / "product-feature"             # a working copy next to it
        for d in (self.agent_dir, self.project, self.copy / "logs", self.copy / "tools"):
            d.mkdir(parents=True, exist_ok=True)
        (self.copy / "logs/app.log").write_text("started\nready\n")
        (self.copy / "tools/run.py").write_text("print('ok')\n")
        (self.copy / "notes.txt").write_text("todo\n")
        (self.agent_dir / "private-notes.txt").write_text("mine\n")
        self.dbo = Database(t / "journal.db")
        self.addCleanup(self.dbo.close)
        self.conn = sqlite3.connect(self.dbo.db_path)
        self.addCleanup(self.conn.close)
        for p in (patch.object(ai, "HOME", self.home), patch.object(ai, "harnesses", return_value=[])):
            p.start()
            self.addCleanup(p.stop)
        # Inspector scope as the OpenBot adapter builds it: the agent folder and the shared folder.
        self.scope = ai.Scope([self.agent_dir, self.shared], {str(self.agent_dir): "agent-one"}, "host-t")
        self.rollout = self.home / ".codex/rollout.jsonl"
        self.rollout.parent.mkdir(parents=True)
        with sqlite3.connect(self.home / ".codex/state_5.sqlite") as c:
            c.execute("CREATE TABLE threads (id TEXT, cwd TEXT, model TEXT, tokens_used INT, updated_at INT, rollout_path TEXT,"
                      " model_provider TEXT)")
            c.execute("INSERT INTO threads VALUES ('t1',?,?,?,?,?,?)",
                      (str(self.agent_dir), "gpt-x", 1, int(time.time()), str(self.rollout), "openai"))
        self.n = 0

    def command(self, cmd, cwd, output="", code=0):
        self.n += 1
        append(self.rollout, [{"timestamp": stamp(self.n), "payload": {"type": "item_completed", "item": {
            "type": "CommandExecution", "cwd": str(cwd), "command": ["bash", "-lc", cmd],
            "parsed_cmd": [{"type": "unknown", "cmd": cmd}], "aggregated_output": output, "exit_code": code}}}])

    def scan(self, roots):
        with patch.dict(os.environ, SHARE):
            return wj.capture_once(self.conn, {"agent-one"}, self.project, time.time(), ai.Scope(roots), self.scope)

    def events(self):
        out = {}
        for row in self.dbo.query_all("SELECT id, metadata_json FROM events WHERE event_type='observed_step' ORDER BY id"):
            meta = json.loads(row["metadata_json"])
            out[meta.get("program")] = (meta, event_evidence.detail(self.dbo, 1, row["id"]))
        return out

    def test_commands_in_a_shared_copy_list_their_files_and_keep_input_and_output(self):
        self.command("tail -n 2 logs/app.log", self.copy, "started\nready\n")
        self.command("python3 tools/run.py --fast", self.copy, "ok\n")
        self.command(f"cd {self.copy} && cat notes.txt", self.agent_dir, "todo\n")
        self.command("curl -s https://example.invalid/health", self.copy, '{"status":"ok"}', 0)
        self.scan([self.shared])
        got = self.events()
        tail, tail_ev = got["tail"]
        self.assertEqual(tail["files"], ["team/product-feature/logs/app.log"])
        self.assertEqual(tail_ev["command_input"], "tail -n 2 logs/app.log")
        self.assertEqual(tail_ev["command_output"], "started\nready\n")
        self.assertEqual(got["python3"][0]["files"], ["team/product-feature/tools/run.py"])
        self.assertEqual(got["python3"][1]["command_output"], "ok\n")
        cat, cat_ev = got["cat"]   # started in the agent's folder, `cd` into the shared copy first
        self.assertEqual(cat["files"], ["team/product-feature/notes.txt"])
        self.assertEqual(cat_ev["command_output"], "todo\n")
        curl, curl_ev = got["curl"]  # no file, but it ran inside the shared copy
        self.assertEqual(curl["files"], [])
        self.assertEqual((curl_ev["command_input"], curl_ev["command_output"], curl_ev["exit_code"]),
                         ("curl -s https://example.invalid/health", '{"status":"ok"}', 0))

    def test_a_command_only_in_the_agents_own_folder_shares_nothing(self):
        self.command("cat private-notes.txt", self.agent_dir, "mine\n")
        self.scan([self.shared])
        meta, ev = self.events()["cat"]
        self.assertEqual(meta["files"], [])
        self.assertEqual(meta["workspace"], "Agent workspace")
        self.assertIsNone(ev["command_output"])
        self.assertIsNone(ev["command_input"])
        blob = json.dumps(self.dbo.query_all("SELECT metadata_json, message FROM events"), default=str)
        self.assertNotIn("private-notes", blob)

    def test_files_outside_the_journal_roots_stay_out(self):
        """Journal roots narrower than the copy (only the project): the copy's files and output are not stored."""
        self.command("tail -n 2 logs/app.log", self.copy, "started\nready\n")
        self.scan([self.project])
        meta, ev = self.events()["tail"]
        self.assertEqual(meta["files"], [])
        self.assertIsNone(ev["command_output"])

    def test_operands_are_existing_files_only(self):
        self.assertEqual(ai.command_files("head -n 40 logs/app.log missing.txt '*.py' -", self.copy),
                         [str(self.copy / "logs/app.log")])
        self.assertEqual(ai.command_files("git log --oneline -3", self.copy), [], "not a file-taking program")
        self.assertEqual(ai.command_files("sed -n '1,5p' notes.txt | wc -l", self.copy), [str(self.copy / "notes.txt")])
        self.assertEqual(ai.command_files("python3 -m unittest discover", self.copy), [])
        link = self.copy / "link.txt"
        link.symlink_to(self.agent_dir / "private-notes.txt")
        self.assertEqual(ai.command_files("cat link.txt ../../Agents/agent-one/private-notes.txt", self.copy), [],
                         "links and parent-relative paths are never followed")

    def test_no_private_key_leaves_the_snapshot(self):
        self.command("tail -n 2 logs/app.log", self.copy, "x")
        with patch.dict(os.environ, SHARE):
            snap = ai.collect_activity(self.scope)
            cap = ai.collect_activity(self.scope, ai.Capture({}))
        for s in snap["sessions"] + cap["sessions"]:
            for st in s.get("steps", []) + s.get("capture_steps", []):
                self.assertFalse([k for k in st if k in ("_shell", "_cwd")])
        self.assertFalse(any("cwd" in st for s in snap["sessions"] for st in s["steps"]), "the map never gets a folder path")


if __name__ == "__main__":
    unittest.main()
