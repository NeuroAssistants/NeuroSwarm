"""Live event files and command evidence for agents whose session starts outside the shared folders.

Real layout reproduced: each agent's session starts in its own folder (not shared), and its commands run inside a
shared project copy (`cwd` of the command) or name shared files (`tail -n 20 logs/app.log`, `python3 tools/run.py`).
The event must list those files and keep the command's input and output when output sharing is on. A command that
runs and reads only inside the agent's own folder shares nothing.
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import sqlite3
import subprocess
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
import event_feed
import live_history
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

    def command(self, cmd, cwd, output="", code=0, shell=("bash", "-lc"), **fields):
        self.n += 1
        append(self.rollout, [{"timestamp": stamp(self.n), "payload": {"type": "item_completed", "item": {
            "type": "CommandExecution", "cwd": str(cwd), "command": [*shell, cmd],
            "parsed_cmd": [{"type": "unknown", "cmd": cmd}], "aggregated_output": output, "exit_code": code, **fields}}}])

    def run_shell(self, cmd, shell=("sh", "-c"), **env):
        run = subprocess.run([*shell, cmd], cwd=self.agent_dir, text=True, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, timeout=5, env={"PATH": os.defpath, "LC_ALL": "C", **env})
        self.command(cmd, self.agent_dir, run.stdout, run.returncode, shell)
        return run

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

    def test_mixed_journal_roots_withhold_combined_output(self):
        private = self.agent_dir / "private-notes.txt"
        self.command(f"tail logs/app.log {private}", self.copy, "ready\nmine")
        self.scan([self.copy])
        meta, ev = self.events()["tail"]
        self.assertEqual(meta["files"], ["product-feature/logs/app.log"])
        self.assertIsNone(ev["command_output"])
        self.assertIsNone(ev["command_input"])

    def test_python_and_wc_after_literal_cd(self):
        self.command(f"cd {self.copy} && python3 tools/run.py", self.agent_dir, "ok\n")
        self.command(f"cd {self.copy} && wc -l notes.txt", self.agent_dir, "1 notes.txt\n")
        self.scan([self.copy])
        results = self.events()
        self.assertEqual(results["python3"][0]["files"], ["product-feature/tools/run.py"])
        self.assertEqual(results["python3"][1]["command_output"], "ok\n")
        self.assertEqual(results["wc"][1]["command_output"], "1 notes.txt\n")

    def test_failed_cd_does_not_share_its_output(self):
        self.command(f"cd {self.copy}/missing && python3 -V", self.agent_dir, "cd failed", 1)
        self.scan([self.copy])
        self.assertIsNone(self.events()["python3"][1]["command_output"])

    @unittest.skipUnless(shutil.which("bash") and shutil.which("sh") and shutil.which("python3"), "POSIX shell fixture")
    def test_failed_python_and_custom_program_have_their_own_historical_output(self):
        repo = self.copy / "quoted project && subdir"
        repo.mkdir()
        (repo / "job.py").write_text("raise ValueError('cd check failed')\n")
        tool = repo / "check-ledger"
        tool.write_text("#!/bin/sh\nprintf 'report rows differ\\n' >&2\nexit 23\n")
        tool.chmod(0o700)
        cursor = event_feed.feed(self.dbo)["cursor"]
        prefix = "cd -- " + shlex.quote(str(repo)) + " && "
        python = self.run_shell(prefix + "python3 job.py", ("bash", "--noprofile", "--norc", "-c"))
        custom = self.run_shell(prefix + "./check-ledger")
        self.assertEqual((python.returncode, custom.returncode), (1, 23))
        self.assertIn("ValueError: cd check failed", python.stdout)
        self.assertEqual(self.scan([self.copy])["inserted"], 2)
        fresh = event_feed.feed(self.dbo, cursor)["records"]
        self.assertEqual(len(fresh), 2)
        (repo / "job.py").write_text("print('changed after execution')\n")
        tool.write_text("changed after execution\n")
        reopened = Database(self.dbo.db_path)
        self.addCleanup(reopened.close)
        history = live_history.history(reopened, 1, {})["records"]
        self.assertEqual({r["id"] for r in history}, {r["id"] for r in fresh})
        results = {r["details"]["program"]: event_evidence.detail(reopened, 1, r["id"]) for r in fresh}
        for program, path, marker, code in (("python3", "job.py", "ValueError: cd check failed", 1),
                                            ("check-ledger", "check-ledger", custom.stdout, 23)):
            with self.subTest(program=program):
                ev = results[program]
                self.assertEqual(ev["files"], ["product-feature/quoted project && subdir/" + path])
                self.assertIn(path, ev["command_input"])
                self.assertIn(marker, ev["command_output"])
                self.assertEqual(ev["exit_code"], code)
                self.assertNotIn("changed after", ev["command_output"])

    @unittest.skipUnless(shutil.which("bash") and shutil.which("python3"), "POSIX shell fixture")
    def test_failed_module_after_cd_keeps_the_interpreter_diagnostic(self):
        result = self.run_shell(f"cd {self.copy} && python3 -m neuroswarm_module_missing", ("bash", "-c"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("No module named neuroswarm_module_missing", result.stdout)
        self.scan([self.copy])
        _, evidence = self.events()["python3"]
        self.assertEqual(evidence["files"], [])
        self.assertIn("No module named neuroswarm_module_missing", evidence["command_output"])
        self.assertEqual(evidence["exit_code"], result.returncode)

    @unittest.skipUnless(shutil.which("bash") and shutil.which("sh"), "POSIX shell fixture")
    def test_failed_cd_and_shell_startup_do_not_borrow_project_permissions(self):
        late = self.copy / "created-later"
        cd_failure = self.run_shell(f"cd {shlex.quote(str(late))} && cat notes.txt")
        self.assertNotEqual(cd_failure.returncode, 0)
        late.mkdir()
        (late / "notes.txt").write_text("never read")
        startup = self.agent_dir / "startup.sh"
        startup.write_text("echo 'private launcher message' >&2\nexit 1\n")
        unexecuted = self.run_shell(f"cd {shlex.quote(str(self.copy))} && python3 tools/run.py",
                                    ("bash", "-c"), BASH_ENV=str(startup))
        self.assertEqual(unexecuted.stdout, "private launcher message\n")
        self.assertEqual(unexecuted.returncode, 1)
        self.scan([self.copy])
        for program in ("cat", "python3"):
            meta, ev = self.events()[program]
            self.assertEqual(meta["files"], [])
            self.assertIsNone(ev["command_input"])
            self.assertIsNone(ev["command_output"])
            self.assertNotIn("private launcher message", json.dumps(ev))

    def test_partial_results_and_private_operands_cannot_promote_a_cd(self):
        cmd = f"cd {self.copy} && "
        (self.copy / "linked.txt").symlink_to(self.agent_dir / "private-notes.txt")
        for argv in (f"cat {self.agent_dir / 'private-notes.txt'}", "head linked.txt",
                     f"git -C{self.agent_dir} status", f"rg token --file={self.agent_dir / 'private-notes.txt'}"):
            self.command(cmd + argv, self.agent_dir, "private file data", 0)
        possible_error = f'Traceback (most recent call last):\n  File "{self.copy}/tools/run.py", line 1\nValueError\n'
        self.command(cmd + "python3 tools/run.py", self.agent_dir, possible_error, 1, output_truncated=True)
        self.command(cmd + "wc -l notes.txt", self.agent_dir, None, 1)
        self.scan([self.copy])
        results = self.events()
        self.assertEqual(len(results), 6)
        for program, (meta, ev) in results.items():
            with self.subTest(program=program):
                self.assertEqual(meta["files"], [])
                self.assertIsNone(ev["command_output"])
                self.assertIsNone(ev["command_input"])

    def test_ambiguous_shell_result_keeps_the_launchers_policy(self):
        self.command(f"cd {self.copy / 'tools'} && custom-reader run.py", self.copy, "opaque error", 1)
        self.command(f"cd {self.copy} && custom-exporter notes.txt", self.shared, "private parent result", 1)
        self.scan([self.copy])
        _, inside = self.events()["custom-reader"]
        self.assertEqual((inside["command_output"], inside["exit_code"], inside["files"]), ("opaque error", 1, []))
        _, outside = self.events()["custom-exporter"]
        self.assertIsNone(outside["command_output"])
        self.assertIsNone(outside["command_input"])
        self.assertEqual(outside["files"], [])

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
