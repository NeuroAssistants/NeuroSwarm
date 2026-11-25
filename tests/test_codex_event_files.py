"""Run with python3 -m unittest discover -s tests -p test_codex_event_files.py -v."""
import json
import os
import shutil
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

try:
    from .test_capture_incremental import CaptureHarness, append, stamp
except ImportError:
    from test_capture_incremental import CaptureHarness, append, stamp

import activity_inspector as inspector
import event_evidence
import event_feed
import live_history
from db import Database


class CodexEventFilesTests(CaptureHarness):
    def setUp(self):
        super().setUp()
        self.log = self.codex(0)
        self.root = self.roots["codex-team"]
        self.when = stamp()
        env = patch.dict(os.environ, {"CODEX_HOME": str(self.home / ".codex"), "SWARMCONTROL_SHARE_COMMANDS": "0",
                                      "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "0"})
        env.start()
        self.addCleanup(env.stop)

    def completed(self, **item):
        append(self.log, [{"timestamp": self.when, "payload": {"type": "item_completed", "item": item}}])

    def details(self, db):
        return [event_evidence.detail(db, 1, row["id"]) for row in
                db.query_all("SELECT id FROM events WHERE event_type='observed_step' ORDER BY id")]

    @unittest.skipUnless(shutil.which("sh") and shutil.which("tail"), "requires POSIX sh and tail")
    def test_same_name_from_two_workdirs_keeps_each_real_result_in_history(self):
        expected = {}
        calls = []
        folders = ("north side", "south")
        for name in folders:
            cwd = self.root / name
            cwd.mkdir()
            (cwd / "run log.txt").write_text(f"old\n{name}\n")
            (cwd / "job.py").write_text(f"print('run {name}')")
            for argv, target in (([shutil.which("sh"), "-c", 'tail -n 1 -- "run log.txt"'], "run log.txt"),
                                 ([sys.executable, "-B", "job.py", "unused.py"], "job.py")):
                calls.append((argv, cwd, target))
        with ThreadPoolExecutor(max_workers=len(calls)) as pool:
            results = [pool.submit(subprocess.run, argv, cwd=cwd, text=True, capture_output=True, check=True, timeout=5)
                       for argv, cwd, _ in calls]
            for (argv, cwd, target), future in reversed(list(zip(calls, results))):
                result = future.result()
                expected[f"codex-team/{cwd.name}/{target}"] = result.stdout
                self.completed(type="CommandExecution", cwd=cwd.as_uri(), command=argv,
                               parsed_cmd=[{"type": "unknown"}], exit_code=result.returncode,
                               aggregated_output=result.stdout)
        cursor = event_feed.feed(self.dbo)["cursor"]
        with patch.dict(os.environ, {"SWARMCONTROL_SHARE_COMMANDS": "1", "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "1"}):
            self.assertEqual(self.scan()["inserted"], 4)
        fresh = event_feed.feed(self.dbo, cursor)["records"]
        self.assertEqual({tuple(row["details"]["files"]) for row in fresh}, {(f,) for f in expected})
        for name in folders:
            (self.root / name / "run log.txt").write_text("changed after capture")
            (self.root / name / "job.py").unlink()
        self.assertEqual(self.scan().get("inserted", 0), 0)
        reopened = Database(self.dbo.db_path)
        self.addCleanup(reopened.close)
        history = live_history.history(reopened, 1, {})["records"]
        self.assertEqual({r["id"]: r["work"]["files"] for r in history},
                         {r["id"]: r["details"]["files"] for r in fresh})
        for detail in self.details(reopened):
            path, = detail["files"]
            self.assertEqual(detail["command_output"], expected[path])
            self.assertEqual(detail["exit_code"], 0)
            self.assertTrue(detail["command_input"])
            self.assertEqual(detail["event_id"], next(r["id"] for r in fresh if path in r["details"]["files"]))

    def test_only_literal_file_operands_are_attached(self):
        cases = [
            (["tail", "-n20", "first", "second"], ["first", "second"]),
            (["tail", "--lines=+2", "--", "-odd.txt"], ["-odd.txt"]),
            (["python3.12", "-I", "-X", "dev", "--", "job.py", "argument.py"], ["job.py"]),
            (["python3", "-c", "print('example.py')"], []),
            (["python3", "-m", "lib", "looks_like_a_script.py"], []),
            (["python3", "-", "also_an_argument.py"], []),
            (["tail", "--pid", "123", "-"], []),
            (["sh", "-c", 'tail "$UNRESOLVED"'], []),
            (["sh", "-c", "cd another && tail ambiguous.log"], []),
            (["sh", "-c", "tail *.log"], []),
            (["sh", "-c", "echo tail referred.log"], []),
            (["tail", str(self.outside / "private.log"), ".env"], []),
        ]
        for argv, _ in cases:
            self.completed(type="CommandExecution", cwd=str(self.root), command=argv)
        self.scan()
        details = self.details(self.dbo)
        self.assertEqual(len(details), len(cases))
        for (argv, paths), detail in zip(cases, details):
            with self.subTest(argv=argv):
                self.assertEqual(detail["files"], ["codex-team/" + path for path in paths])
                self.assertIsNone(detail["command_input"])
                self.assertIsNone(detail["command_output"])
        self.assertEqual(details[3]["program"], "python3")
        self.assertIn("Run inline Python", details[3]["record"]["message"])
        self.assertIn("Run a Python module", details[4]["record"]["message"])
        self.assertIn("Run Python from standard input", details[5]["record"]["message"])
        self.assertEqual(inspector.command_kind("sed -n '/pytest/p' report.txt"), "Read a file")
        self.assertEqual(inspector.command_kind("python3 -m unittest -v"), "Run tests")

    def test_mixed_private_operands_never_publish_the_combined_output(self):
        self.completed(type="CommandExecution", cwd=str(self.root),
                       command=["tail", "shared.log", str(self.outside / "private.log")],
                       parsed_cmd=[{"type": "read", "path": "shared.log"}],
                       aggregated_output="private result", exit_code=0)
        with patch.dict(os.environ, {"SWARMCONTROL_SHARE_COMMANDS": "1", "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "1"}):
            self.scan()
        detail, = self.details(self.dbo)
        self.assertEqual(detail["files"], ["codex-team/shared.log"])
        self.assertIsNone(detail["command_input"])
        self.assertIsNone(detail["command_output"])
        self.assertEqual(detail["exit_code"], 0)
        self.assertNotIn("private.log", json.dumps(detail))

    def test_descriptor_directory_wins_and_an_unresolved_cd_cannot_borrow_it(self):
        self.completed(type="CommandExecution", cwd=str(self.root), command=["tail", "one.log"],
                       parsed_cmd=[{"type": "read", "path": "one.log", "cwd": str(self.root / "src")}])
        self.completed(type="CommandExecution", cwd=str(self.root), command=["sh", "-c", "cd unknown && tail one.log"],
                       parsed_cmd=[{"type": "read", "path": "one.log"}])
        self.scan()
        self.assertEqual([d["files"] for d in self.details(self.dbo)], [["codex-team/src/one.log"], []])

    def test_explicit_edit_and_write_use_the_call_directory(self):
        changes = {"app.py": {"type": "update", "unified_diff": "body stays private"}}
        sub = self.root / "src"
        self.completed(type="FileChange", id="patch-a", cwd=str(sub), changes=changes, status="completed")
        self.completed(type="DynamicToolCall", tool="tool_call", success=True, arguments={
            "name": "mcp__filesystem__edit_file", "arguments": {"path": "app.py", "workdir": str(self.root)}})
        self.completed(type="DynamicToolCall", tool="write_file", success=True, cwd=sub.as_uri(),
                       arguments={"file_path": "new.md", "content": "body stays private"})
        self.completed(type="DynamicToolCall", tool="write_file", success=False,
                       arguments={"path": "failed.md"})
        self.completed(type="DynamicToolCall", tool="Write", success=True, cwd=str(self.outside),
                       arguments={"file_path": "not_shared.md"})
        self.completed(type="DynamicToolCall", tool="edit", success=True, arguments={"file_path": ".env"})
        self.completed(type="DynamicToolCall", tool="edit_file", success=True,
                       arguments={"path": "preview.md", "dryRun": True})
        self.assertEqual(self.scan()["inserted"], 7)
        details = self.details(self.dbo)
        self.assertEqual([d["files"] for d in details], [
            ["codex-team/src/app.py"], ["codex-team/app.py"], ["codex-team/src/new.md"], [], [], [], ["codex-team/preview.md"]])
        self.assertEqual(details[3]["record"]["work"]["outcome"], "error")
        session, = inspector.collect_activity(self.scope)["sessions"]
        self.assertEqual(set(session["files_edited"]),
                         {str(sub / "app.py"), str(self.root / "app.py"), str(sub / "new.md")})
        for private in ("body stays private", "failed.md", "not_shared.md", ".env"):
            self.assertNotIn(private, json.dumps([session, details]))
