"""Real shell results replayed through the Codex reader and activity journal."""
from __future__ import annotations

import shlex
import shutil
import subprocess
import unittest

import test_step_scope_evidence as fixture
import remote_activity


class LiveCdFailureTests(unittest.TestCase):
    setUp = fixture.StepScopeTests.setUp
    scan = fixture.StepScopeTests.scan
    command = fixture.StepScopeTests.command
    events = fixture.StepScopeTests.events

    def run_compound(self, destination, *argv):
        command = f"cd {shlex.quote(str(destination))} && {shlex.join(argv)}"
        run = subprocess.run(
            ["bash", "--noprofile", "--norc", "-c", command],
            cwd=self.agent_dir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=10,
        )
        self.command(command, self.agent_dir, run.stdout, run.returncode)
        return run

    def test_a_failed_script_after_successful_cd_keeps_its_traceback(self):
        (self.copy / "tools/run.py").write_text("raise RuntimeError('QA script reached')\n")
        run = self.run_compound(self.copy, "python3", "tools/run.py")
        self.assertEqual(run.returncode, 1)
        self.assertIn("RuntimeError: QA script reached", run.stdout)
        self.scan([self.copy])
        _, evidence = self.events()["python3"]
        self.assertIn("RuntimeError: QA script reached", evidence["command_output"] or "")
        self.assertEqual(evidence["files"], ["product-feature/tools/run.py"])
        self.assertEqual(evidence["exit_code"], run.returncode)

    def test_a_non_python_failure_after_successful_cd_keeps_its_result(self):
        if not shutil.which("grep"):
            self.skipTest("grep is unavailable")
        run = self.run_compound(self.copy, "grep", "-c", "QA-no-match", "notes.txt")
        self.assertEqual((run.returncode, run.stdout), (1, "0\n"))
        self.scan([self.copy])
        _, evidence = self.events()["grep"]
        self.assertEqual(evidence["command_output"], "0\n")
        self.assertEqual(evidence["exit_code"], 1)

    def test_a_failed_cd_never_attributes_a_script_or_its_output(self):
        target = self.copy / "qa-created-after-execution"
        run = self.run_compound(target, "python3", "tools/run.py")
        self.assertEqual(run.returncode, 1)
        self.assertIn(target.name, run.stdout)
        # The collector runs later. Existence now cannot prove the earlier cd worked.
        (target / "tools").mkdir(parents=True)
        (target / "tools/run.py").write_text("print('not executed')\n")
        self.scan([self.copy])
        _, evidence = self.events()["python3"]
        self.assertEqual(evidence["files"], [])
        self.assertIsNone(evidence["command_input"])
        self.assertIsNone(evidence["command_output"])


    def test_claude_does_not_infer_scope_from_a_directory_created_after_cd(self):
        target = self.copy / "qa-claude-created-later"
        command = f"cd {shlex.quote(str(target))} && cat notes.txt"
        run = subprocess.run(["sh", "-c", command], cwd=self.agent_dir, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn(target.name, run.stdout)
        target.mkdir()
        (target / "notes.txt").write_text("not read\n")

        log = self.home / ".claude/projects/agent-one/failed-cd.jsonl"
        fixture.append(log, [
            {"type": "assistant", "cwd": str(self.agent_dir), "timestamp": fixture.stamp(),
             "message": {"content": [
                 {"type": "tool_use", "id": "call-cd", "name": "Bash", "input": {"command": command}},
             ]}},
            {"type": "user", "cwd": str(self.agent_dir), "timestamp": fixture.stamp(1),
             "toolUseResult": {"exitCode": run.returncode},
             "message": {"content": [
                 {"type": "tool_result", "tool_use_id": "call-cd", "is_error": True, "content": run.stdout},
             ]}},
        ])
        self.scan([self.copy])
        _, evidence = self.events()["cat"]
        self.assertEqual(evidence["files"], [])
        self.assertIsNone(evidence["command_input"])
        self.assertIsNone(evidence["command_output"])


    def test_remote_journal_does_not_use_the_intended_directory_as_scope(self):
        target = self.copy / "qa-remote-created-later"
        command = f"cd {shlex.quote(str(target))} && cat notes.txt"
        run = subprocess.run(["sh", "-c", command], cwd=self.agent_dir, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn(target.name, run.stdout)
        target.mkdir()
        stamp = fixture.stamp()
        step = {
            "tool": "exec_command", "category": "shell", "program": "cat",
            "status": "failed", "time": stamp, "src": "record:221:0",
            "command_input": command, "command_output": run.stdout, "exit_code": run.returncode,
        }
        remote_activity.ingest_remote_activity(self.dbo, {
            "host_id": "remote-qa", "activity_enabled": True, "activity_roots": [str(self.copy)],
            "sessions": [
                {"session_id": "codex:remote-failed-cd", "agent_name": "qa", "harness": "codex",
                 "workspace": str(self.agent_dir), "capture_steps": [step]},
            ],
        })
        _, evidence = self.events()["cat"]
        self.assertEqual(evidence["files"], [])
        self.assertIsNone(evidence["command_input"])
        self.assertIsNone(evidence["command_output"])


class LiveHttpResultTests(unittest.TestCase):
    setUp = fixture.StepScopeTests.setUp
    scan = fixture.StepScopeTests.scan
    command = fixture.StepScopeTests.command
    events = fixture.StepScopeTests.events

    def test_curl_process_exit_does_not_override_http_status(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from threading import Thread

        if not shutil.which("curl"):
            self.skipTest("curl is unavailable")

        class RejectedRequest(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(401)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"QA response excerpt\n")

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), RejectedRequest)
        self.addCleanup(server.server_close)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(worker.join)
        self.addCleanup(server.shutdown)

        url = f"http://127.0.0.1:{server.server_port}/demo"
        argv = ["curl", "-q", "--noproxy", "127.0.0.1", "-si", url]
        result = subprocess.run(argv, cwd=self.copy, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertIn("401", result.stdout)
        self.command(shlex.join(argv), self.copy, result.stdout, result.returncode)
        self.scan([self.copy])
        _, evidence = self.events()["curl"]
        self.assertEqual(evidence["exit_code"], 0)
        self.assertRegex(evidence["command_output"] or "", r"HTTP/\S+ 401\b")
        self.assertIn("QA response excerpt", evidence["command_output"])
