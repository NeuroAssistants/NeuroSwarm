"""Verify native execution and confirmed edits through the observer and Live APIs."""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import time

try:
    from .test_capture_incremental import append, stamp
    from .test_remote_observer_isolation import OBSERVER_SCAN
    from .test_security import ROOT, ServerHarness
except ImportError:
    from test_capture_incremental import append, stamp
    from test_remote_observer_isolation import OBSERVER_SCAN
    from test_security import ROOT, ServerHarness


POWERSHELL = os.environ.get("NEUROSWARM_TEST_POWERSHELL") or shutil.which("powershell.exe") or shutil.which("pwsh")
HOST = "native-live-qa"
PUBLIC_OUTPUT = "verified workstation output"
PROTECTED_OUTPUT = "fixture outside the sharing contract"


class NativeLiveEvidenceTests(ServerHarness):
    def record_workspace(self, workspace, rollout, *, use_uri: bool):
        workspace.mkdir(parents=True)
        target = workspace / "src" / "changed file.txt"
        target.parent.mkdir()
        private = workspace / ".env"
        private.write_text(PROTECTED_OUTPUT, encoding="utf-8")
        if POWERSHELL:
            command = [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command",
                       "Set-Content -LiteralPath 'src/changed file.txt' -Value 'verified workstation output'; "
                       "Get-Content -LiteralPath 'src/changed file.txt'"]
            private_command = [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command",
                               "Get-Content -LiteralPath '.env'"]
        else:
            command = [sys.executable, "-c",
                       "from pathlib import Path; p = Path('src/changed file.txt'); "
                       "p.write_text('verified workstation output'); print(p.read_text())"]
            private_command = [sys.executable, "-c", "from pathlib import Path; print(Path('.env').read_text())"]

        cwd = workspace.as_uri() if use_uri else str(workspace)
        filepath = target.as_uri() if use_uri else str(target)
        self.assertTrue(target.is_absolute())
        execution = subprocess.run(command, cwd=workspace, check=True, capture_output=True, text=True, timeout=10)
        protected = subprocess.run(private_command, cwd=workspace, check=True, capture_output=True, text=True, timeout=10)
        self.assertEqual(execution.stdout.strip(), PUBLIC_OUTPUT)
        self.assertEqual(protected.stdout.strip(), PROTECTED_OUTPUT)

        def record(item, number):
            return {"timestamp": stamp(number), "payload": {"type": "item_completed", "item": item}}

        append(rollout, [
            record({"type": "FileChange", "id": "edit-1", "status": "completed", "cwd": cwd,
                    "changes": {filepath: {"type": "update", "unified_diff": "+ actual edit"}}}, 0),
            record({"type": "CommandExecution", "id": "command-1", "cwd": cwd, "command": command,
                    "parsed_cmd": [{"type": "read", "cmd": "read changed file", "path": filepath}],
                    "aggregated_output": execution.stdout, "exit_code": execution.returncode}, 1),
            record({"type": "CommandExecution", "id": "command-2", "cwd": cwd, "command": private_command,
                    "parsed_cmd": [{"type": "read", "cmd": "read configuration", "path": str(private)}],
                    "aggregated_output": protected.stdout, "exit_code": protected.returncode}, 2),
        ])
        with closing(sqlite3.connect(rollout.parent / "state_5.sqlite")) as db, db:
            db.execute("""CREATE TABLE threads (
                       id TEXT PRIMARY KEY, cwd TEXT, model TEXT, tokens_used INT,
                       updated_at INT, rollout_path TEXT, model_provider TEXT)""")
            db.execute("INSERT INTO threads VALUES ('qa-session', ?, 'gpt-x', 1, ?, ?, 'openai')",
                       (str(workspace), int(time.time()), str(rollout)))

    def run_observer(self, root, *, use_uri):
        workspace = root / "project with spaces"
        rollout = root / "profile/.codex/rollout.jsonl"
        self.record_workspace(workspace, rollout, use_uri=use_uri)
        cfg = {"host": HOST, "token": self.token()["token"], "server": f"http://127.0.0.1:{self.port}",
               "home": str(root / "profile"), "state": str(root / "state"),
               "workspace": str(workspace), "drop_ack": False}
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("SWARMCONTROL_") and key != "CODEX_HOME"}
        env.update(PYTHONPATH=str(ROOT / "agent"),
                   SWARMCONTROL_SHARE_COMMANDS="1", SWARMCONTROL_SHARE_COMMAND_OUTPUT="1")
        observer = subprocess.run([sys.executable, "-c", OBSERVER_SCAN], cwd=root, input=json.dumps(cfg),
                                  env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(observer.returncode, 0, observer.stderr)
        self.assertEqual(json.loads(observer.stdout)["steps_persisted"], 3)

    def assert_live_evidence(self, *, use_uri):
        self.assertEqual(self.login()[0], 200)
        self.run_observer(Path(self.tmp.name), use_uri=use_uri)
        status, feed, _ = self.req("GET", "/api/v1/live-records")
        self.assertEqual(status, 200)
        details = []
        for event in feed["records"]:
            if event["host_id"] == HOST and event["source"] == "observed_step":
                status, detail, _ = self.req("GET", f"/api/v1/events/{event['id']}/evidence")
                self.assertEqual(status, 200)
                self.assertEqual(detail["session"], "codex:qa-session")
                self.assertNotIn(PROTECTED_OUTPUT, json.dumps(detail))
                self.assertNotIn(".env", json.dumps(detail))
                details.append(detail)
        self.assertEqual(len(details), 3)
        executed = [detail for detail in details if PUBLIC_OUTPUT in str(detail.get("command_output"))]
        self.assertEqual(len(executed), 1, details)
        self.assertEqual(executed[0]["exit_code"], 0)
        self.assertEqual([f.replace("\\", "/") for f in executed[0]["files"]], ["src/changed file.txt"])
        edits = [detail for detail in details if detail["record"]["work"]["action"] == "file_edit"]
        self.assertEqual(len(edits), 1, details)
        self.assertEqual([f.replace("\\", "/") for f in edits[0]["files"]], ["src/changed file.txt"])

    def test_native_paths_arrive_with_output_and_confirmed_edit(self):
        self.assert_live_evidence(use_uri=False)

    def test_file_uris_arrive_with_output_and_confirmed_edit(self):
        self.assert_live_evidence(use_uri=True)
