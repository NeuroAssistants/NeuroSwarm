"""Command labels and failed-test counts across capture, ingestion and Live."""
import shlex
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "agent"))

import activity_inspector as inspector
import activity_shipper as shipper
import event_feed
import needs_attention
import remote_activity
from db import Database


CASES = (
    ("sed -n '1p' tests/test_parser.py", "sed", "Read a file"),
    ("rg pytest tests", "rg", "Search files"),
    ("python -m pytest", "python", "Run tests"),
    ("python -m unittest", "python", "Run tests"),
)


class CommandClassificationTests(unittest.TestCase):
    def test_labels_and_dashboard_counts_before_and_after_cd(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "test project"
            project.mkdir()
            stamp = datetime.now(timezone.utc).isoformat()
            for prefix in ("", f"cd {shlex.quote(str(project))} && "):
                with self.subTest(prefix=prefix), closing(Database(":memory:")) as db:
                    sessions = []
                    for index, (cmd, program, expected) in enumerate(CASES):
                        recorded = prefix + cmd
                        self.assertEqual(inspector.command_kind(recorded), expected)
                        with patch.object(shipper, "_CLASSIFIER_CORE", None):
                            self.assertEqual(shipper.command_kind(recorded), expected)
                        # Simulate an old observer mislabelling argument mentions.
                        # A failing read/search must not generate a failed-test item.
                        step = {"tool": "exec_command", "category": "shell", "label": "Run tests",
                                "program": program, "command_input": recorded, "exit_code": 1,
                                "status": "failed", "time": stamp}
                        sessions.append({"session_id": f"codex:case-{index}", "harness": "codex",
                                         "agent_name": "qa", "workspace": str(project),
                                         "steps": [step], "capture_steps": [step]})
                    result = remote_activity.ingest_remote_activity(db, {
                        "host_id": "classification-host", "activity_enabled": True,
                        "activity_roots": [str(project)], "sessions": sessions})
                    self.assertEqual(result["steps_persisted"], 4)
                    records = event_feed.feed(db)["records"]
                    labels = {row["details"]["session"]: row["title"].partition(" · ")[0] for row in records}
                    self.assertEqual(labels, {f"codex:case-{i}": case[2] for i, case in enumerate(CASES)})
                    dashboard = needs_attention.build_needs_attention(db, 1)
                    self.assertEqual(dashboard["counts"]["failed_test"], 2)
                    self.assertEqual({item["session"] for item in dashboard["items"]},
                                     {"codex:case-2", "codex:case-3"})

    def test_runner_arguments_and_shell_boundaries(self):
        for command in ("pytest -q", "python3.12 -I -X dev -m pytest",
                        "CI=1 /usr/bin/python3 -m unittest discover", "npm run test", "go test ./..."):
            with self.subTest(command=command):
                self.assertEqual(inspector.command_kind(command), "Run tests")
        for command in ("rg 'npm test' reports", "rg x | grep pytest", "echo ok && pytest -q",
                        "python tests/test_parser.py -m pytest", 'python -c "import pytest"',
                        "python -m pytest_helper", "python -m http.server pytest", "npm run test-report"):
            with self.subTest(command=command):
                self.assertNotEqual(inspector.command_kind(command), "Run tests")

    def test_historical_metadata_and_failed_cd(self):
        self.assertEqual(inspector.recorded_command_kind("Run tests", "rg", ""), "Search files")
        self.assertEqual(inspector.recorded_command_kind("Run tests", "python3", ""), "Run tests")
        self.assertEqual(inspector.recorded_command_kind("Shell command", "pytest", "cd gone && pytest", "not_recorded"),
                         "Shell command")
