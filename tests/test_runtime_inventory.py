"""Regression tests for inventory evidence and independently retained work reports."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "agent"), str(ROOT / "backend")]
import detector
from db import Database
from validation import sanitize_heartbeat


class InventoryEvidenceTests(unittest.TestCase):
    def test_managed_version_requires_an_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            exe = root / "claude/linux-x64/2.1.3/bin/claude"
            exe.parent.mkdir(parents=True)
            exe.write_text("")
            exe.chmod(0o600)
            self.assertNotIn("claude-code", detector._managed_installations(root))
            exe.chmod(0o700)
            self.assertEqual(detector._managed_installations(root)["claude-code"],
                             ["managed:claude/linux-x64/2.1.3/bin/claude"])

    def test_directory_alone_is_unconfirmed(self):
        with tempfile.TemporaryDirectory() as tmp:
            spec = {"id":"test", "name":"Test", "runtime_keys":[], "dirs":[tmp], "bins":[],
                    "proc_names":["sample"], "systemd_prefixes":[]}
            with patch.object(detector,"HARNESS_SPECS",[spec]), patch.object(detector,"_list_safe_processes",return_value=[]), patch.object(detector,"_list_running_systemd_units",return_value=[]):
                result = detector.collect_host_snapshot()["harnesses"]
                self.assertEqual(result[0]["status"], "configured")

    def test_only_workspace_roots_survive_collection_and_ingestion(self):
        root = Path("/home/example/OpenBot")
        agent = "Agents/agent-00000000-0000-0000-0000-000000000001"
        valid = "Shared/sample-team"
        self.assertEqual(detector._workspace_label(root / agent / "private", root), agent)
        self.assertEqual(detector._workspace_label(root / valid / "frontend", root), valid)
        self.assertIsNone(detector._workspace_label(Path("/other/users"), root))
        self.assertIsNone(detector._workspace_label(root / agent / ".." / "other", root))
        for sample,expected in [(valid,valid), (agent,agent), ("/private",None), ("other","other"), ("projects/api","projects/api"),
                                ("../escape",None), ("a/b/c/d/e",None), (None,None)]:
            cleaned = sanitize_heartbeat({"host_id":"fixture","processes":[{"workspace":sample}]})
            self.assertEqual(cleaned["processes"][0].get("workspace"),expected)

    def test_reports_outlive_unrelated_feed_traffic(self):
        db = Database(":memory:")
        try:
            for i, event_type in enumerate(["plan","work_done"] + ["info"]*65):
                db.execute("INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
                           ("host","runtime","agent",event_type,"INFO","sample",json.dumps({"task_id":"id","method":"checked","files":["file.txt"],"unused":"ignore"}),i))
            rows = db.recent_work_reports()
            self.assertEqual([r["event_type"] for r in rows],["work_done","plan"])
            self.assertEqual(rows[0]["metadata"],{"task_id":"id","method":"checked","files":["file.txt"]})
        finally:
            db.close()


class WorkspaceHistoryTests(unittest.TestCase):
    def test_first_read_is_a_baseline_and_changes_use_only_metadata(self):
        from workspace_activity import WorkspaceActivity
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / "frontend"
            folder.mkdir()
            file = folder / "app.js"
            file.write_text("private fixture contents")
            sampler = WorkspaceActivity(root)
            baseline = sampler.sample()
            self.assertEqual(baseline["changes"], [])
            self.assertNotIn("private fixture contents", str(baseline))
            file.write_text("changed fixture")
            other = folder / "styles.css"
            other.touch()
            changes = sampler.sample()["changes"]
            self.assertEqual({(c["path"],c["change"]) for c in changes},
                             {("frontend/app.js","updated"),("frontend/styles.css","appeared")})
            other.unlink()
            after = sampler.sample()
            self.assertEqual(after["changes"][0]["change"],"missing")
            self.assertEqual(after["since"],baseline["since"])
            self.assertEqual(after["folders"][0]["total"],1)
