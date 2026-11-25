"""Follow original alert evidence after file changes and a backup restore."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import browser_cdp
import test_needs_attention as qa


class LiveAlertOriginals(unittest.TestCase):
    setUp = qa.NeedsAttentionAPITests.setUp
    tearDown = qa.NeedsAttentionAPITests.tearDown

    def test_two_alerts_one_session_survive_reload_and_restore(self):
        workspace = Path(self.tmp.name) / "project"
        workspace.mkdir()
        scripts = [
            ("test_first.py", "python3", ["python3", "-m", "unittest", "test_first"],
             "import unittest\nclass Example(unittest.TestCase):\n def test_first(self): self.fail('first failure')\n", "first failure"),
            ("second.sh", "sh", ["sh", "second.sh"],
             "echo 'HTTP 429 quota exceeded for second request' >&2\nexit 7\n", "second request"),
        ]
        steps = []
        expected = {}
        for index, (name, program, argv, contents, marker) in enumerate(scripts):
            path = workspace / name
            path.write_text(contents)
            run = subprocess.run(argv, cwd=workspace, text=True, capture_output=True)
            self.assertNotEqual(run.returncode, 0)
            command = " ".join(argv)
            expected[command] = (name, marker, run.returncode)
            steps.append(dict(tool="exec_command", category="shell", label="Run command",
                              program=program, status="failed", time=qa._iso_offset(20-index),
                              files=[name], command_input=command, command_output=run.stderr + '\nAPI_KEY=backup-test-private-value\n',
                              exit_code=run.returncode))
            path.write_text("changed after capture")
        st, _, token = self.admin.json("POST", "/api/v1/tokens", {"name":"alert-originals","scope":"ingest"})
        self.assertEqual(st, 201)
        session = dict(session_id="codex:alert-originals", harness="codex", agent_name="qa", workspace=str(workspace),
                       steps=steps, capture_steps=steps)
        st, _, body = self.admin.json("POST", "/api/v1/ingest/activity",
                                      dict(host_id="qa-host", activity_enabled=True, activity_roots=[str(workspace)],
                                           sessions=[session]), headers={"Authorization":"Bearer "+token["token"]})
        self.assertEqual(st, 200, body)
        browser = browser_cdp.Browser(browser_cdp.find_browser())
        self.addCleanup(browser.close)
        original = self.alerts_and_evidence()
        self.assertEqual(len(original), 2)
        self.assertEqual({entry["category"] for entry in original.values()}, {"failed_test", "quota_exhausted"})
        self.assertEqual(len({entry["event_id"] for entry in original.values()}), 2)
        for entry in original.values():
            name, marker, exit_code = expected[entry["command_input"]]
            self.assertEqual(entry["files"], [name])
            self.assertEqual(entry["exit_code"], exit_code)
            self.assertIn(marker, entry["command_output"])
            self.assertNotIn("backup-test-private-value", entry["command_output"])

        self.check_live_links(browser, original, expected)

        with tempfile.TemporaryDirectory(prefix="ns-alerts-restore-") as backup_tmp:
            backup_dir = Path(backup_tmp)
            self.srv.stop()
            snapshot = Path(self.run_backup("snapshot", Path(self.tmp.name), backup_dir / "backups"))
            restored_dir = backup_dir / "restored"
            self.run_backup("restore", snapshot, restored_dir)
            restored = qa.SpawnedConsole(restored_dir)
            try:
                self.admin = qa.HttpClient(restored.base_url)
                st, _, _ = self.admin.json("POST", "/api/v1/auth/login",
                                           {"username": qa.ORG_A[0], "password": qa.ORG_A[1]})
                self.assertEqual(st, 200)
                after_restore = self.alerts_and_evidence()
                self.assertEqual(after_restore, original)
                self.check_live_links(browser, after_restore, expected, base_url=restored.base_url)
            finally:
                restored.stop()

    def run_backup(self, action, source, dest):
        script = Path(__file__).resolve().parents[1] / "deploy/backup.py"
        result = subprocess.run([sys.executable, str(script), action, str(source), str(dest)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def alerts_and_evidence(self):
        st, _, attention = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(st, 200)
        entries = {}
        for item in attention["items"]:
            st, _, evidence = self.admin.json("GET", f"/api/v1/events/{item['event_id']}/evidence")
            self.assertEqual(st, 200)
            self.assertEqual(evidence["event_id"], item["event_id"])
            entries[item["id"]] = {
                "category": item["category"], "link": item["link"], "event_id": item["event_id"],
                "files": evidence["files"], "command_input": evidence["command_input"],
                "command_output": evidence["command_output"], "exit_code": evidence["exit_code"],
            }
        return entries

    def check_live_links(self, browser, entries, expected, base_url=None):
        base_url = base_url or self.srv.base_url
        page = browser.new_page(1440, 900)
        try:
            page.goto(base_url + "/")
            page.settled("#login-form button[type=submit]", 15)
            page.type("#username", qa.ORG_A[0])
            page.type("#password", qa.ORG_A[1])
            page.click("#login-form button[type=submit]")
            page.wait("!document.querySelector('#app-view').hidden && getComputedStyle(document.querySelector('#app-view')).display !== 'none'")
            for entry in entries.values():
                _, marker, _ = expected[entry["command_input"]]
                page.goto(base_url + entry["link"])
                page.wait("document.querySelector('#detail-evidence-slot .ev-cmd-out')?.textContent.includes(" +
                          json.dumps(marker) + ")")
                shown = page.eval("document.querySelector('#detail-evidence-slot').textContent")
                self.assertNotIn("changed after capture", shown)
                self.assertNotIn("backup-test-private-value", shown)
        finally:
            page.close()
