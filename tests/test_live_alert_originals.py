"""Exercise recorded alert links through the running console after the inputs change."""
import json
from pathlib import Path
import subprocess
import unittest

import browser_cdp
import test_needs_attention as qa


class LiveAlertOriginals(unittest.TestCase):
    setUp = qa.NeedsAttentionAPITests.setUp
    tearDown = qa.NeedsAttentionAPITests.tearDown

    def test_two_alerts_one_session_survive_reload(self):
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
                              files=[name], command_input=command, command_output=run.stderr,
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
        st, _, attention = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(st, 200)
        items = attention["items"]
        self.assertCountEqual([item["category"] for item in items], ["failed_test", "quota_exhausted"])
        browser = browser_cdp.Browser(browser_cdp.find_browser())
        self.addCleanup(browser.close)
        page = browser.new_page(1440, 900)
        page.goto(self.srv.base_url + "/")
        page.settled("#login-form button[type=submit]", 15)
        page.type("#username", qa.ORG_A[0])
        page.type("#password", qa.ORG_A[1])
        page.click("#login-form button[type=submit]")
        page.wait("!document.querySelector('#app-view').hidden && getComputedStyle(document.querySelector('#app-view')).display !== 'none'")
        for item in items:
            st, _, original = self.admin.json("GET", f"/api/v1/events/{item['event_id']}/evidence")
            self.assertEqual(st, 200)
            name, marker, code = expected.pop(original["command_input"])
            self.assertTrue(any(Path(path).name == name for path in item["files"]), item)
            self.assertEqual(original["exit_code"], code)
            url = self.srv.base_url + item["link"]
            for _ in range(2):
                page.goto(url)
                page.wait("document.querySelector('#detail-evidence-slot .ev-cmd-out')?.textContent.includes(" +
                          json.dumps(marker) + ")")
                self.assertNotIn("changed after capture", page.eval("document.querySelector('#detail-evidence-slot').textContent"))
        self.assertFalse(expected)
