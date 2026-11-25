"""A running Live console follows command evidence added after its event arrived."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlencode

from test_capture_incremental import append, stamp

import browser_cdp  # noqa: E402
from activity_shipper import collect_incremental_activity  # noqa: E402
from product_qa.test_acceptance_blackbox import HttpClient, SpawnedConsole  # noqa: E402


class LiveLateEvidenceBrowserTests(unittest.TestCase):
    def test_two_commands_get_their_own_late_output_in_live_and_history(self):
        if os.environ.get("SWARMCONTROL_BROWSER_TESTS", "").lower() == "skip":
            self.skipTest("SWARMCONTROL_BROWSER_TESTS=skip")
        binary = browser_cdp.find_browser()
        self.assertIsNotNone(binary, "Set SWARMCONTROL_CHROMIUM or run deploy/fetch_test_browser.py")

        tmp = tempfile.TemporaryDirectory(prefix="ns-live-late-qa-")
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        workspace = root / "shared-project"
        workspace.mkdir()
        home = root / "observer-home"
        journal = home / ".claude/projects/shared-project/late-results.jsonl"
        srv = SpawnedConsole(root / "server")
        self.addCleanup(srv.stop)
        admin = HttpClient(srv.base_url)
        user, password = "bootstrap_admin", "BootstrapPass!2026#QA"
        status, _, _ = admin.json("POST", "/api/v1/auth/login", {"username": user, "password": password})
        self.assertEqual(status, 200)
        status, _, token = admin.json("POST", "/api/v1/tokens", {"name": "late-results", "scope": "ingest"})
        self.assertEqual(status, 201)

        calls, results, commands = [], [], []
        for name, content in (("first", "first tail result\n"), ("second", "")):
            filename = f"{name}.log"
            (workspace / filename).write_text(content, encoding="utf-8")
            argv = ["tail", "-n", "1", filename]
            command = shlex.join(argv)
            commands.append(command)
            completed = subprocess.run(argv, cwd=workspace, check=True, capture_output=True, text=True)
            calls.append({"type": "tool_use", "name": "Bash", "id": name, "input": {"command": command}})
            results.append({"type": "user", "cwd": str(workspace), "timestamp": stamp(1),
                            "toolUseResult": {"exitCode": completed.returncode},
                            "message": {"content": [
                                {"type": "tool_result", "tool_use_id": name, "content": completed.stdout},
                            ]}})
        append(journal, [{"type": "assistant", "cwd": str(workspace), "timestamp": stamp(),
                          "message": {"content": calls}}])

        def scan(offsets=None):
            with patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(home / ".claude"),
                                         "SWARMCONTROL_SHARE_COMMANDS": "1",
                                         "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "1"}):
                payload, next_offsets, backlog = collect_incremental_activity(
                    [str(workspace)], host_id="late-host", home_dir=home, offsets=offsets, use_core=True)
            self.assertFalse(backlog)
            status, _, result = admin.json("POST", "/api/v1/ingest/activity", payload,
                                           headers={"Authorization": f"Bearer {token['token']}"})
            self.assertEqual(status, 200, result)
            return next_offsets

        offsets = scan()
        status, _, feed = admin.json("GET", "/api/v1/event-feed")
        self.assertEqual(status, 200)
        rows = [row for row in feed["records"] if row["source"] == "observed_step"]
        self.assertEqual(len(rows), 2)
        records = {}
        for row in rows:
            status, _, detail = admin.json("GET", f"/api/v1/events/{row['id']}/evidence")
            self.assertEqual(status, 200)
            self.assertIsNone(detail["command_output"])
            records[detail["command_input"]] = row
        self.assertCountEqual(records, commands)
        first, second = (records[command] for command in commands)
        first_selector = f"#rows tr[data-key={json.dumps(first['key'])}]"

        browser = browser_cdp.Browser(binary)
        self.addCleanup(browser.close)
        page = browser.new_page(1440, 900)
        page.goto(srv.base_url + "/")
        page.settled("#login-form button[type=submit]", 15)
        page.type("#username", user)
        page.type("#password", password)
        page.click("#login-form button[type=submit]")
        page.wait("!document.querySelector('#app-view').hidden && getComputedStyle(document.querySelector('#app-view')).display !== 'none'")

        def live_link(row):
            return srv.base_url + "/live?" + urlencode({"event": row["key"]})

        page.goto(live_link(first))
        page.wait(f"document.querySelector({json.dumps(first_selector)})?.getAttribute('aria-selected') === 'true'")
        page.wait("document.querySelector('#detail-evidence-slot')?.textContent.includes('first.log')")
        page.click("#detail-quick [data-act='open-popup']")
        page.wait("document.querySelector('#event-dialog-evidence')?.textContent.includes('first.log')")

        # Results arrive in reverse order in a second capture. The journal updates
        # evidence in place, so there is no new event row to prompt a re-render.
        append(journal, reversed(results))
        scan(offsets)
        for row, expected in ((first, "first tail result\n"), (second, "")):
            status, _, detail = admin.json("GET", f"/api/v1/events/{row['id']}/evidence")
            self.assertEqual((status, detail["command_output"], detail["exit_code"]), (200, expected, 0))

        for slot_id in ("event-dialog-evidence", "detail-evidence-slot"):
            slot = f"document.getElementById({slot_id!r})"
            page.wait(f"{slot}?.querySelector('.ev-cmd-out')?.textContent.includes('first tail result')",
                      12, what=f"late result in {slot_id} without reloading")
            self.assertNotIn("second.log", page.eval(f"{slot}.textContent"))
        self.assertTrue(page.eval(f"document.querySelector({json.dumps(first_selector)}).getAttribute('aria-selected') === 'true'"))
        self.assertTrue(page.eval("document.querySelector('#event-dialog').open"))
        (workspace / "second.log").write_text("later file contents\n", encoding="utf-8")
        page.goto(live_link(second))
        page.wait("document.querySelector('#detail-evidence-slot .ev-cmd-out')?.textContent.includes('captured output is empty')")
        archived = page.eval("document.querySelector('#detail-evidence-slot').textContent")
        self.assertIn("second.log", archived)
        self.assertNotIn("first tail result", archived)
        self.assertNotIn("later file contents", archived)
