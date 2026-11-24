"""End-to-end headless Chromium tests for /live event popup, on-demand evidence,
files sidebar, dashboard clarity folds, token revoke UX, and org isolation."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))
QA_DIR = TESTS_DIR / "product_qa"
if str(QA_DIR) not in sys.path:
    sys.path.insert(0, str(QA_DIR))

import browser_cdp as bc
from test_acceptance_blackbox import HttpClient, SpawnedConsole

# Synthetic 1x1 blue RGBA PNG
SAMPLE_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGOwmPngPwAFbwKxEfU0EQAAAABJRU5ErkJggg=="
)
ORG_A = ("bootstrap_admin", "BootstrapPass!2026#QA")
ORG_B = ("orgb_evidence_user", "OrgBEvidencePass!2026", "Beta Evidence Org")


class LiveUxAndEvidenceBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chrome = bc.find_browser()
        cls.tmp = tempfile.TemporaryDirectory(prefix="ns-ux-evidence-")
        cls.srv = SpawnedConsole(Path(cls.tmp.name))
        cls.admin = HttpClient(cls.srv.base_url)
        st, _, _ = cls.admin.json("POST", "/api/v1/auth/login", {"username": ORG_A[0], "password": ORG_A[1]})
        assert st == 200
        st, _, tok = cls.admin.json("POST", "/api/v1/tokens", {"name": "ux-host-01", "scope": "ingest"})
        assert st == 201
        cls.ingest_token = tok["token"]

        now_iso = datetime.now(timezone.utc).isoformat()
        cls.xss_payload = '<script>window.__xss=1</script><img src=x onerror="window.__xss=2">'
        steps = [
            {
                "tool": "view_image",
                "category": "file_read",
                "label": "Inspect mockup screenshot",
                "status": "completed",
                "time": now_iso,
                "files": ["ui/tile.png"],
                "image_previews": [
                    {
                        "path": "ui/tile.png",
                        "mime_type": "image/png",
                        "data_base64": SAMPLE_PNG_B64,
                        "source": "tool_result",
                    }
                ],
            },
            {
                "tool": "exec_command",
                "category": "shell",
                "label": "Run pytest suite",
                "program": "pytest",
                "status": "failed",
                "time": now_iso,
                "command_input": "pytest -q tests/test_demo.py",
                "exit_code": 1,
                "command_output": f"FAILED test_demo.py\n{cls.xss_payload}\n" + ("x" * 6000),
            },
            {
                "tool": "edit_file",
                "category": "file_edit",
                "label": "Update demo handler",
                "status": "completed",
                "time": now_iso,
                "files": ["src/demo.py"],
                "text_previews": [
                    {
                        "path": "src/demo.py",
                        "text": f"def greet():\n    return {cls.xss_payload!r}\n",
                        "source": "workspace_snapshot",
                    }
                ],
            },
        ]
        payload = {
            "host_id": "ux-host-01",
            "activity_enabled": True,
            "activity_roots": ["/work/demo"],
            "sessions": [
                {
                    "session_id": "codex:ux-demo",
                    "harness": "codex",
                    "agent_name": "ux-agent",
                    "workspace": "/work/demo",
                    "steps": steps,
                    "capture_steps": steps,
                }
            ],
        }
        st, _, body = cls.admin.json(
            "POST",
            "/api/v1/ingest/activity",
            payload,
            headers={"Authorization": f"Bearer {cls.ingest_token}"},
        )
        assert st in (200, 201), body

        beta = HttpClient(cls.srv.base_url)
        st, _, reg = beta.json(
            "POST",
            "/api/v1/auth/register",
            {"username": ORG_B[0], "password": ORG_B[1], "organization": ORG_B[2]},
        )
        assert st == 201, reg

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()
        cls.tmp.cleanup()

    def _login(self, page, user, pw):
        page.goto(self.srv.base_url + "/")
        page.settled("#login-form button[type=submit]", 15)
        page.type("#username", user)
        page.type("#password", pw)
        page.click("#login-form button[type=submit]")
        page.wait(
            "getComputedStyle(document.querySelector('#app-view')).display!=='none'"
            " && !document.querySelector('#app-view').hidden",
            15,
        )

    def _dblclick_row(self, page, selector):
        box = page.eval(
            f"(()=>{{const e=document.querySelector({json.dumps(selector)});"
            " e.scrollIntoView({block:'center',behavior:'instant'});"
            " const r=e.getBoundingClientRect(); return [r.left+r.width/2, r.top+r.height/2];})()"
        )
        for kind, cc in (("mousePressed", 1), ("mouseReleased", 1), ("mousePressed", 2), ("mouseReleased", 2)):
            page.send(
                "Input.dispatchMouseEvent",
                {"type": kind, "x": box[0], "y": box[1], "button": "left", "clickCount": cc},
            )

    def test_live_popup_evidence_xss_files_and_stream_stability_desktop(self):
        b = bc.Browser(self.chrome)
        try:
            p = b.new_page(1440, 900)
            self._login(p, ORG_A[0], ORG_A[1])
            p.goto(self.srv.base_url + "/live")
            p.wait("document.querySelectorAll('#rows tr[data-key]').length >= 3", 20)

            # Files sidebar lists recorded files and filters cleanly
            p.wait("document.querySelectorAll('#file-tree [data-scope-file]').length >= 2", 10)
            sidebar_files = p.eval("[...document.querySelectorAll('#file-tree [data-scope-file]')].map(b=>b.dataset.scopeFile)")
            self.assertIn("ui/tile.png", sidebar_files)
            self.assertIn("src/demo.py", sidebar_files)

            # Click file in sidebar -> narrows rows, then clear filter
            p.click("#file-tree [data-scope-file='ui/tile.png']")
            p.wait("document.querySelectorAll('#rows tr[data-key]').length === 1", 10)
            p.click("#clear-scope")
            p.wait("document.querySelectorAll('#rows tr[data-key]').length >= 3", 10)

            # Double-click persisted shell command event -> modal opens with command, output, exit code, truncated pill, zero XSS
            cmd_key = p.eval(
                "([...document.querySelectorAll('#rows tr[data-key]')]"
                ".find(r => r.dataset.key.startsWith('event:') && r.textContent.includes('pytest')) || {}).dataset?.key || ''"
            )
            self.assertTrue(cmd_key, "Expected persisted shell command event row in /live table")
            p.click(f"#rows tr[data-key={json.dumps(cmd_key)}]")
            p.click("[data-dtab='files']")
            p.wait("document.querySelector('#detail').textContent.includes('No file path was recorded for this event.')", 10)
            self.assertEqual(p.eval("document.querySelector('#files-count').textContent"), "0")
            related = "#detail [data-jump]"
            image_button = p.eval(f"[...document.querySelectorAll('{related}')].find(b => b.textContent.includes('ui/tile.png')).dataset.jump")
            p.click(f'#detail [data-jump="{image_button}"]')
            p.wait("document.querySelector('#detail img.ev-image-thumb')?.naturalWidth > 0", 10)
            self.assertEqual(p.eval("document.querySelector('#files-count').textContent"), "1")
            self.assertIn("ui/tile.png", p.eval("document.querySelector('#detail-evidence-slot').textContent"))

            edit_button = p.eval(f"[...document.querySelectorAll('{related}')].find(b => b.textContent.includes('src/demo.py')).dataset.jump")
            p.click(f'#detail [data-jump="{edit_button}"]')
            p.wait("document.querySelector('#detail-evidence-slot [data-scope-file]')?.textContent.includes('src/demo.py')", 10)
            self.assertEqual(p.eval("document.querySelector('#files-count').textContent"), "1")
            self.assertIn("src/demo.py", p.eval("document.querySelector('#detail-evidence-slot').textContent"))

            self._dblclick_row(p, f"#rows tr[data-key={json.dumps(cmd_key)}]")
            p.wait("Boolean(document.querySelector('#event-dialog[open]'))", 10)
            p.wait("document.querySelector('#event-dialog-body').textContent.includes('FAILED test_demo.py')", 10)

            modal_text = p.eval("document.querySelector('#event-dialog-body').textContent")
            self.assertIn("pytest -q tests/test_demo.py", modal_text)
            self.assertIn("Exit 1", modal_text)
            self.assertIn("Output truncated", modal_text)
            self.assertIn("<script>window.__xss=1</script>", modal_text)
            self.assertIsNone(p.eval("window.__xss ?? null"))

            # While modal is open, stream in a brand-new event -> modal stays open on same event
            live_iso = datetime.now(timezone.utc).isoformat()
            st, _, _ = self.admin.json(
                "POST",
                "/api/v1/ingest/activity",
                {
                    "host_id": "ux-host-01",
                    "activity_enabled": True,
                    "activity_roots": ["/work/demo"],
                    "sessions": [
                        {
                            "session_id": "codex:ux-demo-live",
                            "harness": "codex",
                            "agent_name": "ux-agent",
                            "workspace": "/work/demo",
                            "steps": [
                                {
                                    "tool": "exec_command",
                                    "category": "shell",
                                    "label": "Background live tick",
                                    "program": "liveprobe",
                                    "status": "completed",
                                    "time": live_iso,
                                    "command_input": "liveprobe --ok",
                                }
                            ],
                        }
                    ],
                },
                headers={"Authorization": f"Bearer {self.ingest_token}"},
            )
            self.assertIn(st, (200, 201))
            p.wait("document.querySelector('#rows').textContent.includes('liveprobe')", 15)
            self.assertTrue(p.eval("Boolean(document.querySelector('#event-dialog[open]'))"))
            self.assertIn("FAILED test_demo.py", p.eval("document.querySelector('#event-dialog-body').textContent"))

            # Escape closes dialog and restores focus to originating row
            p.key("Escape", "Escape", key_code=27)
            p.wait("!document.querySelector('#event-dialog[open]')", 5)

            # Double-click persisted image event -> renders raster PNG with naturalWidth > 0 + tool_result badge + zoom overlay
            img_key = p.eval(
                "([...document.querySelectorAll('#rows tr[data-key]')]"
                ".find(r => r.dataset.key.startsWith('event:') && r.textContent.includes('tile.png')) || {}).dataset?.key || ''"
            )
            self.assertTrue(img_key, "Expected persisted image event row in /live table")
            self._dblclick_row(p, f"#rows tr[data-key={json.dumps(img_key)}]")
            p.wait("Boolean(document.querySelector('#event-dialog[open] img.ev-image-thumb'))", 10)
            p.wait(
                "(()=>{const i=document.querySelector('#event-dialog[open] img.ev-image-thumb');"
                " return Boolean(i && i.complete && i.naturalWidth > 0);})()",
                10,
            )
            self.assertIn("Captured from tool result", p.eval("document.querySelector('#event-dialog-body').textContent"))
            p.click("#event-dialog[open] .ev-image-btn")
            p.wait("Boolean(document.querySelector('.ev-zoom-overlay'))", 5)
            p.key("Escape", "Escape", key_code=27)
            p.wait("!document.querySelector('.ev-zoom-overlay')", 5)
            p.key("Escape", "Escape", key_code=27)
            p.wait("!document.querySelector('#event-dialog[open]')", 5)

            # Enter opens popup for focused/selected row
            p.click(f"#rows tr[data-key={json.dumps(cmd_key)}]")
            p.key("Enter", "Enter", key_code=13)
            p.wait("Boolean(document.querySelector('#event-dialog[open]'))", 5)
            p.key("Escape", "Escape", key_code=27)
            p.wait("!document.querySelector('#event-dialog[open]')", 5)

            # Zero unexpected JS errors & no horizontal overflow
            js_errors = [e for e in p.errors if "/api/v1/auth/me" not in e]
            self.assertEqual(js_errors, [])
            self.assertLessEqual(p.eval("document.documentElement.scrollWidth"), 1441)
        finally:
            b.close()

    def test_mobile_popup_and_dashboard_clarity_and_revoke_ux(self):
        b = bc.Browser(self.chrome)
        try:
            # 1) Dashboard clarity + collapsed secondary sections + token revoke UX at desktop 1440x900
            p = b.new_page(1440, 900)
            self._login(p, ORG_A[0], ORG_A[1])
            p.wait("document.querySelectorAll('.section-lead').length >= 8", 10)

            # Secondary sections collapsed by default
            for fold_id in ("enrollment-fold", "organization-fold", "security-fold", "events-fold", "audit-fold"):
                self.assertFalse(p.eval(f"document.getElementById({json.dumps(fold_id)}).open"), f"{fold_id} should start collapsed")

            # Clicking sidebar link expands folded section in 1 click
            p.click(".section-nav a[href='#enrollment']")
            p.wait("document.getElementById('enrollment-fold').open === true", 5)
            p.settled("#token-form button[type=submit]", 5)

            # Token create -> install command visible -> revoke -> install box hidden & command cleared
            p.type("#token-name", "ephemeral-revoke-test")
            p.click("#token-form button[type=submit]")
            p.wait("!document.getElementById('install-output').classList.contains('hidden')", 10)
            self.assertTrue(p.eval("document.getElementById('install-cmd').textContent.trim().length > 10"))
            p.wait("document.querySelectorAll('#tokens-list [data-revoke]').length > 0", 10)
            p.click("#tokens-list [data-revoke]")
            p.wait("document.getElementById('install-output').classList.contains('hidden')", 10)
            self.assertEqual(p.eval("document.getElementById('install-cmd').textContent"), "")

            self.assertLessEqual(p.eval("document.documentElement.scrollWidth"), 1441)
            js_errors = [e for e in p.errors if "/api/v1/auth/me" not in e]
            self.assertEqual(js_errors, [])

            # 2) Mobile 390x844 on dashboard AND /live popup button
            pm = b.new_page(390, 844)
            self._login(pm, ORG_A[0], ORG_A[1])
            pm.wait("document.querySelectorAll('.section-lead').length >= 8", 10)
            self.assertLessEqual(pm.eval("document.documentElement.scrollWidth"), 391)

            pm.goto(self.srv.base_url + "/live")
            pm.wait("document.querySelectorAll('#rows tr[data-key]').length >= 3", 20)
            pm.click("#rows tr[data-key]:first-child")
            pm.click("#detail-quick [data-act='open-popup']")
            pm.wait("Boolean(document.querySelector('#event-dialog[open]'))", 10)
            self.assertLessEqual(pm.eval("document.documentElement.scrollWidth"), 391)
            pm.click("#event-dialog-close")
            pm.wait("!document.querySelector('#event-dialog[open]')", 5)
            js_errors_m = [e for e in pm.errors if "/api/v1/auth/me" not in e]
            self.assertEqual(js_errors_m, [])
        finally:
            b.close()

    def test_org_b_isolation_no_files_or_evidence_leak(self):
        b = bc.Browser(self.chrome)
        try:
            p = b.new_page(1440, 900)
            self._login(p, ORG_B[0], ORG_B[1])
            p.goto(self.srv.base_url + "/live")
            p.wait("document.getElementById('sync').textContent.includes('Connected')", 15)
            self.assertEqual(p.eval("document.querySelectorAll('#file-tree [data-scope-file]').length"), 0)
            self.assertNotIn("ui/tile.png", p.eval("document.body.textContent"))
            self.assertNotIn("Run pytest suite", p.eval("document.body.textContent"))
        finally:
            b.close()


if __name__ == "__main__":
    unittest.main()
