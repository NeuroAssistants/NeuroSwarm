"""Activity map step detail in a real headless Chromium: the command, its output and the image the agent saw.

An observer sends synthetic file actions and two commands at the same time. Each step
must show its own result. A legacy step without a source position can open the session
history, and a second organization must not see any of the recorded evidence.

Needs a Chromium binary (see tests/BROWSER-TESTS.md); SWARMCONTROL_BROWSER_TESTS=skip opts out explicitly.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(Path(__file__).resolve().parent)]
import browser_cdp  # noqa: E402
from product_qa.test_acceptance_blackbox import HttpClient, SpawnedConsole  # noqa: E402

ADMIN = ("bootstrap_admin", "BootstrapPass!2026#QA")
OTHER = ("other_ops", "OtherStrongPass!2026#QA", "Other Team")
# Synthetic 1x1 blue RGBA pixel.
PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGOwmPngPwAFbwKxEfU0EQAAAABJRU5ErkJggg=="
SESSION = "codex:evidence-run-01"


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


class ActivityEvidenceBrowserTests(unittest.TestCase):
    browser: browser_cdp.Browser | None = None

    @classmethod
    def setUpClass(cls) -> None:
        if os.environ.get("SWARMCONTROL_BROWSER_TESTS", "").lower() == "skip":
            raise unittest.SkipTest("SWARMCONTROL_BROWSER_TESTS=skip")
        binary = browser_cdp.find_browser()
        if not binary:
            raise AssertionError("No Chromium found. Run `python3 deploy/fetch_test_browser.py` once, or set "
                                 "SWARMCONTROL_CHROMIUM; SWARMCONTROL_BROWSER_TESTS=skip opts out explicitly.")
        cls.tmp = tempfile.TemporaryDirectory(prefix="ns-evidence-qa-")
        cls.srv = SpawnedConsole(Path(cls.tmp.name))
        try:
            cls._seed()
            cls.browser = browser_cdp.Browser(binary)
        except Exception:
            cls.srv.stop()
            cls.tmp.cleanup()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.browser:
            cls.browser.close()
        cls.srv.stop()
        cls.tmp.cleanup()

    @classmethod
    def _seed(cls) -> None:
        admin = HttpClient(cls.srv.base_url)
        st, _, _ = admin.json("POST", "/api/v1/auth/login", {"username": ADMIN[0], "password": ADMIN[1]})
        assert st == 200, st
        st, _, tok = admin.json("POST", "/api/v1/tokens", {"name": "evidence-box", "scope": "ingest"})
        assert st == 201, (st, tok)
        now = time.time()
        steps = [
            {"tool": "view_image", "category": "file_read", "label": "Look at the chart", "status": "completed",
             "time": _iso(now - 90), "files": ["reports/chart.png"],
             "image_previews": [{"path": "reports/chart.png", "mime_type": "image/png", "data_base64": PNG, "source": "tool_result"}]},
            {"tool": "exec_command", "category": "shell", "label": "Run the test suite", "program": "pytest", "status": "completed",
             "time": _iso(now - 60), "command_input": "pytest -q tests/test_totals.py --password DEMO_VALUE",
             "command_output": "F.\nFAILED tests/test_totals.py::test_sum - assert 3 == 4\nAPI_KEY=DEMO_VALUE\n", "exit_code": 1},
            {"tool": "apply_patch", "category": "file_edit", "label": "Edit totals.py", "status": "completed",
             "time": _iso(now - 30), "files": ["src/totals.py"]},
        ]
        steps.append({**steps[1], "label": "Run parallel suite", "command_output": "Parallel suite passed", "exit_code": 0})
        for n, step in enumerate(steps):
            step["src"] = f"record:240:{n}"
        legacy = {k: v for k, v in steps[1].items() if k not in ("src", "command_input", "command_output", "exit_code")}
        legacy["label"] = "Older command"
        payload = {"host_id": "evidence-box", "hostname": "evidence-box", "activity_enabled": True, "activity_roots": ["/work/demo"],
                   "collected_at": now,
                   "sessions": [{"session_id": SESSION, "harness": "codex", "harness_name": "Codex CLI", "agent_name": "demo-agent",
                                 "workspace": "/work/demo", "status": "active", "updated_at": now, "what_done": "Fixed the totals",
                                 "steps": [*steps, legacy], "capture_steps": steps}]}
        st, _, body = admin.json("POST", "/api/v1/ingest/activity", payload, headers={"Authorization": f"Bearer {tok['token']}"})
        assert st in (200, 201), (st, body)
        other = HttpClient(cls.srv.base_url)
        st, _, body = other.json("POST", "/api/v1/auth/register", {"username": OTHER[0], "password": OTHER[1], "organization": OTHER[2]})
        assert st == 201, (st, body)

    def login(self, pg, user, password):
        pg.goto(self.srv.base_url + "/")
        pg.wait("document.querySelector('#login-form') && getComputedStyle(document.querySelector('#login-view')).display !== 'none'",
                what="login form")
        pg.type("#username", user)
        pg.type("#password", password)
        pg.click("#login-form button[type=submit]")
        pg.wait("!document.querySelector('#app-view').hidden && getComputedStyle(document.querySelector('#app-view')).display !== 'none'",
                what="console after sign-in")

    def open_step(self, pg, label):
        pg.click("#activity-map .ap-tab[data-view='sessions']")
        sel = f"[...document.querySelectorAll('#activity-map .am-inspect[data-kind=step]')].find(b => b.textContent.includes({label!r}))"
        pg.wait(f"!!{sel}", what=f"step '{label}' in the session card")
        pg.eval(f"(b => {{ b.closest('details') && (b.closest('details').open = true); b.click(); }})({sel})")
        pg.wait("!!document.querySelector('dialog.am-detail[open] [data-evidence]:not([aria-busy])')", what="evidence loaded")
        return pg.eval("document.querySelector('dialog.am-detail[open] [data-evidence]').textContent")

    def shot(self, pg, name):
        art = os.environ.get("SWARMCONTROL_BROWSER_ARTIFACTS", "").strip()
        if art:
            Path(art).mkdir(parents=True, exist_ok=True)
            pg.screenshot(Path(art) / f"{name}.png")

    def close_dialog(self, pg):
        pg.key("Escape", "Escape", key_code=27)
        pg.wait("!document.querySelector('dialog[open]')", what="dialog closed")

    def assert_clean(self, pg, where):
        errors = [e for e in pg.errors if not ("status of 401" in e and e.endswith("/api/v1/auth/me"))]
        bad = [(s, u) for s, u in pg.http_errors if not (s == 401 and u.endswith("/api/v1/auth/me"))]
        self.assertEqual(errors, [], f"{where}: browser errors")
        self.assertEqual(bad, [], f"{where}: failed requests")

    def test_step_detail_shows_command_output_and_the_image_the_agent_saw(self):
        for view, (w, h, mobile) in {"desktop": (1440, 900, False), "mobile": (390, 844, True)}.items():
            with self.subTest(view=view):
                pg = self.browser.new_page(w, h, mobile)
                self.addCleanup(pg.close)
                self.login(pg, *ADMIN)
                pg.wait("document.querySelector('#activity-map').innerText.includes('demo-agent')", what="session on the map")

                text = self.open_step(pg, "Run the test suite")
                self.assertIn("pytest -q tests/test_totals.py", text)
                self.assertIn("FAILED tests/test_totals.py::test_sum", text)
                self.assertIn("exit 1", text)
                self.assertNotIn("DEMO_VALUE", text, "secrets stay redacted")
                self.assertTrue(pg.eval("!!document.querySelector('dialog.am-detail[open] .am-exit.bad')"))
                href = pg.eval("document.querySelector('dialog.am-detail[open] [data-evidence] a.link-hop-btn').getAttribute('href')")
                self.assertTrue(href.startswith("/live?") and "event=event%3A" in href, href)
                self.shot(pg, f"{view}-step-command")
                self.close_dialog(pg)

                text = self.open_step(pg, "Run parallel suite")
                self.assertIn("Parallel suite passed", text)
                self.assertIn("exit 0", text)
                self.assertNotIn("FAILED tests/test_totals.py", text)
                self.close_dialog(pg)

                text = self.open_step(pg, "Older command")
                self.assertIn("no exact journal link", text)
                self.assertNotIn("Parallel suite passed", text)
                self.assertNotIn("FAILED tests/test_totals.py", text)
                href = pg.eval("document.querySelector('dialog.am-detail[open] [data-evidence] a').getAttribute('href')")
                self.assertIn("session=", href)
                self.assertNotIn("event=", href)
                self.close_dialog(pg)

                text = self.open_step(pg, "Look at the chart")
                self.assertIn("Images the agent saw", text)
                self.assertIn("What the tool returned to the agent", text)
                pg.wait("(() => { const i = document.querySelector('dialog.am-detail[open] .am-shot img'); return i && i.complete && i.naturalWidth === 1; })()",
                        what="recorded image decoded")
                self.shot(pg, f"{view}-step-image")
                self.close_dialog(pg)

                text = self.open_step(pg, "Edit totals.py")
                self.assertIn("did not share its command text, output or file contents", text)
                self.close_dialog(pg)
                self.assert_clean(pg, view)

    def test_other_organization_cannot_open_the_evidence(self):
        pg = self.browser.new_page(1440, 900, False)
        self.addCleanup(pg.close)
        self.login(pg, OTHER[0], OTHER[1])
        pg.wait("!!document.querySelector('#activity-map .ap-empty, #activity-map .ap-tab')", what="map rendered")
        self.assertNotIn("demo-agent", pg.eval("document.querySelector('#activity-map').innerText"))
        status = pg.eval("fetch('/api/v1/events/1/evidence').then(r => r.status)", timeout=10)
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
