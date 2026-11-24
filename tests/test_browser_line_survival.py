"""Activity map step detail in headless Chromium: "Lines still in the code" for an agent's edit.

A remote observer reads a real Git repository and Claude Code logs (synthetic content, loopback only) and reports through
the normal ingest API. Opening the edit on the map must show the counted lines when the session's own commit names
them, and a reason instead of a number when the evidence is not explicit. Needs a Chromium binary (see
tests/BROWSER-TESTS.md); SWARMCONTROL_BROWSER_TESTS=skip opts out explicitly.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "agent"), str(Path(__file__).resolve().parent)]
import activity_inspector as ai  # noqa: E402
import activity_shipper  # noqa: E402
import browser_cdp  # noqa: E402
from product_qa.test_acceptance_blackbox import HttpClient, SpawnedConsole  # noqa: E402
from test_line_survival import SECRET_LINE, Lab, git, line_of  # noqa: E402

ADMIN = ("bootstrap_admin", "BootstrapPass!2026#QA")


class LineSurvivalBrowserTests(unittest.TestCase):
    browser = None

    @classmethod
    def setUpClass(cls):
        if os.environ.get("SWARMCONTROL_BROWSER_TESTS", "").lower() == "skip":
            raise unittest.SkipTest("SWARMCONTROL_BROWSER_TESTS=skip")
        binary = browser_cdp.find_browser()
        if not binary:
            raise AssertionError("No Chromium found. Run `python3 deploy/fetch_test_browser.py` once, or set "
                                 "SWARMCONTROL_CHROMIUM; SWARMCONTROL_BROWSER_TESTS=skip opts out explicitly.")
        cls.tmp = tempfile.TemporaryDirectory(prefix="ns-lines-qa-")
        t = Path(cls.tmp.name)
        cls.lab = Lab(t / "lab")
        cls.lab.script()
        cls.srv = SpawnedConsole(t / "console")
        try:
            admin = HttpClient(cls.srv.base_url)
            assert admin.json("POST", "/api/v1/auth/login", {"username": ADMIN[0], "password": ADMIN[1]})[0] == 200
            st, _, tok = admin.json("POST", "/api/v1/tokens", {"name": "lines-box", "scope": "ingest"})
            assert st == 201, tok
            with patch.object(ai, "HOME", cls.lab.home), patch.object(ai, "harnesses", return_value=[]), \
                    patch.dict(os.environ, {"SWARMCONTROL_SHARE_LINE_SURVIVAL": "1"}):
                ai._SURVIVAL_LAST.clear()
                payload, _, _ = activity_shipper.collect_incremental_activity(
                    raw_roots=[str(cls.lab.repo)], host_id="lines-box", home_dir=cls.lab.home, use_core=True)
            st, _, body = admin.json("POST", "/api/v1/ingest/activity", payload, headers={"Authorization": f"Bearer {tok['token']}"})
            assert st in (200, 201), (st, body)
            cls.browser = browser_cdp.Browser(binary)
        except Exception:
            cls.srv.stop()
            cls.tmp.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        if cls.browser:
            cls.browser.close()
        cls.srv.stop()
        cls.tmp.cleanup()

    def open_step(self, pg, label, last=False):
        pg.settled("#activity-map .ap-tab[data-view='sessions']", 10)
        pg.click("#activity-map .ap-tab[data-view='sessions']")
        pick = "filter(b => b.textContent.trim() === %r).at(-1)" % label if last else "find(b => b.textContent.trim() === %r)" % label
        sel = f"[...document.querySelectorAll('#activity-map .am-inspect[data-kind=step]')].{pick}"
        pg.wait(f"!!{sel}", what=f"step '{label}'")
        pg.eval(f"(b => {{ b.closest('details') && (b.closest('details').open = true); b.click(); }})({sel})")
        pg.wait("!!document.querySelector('dialog.am-detail[open] [data-survival]:not([aria-busy])')", what="line survival loaded")
        return pg.eval("document.querySelector('dialog.am-detail[open] [data-survival]').textContent")

    def test_edit_detail_shows_lines_that_remain_or_why_it_cannot_tell(self):
        for view, (w, h, mobile) in {"desktop": (1440, 900, False), "mobile": (390, 844, True)}.items():
            with self.subTest(view=view):
                pg = self.browser.new_page(w, h, mobile)
                self.addCleanup(pg.close)
                pg.goto(self.srv.base_url + "/")
                pg.wait("document.querySelector('#login-form') && getComputedStyle(document.querySelector('#login-view')).display !== 'none'",
                        what="login form")
                pg.type("#username", ADMIN[0])
                pg.type("#password", ADMIN[1])
                pg.click("#login-form button[type=submit]")
                pg.wait("document.querySelector('#activity-map') && document.querySelector('#activity-map').innerText.includes('shop')",
                        what="sessions on the map")
                text = self.open_step(pg, "Edit app.py")
                self.assertIn("1 of 3 lines remain", text)
                self.assertIn("2 changed or removed since commit", text)
                n = line_of(self.lab.repo, "app.py", SECRET_LINE)
                head = git(self.lab.repo, "rev-parse", "HEAD").strip()
                ranges = pg.eval("[...document.querySelectorAll('dialog.am-detail[open] .am-line-range')].map(e => e.textContent)")
                self.assertEqual(ranges, [str(n)], "the surviving line, at its number in the measured revision")
                self.assertIn(f"Line {n} of app.py at revision {head[:7]}", " ".join(text.split()))
                cmd = pg.eval("document.querySelector('dialog.am-detail[open] .am-verify pre').textContent")
                self.assertEqual(cmd, f"git blame -M -L {n},{n} {head[:7]} -- app.py")
                blame = git(self.lab.repo, "blame", "-M", "-l", "-L", f"{n},{n}", head[:7], "--", "app.py")
                self.assertIn(f"commit {blame[:7]}", text.replace("commit\n", "commit "), "the command shows the commit the UI names")
                self.observed = getattr(self, "observed", []) + [(view, ranges, cmd)]
                self.assertNotIn(SECRET_LINE, pg.eval("document.body.innerText"))
                self.assertTrue(pg.eval("!!document.querySelector('dialog.am-detail[open] .am-survival-bar span')"))
                art = os.environ.get("SWARMCONTROL_BROWSER_ARTIFACTS", "").strip()
                if art:
                    Path(art).mkdir(parents=True, exist_ok=True)
                    pg.screenshot(Path(art) / f"{view}-line-survival.png")
                pg.key("Escape", "Escape", key_code=27)
                pg.wait("!document.querySelector('dialog[open]')", what="dialog closed")
                text = self.open_step(pg, "Edit late.py", last=True)        # D's second edit: two lines, one range
                first = line_of(self.lab.repo, "late.py", "d second 1")
                ranges = pg.eval("[...document.querySelectorAll('dialog.am-detail[open] .am-line-range')].map(e => e.textContent)")
                self.assertEqual(ranges, [f"{first}–{first + 1}"])
                self.assertIn(f"Lines {first}–{first + 1} of late.py at revision {head[:7]}", " ".join(text.split()))
                self.observed.append((view, ranges, pg.eval("document.querySelector('dialog.am-detail[open] .am-verify pre').textContent")))
                if art:
                    pg.screenshot(Path(art) / f"{view}-line-ranges.png")
                pg.key("Escape", "Escape", key_code=27)
                pg.wait("!document.querySelector('dialog[open]')", what="dialog closed")
                text = self.open_step(pg, "Edit shared.py")
                self.assertNotIn("lines remain", text, "no number without explicit evidence")
                self.assertTrue("Another session also edited this file" in text or "No commit recorded by this session" in text, text)
                pg.key("Escape", "Escape", key_code=27)
                errors = [e for e in pg.errors if not ("status of 401" in e and e.endswith("/api/v1/auth/me"))]
                bad = [(s, u) for s, u in pg.http_errors if not (s == 401 and u.endswith("/api/v1/auth/me"))]
                self.assertEqual((errors, bad), ([], []))
                print(f"\nobserved in {view}: {self.observed[-2:]}")


if __name__ == "__main__":
    unittest.main()
