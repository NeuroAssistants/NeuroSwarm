"""Toon ink look of the Activity map in headless Chromium: drawn outlines without filtering text, the mark as a character
in the empty state, and no motion when the visitor asks for reduced motion. Synthetic data on loopback only.
Needs a Chromium binary (see tests/BROWSER-TESTS.md); SWARMCONTROL_BROWSER_TESTS=skip opts out explicitly.
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
from test_line_survival import Lab  # noqa: E402

ADMIN = ("bootstrap_admin", "BootstrapPass!2026#QA")
VIEWS = {"desktop": (1440, 900, False), "mobile": (390, 844, True)}


class ToonInkBrowserTests(unittest.TestCase):
    browser = None

    @classmethod
    def setUpClass(cls):
        if os.environ.get("SWARMCONTROL_BROWSER_TESTS", "").lower() == "skip":
            raise unittest.SkipTest("SWARMCONTROL_BROWSER_TESTS=skip")
        binary = browser_cdp.find_browser()
        if not binary:
            raise AssertionError("No Chromium found. Run `python3 deploy/fetch_test_browser.py` once, or set "
                                 "SWARMCONTROL_CHROMIUM; SWARMCONTROL_BROWSER_TESTS=skip opts out explicitly.")
        cls.tmp = tempfile.TemporaryDirectory(prefix="ns-toon-qa-")
        t = Path(cls.tmp.name)
        cls.lab = Lab(t / "lab")
        cls.lab.script()
        cls.srv = SpawnedConsole(t / "console")
        try:
            cls.admin = HttpClient(cls.srv.base_url)
            assert cls.admin.json("POST", "/api/v1/auth/login", {"username": ADMIN[0], "password": ADMIN[1]})[0] == 200
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

    def signed_in(self, view, ready):
        w, h, mobile = VIEWS[view]
        pg = self.browser.new_page(w, h, mobile)
        self.addCleanup(pg.close)
        pg.reduced_motion(True)
        pg.goto(self.srv.base_url + "/")
        pg.wait("document.querySelector('#login-form') && getComputedStyle(document.querySelector('#login-view')).display !== 'none'",
                what="login form")
        pg.type("#username", ADMIN[0])
        pg.type("#password", ADMIN[1])
        pg.click("#login-form button[type=submit]")
        pg.wait(ready, what="activity map")
        return pg

    def clean(self, pg):
        errors = [e for e in pg.errors if not ("status of 401" in e and e.endswith("/api/v1/auth/me"))]
        bad = [(s, u) for s, u in pg.http_errors if not (s == 401 and u.endswith("/api/v1/auth/me"))]
        self.assertEqual((errors, bad), ([], []))
        self.assertEqual(pg.overflow()["offenders"], [])

    def test_1_empty_map_shows_the_mark_as_a_character_with_words(self):
        for view in VIEWS:
            with self.subTest(view=view):
                pg = self.signed_in(view, "!!document.querySelector('#activity-map .ap-empty')")
                got = pg.eval("""(() => { const e = document.querySelector('#activity-map .ap-empty'), m = e.querySelector('svg.ap-mascot');
                  return {mascot: !!m, hidden: m && m.getAttribute('aria-hidden'), title: e.querySelector('h3').textContent,
                    animation: m && getComputedStyle(m).animationName,
                    wide: m && m.getBoundingClientRect().width,
                    defs: document.querySelectorAll('#ns-ink-defs').length, filter: !!document.getElementById('ns-ink')}; })()""")
                self.assertEqual((got["mascot"], got["hidden"]), (True, "true"), "decorative: the heading says it")
                self.assertEqual(got["title"], "No machine has shared activity yet")
                self.assertEqual(got["animation"], "none", "reduced motion: the character stays still")
                self.assertGreater(got["wide"], 60)
                self.assertEqual((got["defs"], got["filter"]), (1, True), "one shared ink filter")
                self.clean(pg)

    def test_2_frames_are_inked_and_text_is_never_filtered(self):
        st, _, tok = self.admin.json("POST", "/api/v1/tokens", {"name": "toon-box", "scope": "ingest"})
        self.assertEqual(st, 201, tok)
        with patch.object(ai, "HOME", self.lab.home), patch.object(ai, "harnesses", return_value=[]):
            payload, _, _ = activity_shipper.collect_incremental_activity(
                raw_roots=[str(self.lab.repo)], host_id="toon-box", home_dir=self.lab.home, use_core=True)
        st, _, body = self.admin.json("POST", "/api/v1/ingest/activity", payload, headers={"Authorization": f"Bearer {tok['token']}"})
        self.assertIn(st, (200, 201), body)
        for view in VIEWS:
            with self.subTest(view=view):
                pg = self.signed_in(view, "document.querySelector('#activity-map') && document.querySelector('#activity-map').innerText.includes('shop')")
                got = pg.eval("""(() => {
                  const card = document.querySelector('#activity-map .ap-hosts > li'), before = getComputedStyle(card, '::before');
                  const textFiltered = [...document.querySelectorAll('#activity-map *')].filter(e => {
                    const f = getComputedStyle(e).filter; return f && f !== 'none' && e.textContent.trim() && !(e instanceof SVGPathElement); })
                    .map(e => e.tagName + '.' + e.getAttribute('class'));
                  const tab = getComputedStyle(document.querySelector('#activity-map .ap-tab.on'));
                  const icon = getComputedStyle(document.querySelector('.section-nav .ns-icon'));
                  const node = document.querySelector('#activity-map .am-node .am-face');
                  return {outline: before.filter, border: before.borderTopWidth, shadow: before.boxShadow, textFiltered,
                    tabShadow: tab.boxShadow, iconCap: icon.strokeLinecap, faceRx: node && node.getAttribute('rx'),
                    shade: !!document.querySelector('#activity-map .am-node .am-shade'),
                    sourcesRow: [...document.querySelectorAll('#activity-map .ap-sources li')].every(li => getComputedStyle(li).flexDirection === 'row')}; })()""")
                self.assertIn("ns-ink", got["outline"], "the frame outline is drawn by the ink filter")
                self.assertGreaterEqual(float(got["border"].rstrip("px")), 2, "an ink line, not a hairline")
                self.assertRegex(got["shadow"], r"3px 3px 0px", "hard offset shadow")
                self.assertEqual(got["textFiltered"], [], "text is never displaced")
                self.assertRegex(got["tabShadow"], r"3px 3px 0px", "the selected tab keeps a copper offset")
                self.assertEqual(got["iconCap"], "round")
                self.assertEqual((got["faceRx"], got["shade"]), ("10", True))
                self.assertTrue(got["sourcesRow"], "source stickers read left to right")
                self.clean(pg)


if __name__ == "__main__":
    unittest.main()
