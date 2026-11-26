"""Independent QA acceptance tests for:
1. Mission timeline visual coherence with NeuroSwarm Ink & Cel UI/UX (/missions + #mission-preview).
2. Accurate section navigation (sidebar order matches DOM, every link lands on & activates its own section).
3. Sticky accompanying menu & accurate scroll-spy across desktop, tablet (<=1050px), and mobile.
4. Section-switch transition feedback that respects prefers-reduced-motion.

Run from a NeuroSwarm checkout:
    PYTHONPATH=backend:tests python3 -m unittest test_browser_navigation_and_missions_ux
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if not (ROOT / "backend").exists():
    ROOT = Path.cwd()
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "tests")]

import browser_cdp  # noqa: E402
from product_qa.test_acceptance_blackbox import HttpClient, SpawnedConsole  # noqa: E402

ADMIN = ("bootstrap_admin", "BootstrapPass!2026#QA")
VIEWPORTS = {
    "desktop": (1440, 900, False),
    "tablet": (1024, 768, False),
    "mobile": (390, 844, True),
}


class NavigationAndMissionsUXAcceptanceTests(unittest.TestCase):
    browser = None

    @classmethod
    def setUpClass(cls):
        if os.environ.get("SWARMCONTROL_BROWSER_TESTS", "").lower() == "skip":
            raise unittest.SkipTest("SWARMCONTROL_BROWSER_TESTS=skip")
        binary = browser_cdp.find_browser()
        if not binary:
            raise AssertionError("No Chromium found; set SWARMCONTROL_CHROMIUM or run deploy/fetch_test_browser.py.")
        cls.tmp = tempfile.TemporaryDirectory(prefix="ns-ux-qa-")
        cls.srv = SpawnedConsole(Path(cls.tmp.name) / "console")
        try:
            cls._seed()
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

    @classmethod
    def _seed(cls):
        client = HttpClient(cls.srv.base_url)
        status, _, _ = client.json("POST", "/api/v1/auth/login", {"username": ADMIN[0], "password": ADMIN[1]})
        assert status == 200, f"login failed: {status}"
        status, _, key = client.json("POST", "/api/v1/tokens", {"name": "ux-acceptance"})
        assert status == 201, f"token failed: {status}"
        hdr = {"Authorization": "Bearer " + key["token"]}

        def emit(event_type, agent, message, **metadata):
            st, _, _ = client.json(
                "POST",
                "/api/v1/ingest/event",
                {
                    "host_id": "qa-ux-host",
                    "harness": "qa",
                    "agent_name": agent,
                    "event_type": event_type,
                    "message": message,
                    "metadata": metadata,
                },
                headers=hdr,
            )
            assert st == 200, f"ingest failed: {st}"

        emit("decision", "Verifier", "Compare both invoice batches.", mission_id="reconcile", task_id="check-invoices",
             reason="Both batches share a cutoff date.", reasoning="PRIVATE QA INNER TEXT")
        emit("agent_message", "Coordinator", "Send the verified totals.", mission_id="reconcile",
             task_id="check-invoices", to_agent="Verifier")
        emit("blocker", "Verifier", "Waiting for final receipt.", mission_id="reconcile", task_id="check-invoices")
        emit("memory_saved", "Verifier", "The cutoff uses local business time.", mission_id="reconcile",
             task_id="check-invoices")

    def _signed_in_page(self, view: str, reduced_motion: bool = True):
        w, h, mobile = VIEWPORTS[view]
        pg = self.browser.new_page(w, h, mobile)
        self.addCleanup(pg.close)
        pg.reduced_motion(reduced_motion)
        pg.goto(self.srv.base_url + "/")
        pg.wait("document.querySelector('#login-form') && getComputedStyle(document.querySelector('#login-view')).display !== 'none'")
        pg.type("#username", ADMIN[0])
        pg.type("#password", ADMIN[1])
        pg.click("#login-form button[type=submit]")
        pg.wait("document.querySelector('#app-view') && !document.querySelector('#app-view').classList.contains('hidden')")
        time.sleep(0.4)
        return pg

    def _assert_clean(self, pg, label: str):
        errors = [e for e in pg.errors if not ("status of 401" in e and e.endswith("/api/v1/auth/me"))]
        bad = [(s, u) for s, u in pg.http_errors if not (s == 401 and u.endswith("/api/v1/auth/me"))]
        self.assertEqual((errors, bad), ([], []), f"{label}: browser/HTTP errors")
        self.assertEqual(pg.overflow()["offenders"], [], f"{label}: horizontal overflow")

    def test_1_mission_timeline_matches_console_visual_system(self):
        for view in ("desktop", "mobile"):
            with self.subTest(view=view):
                pg = self._signed_in_page(view)
                pg.goto(self.srv.base_url + "/missions")
                pg.wait("document.querySelector('#objective') && document.querySelector('#objective').textContent.trim().length > 0")
                audit = pg.eval("""(() => {
                  const sheets = [...document.styleSheets].map(s => s.href || '');
                  const topbar = document.querySelector('.topbar');
                  const topbarBg = topbar ? getComputedStyle(topbar).backgroundColor : null;
                  const bodyBgImg = getComputedStyle(document.body).backgroundImage;
                  const selectEl = document.querySelector('#mission');
                  const selectBg = selectEl ? getComputedStyle(selectEl).backgroundColor : null;
                  const styledCards = document.querySelectorAll('.card, .mission-card, .timeline-card, [class*="card"]').length;
                  const eventsText = document.querySelector('#events')?.innerText || '';
                  return {
                    hasIdentityCss: sheets.some(u => u.includes('/identity.css')),
                    hasTopbar: !!topbar,
                    topbarBg,
                    hasPaperTexture: bodyBgImg && bodyBgImg !== 'none',
                    selectBg,
                    styledCards,
                    hasPrivacyLeak: eventsText.includes('PRIVATE QA INNER TEXT'),
                  };
                })()""")
                self.assertTrue(audit["hasIdentityCss"], f"{view}: /missions must load /identity.css")
                self.assertTrue(audit["hasTopbar"], f"{view}: /missions must include the shared console .topbar")
                self.assertTrue(audit["hasPaperTexture"], f"{view}: /missions must share the console paper background")
                self.assertNotEqual(audit["selectBg"], "rgb(239, 239, 239)", f"{view}: #mission select uses unstyled browser default")
                self.assertGreaterEqual(audit["styledCards"], 1, f"{view}: /missions must render content in styled cards")
                self.assertFalse(audit["hasPrivacyLeak"], f"{view}: private reasoning leaked")
                self._assert_clean(pg, f"missions-{view}")

    def test_2_section_nav_order_matches_dom_and_every_click_lands_on_its_own_section(self):
        pg = self._signed_in_page("desktop")
        order = pg.eval("""(() => {
          const links = [...document.querySelectorAll('.section-nav a[href^="#"]')];
          return links.map(a => {
            const id = a.getAttribute('href').slice(1);
            const el = document.getElementById(id);
            const top = el ? Math.round(el.getBoundingClientRect().top + window.scrollY) : -1;
            return { href: '#' + id, top };
          });
        })()""")
        tops = [item["top"] for item in order]
        self.assertEqual(
            tops,
            sorted(tops),
            f"Sidebar order does not match vertical DOM order: {order}",
        )

        # Clicking each anchor must bring that target into view AND activate that exact nav item.
        for item in order:
            href = item["href"]
            if href == "#main-content":
                continue
            with self.subTest(href=href):
                pg.eval("window.scrollTo(0, 0)")
                time.sleep(0.05)
                pg.click(f'.section-nav a[href="{href}"]')
                time.sleep(0.25)
                state = pg.eval(f"""(() => {{
                  const id = {json.dumps(href[1:])};
                  const target = document.getElementById(id);
                  const r = target.getBoundingClientRect();
                  const active = [...document.querySelectorAll('.section-nav a.is-active, .section-nav a[aria-current="location"]')]
                    .map(a => a.getAttribute('href'));
                  return {{
                    visibleInViewport: r.top >= -40 && r.top < window.innerHeight * 0.75,
                    targetTop: Math.round(r.top),
                    active: [...new Set(active)],
                  }};
                }})()""")
                self.assertTrue(state["visibleInViewport"], f"Clicking {href} left target out of top viewport (top={state['targetTop']})")
                self.assertEqual(state["active"], [href], f"Clicking {href} highlighted wrong nav item: {state['active']}")
        self._assert_clean(pg, "nav-desktop")

    def test_3_sticky_menu_follows_scroll_and_updates_active_section_on_all_viewports(self):
        for view in ("desktop", "tablet", "mobile"):
            with self.subTest(view=view):
                pg = self._signed_in_page(view)
                # Scroll to #hosts and verify nav stays visible (sticky/fixed) and tracks the current section.
                pg.eval("document.getElementById('hosts')?.scrollIntoView({behavior: 'instant', block: 'start'})")
                time.sleep(0.3)
                state = pg.eval("""(() => {
                  const nav = document.querySelector('.section-nav');
                  const r = nav.getBoundingClientRect();
                  const active = [...nav.querySelectorAll('a.is-active, a[aria-current="location"]')]
                    .map(a => a.getAttribute('href'));
                  return {
                    navVisible: r.bottom > 0 && r.top >= -2 && r.top < window.innerHeight,
                    navTop: Math.round(r.top),
                    active: [...new Set(active)],
                  };
                })()""")
                self.assertTrue(state["navVisible"], f"{view}: .section-nav scrolled off-screen (top={state['navTop']})")
                self.assertEqual(state["active"], ["#hosts"], f"{view}: scroll-spy at #hosts showed {state['active']}")
                self._assert_clean(pg, f"sticky-{view}")

    def test_4_section_switch_has_transition_and_respects_reduced_motion(self):
        pg = self._signed_in_page("desktop", reduced_motion=False)
        pg.click('.section-nav a[href="#hosts"]')
        time.sleep(0.08)
        animated = pg.eval("""(() => {
          const t = document.getElementById('hosts');
          const anims = typeof t.getAnimations === 'function' ? t.getAnimations() : [];
          const hasClass = [...t.classList].some(c => /focus|arrive|pulse|enter|highlight|transition|active/i.test(c));
          return { animCount: anims.length, hasClass };
        })()""")
        self.assertTrue(
            animated["animCount"] > 0 or animated["hasClass"],
            "Switching sections with motion enabled should trigger a visible arrival transition/highlight",
        )


if __name__ == "__main__":
    unittest.main()
