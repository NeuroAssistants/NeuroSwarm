"""Console navigation in Chromium: every menu button lands on its own section, also while the panels above it are
still loading; the menu stays on screen and marks exactly one section while scrolling (desktop sidebar, mobile
strip); the chosen section plays an arrival effect (a static ring with reduced motion); and the Activity map shows
the latest missions as cards that open the mission timeline.
"""
import json
import time
import unittest

import test_browser_live_readability as fixtures

VIEWPORTS = {**fixtures.VIEWPORTS, "tablet": (1024, 768, False)}
ACTIVE = """[...new Set([...document.querySelectorAll('.section-nav a.is-active, .section-nav a[aria-current="location"]')]
             .map(a => a.getAttribute('href')))]"""


class SectionNavBrowserTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.LiveReadabilityBrowserTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.LiveReadabilityBrowserTests.tearDownClass.__func__)
    assert_clean = fixtures.LiveReadabilityBrowserTests.assert_clean

    @classmethod
    def _seed(cls):
        client = fixtures.HttpClient(cls.srv.base_url)
        assert client.json("POST", "/api/v1/auth/login", {"username": fixtures.ADMIN[0], "password": fixtures.ADMIN[1]})[0] == 200
        status, _, key = client.json("POST", "/api/v1/tokens", {"name": "nav-fixture"})
        assert status == 201
        for event_type, agent, text, meta in (
            ("agent_message", "Coordinator", "Please verify the invoice totals.", {"to_agent": "Verifier"}),
            ("decision", "Verifier", "Use the bank export as the source of truth.", {"reason": "Settlement dates."}),
            ("blocker", "Verifier", "Waiting for the final receipt.", {}),
        ):
            status, _, body = client.json("POST", "/api/v1/ingest/event", {
                "host_id": "qa-nav-host", "harness": "qa", "agent_name": agent, "event_type": event_type, "message": text,
                "metadata": {"mission_id": "close-books", "task_id": "verify", **meta},
            }, headers={"Authorization": "Bearer " + key["token"]})
            assert status == 200, body

    def page(self, view, reduced=True):
        width, height, mobile = VIEWPORTS[view]
        pg = self.browser.new_page(width, height, mobile)
        self.addCleanup(pg.close)
        pg.reduced_motion(reduced)
        pg.goto(self.srv.base_url + "/")
        pg.wait("document.querySelector('#login-form') && getComputedStyle(document.querySelector('#login-view')).display !== 'none'")
        pg.type("#username", fixtures.ADMIN[0])
        pg.type("#password", fixtures.ADMIN[1])
        pg.click("#login-form button[type=submit]")
        pg.wait("!document.querySelector('#app-view').classList.contains('hidden')")
        pg.wait("document.querySelectorAll('#mission-preview .mp-card').length > 0", what="mission cards")
        return pg

    def offset_of(self, pg, section):
        """How far the section's top is from where the menu leaves room for it (0 = resting at the top)."""
        return pg.eval("(() => { const el = document.getElementById(%s); const pad = parseFloat(getComputedStyle(document.documentElement).scrollPaddingTop) || 0; return Math.round(el.getBoundingClientRect().top - pad) || 0; })()" % json.dumps(section))

    def test_menu_order_follows_the_page_and_each_button_lands_on_its_own_section(self):
        for view in ("desktop", "mobile"):
            with self.subTest(view=view):
                pg = self.page(view)
                order = pg.eval("""[...document.querySelectorAll('.section-nav a[href^="#"]')].map(a => {
                    const el = document.getElementById(a.getAttribute('href').slice(1));
                    return [a.getAttribute('href'), Math.round(el.getBoundingClientRect().top + scrollY)]; })""")
                tops = [top for _, top in order]
                self.assertEqual(tops, sorted(tops), f"menu order differs from the page: {order}")
                for href, _ in order:
                    pg.eval("window.scrollTo({top: 0, behavior: 'instant'})")
                    time.sleep(0.1)
                    pg.click(f'.section-nav a[href="{href}"]')
                    time.sleep(0.3)
                    self.assertEqual(pg.eval(ACTIVE), [href], f"{view}: {href} marked another button")
                    self.assertEqual(pg.eval("location.hash"), href)
                    self.assertLessEqual(abs(self.offset_of(pg, href[1:])), 6, f"{view}: {href} did not reach the top")
                self.assert_clean(pg, view)

    def test_a_section_reached_while_panels_above_it_grow_stays_in_place(self):
        """The production bug: Hosts clicked while the map was still loading ended on Agent work or Alerts."""
        pg = self.page("desktop", reduced=False)
        pg.click('.section-nav a[href="#hosts"]')
        time.sleep(0.15)
        pg.eval("""(() => { const grow = document.createElement('div'); grow.id = 'late-panel'; grow.style.height = '2600px';
                    document.getElementById('activity-map').append(grow); })()""")
        time.sleep(0.6)
        pg.eval("document.getElementById('late-panel').style.height = '3400px'")
        time.sleep(2.0)
        self.assertLessEqual(abs(self.offset_of(pg, "hosts")), 8, "Hosts drifted away while the page grew")
        self.assertEqual(pg.eval(ACTIVE), ["#hosts"])
        # Once the person scrolls on their own, the page is theirs again.
        pg.send("Input.dispatchMouseEvent", {"type": "mouseWheel", "x": 700, "y": 400, "deltaX": 0, "deltaY": -5000})
        pg.wait("scrollY < document.getElementById('hosts').offsetTop - 2000", what="manual scroll")
        time.sleep(0.4)
        self.assertNotEqual(pg.eval(ACTIVE), ["#hosts"])

    def test_menu_stays_on_screen_and_follows_the_scroll(self):
        for view in VIEWPORTS:
            with self.subTest(view=view):
                pg = self.page(view)
                for section in ("hosts", "agent-work", "alerts", "needs-attention"):
                    pg.eval(f"document.getElementById({json.dumps(section)}).scrollIntoView({{behavior: 'instant', block: 'start'}})")
                    time.sleep(0.25)
                    nav = pg.eval("""(() => { const r = document.querySelector('.section-nav').getBoundingClientRect();
                        return {top: Math.round(r.top), bottom: Math.round(r.bottom)}; })()""")
                    self.assertTrue(nav["top"] >= -2 and nav["bottom"] > 0, f"{view}: menu left the screen at {section}: {nav}")
                    self.assertEqual(pg.eval(ACTIVE), ["#" + section], f"{view}: wrong section while at {section}")
                    # The mint marker sits under the current button.
                    gap = pg.eval("""(() => { const m = document.querySelector('.section-nav .nav-indicator').getBoundingClientRect();
                        const a = document.querySelector('.section-nav a.is-active').getBoundingClientRect();
                        return Math.abs(m.left - a.left) + Math.abs(m.top - a.top); })()""")
                    self.assertLessEqual(gap, 2, f"{view}: marker is not under {section}")
                    self.assertTrue(pg.eval("""(() => { const nav = document.querySelector('.section-nav'), a = nav.querySelector('a.is-active');
                        const n = nav.getBoundingClientRect(), r = a.getBoundingClientRect();
                        return r.left >= n.left - 1 && r.right <= n.right + 1; })()"""), f"{view}: current button hidden in the menu")
                self.assert_clean(pg, view)

    def test_arrival_effect_and_reduced_motion(self):
        pg = self.page("desktop", reduced=False)
        pg.click('.section-nav a[href="#alerts"]')
        time.sleep(0.1)
        self.assertGreater(pg.eval("document.getElementById('alerts').getAnimations({subtree: true}).length"), 0)
        quiet = self.page("desktop", reduced=True)
        quiet.click('.section-nav a[href="#hosts"]')
        time.sleep(0.1)
        state = quiet.eval("""(() => { const el = document.getElementById('hosts');
            return {cls: el.classList.contains('is-arriving'), anims: el.getAnimations({subtree: true}).length,
                    ring: getComputedStyle(el, '::after').opacity}; })()""")
        self.assertEqual(state, {"cls": True, "anims": 0, "ring": "1"}, "reduced motion: a still ring, no animation")
        quiet.wait("!document.getElementById('hosts').classList.contains('is-arriving')", what="ring removed")

    def test_activity_map_shows_the_latest_missions_as_cards(self):
        for view in ("desktop", "mobile"):
            with self.subTest(view=view):
                pg = self.page(view)
                card = pg.eval("""(() => { const c = document.querySelector('#mission-preview .mp-card');
                    return {title: c.querySelector('.mp-title').textContent, who: c.querySelector('.mp-who').textContent,
                            kind: c.querySelector('.mp-kind').textContent, text: c.querySelector('.mp-text').textContent,
                            meta: c.querySelector('.mp-meta').textContent, href: c.querySelector('a').getAttribute('href')}; })()""")
                self.assertEqual(card["title"], "close-books")
                self.assertIn("Verifier", card["who"])
                self.assertEqual(card["kind"], "Blocker")
                self.assertEqual(card["text"], "Waiting for the final receipt.")
                self.assertIn("3 updates", card["meta"])
                self.assertIn("2 agents", card["meta"])
                self.assertTrue(card["href"].startswith("/missions?mission="))
                self.assertIn("close-books", card["href"])
                self.assert_clean(pg, view)


if __name__ == "__main__":
    unittest.main()
