"""Open a coverage count in Live and inspect its original event on desktop and mobile."""
import sqlite3
import time
import unittest

import test_browser_live_readability as fixtures
from test_output_coverage import step


class OutputCoverageBrowserTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.LiveReadabilityBrowserTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.LiveReadabilityBrowserTests.tearDownClass.__func__)
    login_and_open = fixtures.LiveReadabilityBrowserTests.login_and_open
    assert_clean = fixtures.LiveReadabilityBrowserTests.assert_clean

    @classmethod
    def _seed(cls):
        now = int(time.time())
        with sqlite3.connect(cls.srv.db_path) as conn:
            cls.older = step(conn, ts=now - 7200, reason="capture_disabled")
            cls.disabled = step(conn, ts=now - 240, reason="capture_disabled")
            cls.empty = step(conn, ts=now - 235, output="", exit_code=0)
            cls.pending = step(conn, ts=now - 232, outcome="in_progress")
            # The requested events are outside the initial feed. Coverage opens by stored ID.
            for _ in range(505):
                step(conn, ts=now - 9, event_type="heartbeat")

    def test_fixed_window_opens_only_the_expected_evidence(self):
        for view, (width, height, mobile) in fixtures.VIEWPORTS.items():
            with self.subTest(view=view):
                pg = self.browser.new_page(width, height, mobile)
                self.addCleanup(pg.close)
                pg.reduced_motion()
                self.login_and_open(pg, "")
                pg.wait("!!document.querySelector('#rows tr[data-key]')")
                if mobile:
                    pg.click("#mobile-tree-btn")
                    pg.settled("#open-output-coverage")
                pg.click("#open-output-coverage")
                pg.wait("!!document.querySelector('#coverage-counts tr:nth-child(2)')")
                for label in ("Completed, 2", "Output recorded, 1", "Output missing, 1", "Empty output, 1", "Pending, 1"):
                    self.assertTrue(pg.eval(f"""!!document.querySelector('[aria-label="grep, {label}"]')"""), label)
                for label, ident in (("Capture disabled", self.disabled), ("Empty output", self.empty),
                                     ("Pending", self.pending)):
                    selector = f'[aria-label="grep, {label}, 1"]'
                    pg.click(selector)
                    pg.wait("document.querySelector('#coverage-status').innerText === '1 of 1 matching events'")
                    self.assertEqual(pg.eval("document.querySelector('#coverage-events button').innerText"),
                                     f"Open event #{ident}")
                    pg.click("#coverage-events button")
                    pg.wait(f"""!!document.querySelector('#event-dialog[open] [data-ev-key="event:{ident}"]')""")
                    if label == "Empty output":
                        pg.wait("document.querySelector('#event-dialog-body').innerText.includes('0 bytes')")
                    if label == "Capture disabled":
                        pg.wait("document.querySelector('#event-dialog-body').innerText.toLowerCase().includes('capture disabled')")
                    pg.click("#event-dialog-close")
                    pg.click("#coverage-back")
                    self.assertTrue(pg.eval(f"document.activeElement.matches('{selector}')"))
                period = pg.eval("document.querySelector('#coverage-period').innerText")
                pg.click("#coverage-refresh")
                pg.wait("!!document.querySelector('#coverage-counts tr:nth-child(2)')")
                self.assertEqual(pg.eval("document.querySelector('#coverage-period').innerText"), period)
                pg.eval("""const select = document.querySelector('#coverage-window');
                    select.value = '86400'; select.dispatchEvent(new Event('change'));""")
                pg.wait("""!!document.querySelector('[aria-label="grep, Capture disabled, 2"]')""")
                pg.click('[aria-label="grep, Capture disabled, 2"]')
                pg.wait("document.querySelector('#coverage-status').innerText === '2 of 2 matching events'")
                self.assertEqual(pg.eval("Array.from(document.querySelectorAll('#coverage-events button'), b => b.innerText)"),
                                 [f"Open event #{self.disabled}", f"Open event #{self.older}"])
                self.assert_clean(pg, view)
