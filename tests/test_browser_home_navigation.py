"""Check fragment navigation and the sign-in scroll position in Chromium."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import browser_cdp
from product_qa.test_acceptance_blackbox import SpawnedConsole
from test_browser_ui import ADMIN, VIEWPORTS


class HomeNavigationBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("SWARMCONTROL_BROWSER_TESTS", "").lower() == "skip":
            raise unittest.SkipTest("SWARMCONTROL_BROWSER_TESTS=skip")
        binary = browser_cdp.find_browser()
        if not binary:
            raise AssertionError("Run python3 deploy/fetch_test_browser.py to install the test browser")
        state = tempfile.TemporaryDirectory(prefix="swarm-home-qa-")
        cls.addClassCleanup(state.cleanup)
        cls.server = SpawnedConsole(Path(state.name))
        cls.addClassCleanup(cls.server.stop)
        cls.browser = browser_cdp.Browser(binary)
        cls.addClassCleanup(cls.browser.close)

    def page(self, viewport):
        page = self.browser.new_page(*viewport)
        self.addCleanup(page.close)
        page.reduced_motion()
        return page

    def test_direct_install_link_reaches_setup(self):
        for name, viewport in VIEWPORTS.items():
            for path in ("/#self-host", "/?view=home#self-host"):
                with self.subTest(viewport=name, path=path):
                    page = self.page(viewport)
                    # The auth probe can finish after Chromium first resolves the fragment.
                    page.send("Network.emulateNetworkConditions", {
                        "offline": False, "latency": 120, "downloadThroughput": -1, "uploadThroughput": -1,
                    })
                    page.goto(self.server.base_url + path)
                    page.wait(
                        "document.querySelector('#self-host').getBoundingClientRect().height > 0",
                        what="public home displayed",
                    )
                    position = page.eval("""new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(() => {
                        const root = document.documentElement;
                        const sectionTop = document.querySelector('#self-host').getBoundingClientRect().top + scrollY;
                        const padding = parseFloat(getComputedStyle(root).scrollPaddingTop) || 0;
                        resolve({actual: scrollY, expected: Math.min(sectionTop - padding, root.scrollHeight - innerHeight)});
                    })))""")
                    self.assertAlmostEqual(position["actual"], position["expected"], delta=2,
                                           msg="The install link should bring its section into view")

    def test_console_opens_at_top_after_sign_in(self):
        for name, viewport in VIEWPORTS.items():
            with self.subTest(viewport=name):
                page = self.page(viewport)
                page.goto(self.server.base_url + "/")
                page.wait("document.querySelector('.folio-enter').getBoundingClientRect().height > 0")
                page.click(".folio-enter")
                page.wait("location.hash === '#access' && scrollY > innerHeight", what="access section")
                page.type("#username", ADMIN[0])
                page.type("#password", ADMIN[1])
                page.click("#login-form button[type=submit]")
                page.wait("document.querySelector('#kpi-hosts').textContent.trim() === '0'",
                          what="loaded dashboard counts")
                scroll_y = page.eval(
                    "new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame("
                    "() => resolve(scrollY))))"
                )
                self.assertLessEqual(scroll_y, 1, "Dashboard inherited the scroll position of the access form")
