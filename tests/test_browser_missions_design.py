"""Mission workspace identity, responsive layout and motion preferences."""
import os
from pathlib import Path
import test_browser_mission_acceptance as fixtures


class MissionDesignTests(fixtures.MissionBrowserAcceptanceTests):
    def test_workspace_layout_and_mission_change_preserve_evidence(self):
        for name, width, height, mobile in [('desktop', 1440, 900, False), ('tablet', 820, 900, False), ('mobile', 390, 844, True)]:
            with self.subTest(view=name):
                page = self.browser.new_page(width, height, mobile)
                self.addCleanup(page.close)
                page.reduced_motion()
                page.goto(self.srv.base_url + '/#access')
                page.wait("document.querySelector('#login-form')?.getBoundingClientRect().height > 0")
                page.type('#username', fixtures.fixtures.ADMIN[0])
                page.type('#password', fixtures.fixtures.ADMIN[1])
                page.click('#login-form button[type=submit]')
                page.wait("!document.querySelector('#app-view').classList.contains('hidden')")
                page.goto(self.srv.base_url + '/missions?mission=Reported%20events%2Freconcile')
                page.wait("document.querySelector('#events li') !== null")
                page.eval("document.querySelector('.skip-link').focus()")
                self.assertTrue(page.eval("""(() => {
                    const link = document.querySelector('.skip-link');
                    const rect = link.getBoundingClientRect();
                    return rect.top >= 0 && rect.width > 20 && getComputedStyle(link).clipPath === 'none';
                })()"""))
                # Use the real select/change path; preserve the selector focus and its shareable URL.
                page.eval("""(() => {
                    const select = document.querySelector('#mission');
                    select.selectedIndex = [...select.options].findIndex(o => o.text === 'reconcile');
                    select.focus(); select.dispatchEvent(new Event('change', {bubbles:true}));
                })()""")
                self.assertEqual(page.eval("document.querySelector('#objective').textContent"), 'reconcile')
                self.assertEqual(page.eval("document.activeElement.id"), 'mission')
                self.assertTrue(page.eval("new URL(location.href).searchParams.get('mission').endsWith('/reconcile')"))
                self.assertEqual(page.eval("document.querySelector('#event-count').textContent"), '4')
                self.assertEqual(page.eval("document.querySelector('#agent-count').textContent"), '2')
                self.assertEqual(page.eval("document.querySelector('[data-kind=memory_saved] .timeline-kind').textContent"), 'Shared memory')
                self.assertNotEqual(page.eval("getComputedStyle(document.querySelector('[data-kind=blocker] .timeline-kind')).backgroundColor"),
                                    page.eval("getComputedStyle(document.querySelector('[data-kind=memory_saved] .timeline-kind')).backgroundColor"))
                audit = page.eval("""(() => {
                    const css = s => getComputedStyle(document.querySelector(s));
                    return {
                        identity: [...document.styleSheets].some(s => s.href?.includes('/identity.css')),
                        texture: css('body').backgroundImage,
                        shadow: css('.timeline-card').boxShadow,
                        border: css('.timeline-card').borderTopWidth,
                        motion: css('.mission-stream').animationName,
                        current: document.querySelector('.mission-nav [aria-current]').textContent,
                        privateText: document.querySelector('#events').textContent.includes('PRIVATE QA INNER TEXT')
                    };
                })()""")
                self.assertTrue(audit['identity'])
                self.assertNotEqual(audit['texture'], 'none')
                self.assertNotEqual(audit['shadow'], 'none')
                self.assertEqual(audit['border'], '2px')
                self.assertEqual(audit['motion'], 'none')
                self.assertEqual(audit['current'], 'Missions')
                self.assertFalse(audit['privateText'])
                page.eval('window.scrollTo(0, 650)')
                self.assertEqual(page.eval("Math.round(document.querySelector('.mission-topbar').getBoundingClientRect().top)"), 0)
                page.eval('window.scrollTo(0, 0)')
                self.assert_clean(page, name)
                if os.environ.get('NEUROSWARM_DESIGN_SHOTS'):
                    directory = Path(os.environ['NEUROSWARM_DESIGN_SHOTS'])
                    directory.mkdir(parents=True, exist_ok=True)
                    page.screenshot(directory / f'missions-{name}.png')
                page.reduced_motion(False)
                page.eval("document.querySelector('#mission').dispatchEvent(new Event('change', {bubbles:true}))")
                self.assertEqual(page.eval("getComputedStyle(document.querySelector('.mission-stream')).animationName"), 'mission-arrive')
