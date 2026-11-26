"""Activity map → Team: who replied to whom, about which mission, and who works on what (recorded messages only)."""
import json
import unittest

import test_browser_live_readability as fixtures


class TeamMapBrowserTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.LiveReadabilityBrowserTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.LiveReadabilityBrowserTests.tearDownClass.__func__)
    assert_clean = fixtures.LiveReadabilityBrowserTests.assert_clean

    @classmethod
    def _seed(cls):
        client = fixtures.HttpClient(cls.srv.base_url)
        assert client.json("POST", "/api/v1/auth/login", {"username": fixtures.ADMIN[0], "password": fixtures.ADMIN[1]})[0] == 200
        status, _, key = client.json("POST", "/api/v1/tokens", {"name": "team-fixture"})
        assert status == 201

        def emit(event_type, agent, message, **metadata):
            status, _, body = client.json("POST", "/api/v1/ingest/event", {
                "host_id": "qa-team-host", "harness": "qa", "agent_name": agent,
                "event_type": event_type, "message": message, "metadata": metadata,
            }, headers={"Authorization": "Bearer " + key["token"]})
            assert status == 200, body
            return body["event_id"]

        emit("agent_message", "Coordinator", "Please verify the invoice totals.", mission_id="close-books", task_id="verify", to_agent="Verifier")
        emit("agent_message", "Verifier", "Totals match except one refund.", mission_id="close-books", task_id="verify", to_agent="Coordinator")
        emit("agent_message", "Coordinator", "Check the refund with the bank export.", mission_id="close-books", task_id="verify", to_agent="Verifier")
        emit("agent_message", "Coordinator", "Draft the release note once totals pass.", mission_id="close-books", task_id="notes", to_agent="Writer")
        emit("decision", "Verifier", "Use the bank export as the source of truth.", mission_id="close-books", task_id="verify",
             reason="It is the only record with settlement dates.")
        emit("agent_message", "Reviewer", "Unrelated: check the queue.", mission_id="other", task_id="queue", to_agent="Writer")

    def test_team_tab_shows_the_conversation_network_and_filters_by_mission(self):
        for view, (width, height, mobile) in fixtures.VIEWPORTS.items():
            with self.subTest(view=view):
                page = self.browser.new_page(width, height, mobile)
                self.addCleanup(page.close)
                page.reduced_motion()
                page.goto(self.srv.base_url + "/#activity")
                page.wait("document.querySelector('#login-form') && getComputedStyle(document.querySelector('#login-view')).display !== 'none'")
                page.type("#username", fixtures.ADMIN[0])
                page.type("#password", fixtures.ADMIN[1])
                page.click("#login-form button[type=submit]")
                page.wait("!!document.querySelector(\"#activity-map .ap-tab[data-view='team']\")", what="team tab")
                page.click("#activity-map .ap-tab[data-view='team']")
                page.wait("document.querySelectorAll('#activity-map .tm-edge').length >= 3", what="team graph")
                edges = page.eval("Object.fromEntries([...document.querySelectorAll('#activity-map .tm-edge')].map(g => [g.dataset.edge, g.querySelector('text').textContent]))")
                self.assertEqual(edges["Coordinator→Verifier"], "2")
                self.assertEqual(edges["Verifier→Coordinator"], "1")
                self.assertEqual(edges["Coordinator→Writer"], "1")
                self.assertEqual(edges["Reviewer→Writer"], "1")
                talks = page.eval("[...document.querySelectorAll('#activity-map .tm-talk')].map(d => d.textContent.replace(/\\s+/g, ' '))")
                self.assertTrue(any("Coordinator → Verifier" in t and "Check the refund with the bank export." in t for t in talks), talks)
                self.assertTrue(page.eval("document.querySelector('#activity-map .tm-talk').open"), "the most recent conversation is open")
                roster = page.eval("document.querySelector('#activity-map .am-ws-grid').innerText")
                self.assertIn("Verifier", roster)
                self.assertIn("Use the bank export as the source of truth.", roster)
                self.assertIn("Stated reason: It is the only record with settlement dates.", roster)
                art = __import__("os").environ.get("SWARMCONTROL_BROWSER_ARTIFACTS", "").strip()
                if art:
                    import base64
                    from pathlib import Path
                    Path(art).mkdir(parents=True, exist_ok=True)
                    box = page.eval("(() => { const r = document.querySelector('#activity-map .ap-view').getBoundingClientRect(); return [r.x + scrollX, r.y + scrollY, r.width, Math.min(r.height, 1600)]; })()")
                    data = page.send("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True,
                                                                 "clip": {"x": box[0], "y": box[1], "width": box[2], "height": box[3], "scale": 1}})["data"]
                    (Path(art) / f"{view}-team.png").write_bytes(base64.b64decode(data))
                # Choose one mission: the unrelated conversation disappears.
                page.eval("(() => { const s = document.querySelector('[data-team-mission]'); s.value = 'close-books'; s.dispatchEvent(new Event('change', {bubbles: true})); })()")
                page.wait("!document.querySelector('#activity-map .tm-edge[data-edge=\"Reviewer→Writer\"]')", what="mission filter")
                self.assertTrue(page.eval("!!document.querySelector('#activity-map a[href=\"/missions?mission=close-books\"]')"))
                self.assertEqual(page.overflow()["offenders"], [])
                self.assert_clean(page, view)


if __name__ == "__main__":
    unittest.main()
