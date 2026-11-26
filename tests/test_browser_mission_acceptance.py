"""Operator journey from the activity map to mission evidence and back to Live."""
import json
import sqlite3
import time
import unittest
from urllib.parse import urlencode

import test_browser_live_readability as fixtures


class MissionBrowserAcceptanceTests(unittest.TestCase):
    setUpClass = classmethod(fixtures.LiveReadabilityBrowserTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.LiveReadabilityBrowserTests.tearDownClass.__func__)
    assert_clean = fixtures.LiveReadabilityBrowserTests.assert_clean

    @classmethod
    def _seed(cls):
        client = fixtures.HttpClient(cls.srv.base_url)
        status, _, _ = client.json("POST", "/api/v1/auth/login", {
            "username": fixtures.ADMIN[0], "password": fixtures.ADMIN[1],
        })
        if status != 200:
            raise AssertionError(f"Fixture login returned {status}")
        status, _, key = client.json("POST", "/api/v1/tokens", {"name": "mission-fixture"})
        if status != 201:
            raise AssertionError(f"Fixture token returned {status}")

        def emit(event_type, agent, message, **metadata):
            status, _, body = client.json("POST", "/api/v1/ingest/event", {
                "host_id": "qa-mission-host", "harness": "qa", "agent_name": agent,
                "event_type": event_type, "message": message, "metadata": metadata,
            }, headers={"Authorization": "Bearer " + key["token"]})
            if status != 200:
                raise AssertionError(f"Mission event returned {status}")
            return body["event_id"]

        cls.decision = emit("decision", "Verifier", "Compare both invoice batches.",
                            mission_id="reconcile", task_id="check-invoices",
                            reason="Both batches share a cutoff date.", reasoning="PRIVATE QA INNER TEXT")
        cls.message = emit("agent_message", "Coordinator", "Send the verified totals.",
                           mission_id="reconcile", task_id="check-invoices", to_agent="Verifier")
        emit("blocker", "Verifier", "Waiting for final receipt.",
             mission_id="reconcile", task_id="check-invoices")
        emit("memory_saved", "Verifier", "The cutoff uses local business time.",
             mission_id="reconcile", task_id="check-invoices")
        # A more recent mission ensures the explicit map link wins over the default selection.
        time.sleep(0.02)
        emit("decision", "Reviewer", "Check the queue independently.",
             mission_id="other-mission", task_id="check-queue")

        with sqlite3.connect(cls.srv.db_path) as db:
            db.executemany(
                """INSERT INTO events
                    (host_id,harness,agent_name,event_type,severity,message,created_at)
                    VALUES ('qa-mission-host','qa','Fixture','note','INFO','Following events',?)""",
                ((time.time(),) for _ in range(505)),
            )

    def test_map_opens_the_selected_mission_and_the_exact_live_event(self):
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
                selector = "#mission-preview a[href*='reconcile']"
                page.wait(f"!!document.querySelector({json.dumps(selector)})")
                link = page.eval(f"document.querySelector({json.dumps(selector)}).href")
                page.goto(link)
                page.wait("document.querySelector('#objective').innerText === 'reconcile'")
                text = page.eval("document.querySelector('#events').innerText")
                for expected in (
                    "Coordinator → Verifier", "Send the verified totals.", "Reported reason: Both batches share a cutoff date.",
                    "Waiting for final receipt.", "The cutoff uses local business time.",
                ):
                    self.assertIn(expected, text)
                self.assertNotIn("Check the queue independently", text)
                self.assertNotIn("PRIVATE QA INNER TEXT", text)
                event_link = "/live?" + urlencode({"event": f"event:{self.decision}", "organization": 1})
                self.assertTrue(page.eval(
                    f"Array.from(document.querySelectorAll('#events a')).some(a => a.getAttribute('href') === {json.dumps(event_link)})"
                ))
                page.goto(self.srv.base_url + event_link)
                selected = f'tr[aria-selected="true"][data-key="event:{self.decision}"]'
                page.wait(f"!!document.querySelector({json.dumps(selected)})")
                page.eval(f"document.querySelector({json.dumps(selected)}).focus()")
                page.key("Enter", "Enter")
                page.wait(f"""!!document.querySelector('#event-dialog[open] [data-ev-key="event:{self.decision}"]')""")
                page.wait("document.querySelector('#event-dialog-body').innerText.includes('Compare both invoice batches.')")
                self.assertNotIn("PRIVATE QA INNER TEXT", page.eval("document.querySelector('#event-dialog-body').textContent"))
                self.assert_clean(page, view)
