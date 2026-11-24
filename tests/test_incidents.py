"""Roadmap 5. Local fixtures only. Exercise migration, writes, actual HTTP and the incident UI."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "tests")]
import browser_cdp
from db import Database, SCHEMA_SQL
from event_feed import feed
from guardrails import GuardrailEngine
import incidents
from live_history import history
from product_qa.test_acceptance_blackbox import HttpClient, SpawnedConsole


class IncidentStorageTests(unittest.TestCase):
    def test_redacted_case_fields_and_evidence(self):
        db = Database(":memory:")
        self.addCleanup(db.close)
        row = db.upsert_open_alert("node", "RUNAWAY_CPU", "WARNING", "CPU on /private/staff/host.csv",
                                   "worker --token opaque-fixture-value at C:\\private\\payroll.csv",
                                   {"process": {"pid": 8, "cpu_pct": 93, "comm": "sc_ro_fixture_reader_example",
                                                "user": "private-user", "cmdline": "private-argument"},
                                    "sample": "private-message"})
        public = json.dumps(incidents.detail(db, row, None))
        for private in ("host.csv", "payroll.csv", "opaque-fixture-value", "sc_ro_fixture", "private-user",
                        "private-argument", "private-message"):
            self.assertNotIn(private, public)
        self.assertIn('"cpu_pct": 93', public)

    def test_migrate_open_and_acked_duplicates_without_losing_legacy_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "v1.db"
            legacy = sqlite3.connect(path)
            legacy.row_factory = sqlite3.Row
            legacy.executescript(SCHEMA_SQL)
            legacy.execute("CREATE TABLE resource_migrations(version INTEGER PRIMARY KEY, applied_at REAL)")
            legacy.execute("INSERT INTO resource_migrations VALUES(1,1)")
            legacy.executemany("""INSERT INTO alerts(id,host_id,rule_code,severity,title,summary,evidence_json,status,
                                  created_at,updated_at,acked_by,acked_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", [
                (10, "node", "HOST_RAM_PRESSURE", "CRITICAL", "RAM", "older", '{"mem_used_mb":94,"old_key":22}', "ACKED", 1, 3, "first-op", 3),
                (11, "node", "HOST_RAM_PRESSURE", "CRITICAL", "RAM", "newer", '{"mem_used_mb":99}', "OPEN", 4, 5, None, None),
                (12, "node", "STALE_HOST_HEARTBEAT", "WARNING", "Missed", "gap", '{}', "RESOLVED", 10, 20, "system", 20),
                (13, "node", "STALE_HOST_HEARTBEAT", "WARNING", "Missed again", "gap", '{}', "OPEN", 30, 40, None, None),
            ])
            Database.append_audit(legacy, "first-op", "ALERT_ACKED", "alert:10", "Acknowledged")
            original = [dict(r) for r in legacy.execute("SELECT * FROM alerts ORDER BY id")]
            old_head = legacy.execute("SELECT entry_hash FROM audit_log").fetchone()[0]
            legacy.commit()
            legacy.close()
            db = Database(path)
            try:
                self.assertEqual(db.query_all("SELECT * FROM incident_v1_snapshots ORDER BY id"), original)
                self.assertEqual(db.verify_audit_chain()["head"], old_head)
                case = incidents.detail(db, 11, None)
                a = case["alert"]
                self.assertEqual((a["id"], a["owner"], a["status"], a["acked_at"]), (10, "first-op", "ACKED", 3))
                self.assertTrue(a["count_is_minimum"])
                self.assertEqual(a["occurrence_count"], 2)
                self.assertEqual([h["data"]["evidence"]["mem_used_mb"] for h in case["history"]
                                  if h["kind"] == "legacy_snapshot"], [99, 94])
                stale = incidents.detail(db, 12, None)["alert"]
                self.assertEqual((stale["resolution"], stale["resolved_at"], stale["acked_by"], stale["owner"]),
                                 ("heartbeat_resumed", 20, None, None))
                self.assertEqual(incidents.find_case(db, 13)["previous_id"], 12)
                self.assertEqual({r["id"] for r in feed(db)["records"]}, {10, 12, 13})
                self.assertEqual({r["id"] for r in history(db, 1, {})["records"]}, {10, 12, 13})
                self.assertEqual(db.upsert_open_alert("node", "HOST_RAM_PRESSURE", "CRITICAL", "RAM", "96%", {}), 10)
            finally:
                db.close()
            db = Database(path)
            try:
                self.assertEqual(incidents.find_case(db, 11)["occurrence_count"], 3)
                self.assertEqual(db.query_one("SELECT COUNT(*) n FROM incident_history WHERE kind='legacy_snapshot'")["n"], 4)
            finally:
                db.close()

    def test_two_writers_and_interrupted_signal_are_atomic(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "concurrent.db"
            first, second = Database(path), Database(path)
            try:
                def send(i):
                    db = first if i % 2 else second
                    return db.upsert_open_alert("node", "HOST_RAM_PRESSURE", "CRITICAL", "RAM", "above threshold",
                                                {"mem_used_mb":96})
                with ThreadPoolExecutor(max_workers=4) as pool:
                    ids = list(pool.map(send, range(60)))
                self.assertEqual(set(ids), {1})
                db = first
                db.execute("""CREATE TRIGGER injected_failure BEFORE INSERT ON incident_history
                              BEGIN SELECT RAISE(ABORT,'fixture'); END""")
                with self.assertRaises(sqlite3.IntegrityError):
                    send(1)
                row = incidents.detail(db, 1, None)
                self.assertEqual(row["alert"]["occurrence_count"], 60)
                self.assertEqual(len(row["history"]), 50)
                page2 = incidents.detail(db, 1, row["next_before"])
                self.assertEqual(len(page2["history"]), 10)
                self.assertFalse({e["id"] for e in row["history"]} & {e["id"] for e in page2["history"]})
                self.assertIsNone(page2["next_before"])
                db.execute("DROP TRIGGER injected_failure")
                self.assertEqual(send(0), 1)
                self.assertEqual(incidents.find_case(db, 1)["occurrence_count"], 61)
            finally:
                first.close()
                second.close()

    def test_stale_dashboard_reads_and_sparse_heartbeats_are_not_extra_signals_or_recovery(self):
        db = Database(":memory:")
        self.addCleanup(db.close)
        engine = GuardrailEngine(db)
        hb = {"host_id":"sparse", "processes":[{"comm":"agent", "cpu_pct":95, "rss_mb":3000}]}
        engine.evaluate_heartbeat(hb)
        engine.evaluate_heartbeat({"host_id":"sparse"})
        engine.evaluate_heartbeat({"host_id":"sparse", "processes":[{"comm":"agent"}]})
        self.assertEqual(len(db.query_all("SELECT id FROM incident_cases WHERE status='OPEN'")), 2)
        engine.evaluate_heartbeat({"host_id":"sparse", "processes":[]})
        self.assertEqual(len(db.query_all("SELECT id FROM incident_cases WHERE status='RESOLVED'")), 2)
        db.upsert_host_heartbeat(hb, "HEALTHY")
        db.execute("UPDATE hosts SET last_seen_at=1")
        engine.check_stale_hosts()
        row = db.query_one("SELECT * FROM incident_cases WHERE rule_code='STALE_HOST_HEARTBEAT'")
        with db.transaction():
            incidents.acknowledge(db, row, "oncall")
        for _ in range(3):
            engine.check_stale_hosts()
        engine.resolve_stale("sparse")
        row = incidents.find_case(db, row["id"])
        self.assertEqual((row["occurrence_count"], row["acked_by"], row["owner"], row["resolved_by"]),
                         (1, "oncall", "oncall", "system"))
        # Refreshing the dashboard cannot open another case for the very same missed heartbeat.
        engine.check_stale_hosts()
        self.assertEqual(db.query_one("SELECT count(*) n FROM incident_cases WHERE rule_code='STALE_HOST_HEARTBEAT'")["n"], 1)
        db.upsert_host_heartbeat(hb, "HEALTHY")
        engine.stale_host_sec = 0
        engine.check_stale_hosts()
        later = db.query_one("SELECT * FROM incident_cases WHERE rule_code='STALE_HOST_HEARTBEAT' AND status='OPEN'")
        self.assertEqual(later["previous_id"], row["id"])


class ConsoleFixture(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.console = SpawnedConsole(Path(tmp.name))
        self.addCleanup(self.console.stop)
        self.pw = secrets.token_urlsafe(20)
        self.admin, self.team = self.register("first-admin")
        self.sensor = self.token(self.admin, "ingest")

    def client(self):
        return HttpClient(self.console.base_url)

    def api(self, who, method, path, body=None, code=200, token=None):
        auth = {"Authorization":"Bearer " + token} if token else None
        status, _, data = who.json(method, "/api/v1/" + path, body, headers=auth)
        self.assertEqual(status, code, (method, path, data.get("error")))
        return data

    def register(self, name):
        who = self.client()
        data = self.api(who, "POST", "auth/register",
                        {"username":name, "password":self.pw, "organization":name + " workspace"}, 201)
        return who, data

    def member(self, name, role):
        invite = self.api(self.admin, "POST", "invitations", {"username":name, "role":role}, 201)
        who = self.client()
        data = self.api(who, "POST", "auth/accept-invitation", {"username":name, "password":self.pw, "token":invite["token"]})
        return who, data["user"]["id"]

    def token(self, who, scope):
        return self.api(who, "POST", "tokens", {"name":scope, "scope":scope}, 201)["token"]

    def beat(self, used, sensor=None, host="rack-01"):
        return self.api(self.client(), "POST", "ingest/heartbeat",
                        {"host_id":host, "mem_total_mb":100, "mem_used_mb":used}, token=sensor or self.sensor)

    def step(self, filename, sensor=None):
        stamp = datetime.fromtimestamp(time.time()-2, timezone.utc).isoformat()
        res = self.api(self.client(), "POST", "ingest/activity", {
            "host_id":"rack-01", "activity_enabled":True, "activity_roots":["/work/invoices"], "sessions":[{
                "session_id":"s-1","harness":"codex","agent_name":"builder","workspace":"/work/invoices",
                "steps":[{"category":"file_edit","tool":"apply_patch","file_basis":"confirmed","time":stamp,
                          "files":["/work/invoices/"+filename, "/work/invoices/.env", "/private/salaries.csv"],
                          "label":"PRIVATE_DIFF_BODY", "command":"PRIVATE_ARGUMENT"}]}]}, token=sensor or self.sensor)
        self.assertEqual(res["steps_persisted"], 1)


class IncidentHTTPTests(ConsoleFixture):
    def test_three_signals_ack_and_recovery_then_recurrence_isolated_by_tenant(self):
        admin = self.admin
        op, op_id = self.member("oncall", "operator")
        viewer, viewer_id = self.member("analyst", "viewer")
        other, beta = self.register("other-admin")
        other_sensor = self.token(other, "ingest")
        # Same host and case IDs in both organizations.
        self.step("src/invoice.py")
        self.step("src/foreign.py", other_sensor)
        first = self.beat(96)["alerts_triggered"][0]["id"]
        self.assertEqual(self.beat(95, other_sensor)["alerts_triggered"][0]["id"], first)
        path = f"alerts/{first}"
        read_token = self.token(admin, "read")
        self.api(self.client(), "GET", path, code=401)
        self.api(self.client(), "GET", path, code=401, token=self.sensor)
        # The actor and organization come from credentials. A foreign account cannot be selected by numeric ID.
        for forbidden_id in (beta["user"]["id"], viewer_id):
            self.api(admin, "POST", path + "/owner", {"owner_id":forbidden_id}, 404)
        self.api(viewer, "POST", path + "/owner", {"owner_id":op_id}, 403)
        self.api(self.client(), "POST", path + "/resolve", {"reason":"operator_verified"}, 403, token=read_token)
        self.api(viewer, "POST", path + "/ack", {}, 403)
        self.api(viewer, "POST", path + "/resolve", {"reason":"operator_verified"}, 403)
        self.api(op, "POST", path + "/owner", {"owner_id":op_id})
        self.assertEqual(self.beat(96)["alerts_triggered"][0]["id"], first)
        self.api(admin, "POST", path + "/ack", {})
        self.api(op, "POST", path + "/ack", {})  # retry does not replace the first acknowledger
        self.api(self.client(), "POST", "ingest/event", {"host_id":"rack-01","event_type":"observed_step",
                 "message":"private note", "metadata":{"journaled":1, "files":["fake-leaked.py"]}}, token=self.sensor)
        self.assertEqual(self.beat(97)["alerts_triggered"][0]["id"], first)
        self.api(self.client(), "POST", "ingest/heartbeat", {"host_id":"rack-01", "mem_total_mb":100}, token=self.sensor)
        a = self.api(viewer, "GET", path)["alert"]
        self.assertEqual((a["owner"], a["acked_by"], a["status"], a["occurrence_count"]), ("oncall", "first-admin", "ACKED", 3))
        self.assertEqual(self.api(admin, "GET", "digest")["fleet_status"], "CRITICAL")
        self.assertEqual(a["last_step"]["confirmed_files"], ["src/invoice.py"])
        self.assertEqual([r["id"] for r in self.api(admin, "GET", "alerts?status=ACTIVE")["alerts"]], [first])
        self.step("src/settled.py")
        self.assertEqual(self.beat(72)["status"], "HEALTHY")
        detail = self.api(self.client(), "GET", path, token=read_token)
        self.assertNotIn("assignees", detail)
        a = detail["alert"]
        self.assertEqual((a["acked_by"], a["owner"], a["status"], a["resolved_by"], a["resolution"]),
                         ("first-admin", "oncall", "RESOLVED", "system", "measurement_recovered"))
        self.assertEqual(a["last_step"]["confirmed_files"], ["src/settled.py"])
        self.assertEqual(self.api(admin, "GET", "alerts?status=ACTIVE")["alerts"], [])
        history_entries = list(reversed(detail["history"]))
        self.assertEqual([e["kind"] for e in history_entries],
                         ["opened", "assigned", "repeated", "acknowledged", "repeated", "resolved"])
        self.assertEqual([e["data"]["evidence"]["mem_used_mb"] for e in history_entries if "evidence" in e["data"]],
                         [96, 96, 97, 72])
        self.assertEqual(history_entries[0]["data"]["last_step"]["confirmed_files"], ["src/invoice.py"])
        self.assertEqual(history_entries[-1]["data"]["last_step"]["confirmed_files"], ["src/settled.py"])
        for private in (".env","/work/invoices","salaries.csv","fake-leaked","PRIVATE_DIFF_BODY","PRIVATE_ARGUMENT","src/foreign.py"):
            self.assertNotIn(private, json.dumps(detail))
        self.assertTrue(self.api(admin, "GET", "audit/verify")["ok"])
        relapse = self.beat(96)["alerts_triggered"][0]["id"]
        self.assertNotEqual(first, relapse)
        later = self.api(admin,"GET",f"alerts/{relapse}")["alert"]
        self.assertEqual((later["previous_id"], later["owner"], later["status"], later["occurrence_count"]),
                         (first, None, "OPEN", 1))
        self.api(op, "POST", path + "/ack", {}, 409)
        self.assertEqual(len(self.api(admin, "GET", "alerts?status=ALL")["alerts"]), 2)
        records = [r for r in self.api(admin, "GET", "event-feed")["records"] if r["kind"] == "alert"]
        self.assertEqual({(r["id"], r["state"], r["occurrence_count"]) for r in records},
                         {(first, "RESOLVED", 3), (relapse, "OPEN", 1)})
        archive = [r for r in self.api(admin, "GET", "live-records")["records"] if r["kind"] == "Alert"]
        self.assertEqual({(r["id"], r["owner"], r["acked_by"], r["previous_id"]) for r in archive},
                         {(first, "oncall", "first-admin", None), (relapse, None, None, first)})
        b = self.api(other, "GET", path)["alert"]
        self.assertEqual((b["occurrence_count"], b["status"], b["owner"], b["last_step"]["confirmed_files"]),
                         (1, "OPEN", None, ["src/foreign.py"]))
        self.api(other, "GET", f"alerts/{relapse}", code=404)
        oid = self.team["organization"]["id"]
        self.api(other, "POST", path + "/ack", {"organization_id":oid}, 409)
        self.api(other, "GET", path + f"?organization_id={oid}", code=409)
        self.assertEqual(self.api(other, "GET", path)["alert"]["status"], "OPEN")

    def test_event_only_rule_operator_confirmation_retries_and_unknown_step(self):
        for _ in range(4):
            self.api(self.client(), "POST", "ingest/event", {"host_id":"rack-01","event_type":"tool_error",
                "agent_name":"builder","harness":"codex","message":"timeout"}, token=self.sensor)
        a, = self.api(self.admin, "GET", "alerts")["alerts"]
        self.assertEqual(a["rule_code"], "LOOP_SUSPECTED")
        self.assertIsNone(a["last_step"])
        path = f"alerts/{a['id']}"
        self.beat(60)
        self.api(self.admin, "POST", path + "/resolve", {}, 400)
        self.api(self.admin, "POST", path + "/ack", {})
        self.assertEqual(self.api(self.admin, "GET", path)["alert"]["owner"], "first-admin")
        for _ in range(2):
            self.api(self.admin, "POST", path + "/resolve", {"reason":"operator_verified"})
        result = self.api(self.admin, "GET", path)
        self.assertEqual((result["alert"]["resolved_by"], result["alert"]["resolution"]), ("first-admin","operator_verified"))
        self.assertEqual([h["kind"] for h in result["history"]].count("resolved"), 1)
        self.api(self.admin, "GET", path + "?before=bad", code=400)


class IncidentBrowserTests(ConsoleFixture):
    def test_dashboard_live_history_recurrence_and_read_only_mobile(self):
        if os.environ.get("SWARMCONTROL_BROWSER_TESTS", "").lower() == "skip":
            self.skipTest("SWARMCONTROL_BROWSER_TESTS=skip")
        binary = browser_cdp.find_browser()
        self.assertTrue(binary, "Install the test browser with python3 deploy/fetch_test_browser.py")
        browser = browser_cdp.Browser(binary)
        self.addCleanup(browser.close)
        _, owner_id = self.member("ui-oncall", "operator")
        self.member("ui-reader", "viewer")
        self.step("src/invoice.py")
        case_id = self.beat(96)["alerts_triggered"][0]["id"]
        self.beat(96)

        def sign_in(name, mobile=False):
            page = browser.new_page(390, 844, True) if mobile else browser.new_page(1280, 900, False)
            self.addCleanup(page.close)
            page.goto(self.console.base_url + "/")
            page.wait("document.querySelector('#login-form') && getComputedStyle(document.querySelector('#login-view')).display !== 'none'")
            page.type("#username", name)
            page.type("#password", self.pw)
            page.click("#login-form button[type=submit]")
            page.wait("!!document.querySelector('#alerts-list a[href*=incident]')", what="Dashboard incident link")
            return page

        def heading(page, ident, status):
            expected = json.dumps(f"Incident #{ident} · {status}")
            page.wait(f"document.querySelector('#incident-dialog')?.open && document.querySelector('#incident-heading').textContent === {expected}")

        page = sign_in("first-admin")
        first_link = page.eval("document.querySelector('#alerts-list a[href*=incident]').href")
        page.click("#alerts-list a[href*=incident]")
        heading(page, case_id, "OPEN")
        self.assertEqual(page.eval("document.querySelector('#incident-count').textContent"), "2")
        page.eval(f"document.querySelector('#incident-owner').value = '{owner_id}'")
        page.click("[data-case-action=owner]")
        page.wait("document.querySelector('#incident-current-owner')?.textContent === 'ui-oncall'")
        page.click("[data-case-action=ack]")
        heading(page, case_id, "ACKED")
        self.beat(97)
        page.click("#incident-refresh")
        page.wait("document.querySelector('#incident-count')?.textContent === '3'")
        self.assertEqual(page.eval("document.querySelector('#incident-current-owner').textContent"), "ui-oncall")
        self.beat(72)
        page.click("#incident-refresh")
        heading(page, case_id, "RESOLVED")
        content = page.eval("document.querySelector('#incident-content').textContent")
        for expected in ("first-admin", "ui-oncall", "Reading returned below threshold", "src/invoice.py"):
            self.assertIn(expected, content)
        self.assertNotIn("PRIVATE_ARGUMENT", content)
        self.assertEqual(page.eval("document.querySelectorAll('[data-case-action]').length"), 0)
        page.wait("document.querySelector('#open-alerts-cnt')?.textContent === '0 open alerts'")
        page.click("#incident-history details summary")
        self.assertIn('"mem_used_mb": 72', page.eval("document.querySelector('#incident-history details[open]').innerText"))
        artifacts = os.environ.get("SWARMCONTROL_BROWSER_ARTIFACTS")
        if artifacts:
            Path(artifacts).mkdir(parents=True, exist_ok=True)
            page.screenshot(Path(artifacts) / "incident-resolved.png")

        relapse = self.beat(96)["alerts_triggered"][0]["id"]
        page.click("#incident-close")
        page.goto(self.console.base_url + "/live")
        selector = f'#rows tr[data-key="alert:{relapse}"]'
        page.wait(f"!!document.querySelector({json.dumps(selector)})", what="new incident in the live table")
        page.click(selector)
        page.click('[data-act=incident]')
        heading(page, relapse, "OPEN")
        self.assertEqual(page.eval("document.querySelector('#incident-count').textContent"), "1")
        viewer = sign_in("ui-reader", mobile=True)
        viewer.click("#alerts-list a[href*=incident]")
        heading(viewer, relapse, "OPEN")
        self.assertEqual(viewer.eval("document.querySelectorAll('[data-case-action]').length"), 0)
        viewer.click("[data-case-previous]")
        heading(viewer, case_id, "RESOLVED")
        self.assertEqual(viewer.eval("document.querySelector('#incident-count').textContent"), "3")
        self.assertLessEqual(viewer.overflow()["scrollWidth"], viewer.overflow()["clientWidth"] + 1)

        page.click('[data-case-action=resolve]')
        heading(page, relapse, "RESOLVED")
        self.assertIn("Recovery verified by operator", page.eval("document.querySelector('#incident-history').innerText"))
        other, _ = self.register("second-ui-admin")
        beta_sensor = self.token(other, "ingest")
        self.step("src/beta-ui.py", beta_sensor)
        self.assertEqual(self.beat(96, beta_sensor)["alerts_triggered"][0]["id"], case_id)
        beta = sign_in("second-ui-admin")
        beta.goto(first_link)
        beta_row = f'#rows tr[data-key="alert:{case_id}"]'
        beta.wait(f"!!document.querySelector({json.dumps(beta_row)})")
        self.assertFalse(beta.eval("document.querySelector('#incident-dialog').open"))
        beta.click(beta_row)
        beta.click('[data-act=incident]')
        heading(beta, case_id, "OPEN")
        beta_content = beta.eval("document.querySelector('#incident-content').innerText")
        self.assertIn("src/beta-ui.py", beta_content)
        self.assertNotIn("src/invoice.py", beta_content)
        self.assertNotIn("ui-oncall", beta_content)
        for checked in (page, viewer, beta):
            self.assertEqual([e for e in checked.errors if not ("status of 401" in e and e.endswith("/api/v1/auth/me"))], [])
            self.assertEqual([(s, url) for s, url in checked.http_errors
                              if not (s == 401 and url.endswith("/api/v1/auth/me"))], [])
