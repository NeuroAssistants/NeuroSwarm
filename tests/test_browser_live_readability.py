"""Browser regression suite for Live NOC readability:
1. curl HTTP 401 with exit 0 highlights HTTP failure, redacts credentials, and formats JSON excerpt.
2. Browser actions clearly distinguish Page visit, Web search, Page snapshot, and Credential step.
3. Command & Output and Files & Workspace explain empty output, disabled capture, outside scope,
   and legacy 'Not recorded' states instead of showing an opaque empty panel.
4. Two alerts from the same session each open their own original command, file, and output
   after reloading Live, even if the underlying file changed afterwards.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(Path(__file__).resolve().parent)]

import browser_cdp  # noqa: E402
from product_qa.test_acceptance_blackbox import HttpClient, SpawnedConsole  # noqa: E402

ADMIN = ("bootstrap_admin", "BootstrapPass!2026#QA")
VIEWPORTS = {"desktop": (1440, 900, False), "mobile": (390, 844, True)}


class LiveReadabilityBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if os.environ.get("SWARMCONTROL_BROWSER_TESTS", "").lower() == "skip":
            raise unittest.SkipTest("SWARMCONTROL_BROWSER_TESTS=skip")
        binary = browser_cdp.find_browser()
        if not binary:
            raise AssertionError("No Chromium found. Run python3 deploy/fetch_test_browser.py or set SWARMCONTROL_CHROMIUM.")
        cls.tmp = tempfile.TemporaryDirectory(prefix="ns-live-readability-qa-")
        cls.state = Path(cls.tmp.name)
        cls.srv = SpawnedConsole(cls.state / "server")
        cls.browser = browser_cdp.Browser(binary)
        try:
            cls._seed()
        except Exception:
            cls.browser.close()
            cls.srv.stop()
            cls.tmp.cleanup()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls.browser.close()
        cls.srv.stop()
        cls.tmp.cleanup()

    @classmethod
    def _seed(cls) -> None:
        admin = HttpClient(cls.srv.base_url)
        st, _, _ = admin.json("POST", "/api/v1/auth/login", {"username": ADMIN[0], "password": ADMIN[1]})
        assert st == 200, st

        now = time.time()
        cls.ids: dict[str, int] = {}
        with sqlite3.connect(cls.srv.db_path) as conn:
            def add_event(name, *, msg, meta, cmd_in=None, cmd_out=None, exit_code=None, truncated=0, sev="INFO", offset=0):
                cur = conn.execute(
                    "INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    ("qa-box-01", "codex", "agent-reader", "observed_step", sev, msg, json.dumps(meta), now - offset),
                )
                eid = int(cur.lastrowid)
                if cmd_in is not None or cmd_out is not None or exit_code is not None:
                    conn.execute(
                        "INSERT INTO event_execution(event_id,command_input,command_output,exit_code,output_truncated) "
                        "VALUES(?,?,?,?,?)",
                        (eid, cmd_in, cmd_out, exit_code, truncated),
                    )
                cls.ids[name] = eid
                return eid

            # 1. curl HTTP 401 with exit 0 + credentials in URL + JSON response body
            add_event(
                "curl_401",
                msg="Call a web address · curl",
                meta={"action": "shell", "tool": "exec_command", "program": "curl", "session": "codex:sess-web", "workspace": "demo-app"},
                cmd_in="curl -i -X POST https://alice:supersecret@api.example.test/v1/jobs?token=tok_secret_999&mode=live",
                cmd_out='HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{"error":"invalid_token","detail":"Bearer expired"}',
                exit_code=0,
                offset=5,
            )

            # 2. Browser actions: visit, search, snapshot, credential step
            add_event(
                "browser_visit",
                msg="Web request",
                meta={
                    "action": "web", "tool": "openbot_browser.navigate", "session": "codex:sess-web", "workspace": "demo-app",
                    "web_resource": {"kind": "visit", "url": "https://docs.example.test/guide?api_key=leak123&page=2", "title": "API Guide"},
                },
                offset=10,
            )
            add_event(
                "browser_search",
                msg="Search: pytest exit codes",
                meta={"action": "web", "tool": "search_web", "session": "codex:sess-web", "workspace": "demo-app", "query": "pytest exit codes"},
                offset=15,
            )
            add_event(
                "browser_snapshot",
                msg="Web request",
                meta={"action": "web", "tool": "openbot_browser.snapshot", "session": "codex:sess-web", "workspace": "demo-app"},
                offset=20,
            )
            add_event(
                "browser_cred",
                msg="Web request",
                meta={"action": "web", "tool": "openbot_browser.submit_secret", "session": "codex:sess-web", "workspace": "demo-app"},
                offset=25,
            )

            # 3. Missing-evidence reason distinctions
            add_event(
                "empty_out",
                msg="Read a file · tail",
                meta={"action": "file_read", "tool": "exec_command", "program": "tail", "files": ["logs/empty.log"], "session": "codex:sess-reasons", "workspace": "demo-app"},
                cmd_in="tail -n 1 logs/empty.log",
                cmd_out="",
                exit_code=0,
                offset=30,
            )
            add_event(
                "capture_disabled",
                msg="Shell command · python3",
                meta={"action": "shell", "tool": "exec_command", "program": "python3", "session": "codex:sess-reasons", "workspace": "demo-app", "evidence_reason": "capture_disabled", "files_reason": "capture_disabled"},
                offset=35,
            )
            add_event(
                "outside_scope",
                msg="Shell command · python3",
                meta={"action": "shell", "tool": "exec_command", "program": "python3", "session": "codex:sess-reasons", "workspace": "Agent workspace", "evidence_reason": "outside_scope", "files_reason": "outside_scope"},
                offset=40,
            )
            add_event(
                "legacy_unrecorded",
                msg="Shell command · sed",
                meta={"action": "shell", "tool": "exec_command", "program": "sed", "session": "codex:sess-reasons", "workspace": "Agent workspace"},
                offset=45,
            )

            # 4. Two alerts from the SAME session pointing to two distinct original events
            beta_file = cls.state / "beta.log"
            beta_file.write_text("original-beta-line-v1\n", encoding="utf-8")
            ev_a = add_event(
                "origin_a",
                msg="Run a Python script · python3",
                meta={"action": "shell", "tool": "exec_command", "program": "python3", "files": ["jobs/alpha.py"], "session": "codex:shared-alert-session", "workspace": "demo-app"},
                cmd_in="cd demo-app && python3 jobs/alpha.py",
                cmd_out="Traceback (most recent call last):\nValueError: alpha boom",
                exit_code=2,
                sev="ERROR",
                offset=50,
            )
            ev_b = add_event(
                "origin_b",
                msg="Read a file · tail",
                meta={"action": "file_read", "tool": "exec_command", "program": "tail", "files": ["logs/beta.log"], "session": "codex:shared-alert-session", "workspace": "demo-app"},
                cmd_in="tail -n 5 logs/beta.log",
                cmd_out="original-beta-line-v1\n",
                exit_code=0,
                sev="WARNING",
                offset=55,
            )
            # Mutate the file after capture to confirm historical output stays unchanged
            beta_file.write_text("mutated-beta-line-v2\n", encoding="utf-8")

            def add_alert(name, rule, title, summary, source_eid, offset):
                cur = conn.execute(
                    "INSERT INTO alerts(host_id,rule_code,severity,status,title,summary,evidence_json,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        "qa-box-01",
                        rule,
                        "CRITICAL",
                        "OPEN",
                        title,
                        summary,
                        json.dumps({"source_event_id": source_eid, "session": "codex:shared-alert-session", "workspace": "demo-app"}),
                        now - offset,
                        now - offset,
                    ),
                )
                cls.ids[name] = int(cur.lastrowid)

            add_alert("alert_a", "SCRIPT_FAIL_A", "Python job alpha failed", "alpha.py exited with code 2", ev_a, 49)
            add_alert("alert_b", "LOG_ANOMALY_B", "Log beta warning observed", "beta.log emitted warning marker", ev_b, 54)

    def login_and_open(self, pg: browser_cdp.Page, event_key: str) -> None:
        pg.goto(self.srv.base_url + "/")
        pg.wait("document.querySelector('#login-form') && getComputedStyle(document.querySelector('#login-view')).display !== 'none'")
        pg.type("#username", ADMIN[0])
        pg.type("#password", ADMIN[1])
        pg.click("#login-form button[type=submit]")
        pg.wait("!document.querySelector('#app-view').hidden && getComputedStyle(document.querySelector('#app-view')).display !== 'none'")
        pg.goto(self.srv.base_url + "/live?" + urlencode({"event": event_key}))

    def assert_clean(self, pg: browser_cdp.Page, where: str) -> None:
        bad_http = [(s, u) for s, u in pg.http_errors if not (s == 401 and u.endswith("/api/v1/auth/me"))]
        errors = [e for e in pg.errors if not ("status of 401" in e and e.endswith("/api/v1/auth/me"))]
        self.assertEqual(errors, [], f"{where}: console errors")
        self.assertEqual(bad_http, [], f"{where}: http errors")
        ov = pg.overflow()
        self.assertLessEqual(ov["scrollWidth"], ov["clientWidth"] + 1, f"{where}: horizontal overflow {ov}")

    def test_curl_401_browser_kinds_missing_reasons_and_two_session_alerts(self) -> None:
        for view, (w, h, mobile) in VIEWPORTS.items():
            with self.subTest(viewport=view):
                pg = self.browser.new_page(w, h, mobile)
                self.addCleanup(pg.close)
                pg.reduced_motion()

                # 1. curl HTTP 401 with exit 0 + credential redaction
                curl_key = f"event:{self.ids['curl_401']}"
                self.login_and_open(pg, curl_key)
                pg.wait("!!document.querySelector('#detail-evidence-slot [data-http-mismatch=\"1\"]')", what="curl 401 mismatch callout")
                curl_text = pg.eval("document.querySelector('#detail-evidence-slot').innerText")
                self.assertIn("POST", curl_text)
                self.assertIn("HTTP 401", curl_text)
                self.assertIn("exited 0", curl_text)
                self.assertIn("invalid_token", curl_text)
                self.assertIn("api.example.test/v1/jobs", curl_text)
                self.assertNotIn("supersecret", curl_text)
                self.assertNotIn("tok_secret_999", curl_text)
                self.assert_clean(pg, f"{view} curl 401")

                # 2. Browser actions distinguished cleanly in table & detail
                rows_text = pg.eval("document.querySelector('#rows').innerText").lower()
                self.assertIn("page visit", rows_text)
                self.assertIn("web search", rows_text)
                self.assertIn("page snapshot", rows_text)
                self.assertIn("credential step", rows_text)
                pg.goto(self.srv.base_url + "/live?" + urlencode({"event": f"event:{self.ids['browser_visit']}"}))
                pg.wait("document.querySelector('#detail-evidence-slot [data-browser-kind=\"visit\"]') !== null", what="browser visit card")
                visit_text = pg.eval("document.querySelector('#detail-evidence-slot').innerText")
                self.assertIn("docs.example.test/guide", visit_text)
                self.assertIn("API Guide", visit_text)
                self.assertNotIn("leak123", visit_text)

                # 3. Missing-evidence reason distinctions in Command & Output and Files & Workspace
                for name, expected_ev_reason, expected_files_reason, must_contain in (
                    ("empty_out", "empty_output", None, "captured output is empty"),
                    ("capture_disabled", "capture_disabled", "capture_disabled", "Capture disabled"),
                    ("outside_scope", "outside_scope", "outside_scope", "Outside authorized folders"),
                    ("legacy_unrecorded", "not_recorded", "not_recorded", "Not recorded"),
                ):
                    pg.goto(self.srv.base_url + "/live?" + urlencode({"event": f"event:{self.ids[name]}"}))
                    pg.wait(f"document.querySelector('#detail-evidence-slot [data-evidence-reason=\"{expected_ev_reason}\"]') !== null",
                            what=f"evidence reason {expected_ev_reason} for {name}")
                    gen_txt = pg.eval("document.querySelector('#detail-evidence-slot').innerText").lower()
                    self.assertIn(must_contain.lower(), gen_txt)
                    if expected_files_reason:
                        pg.click("[data-dtab='files']")
                        pg.wait(f"document.querySelector('#detail-evidence-slot [data-files-reason=\"{expected_files_reason}\"]') !== null",
                                what=f"files reason {expected_files_reason} for {name}")
                        pg.click("[data-dtab='general']")

                # Verify Evidence & JSON tab includes gap summary breakdown
                pg.click("[data-dtab='evidence']")
                pg.wait("document.querySelector('#detail .ev-gap-section') !== null", what="evidence gap summary")
                gap_txt = pg.eval("document.querySelector('#detail .ev-gap-section').innerText")
                self.assertIn("python3", gap_txt)
                pg.click("[data-dtab='general']")

                # 4. Two alerts from the same session survive reload and each shows its own command/file/output
                alert_a_key = f"alert:{self.ids['alert_a']}"
                alert_b_key = f"alert:{self.ids['alert_b']}"

                pg.goto(self.srv.base_url + "/live?" + urlencode({"event": alert_a_key}))
                pg.wait("document.querySelector('#detail-evidence-slot')?.innerText.includes('ValueError: alpha boom')",
                        what="alert A original python error after reload")
                txt_a = pg.eval("document.querySelector('#detail').innerText")
                self.assertIn("jobs/alpha.py", txt_a)
                self.assertIn("exit 2", txt_a.lower())
                self.assertNotIn("original-beta-line-v1", txt_a)
                pg.click("[data-dtab='files']")
                pg.wait("document.querySelector('#detail-evidence-slot')?.innerText.includes('jobs/alpha.py')",
                        what="alert A original file in Files tab")
                pg.click("[data-dtab='general']")

                pg.goto(self.srv.base_url + "/live?" + urlencode({"event": alert_b_key}))
                pg.wait("document.querySelector('#detail-evidence-slot')?.innerText.includes('original-beta-line-v1')",
                        what="alert B original tail output after reload")
                txt_b = pg.eval("document.querySelector('#detail').innerText")
                self.assertIn("logs/beta.log", txt_b)
                self.assertNotIn("alpha boom", txt_b)
                self.assertNotIn("mutated-beta-line-v2", txt_b)
                pg.click("[data-dtab='files']")
                pg.wait("document.querySelector('#detail-evidence-slot')?.innerText.includes('logs/beta.log')",
                        what="alert B original file in Files tab")
                self.assert_clean(pg, f"{view} two alerts reload")


if __name__ == "__main__":
    unittest.main()
