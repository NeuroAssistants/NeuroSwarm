"""HTTP evidence for every supported agent runtime, and a curl redirect chain (issues #2 and #12).

A local fixture answers 302 (Location with a token) then 401. Real `curl -s -i -L` is run against it once; its exact
output and exit code (0) are written in each runtime's own record format (Codex, Claude Code, OpenCode, Antigravity,
Hermes, Pi) and read through the real journal. Every event must show the method, the address without credentials,
both hops in order, the final 401 with its response excerpt, and the process exit code; reopening the database after
the fixture changed must show the same, without fetching the address again. Chromium renders the chain in Live.

Fields a runtime does not record (documented in ACTIVITY-CONTRACT.md 6.4): Claude Code reports no exit code for Bash,
Hermes and Antigravity report the exit code only when their tool result includes it.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "agent"), str(Path(__file__).resolve().parent)]

try:
    from .test_capture_incremental import append, stamp
except ImportError:
    from test_capture_incremental import append, stamp

import activity_inspector as ai
import event_evidence
import work_journal as wj
from db import Database

ON = {"SWARMCONTROL_SHARE_COMMANDS": "1", "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "1", "SWARMCONTROL_SHARE_FILE_PREVIEWS": "1",
      "PI_CODING_AGENT_DIR": "", "PI_CODING_AGENT_SESSION_DIR": "", "HERMES_HOME": "", "CODEX_HOME": "",
      "CLAUDE_CONFIG_DIR": "", "XDG_DATA_HOME": ""}


class Fixture(BaseHTTPRequestHandler):
    body = b'{"error":"unauthorized","hint":"sign in"}'

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/start"):
            self.send_response(302)
            self.send_header("Location", "/login?token=REDIRECT_SECRET_77&next=/home")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(self.body)))
            self.end_headers()
            self.wfile.write(self.body)

    def log_message(self, *args):
        pass


def run_curl():
    """Real curl against the loopback fixture: returns (command, output, exit code)."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://bot:pw@127.0.0.1:{server.server_port}/start?api_key=QUERY_SECRET_42&page=2"
        command = f"curl -s -i -L '{url}'"
        done = subprocess.run(["curl", "-s", "-i", "-L", url], capture_output=True, text=True, timeout=20)
        return command, done.stdout, done.returncode, server.server_port
    finally:
        server.shutdown()
        server.server_close()


@unittest.skipUnless(shutil.which("curl"), "curl is required for the real fixture")
class HttpAcrossRuntimes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.command, cls.output, cls.code, cls.port = run_curl()
        assert cls.code == 0 and "HTTP/1.0 302" in cls.output or "HTTP/1.1 302" in cls.output, cls.output

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = Path(self.tmp.name)
        self.home, self.project = t / "home", t / "work" / "team"
        self.project.mkdir(parents=True)
        self.db_path = t / "journal.db"
        self.dbo = Database(self.db_path)
        self.addCleanup(lambda: self.dbo.close())
        self.conn = sqlite3.connect(self.dbo.db_path)
        self.addCleanup(self.conn.close)
        for p in (patch.object(ai, "HOME", self.home), patch.object(ai, "harnesses", return_value=[]), patch.dict(os.environ, ON)):
            p.start()
            self.addCleanup(p.stop)
        self.scope = ai.Scope([self.project], {}, "host-t")

    # ---- one writer per runtime, each in that runtime's own record format ----
    def codex(self):
        rollout = self.home / ".codex/rollout.jsonl"
        append(rollout, [{"timestamp": stamp(1), "payload": {"type": "item_completed", "item": {
            "type": "CommandExecution", "cwd": str(self.project), "command": ["bash", "-lc", self.command],
            "parsed_cmd": [{"type": "unknown", "cmd": self.command}], "aggregated_output": self.output, "exit_code": self.code}}}])
        with sqlite3.connect(self.home / ".codex/state_5.sqlite") as c:
            c.execute("CREATE TABLE threads (id TEXT, cwd TEXT, model TEXT, tokens_used INT, updated_at INT, rollout_path TEXT, model_provider TEXT)")
            c.execute("INSERT INTO threads VALUES ('t1',?,?,?,?,?,?)", (str(self.project), "gpt-x", 1, int(time.time()), str(rollout), "openai"))

    def claude(self):
        f = self.home / ".claude/projects/p/c1.jsonl"
        root = str(self.project)
        append(f, [{"type": "user", "cwd": root, "message": {"role": "user", "content": "go"}},
                   {"type": "assistant", "cwd": root, "timestamp": stamp(1), "message": {"model": "claude-x", "content": [
                       {"type": "tool_use", "id": "b1", "name": "Bash", "input": {"command": self.command, "description": "Call the API"}}]}},
                   {"type": "user", "cwd": root, "timestamp": stamp(2), "message": {"role": "user", "content": [
                       {"type": "tool_result", "tool_use_id": "b1", "content": self.output}]}}])

    def opencode(self):
        db = self.home / ".local/share/opencode/opencode.db"
        db.parent.mkdir(parents=True, exist_ok=True)
        now_ms = int(time.time() * 1000)
        with sqlite3.connect(db) as c:
            c.execute("CREATE TABLE session_v2(id TEXT PRIMARY KEY, directory TEXT, time_updated INTEGER, model TEXT, title TEXT)")
            c.execute("CREATE TABLE session_message(session_id TEXT, type TEXT, seq INTEGER, time_created INTEGER, data TEXT)")
            c.execute("INSERT INTO session_v2 VALUES ('oc1', ?, ?, 'glm-x', 'Fix')", (str(self.project), now_ms))
            part = {"type": "tool", "name": "bash", "state": {"status": "completed", "input": {"command": self.command},
                                                               "output": self.output, "metadata": {"exit": self.code}}}
            c.execute("INSERT INTO session_message VALUES ('oc1','assistant',1,?,?)", (now_ms - 5000, json.dumps({"content": [part]})))

    def antigravity(self):
        conv = "c0ffee00-0000-4000-8000-0000000000aa"
        t = self.home / ".gemini/antigravity-acp/brain" / conv / ".system_generated/logs/transcript.jsonl"
        append(t, [{"type": "PLANNER_RESPONSE", "content": "working", "created_at": stamp(1), "model": "gemini-x",
                    "tool_calls": [{"name": "run_command", "args": {"CommandLine": json.dumps(self.command), "toolSummary": "Call the API"},
                                    "output": self.output, "exit_code": self.code}]}])
        convdb = self.home / ".gemini/antigravity-acp/conversations" / f"{conv}.db"
        convdb.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(convdb) as c:
            c.execute("CREATE TABLE trajectory_metadata_blob (id TEXT, data BLOB)")
            c.execute("INSERT INTO trajectory_metadata_blob VALUES ('main', ?)", (b"\x0a\x10file://" + str(self.project).encode() + b"\x12:",))

    def hermes(self):
        db = self.home / ".hermes/state.db"
        db.parent.mkdir(parents=True)
        now = time.time()
        with sqlite3.connect(db) as c:
            c.execute("""CREATE TABLE sessions (id TEXT PRIMARY KEY, title TEXT, source TEXT, model TEXT, model_config TEXT,
                         parent_session_id TEXT, started_at REAL, last_activity_at REAL, ended_at REAL, cwd TEXT,
                         input_tokens INTEGER, output_tokens INTEGER, billing_provider TEXT, profile_name TEXT)""")
            c.execute("""CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, role TEXT NOT NULL,
                         content TEXT, tool_calls TEXT, tool_call_id TEXT, tool_name TEXT, timestamp REAL)""")
            c.execute("INSERT INTO sessions VALUES ('h1','API','cli','gpt-x',?,NULL,?,?,NULL,?,1,1,'openai','')",
                      (json.dumps({"cwd": str(self.project)}), now - 60, now - 5, str(self.project)))
            calls = [{"id": "call_curl", "type": "function", "function": {"name": "terminal", "arguments": json.dumps({"command": self.command})}}]
            c.execute("INSERT INTO messages(session_id, role, content, tool_calls, timestamp) VALUES ('h1','assistant','',?,?)",
                      (json.dumps(calls), now - 30))
            c.execute("INSERT INTO messages(session_id, role, content, tool_call_id, tool_name, timestamp) VALUES ('h1','tool',?,?,?,?)",
                      (json.dumps({"output": self.output, "exit_code": self.code}), "call_curl", "terminal", now - 29))

    def pi(self):
        log = self.home / ".pi/agent/sessions/--team--/session.jsonl"
        when = datetime.now(timezone.utc).isoformat()
        rows = [{"type": "session", "id": "00000000-0000-4000-a000-000000000001", "version": 3, "cwd": str(self.project), "timestamp": when},
                {"type": "message", "id": "a", "parentId": None, "timestamp": when, "message": {"role": "assistant", "model": "demo",
                 "content": [{"type": "toolCall", "id": "c1", "name": "bash", "arguments": {"command": self.command}}]}},
                {"type": "message", "id": "r", "parentId": "a", "timestamp": when, "message": {"role": "toolResult", "toolCallId": "c1",
                 "toolName": "bash", "isError": False, "content": [{"type": "text", "text": self.output}], "details": {"exitCode": self.code}}}]
        append(log, rows)

    def check(self, runtime, exit_code_recorded=True):
        getattr(self, runtime)()
        wj.capture_once(self.conn, {"team"}, self.project, time.time(), None, self.scope)
        rows = self.dbo.query_all("SELECT id, metadata_json FROM events WHERE event_type='observed_step' AND "
                                  "json_extract(metadata_json,'$.program')='curl'")
        self.assertEqual(len(rows), 1, f"{runtime}: one curl event")
        event_id, meta = rows[0]["id"], json.loads(rows[0]["metadata_json"])
        web = meta["web_resource"]
        self.assertEqual((web["kind"], web["method"], web["status_code"]), ("http", "GET", 401), runtime)
        self.assertEqual(web["url"], f"http://127.0.0.1:{self.port}/start?api_key=[redacted]&page=2", runtime)
        self.assertEqual([h["status_code"] for h in web["hops"]], [302, 401], runtime)
        self.assertEqual(web["hops"][0]["location"], "/login?token=[redacted]&next=/home", runtime)
        self.assertEqual(json.loads(web["response_excerpt"]), {"error": "unauthorized", "hint": "sign in"}, runtime)
        detail = event_evidence.detail(self.dbo, 1, event_id)
        self.assertEqual(detail["exit_code"], 0 if exit_code_recorded else None, runtime)
        self.assertNotIn("output_reason", meta, f"{runtime}: the output was recorded, so no missing-output reason")
        blob = json.dumps([meta, detail])
        for secret in ("bot:pw", "QUERY_SECRET_42", "REDIRECT_SECRET_77"):
            self.assertNotIn(secret, json.dumps(meta), f"{runtime}: {secret}")
            self.assertNotIn(secret, json.dumps(detail.get("web_resource")), f"{runtime}: {secret}")
        # History: the fixture is gone and changed; reopening the database shows the same, nothing is fetched again.
        Fixture.body = b'{"changed":true}'
        self.addCleanup(setattr, Fixture, "body", b'{"error":"unauthorized","hint":"sign in"}')
        self.dbo.close()
        self.dbo = Database(self.db_path)
        again = event_evidence.detail(self.dbo, 1, event_id)
        self.assertEqual(again["web_resource"], detail["web_resource"], runtime)
        self.assertEqual((again["command_output"], again["exit_code"]), (detail["command_output"], detail["exit_code"]), runtime)
        self.assertIn("401", blob)

    def test_codex(self):
        self.check("codex")

    def test_claude_code(self):
        self.check("claude", exit_code_recorded=False)  # Claude Code's Bash result carries no exit code

    def test_opencode(self):
        self.check("opencode")

    def test_antigravity(self):
        self.check("antigravity")

    def test_hermes(self):
        self.check("hermes")

    def test_pi(self):
        self.check("pi")


@unittest.skipUnless(shutil.which("curl"), "curl is required for the real fixture")
class RedirectChainInLive(unittest.TestCase):
    """Observer -> ingest API -> /live in Chromium: both hops in order, the final 401 with its excerpt, exit 0, and the
    same after reloading the page."""

    def test_live_shows_the_chain_and_keeps_it_after_reload(self):
        if os.environ.get("SWARMCONTROL_BROWSER_TESTS", "").lower() == "skip":
            self.skipTest("SWARMCONTROL_BROWSER_TESTS=skip")
        import activity_shipper
        import browser_cdp
        from product_qa.test_acceptance_blackbox import HttpClient, SpawnedConsole
        binary = browser_cdp.find_browser()
        self.assertTrue(binary, "No Chromium found; see tests/BROWSER-TESTS.md")
        command, output, code, port = run_curl()
        tmp = tempfile.TemporaryDirectory(prefix="ns-hops-")
        self.addCleanup(tmp.cleanup)
        t = Path(tmp.name)
        home, project = t / "home", t / "work" / "team"
        project.mkdir(parents=True)
        rollout = home / ".codex/rollout.jsonl"
        append(rollout, [{"timestamp": stamp(1), "payload": {"type": "item_completed", "item": {
            "type": "CommandExecution", "cwd": str(project), "command": ["bash", "-lc", command],
            "parsed_cmd": [{"type": "unknown", "cmd": command}], "aggregated_output": output, "exit_code": code}}}])
        with sqlite3.connect(home / ".codex/state_5.sqlite") as c:
            c.execute("CREATE TABLE threads (id TEXT, cwd TEXT, model TEXT, tokens_used INT, updated_at INT, rollout_path TEXT, model_provider TEXT)")
            c.execute("INSERT INTO threads VALUES ('t1',?,?,?,?,?,?)", (str(project), "gpt-x", 1, int(time.time()), str(rollout), "openai"))
        srv = SpawnedConsole(t / "console")
        self.addCleanup(srv.stop)
        admin = HttpClient(srv.base_url)
        self.assertEqual(admin.json("POST", "/api/v1/auth/login", {"username": "bootstrap_admin", "password": "BootstrapPass!2026#QA"})[0], 200)
        _, _, tok = admin.json("POST", "/api/v1/tokens", {"name": "box", "scope": "ingest"})
        with patch.object(ai, "HOME", home), patch.object(ai, "harnesses", return_value=[]), patch.dict(os.environ, ON):
            payload, _, _ = activity_shipper.collect_incremental_activity(raw_roots=[str(project)], host_id="box", home_dir=home, use_core=True)
        st, _, body = admin.json("POST", "/api/v1/ingest/activity", payload, headers={"Authorization": f"Bearer {tok['token']}"})
        self.assertIn(st, (200, 201), body)
        _, _, feed = admin.json("GET", "/api/v1/events?limit=50")
        event_id = next(e["id"] for e in feed["events"] if e.get("event_type") == "observed_step")
        browser = browser_cdp.Browser(binary)
        self.addCleanup(browser.close)
        for view, (w, h, mobile) in {"desktop": (1440, 900, False), "mobile": (390, 844, True)}.items():
            with self.subTest(view=view):
                pg = browser.new_page(w, h, mobile)
                self.addCleanup(pg.close)
                pg.goto(srv.base_url + "/")
                pg.wait("document.querySelector('#login-form') && getComputedStyle(document.querySelector('#login-view')).display !== 'none'")
                pg.type("#username", "bootstrap_admin")
                pg.type("#password", "BootstrapPass!2026#QA")
                pg.click("#login-form button[type=submit]")
                pg.wait("getComputedStyle(document.querySelector('#app-view')).display !== 'none'", what="console")
                seen = []
                for _ in range(2):  # open, then reload the same address
                    pg.goto(f"{srv.base_url}/live?event=event%3A{event_id}")
                    pg.wait("!!document.querySelector('.ev-http-hops li')", what="redirect chain")
                    seen.append(pg.eval("""(() => { const card = document.querySelector('.ev-http-card');
                      return {hops: [...card.querySelectorAll('.ev-http-hops li')].map(li => li.innerText.replace(/\\s+/g, ' ').trim()),
                              status: card.dataset.httpStatus, body: (card.querySelector('.ev-http-body-wrap') || {}).innerText || '',
                              mismatch: !!card.querySelector('[data-http-mismatch]'), text: document.body.innerText}; })()"""))
                first, second = seen
                self.assertEqual(len(first["hops"]), 2)
                self.assertIn("HTTP 302", first["hops"][0])
                self.assertIn("/login?token=[redacted]&next=/home", first["hops"][0])
                self.assertIn("HTTP 401", first["hops"][1])
                self.assertEqual(first["status"], "401")
                self.assertIn("unauthorized", first["body"])
                self.assertTrue(first["mismatch"], "a 401 with exit 0 is called out")
                for secret in ("REDIRECT_SECRET_77", "QUERY_SECRET_42", "bot:pw"):
                    self.assertNotIn(secret, first["text"])
                self.assertEqual({k: v for k, v in first.items() if k != "text"}, {k: v for k, v in second.items() if k != "text"})
                self.assertEqual(pg.overflow()["offenders"], [])


class HopHelpers(unittest.TestCase):
    def test_hops_from_verbose_and_relative_locations(self):
        out = ("< HTTP/1.1 301 Moved Permanently\r\n< Location: https://u:p@new.example.invalid/a?session=s1\r\n<\r\n"
               "< HTTP/1.1 302 Found\r\n< location: /b?sig=zz&x=1\r\n<\r\n< HTTP/2 200\r\n< content-type: text/plain\r\n<\r\nok\n")
        web = ai.http_resource("curl -v -L https://old.example.invalid/a", out, True)
        self.assertEqual([h["status_code"] for h in web["hops"]], [301, 302, 200])
        self.assertEqual(web["hops"][0]["location"], "https://new.example.invalid/a?session=[redacted]")
        self.assertEqual(web["hops"][1]["location"], "/b?sig=[redacted]&x=1")
        self.assertNotIn("location", web["hops"][2])
        self.assertEqual(web["status_code"], 200)

    def test_no_location_without_command_sharing_and_single_response_has_no_hops(self):
        out = "HTTP/1.1 302 Found\r\nLocation: /next\r\n\r\nHTTP/1.1 401 Unauthorized\r\n\r\nno\n"
        web = ai.http_resource("curl -i -L https://e.invalid", out, False)
        self.assertEqual(web["hops"], [{"status_code": 302, "status_text": "Found"}, {"status_code": 401, "status_text": "Unauthorized"}])
        self.assertNotIn("hops", ai.http_resource("curl -i https://e.invalid", "HTTP/1.1 401 Unauthorized\r\n\r\nno", True))
        self.assertEqual(ai.clean_location("//evil.example/x"), "")
        self.assertEqual(ai.clean_location("javascript:alert(1)"), "")


if __name__ == "__main__":
    unittest.main()
