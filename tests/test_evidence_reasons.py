"""Why a Live event has no output or no file, and what a web call asked and got.

Real Codex records and the real journal: every command and web action of a session gets either its evidence or a
reason from a fixed vocabulary (empty_output, capture_disabled, outside_scope, protected, no_file_target), and curl /
browser actions carry a `web_resource` (kind, method, address without credentials, HTTP status, response excerpt).
Older events have no reason; Live then says "not recorded".
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from .test_capture_incremental import append, stamp
except ImportError:
    from test_capture_incremental import append, stamp

import activity_inspector as ai
import event_evidence
import remote_activity
import work_journal as wj
from db import Database

ON = {"SWARMCONTROL_SHARE_COMMANDS": "1", "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "1", "SWARMCONTROL_SHARE_FILE_PREVIEWS": "1"}
TRACEBACK = 'Traceback (most recent call last):\n  File "tools/fail.py", line 2, in <module>\n    raise SystemExit("boom")\nSystemExit: boom\n'
HTTP_401 = 'HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{"error":"unauthorized"}'


class EvidenceReasonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = Path(self.tmp.name)
        self.home = t / "home"
        self.agent_dir = t / "Agents" / "agent-one"
        self.shared = t / "Shared" / "team"
        self.project = self.shared / "product"
        for d in (self.agent_dir, self.project / "tools"):
            d.mkdir(parents=True, exist_ok=True)
        (self.project / "tools/fail.py").write_text("import sys\nraise SystemExit('boom')\n")
        (self.agent_dir / "private-notes.txt").write_text("mine\n")
        (self.project / ".env").write_text("TOKEN=x\n")
        self.dbo = Database(t / "journal.db")
        self.addCleanup(self.dbo.close)
        self.conn = sqlite3.connect(self.dbo.db_path)
        self.addCleanup(self.conn.close)
        for p in (patch.object(ai, "HOME", self.home), patch.object(ai, "harnesses", return_value=[])):
            p.start()
            self.addCleanup(p.stop)
        self.scope = ai.Scope([self.agent_dir, self.shared], {str(self.agent_dir): "agent-one"}, "host-t")
        self.rollout = self.home / ".codex/rollout.jsonl"
        self.rollout.parent.mkdir(parents=True)
        with sqlite3.connect(self.home / ".codex/state_5.sqlite") as c:
            c.execute("CREATE TABLE threads (id TEXT, cwd TEXT, model TEXT, tokens_used INT, updated_at INT, rollout_path TEXT,"
                      " model_provider TEXT)")
            c.execute("INSERT INTO threads VALUES ('t1',?,?,?,?,?,?)",
                      (str(self.agent_dir), "gpt-x", 1, int(time.time()), str(self.rollout), "openai"))
        self.n = 0

    def item(self, item):
        self.n += 1
        append(self.rollout, [{"timestamp": stamp(self.n), "payload": {"type": "item_completed", "item": item}}])

    def command(self, cmd, cwd=None, output="", code=0):
        self.item({"type": "CommandExecution", "cwd": str(cwd or self.project), "command": ["bash", "-lc", cmd],
                   "parsed_cmd": [{"type": "unknown", "cmd": cmd}], "aggregated_output": output, "exit_code": code})

    def tool(self, name, args):
        self.item({"type": "DynamicToolCall", "tool": name, "arguments": args, "success": True})

    def scan(self, env=ON):
        with patch.dict(os.environ, env):
            wj.capture_once(self.conn, {"agent-one"}, self.project, time.time(), ai.Scope([self.project]), self.scope)
        out = []
        for row in self.dbo.query_all("SELECT id, metadata_json FROM events WHERE event_type='observed_step' ORDER BY id"):
            out.append((json.loads(row["metadata_json"]), event_evidence.detail(self.dbo, 1, row["id"])))
        return out

    def test_failing_script_keeps_its_error_and_exit_code(self):
        self.command("python3 tools/fail.py", output=TRACEBACK, code=1)
        [(meta, ev)] = self.scan()
        self.assertEqual((ev["exit_code"], ev["command_output"]), (1, TRACEBACK))
        self.assertNotIn("output_reason", meta)
        self.assertEqual(meta["files"], ["tools/fail.py"])

    def test_empty_output_and_a_command_that_names_no_file(self):
        self.command("git status --short", output="")
        self.command("python3 -c 'print(1)'", output="1\n")
        (git, _), (inline, inline_ev) = self.scan()
        self.assertEqual((git["output_reason"], git["files_reason"]), ("empty_output", "no_file_target"))
        self.assertEqual(inline["files_reason"], "no_file_target")
        self.assertNotIn("output_reason", inline)
        self.assertEqual(inline_ev["command_output"], "1\n")

    def test_curl_401_with_exit_zero_shows_method_clean_address_status_and_body(self):
        self.command("curl -s -i 'https://bot:pw@api.example.invalid/v1/items?token=abc&page=2'", output=HTTP_401, code=0)
        self.command("curl -s -X POST -d name=x -w '%{http_code}' https://api.example.invalid/v1/items", output='{"ok":true}201')
        (get, get_ev), (post, _) = self.scan()
        web = get["web_resource"]
        self.assertEqual((web["kind"], web["method"], web["status_code"], web["status_text"]), ("http", "GET", 401, "Unauthorized"))
        self.assertEqual(web["url"], "https://api.example.invalid/v1/items?token=[redacted]&page=2")
        self.assertEqual(web["response_excerpt"], '{"error":"unauthorized"}')
        self.assertEqual(get_ev["exit_code"], 0, "curl itself succeeded; the 401 is in web_resource")
        self.assertEqual(get_ev["web_resource"]["status_code"], 401)
        self.assertEqual(get_ev["web_resource"]["url"], web["url"])
        self.assertNotIn("response_excerpt", event_evidence.work_summary(get)["web_resource"])
        self.assertNotIn("bot:pw", json.dumps(get))
        self.assertEqual((post["web_resource"]["method"], post["web_resource"]["status_code"]), ("POST", 201))
        self.assertEqual(post["web_resource"]["response_excerpt"], '{"ok":true}')

    def test_outside_scope_capture_disabled_and_protected_are_told_apart(self):
        self.command("cat private-notes.txt", cwd=self.agent_dir, output="mine\n")
        self.command("curl -s -i https://api.example.invalid/private", cwd=self.agent_dir, output=HTTP_401)
        self.command("cat .env", output="TOKEN=x\n")
        (outside, outside_ev), (curl, _), (protected, protected_ev) = self.scan()
        self.assertEqual((outside["output_reason"], outside["files_reason"]), ("outside_scope", "outside_scope"))
        self.assertIsNone(outside_ev["command_output"])
        self.assertEqual(curl["web_resource"], {"kind": "http", "method": "GET"}, "address and response stay private")
        self.assertEqual(protected["output_reason"], "protected")
        self.assertIsNone(protected_ev["command_output"])
        self.assertNotIn("private-notes", json.dumps([outside, curl]))
        self.command("ls tools", output="fail.py\n")
        last, ev = self.scan({**ON, "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "0"})[-1]
        self.assertEqual(last["output_reason"], "capture_disabled")
        self.assertIsNone(ev["command_output"])

    def test_a_command_naming_a_file_outside_the_shared_folders_says_so(self):
        self.command(f"tail -n 1 {self.agent_dir / 'private-notes.txt'}", output="mine\n")
        [(meta, ev)] = self.scan()
        self.assertEqual(meta["output_reason"], "outside_scope")
        self.assertIsNone(ev["command_output"])

    def test_browser_actions_are_a_visit_a_search_a_capture_or_a_credential_step(self):
        self.tool("mcp__openbot_browser__open", {"url": "https://docs.example.invalid/guide?session=s3cr3t#top"})
        self.tool("web_search", {"query": "neuroswarm live events"})
        self.tool("mcp__openbot_browser__snapshot", {})
        self.tool("mcp__openbot_browser__submit_secret", {"secret": "hunter2", "url": "https://login.example.invalid"})
        kinds = [m["web_resource"] for m, _ in self.scan()]
        self.assertEqual(kinds[0], {"kind": "visit", "url": "https://docs.example.invalid/guide?session=[redacted]"})
        self.assertEqual(kinds[1], {"kind": "search", "query": "neuroswarm live events"})
        self.assertEqual(kinds[2], {"kind": "snapshot"})
        self.assertEqual(kinds[3], {"kind": "credential"})
        blob = json.dumps(self.dbo.query_all("SELECT metadata_json, message FROM events"), default=str)
        self.assertNotIn("hunter2", blob)
        self.assertNotIn("s3cr3t", blob)

    def test_without_command_sharing_web_steps_keep_only_their_kind_and_method(self):
        self.tool("mcp__openbot_browser__open", {"url": "https://docs.example.invalid/guide"})
        self.command("curl -s -i https://api.example.invalid/v1", output=HTTP_401)
        (visit, _), (curl, _) = self.scan({"SWARMCONTROL_SHARE_COMMANDS": "0", "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "0"})
        self.assertEqual(visit["web_resource"], {"kind": "visit"})
        self.assertEqual(curl["web_resource"], {"kind": "http", "method": "GET"})
        self.assertEqual(curl["output_reason"], "capture_disabled")

    def test_remote_ingestion_keeps_only_known_reasons_and_clean_resources(self):
        raw = {"tool": "exec_command", "category": "shell", "label": "x", "output_reason": "outside_scope",
               "files_reason": "<script>", "web_resource": {"kind": "http", "method": "get;rm", "url": "javascript:alert(1)",
                                                             "status_code": 401, "response_excerpt": "token=abcdef1234567890"}}
        step = remote_activity._clean_step(raw, capture=True)
        self.assertEqual(step["output_reason"], "outside_scope")
        self.assertNotIn("files_reason", step)
        self.assertEqual(step["web_resource"]["status_code"], 401)
        self.assertNotIn("url", step["web_resource"])
        self.assertNotIn("method", step["web_resource"])
        self.assertNotIn("abcdef1234567890", json.dumps(step))
        self.assertIsNone(remote_activity._clean_step({**raw, "web_resource": {"kind": "evil"}}, capture=True).get("web_resource"))


class HelperTests(unittest.TestCase):
    def test_clean_url(self):
        self.assertEqual(ai.clean_url("https://u:p@Example.org:8443/a/b?api_key=1&q=x#frag"),
                         "https://example.org:8443/a/b?api_key=[redacted]&q=x")
        self.assertEqual(ai.clean_url("ftp://example.org/x"), "")
        self.assertEqual(ai.clean_url("not a url"), "")

    def test_methods(self):
        cases = {"curl https://e.invalid": "GET", "curl -I https://e.invalid": "HEAD", "curl -XDELETE https://e.invalid": "DELETE",
                 "curl -G -d a=1 https://e.invalid": "GET", "curl --json '{}' https://e.invalid": "POST",
                 "wget --method=PUT https://e.invalid": "PUT", "cd /x && curl -T f https://e.invalid | jq .": "PUT"}
        for cmd, method in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(ai.http_resource(cmd, None, True)["method"], method)
        self.assertIsNone(ai.http_resource("git status", None, True))

    def test_names_no_file(self):
        self.assertTrue(ai.names_no_file("git status --short"))
        self.assertTrue(ai.names_no_file("python3 -m unittest discover"))
        self.assertTrue(ai.names_no_file("curl -s https://e.invalid/a.json"))
        self.assertFalse(ai.names_no_file("tail -n 5 app.log"))
        self.assertFalse(ai.names_no_file("cd /x && python3 run.py"))


if __name__ == "__main__":
    unittest.main()
