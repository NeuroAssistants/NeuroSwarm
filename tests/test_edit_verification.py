"""Real file writes and unittest processes through hook, journal, HTTP and Live."""
from datetime import datetime, timezone
from contextlib import closing
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
from unittest.mock import patch

from test_security import ADMIN_PASS, ServerHarness
import browser_cdp
import activity_inspector as inspector
import work_journal

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent"))
import activity_shipper


class EditVerificationTests(ServerHarness):
    def setUp(self):
        super().setUp()
        self.login()
        self.tok = self.token()
        self.repo = Path(self.tmp.name) / "checkout"
        self.repo.mkdir()
        self.home = Path(self.tmp.name) / "home"
        self.file = self.repo / "widget.py"
        self.file.write_text("value = 0\n")
        (self.repo / ".gitignore").write_text("__pycache__/\n")
        (self.repo / "test_widget.py").write_text(
            "import unittest,widget\nclass TestValue(unittest.TestCase):\n"
            "    def test_value(self): self.assertEqual(widget.value, 2)\n")
        for args in (["init", "-q"], ["add", "."], ["-c", "user.name=Example", "-c", "user.email=example@invalid.test",
                                                   "-c", "commit.gpgSign=false", "commit", "-qm", "base"]):
            subprocess.run(["git", *args], cwd=self.repo, check=True)
        self.env = {**os.environ, "SWARMCONTROL_TOKEN": self.tok["token"],
                    "SWARMCONTROL_SERVER": f"http://127.0.0.1:{self.port}", "SWARMCONTROL_HOST_ID": "capture",
                    "SWARMCONTROL_VERIFICATION_STATE": self.tmp.name + "/hook", "SWARMCONTROL_TASK_ID": "task-41",
                    "SWARMCONTROL_ACTIVITY_ROOTS": str(self.repo), "PYTHONDONTWRITEBYTECODE": "1"}
        self.command = "python3 -m unittest -v test_widget"

    def hook(self, phase, sid, uid, actor, tool, args, **extra):
        payload = {"hook_event_name": phase, "session_id": sid, "cwd": str(self.repo), "tool_use_id": uid,
                   "tool_name": tool, "tool_input": args, **extra}
        proc = subprocess.run([sys.executable, str(ROOT / "integrations/verification_hook.py")],
                              input=json.dumps(payload), env={**self.env, "SWARMCONTROL_AGENT_NAME": actor},
                              capture_output=True, text=True, timeout=10)
        self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (0, "", ""))

    def log(self, sid, **record):
        path = self.home / ".claude/projects/example" / (sid + ".jsonl")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as out:
            now = getattr(self, "record_time", None) or datetime.now(timezone.utc).isoformat()
            out.write(json.dumps({"timestamp": now, "cwd": str(self.repo), **record})+"\n")

    def edit(self, sid, uid, actor, value):
        args = {"file_path": str(self.file), "content": f"value = {value}\n"}
        self.log(sid, type="assistant", message={"content": [{"type": "tool_use", "id": uid, "name": "Write", "input": args}]})
        self.hook("PreToolUse", sid, uid, actor, "Write", args)
        self.file.write_text(args["content"])
        self.hook("PostToolUse", sid, uid, actor, "Write", args, tool_response={"filePath": str(self.file)})
        self.log(sid, type="user", message={"content": [{"type": "tool_result", "tool_use_id": uid, "content": "File updated"}]})

    def check(self, sid, uid, actor, change_while_running=False):
        args = {"command": self.command}
        self.log(sid, type="assistant", message={"content": [{"type": "tool_use", "id": uid, "name": "Bash", "input": args}]})
        self.hook("PreToolUse", sid, uid, actor, "Bash", args)
        result = subprocess.run(self.command.split(), cwd=self.repo, env=self.env, capture_output=True, text=True)
        output = result.stdout + result.stderr
        if change_while_running:
            self.file.write_text(self.file.read_text() + "# changed\n")
        self.hook("PostToolUseFailure" if result.returncode else "PostToolUse", sid, uid, actor, "Bash", args,
                  tool_response={"exitCode": result.returncode})
        self.log(sid, type="user", toolUseResult={"exitCode": result.returncode}, message={"content": [
            {"type": "tool_result", "tool_use_id": uid, "is_error": bool(result.returncode), "content": output}]})
        return result.returncode

    def collect(self, local=False, fallback=False, legacy=False):
        with patch.dict(os.environ, {"SWARMCONTROL_SHARE_COMMANDS": "1", "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "1"}), \
             patch.object(inspector, "HOME", self.home):
            if local:
                scope = inspector.Scope([self.repo], host_id="capture")
                with sqlite3.connect(self.db_path) as conn:
                    work_journal.capture_once(conn, {self.repo.name}, self.repo, scope=scope)
                return
            snapshot, _, _ = activity_shipper.collect_incremental_activity(
                [str(self.repo)], host_id="capture", home_dir=self.home, use_core=not fallback)
            if legacy:
                for session in snapshot["sessions"]:
                    for step in session.get("capture_steps", []):
                        step.pop("native_call_ref", None)
            for packet in activity_shipper.chunk_activity_payload(snapshot):
                status, body, _ = self.req("POST", "/api/v1/ingest/activity", packet,
                                           cookie=False, headers=self.bearer(self.tok))
                self.assertEqual(status, 200, body)

    def events(self):
        records = self.req("GET", "/api/v1/live-records")[1]["records"]
        return [r for r in records if r["source"] == "observed_step"]

    def detail(self, row):
        return self.req("GET", f"/api/v1/events/{row['id']}/evidence?organization_id=1")[1]

    def test_two_agents_same_path_task_and_revision_only_named_edit_opens_its_real_output(self):
        self.edit("session-a", "write-a", "builder-a", 2)
        # Both edits end with identical bytes, Git HEAD and task. A blink of the clock cannot identify them.
        self.file.write_text("value = 1\n")
        self.edit("session-b", "write-b", "builder-b", 2)
        self.collect(local=True)
        a, b = sorted(self.events(), key=lambda r:r["work"]["session"])
        self.assertEqual(self.detail(a)["verification"]["status"], "not_recorded")
        self.assertEqual(self.check("session-a", "bash-a", "builder-a"), 0)
        self.collect(local=True)
        self.collect(local=True)
        self.assertEqual(len(self.events()), 3)
        proof = self.detail(a)["verification"]
        self.assertEqual((proof["status"], proof["task_id"], proof["actor"]), ("recorded", "task-41", "builder-a"))
        self.assertEqual(self.detail(b)["verification"], {"status": "not_recorded", "tests": []})
        test, = proof["tests"]
        self.assertEqual((test["result"], test["exit_code"]), ("passed", 0))
        ev = self.req("GET", f"/api/v1/events/{test['event_id']}/evidence")[1]
        self.assertEqual(ev["command_input"], self.command)
        self.assertIn("test_value", ev["command_output"])
        self.assertIn("OK", ev["command_output"])
        self.assertEqual(ev["session"], "claude-code:session-a")

        if os.environ.get("SWARMCONTROL_BROWSER_TESTS", "").lower() == "skip":
            self.skipTest("Browser acceptance disabled by SWARMCONTROL_BROWSER_TESTS")
        chromium = browser_cdp.find_browser()
        self.assertTrue(chromium, "Install the test browser with python3 deploy/fetch_test_browser.py")
        with closing(browser_cdp.Browser(chromium)) as browser:
            self._check_live(browser, a, b, test)

    def _check_live(self, browser, a, b, test):
        page = browser.new_page(1280, 800)
        site = self.env["SWARMCONTROL_SERVER"]
        page.goto(site)
        page.settled("#login-form button[type=submit]")
        page.type("#username", "admin")
        page.type("#password", ADMIN_PASS)
        page.click("#login-form button[type=submit]")
        page.wait("getComputedStyle(document.querySelector('#app-view')).display !== 'none' "
                  "&& !document.querySelector('#app-view').hidden")
        page.goto(site + "/live")
        captures = os.environ.get("SWARMCONTROL_BROWSER_ARTIFACTS")
        if captures:
            Path(captures).mkdir(parents=True, exist_ok=True)
        for row in (b, a):
            selector = f'#rows tr[data-key="event:{row["id"]}"]'
            page.wait(f"Boolean(document.querySelector({json.dumps(selector)}))")
            page.click(selector)
            page.eval(f"document.querySelector({json.dumps(selector)}).focus()")
            page.key("Enter", "Enter", key_code=13)
            page.wait("Boolean(document.querySelector('#event-dialog[open] [aria-label=\"Verification after edit\"]'))")
            if row == b:
                self.assertIn("No verification recorded", page.eval("document.querySelector('#event-dialog-body').textContent"))
                page.click("#event-dialog-close")
        if captures:
            page.screenshot(Path(captures) / "edit-with-verification.png")
        page.click(f'#event-dialog [data-verification-test="{test["event_id"]}"]')
        page.wait("document.querySelector('#event-dialog .ev-cmd-out')?.textContent.includes('test_value')")
        self.assertIn(self.command, page.eval("document.querySelector('#event-dialog .ev-cmd-in').textContent"))
        if captures:
            page.screenshot(Path(captures) / "linked-test-output.png")

    def test_failed_check_remote_and_conditions_that_must_stay_unverified(self):
        self.edit("s", "edit1", "developer", 1)
        self.assertEqual(self.check("s", "failing", "developer"), 1)
        self.check("s", "wrong-agent", "another")
        self.env["SWARMCONTROL_TASK_ID"] = "another-task"
        self.check("s", "wrong-task", "developer")
        self.env["SWARMCONTROL_TASK_ID"] = "task-41"
        self.check("s", "changed-during", "developer", change_while_running=True)
        self.check("s", "wrong-revision", "developer")
        self.command = "python3 -m unittest --help"
        self.check("s", "help-only", "developer")
        self.collect(fallback=True)
        self.collect(fallback=True)
        edit, = [r for r in self.events() if r["work"]["action"]=="file_edit"]
        linked, = self.detail(edit)["verification"]["tests"]
        self.assertEqual((linked["result"], linked["exit_code"]), ("failed", 1))
        self.assertIn("AssertionError", self.req("GET", f"/api/v1/events/{linked['event_id']}/evidence")[1]["command_output"])
        self.assertEqual(self.ctx.db.query_one("SELECT count(*) AS n FROM verification_receipts")["n"], 2)

    def test_legacy_observer_still_opens_its_output_without_attributing_it(self):
        self.edit("old", "old-edit", "builder", 2)
        self.check("old", "old-test", "builder")
        self.collect(legacy=True)
        events = {r["work"]["action"]: r for r in self.events()}
        self.assertEqual(self.detail(events["file_edit"])["verification"], {"status": "not_recorded", "tests": []})
        self.assertIn("test_value", self.detail(events["shell"])["command_output"])

    def test_server_requires_matching_context_named_edit_and_consistent_outcome(self):
        del self.env["SWARMCONTROL_TASK_ID"]
        self.record_time = datetime.now(timezone.utc).isoformat()
        self.file.write_text("value = 2\n")
        self.assertEqual(self.check("s", "before-the-edit", "builder"), 0)
        self.file.write_text("value = 0\n")
        self.edit("s", "edit", "builder", 2)
        session = "claude-code:s"
        def ref(call, sid=session):
            return inspector.native_call_ref(sid, call)
        receipt = {"host_id": "capture", "role": "edit", "session_id": session, "task_id": "T",
                   "revision": "a"*64, "actor": "builder", "call_ref": ref("edit")}
        def send(fields):
            status, body, _ = self.req("POST", "/api/v1/ingest/verification", fields,
                                       cookie=False, headers=self.bearer(self.tok))
            self.assertEqual(status, 200, body)
        send(receipt)
        send({**receipt, "role": "test", "edits": [ref("edit")], "result": "passed", "call_ref": ref("before-the-edit")})
        for name, changes in {"other-task": {"task_id": "T2"}, "other-actor": {"actor": "builder-b"},
                              "other-revision": {"revision": "b"*64}, "other-edit": {"edits": ["c"*64]},
                              "other-session": {"session_id": "claude-code:s2"},
                              "contradiction": {"result": "failed"}, "correct": {}}.items():
            sid = changes.get("session_id", session)
            self.check(sid.removeprefix("claude-code:"), name, "builder")
            send({**receipt, "role": "test", "edits": [ref("edit")], "result": "passed",
                  "call_ref": ref(name, sid), **changes})
        self.collect()
        edit, = [r for r in self.events() if r["work"]["action"] == "file_edit"]
        linked, = self.detail(edit)["verification"]["tests"]
        expected = self.ctx.db.query_one("SELECT event_id FROM verification_calls WHERE ref=?", (ref("correct"),))
        self.assertEqual(linked["event_id"], expected["event_id"])

    def test_receipts_are_host_scoped_immutable_and_tenant_private(self):
        proof = {"host_id": "capture", "session_id": "claude-code:test", "call_ref": "a"*64, "revision": "b"*64,
                 "role": "edit", "task_id": "task", "actor": "developer"}
        endpoint = "/api/v1/ingest/verification"
        def send(data):
            return self.req("POST", endpoint, data, cookie=False, headers=self.bearer(self.tok))[0]
        self.assertEqual(self.req("POST", endpoint, proof, cookie=False)[0], 401)
        self.assertEqual(send(proof), 200)
        self.assertEqual(send(proof), 200)
        self.assertEqual(send({**proof, "actor": "someone-else"}), 400)
        self.assertEqual(send({**proof, "host_id": "another-host"}), 403)
        self.assertEqual(send({**proof, "call_ref": "short"}), 400)
        self.edit("s", "e", "developer", 1)
        self.check("s", "t", "developer")
        self.collect()
        edit, = [r for r in self.events() if r["work"]["action"]=="file_edit"]
        test, = self.detail(edit)["verification"]["tests"]
        status, _, headers = self.req("POST", "/api/v1/auth/register", {"organization": "Other", "username": "orgb-test",
                                     "password": secrets.token_urlsafe(20)}, cookie=False)
        self.assertEqual(status, 201)
        self.cookie = headers["set-cookie"].split(";")[0]
        for ident in (edit["id"], test["event_id"]):
            self.assertEqual(self.req("GET", f"/api/v1/events/{ident}/evidence")[0], 404)
            self.assertEqual(self.req("GET", f"/api/v1/events/{ident}/evidence?organization_id=1")[0], 409)
