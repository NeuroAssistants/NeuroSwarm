"""Regression cases for activity transport, step-local evidence and older OpenCode stores."""
import gzip
import http.cookiejar
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from urllib import error, request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
import activity_inspector as ai
import server


class OpenCodeEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        home = Path(temp.name)
        self.workspace = home / "projects" / "demo-app"  # a generic folder, not a host-app layout
        self.workspace.mkdir(parents=True)
        patch_home = patch.multiple(ai, HOME=home, _CURRENT=ai.Scope([self.workspace]))
        patch_home.start()
        self.addCleanup(patch_home.stop)
        path = home / ".local/share/opencode/opencode.db"
        path.parent.mkdir(parents=True)
        self.db = sqlite3.connect(path)
        self.addCleanup(self.db.close)
        self.db.execute("CREATE TABLE session_v2(id TEXT, directory TEXT, time_updated INTEGER, model TEXT, title TEXT)")
        self.db.execute("INSERT INTO session_v2 VALUES(?,?,?,?,?)", (
            "session-1", str(self.workspace), 1800000000000,
            json.dumps({"id": "deepseek-test-model", "providerID": "opencode"}), "Review a change"))
        self.db.commit()

    def test_missing_message_table_preserves_session_header(self):
        session, = ai.opencode_sessions()
        self.assertEqual(session["provider_id"], "opencode")
        self.assertEqual(session["model"], "deepseek-test-model")
        self.assertEqual(session["steps"], [])

    def test_step_status_file_and_plan_reference_stay_separate(self):
        self.db.execute("CREATE TABLE session_message(session_id TEXT, type TEXT, seq INTEGER, time_created INTEGER, data TEXT)")
        def tool(name, status, **args):
            return {"type": "tool", "name": name, "state": {"status": status, "input": args,
                    "content": [{"text": "private tool output"}]}}

        parts = [{"type": "reasoning", "text": "private reasoning"}, tool("read", "completed", path="src/loader.js"),
                 tool("edit", "completed", path="src/ui.js", newString="private file content"),
                 tool("edit", "error", path="unwritten.txt"), tool("read", "completed", path=".env"),
                 tool("read", "completed", path="../sibling/private.txt"),
                 tool("shell", "completed", command="private command"),
                 tool("todowrite", "completed", todos=[{"content": "Review src/ui.js", "status": "in_progress"}])]
        self.db.executemany("INSERT INTO session_message VALUES(?,?,?,?,?)", [
            ("session-1", "user", 1, 1, json.dumps({"content": [tool("edit", "completed", path="from-user.txt")]})),
            ("session-1", "assistant", 2, 1800000000200, json.dumps({"content": parts})),
            ("session-1", "assistant", 3, 1800000000300, "unfinished JSON")])
        self.db.commit()
        s, = ai.opencode_sessions()
        self.assertEqual(len(s["steps"]), 7)
        self.assertEqual(s["files_edited"], [str(self.workspace / "src/ui.js")])
        self.assertEqual(s["files_read"], [str(self.workspace / "src/loader.js")])
        self.assertEqual(s["steps"][0]["files"], s["files_read"])
        self.assertEqual(s["steps"][1]["files"], s["files_edited"])
        self.assertEqual(s["steps"][2]["status"], "error")
        self.assertNotIn("files", s["steps"][2])
        self.assertEqual(s["plan"][0]["named_files"], s["files_edited"])
        self.assertNotIn("files", s["plan"][0], "A filename in a plan is not a completed edit")
        for hidden in ("unwritten.txt", "from-user.txt", ".env", "sibling/", "private command",
                       "private tool output", "private file content", "private reasoning"):
            self.assertNotIn(hidden, json.dumps(s))

    def test_ambiguous_basename_not_attached_to_plan(self):
        card = {"plan": [{"text": "Check util.py", "status": "pending"}], "what_done": ""}
        ai._finish(card, [], ["/workspace/a/util.py", "/workspace/b/util.py"], [])
        self.assertNotIn("named_files", card["plan"][0])


class CodexFileChangeTests(unittest.TestCase):
    def test_only_completed_structured_edits_are_attributed(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            project = home / "work" / "client-portal"
            project.mkdir(parents=True)
            folder = home / ".codex"
            folder.mkdir()
            log = folder / "example.jsonl"
            def item(status, name, paths):
                return {"type": "item_completed", "item": {"id": name, "type": "FileChange", "status": status,
                        "changes": paths, "stdout": "private command output"}}

            target = str(project / "src/loader.js")
            changes = {target: {"type": "update", "unified_diff": "private file data", "move_path": None},
                       str(project / ".env"): {"type": "add"}}
            records = [{"type": "custom_tool_call", "name": "exec",
                        "input": "print('*** Update File: " + str(project / "sample-only.js") + "')"},
                       {"type": "patch_apply_end", "call_id": "edit-1", "success": True, "changes": changes},
                       item("completed", "edit-1", changes),
                       item("failed", "edit-2", {str(project / "failed.js"): {"type": "add"}})]
            log.write_text("\n".join(json.dumps({"payload": r, "timestamp": "2026-11-22T15:00:00Z"}) for r in records))
            with sqlite3.connect(folder / "state_5.sqlite") as db:
                db.execute("CREATE TABLE threads(id TEXT,cwd TEXT,model TEXT,tokens_used INT,updated_at INT,rollout_path TEXT)")
                db.execute("INSERT INTO threads VALUES(?,?,?,?,?,?)", ("session", str(project), "gpt", 0, 1, str(log)))
            with patch.multiple(ai, HOME=home, _CURRENT=ai.Scope([project])):
                s, = ai.codex_sessions()
            self.assertEqual(s["files_edited"], [target])
            self.assertEqual(len(s["steps"]), 2)
            self.assertEqual(s["steps"][0]["files"], [target])
            self.assertEqual(s["steps"][1]["status"], "error")
            self.assertFalse(s["steps"][1]["files"])
            for private in ("private file data", "private command output", ".env", "failed.js", "sample-only.js"):
                self.assertNotIn(private, json.dumps(s))


class ActivityTransportTests(unittest.TestCase):
    @patch.dict("os.environ", {"SWARMCONTROL_OPENBOT_CHANNEL_ID": ""})
    def test_operator_get_compressed_and_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            httpd, _ = server.create_server(port=0, db_path=str(Path(tmp) / "qa.db"), admin_pass="local-test-only")
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            origin = f"http://127.0.0.1:{httpd.server_port}"
            opener = request.build_opener(request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
            try:
                snap = {"sessions": [{"file": "src/activity.js"}] * 160, "host": "estación"}
                with patch.object(server, "build_tenant_activity_map", return_value=snap) as collect:
                    activity = origin + "/api/v1/activity"
                    with self.assertRaises(error.HTTPError) as anonymous:
                        opener.open(activity, timeout=5)
                    self.assertEqual(anonymous.exception.code, 401)
                    anonymous.exception.close()
                    board_url = origin + "/api/v1/work-board"
                    with self.assertRaises(error.HTTPError) as private_board:
                        opener.open(board_url + "?include=activity", timeout=5)
                    self.assertEqual(private_board.exception.code, 401)
                    private_board.exception.close()
                    collect.assert_not_called()
                    login = request.Request(origin + "/api/v1/auth/login", data=json.dumps({
                        "username": "admin", "password": "local-test-only"}).encode(),
                        headers={"Content-Type": "application/json"})
                    with opener.open(login, timeout=5) as response:
                        self.assertTrue(json.load(response)["authenticated"])
                    for encoding in ("gzip;q=0, identity", "br", "br, gzip;q=0.7"):
                        req = request.Request(activity, headers={"Accept-Encoding": encoding})
                        with opener.open(req, timeout=5) as response:
                            self.assertEqual(response.headers["Vary"], "Accept-Encoding")
                            self.assertEqual(response.headers["Cache-Control"], "no-store")
                            wire = response.read()
                            self.assertEqual(len(wire), int(response.headers["Content-Length"]))
                            if encoding.endswith("0.7"):
                                self.assertEqual(response.headers["Content-Encoding"], "gzip")
                                self.assertLess(len(wire), len(gzip.decompress(wire)))
                                wire = gzip.decompress(wire)
                            else:
                                self.assertIsNone(response.headers.get("Content-Encoding"))
                            self.assertEqual(json.loads(wire), snap)
                    with opener.open(board_url, timeout=5) as ordinary:
                        self.assertNotIn("activity", json.load(ordinary))
                    with opener.open(board_url + "?include=activity", timeout=5) as composed:
                        self.assertEqual(json.load(composed)["activity"], snap)
                    collect.side_effect = OSError("source unavailable")
                    with opener.open(board_url + "?include=activity", timeout=5) as partial:
                        self.assertEqual(json.load(partial), {
                            "project": "Default workspace",
                            "reports": [],
                            "runtimes": [],
                            "collaboration": {"changes": []},
                            "links": {"version": "1", "organization": 1, "by_task": {}, "by_session": {}},
                        })
            finally:
                httpd.shutdown()
                thread.join(timeout=2)
                httpd.server_close()
                httpd.app_ctx.db.close()


class ActivityDetailAndContrastTests(unittest.TestCase):
    def test_claude_channel_result_tool_gets_friendly_label(self):
        step = ai._step("mcp__openbot__channel_result", "openbot channel_result", "2026-11-22T15:10:48")
        self.assertEqual(step["label"], "Post the result to the channel")

    def test_activity_ui_detail_dialog_and_selected_icon_contrast(self):
        js = (ROOT / "frontend" / "activity.js").read_text(encoding="utf-8")
        css = (ROOT / "frontend" / "styles.css").read_text(encoding="utf-8")
        self.assertIn("e.target === dialog || e.target.closest(\"[data-close]\")", js)
        self.assertIn("What the agent did", js)
        self.assertIn("${stepFiles ? \"\" : \" open\"}", js)  # session files open when no step-level file
        self.assertIn("for (let attempt = 0; attempt < 2; attempt++)", js)
        self.assertIn(".am-node.selected .am-map-provider { color: var(--sc-mint); }", css)


if __name__ == "__main__":
    unittest.main()
