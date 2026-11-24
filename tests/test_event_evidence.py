"""End-to-end tests for expanding one event, including its exact recorded image."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
from datetime import datetime, timedelta, timezone
import secrets
import time
from unittest.mock import patch

try:
    from .test_security import ServerHarness
    from .test_capture_incremental import CaptureHarness, append, stamp
except ImportError:
    from test_security import ServerHarness
    from test_capture_incremental import CaptureHarness, append, stamp

import activity_inspector as inspector
import event_evidence
import step_journal

# Synthetic 1x1 blue RGBA pixel.
PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGOwmPngPwAFbwKxEfU0EQAAAABJRU5ErkJggg=="
BASE = "/api/v1/events"


class EvidenceHTTPTests(ServerHarness):
    def test_real_ingestion_reads_are_private_small_and_bound_to_the_event(self):
        self.assertEqual(self.login()[0], 200)
        ingest = self.bearer(self.token())
        _, read, _ = self.req("POST", "/api/v1/tokens", {"name": "reader", "scope": "read"})
        reader = self.bearer(read)
        now = datetime.now(timezone.utc).isoformat()
        image = {"path": "ui/tile.png", "mime_type": "image/png", "data_base64": PNG, "source": "tool_result"}
        steps = [
            {"tool": "view_image", "category": "file_read", "label": "Read image", "status":"completed",
             "time": now, "files": ["ui/tile.png", "../private.png", ".env"], "image_previews": [image]},
            {"tool": "exec_command", "category": "shell", "label": "Run tests", "program": "pytest",
             "time": now, "command_input": "pytest -q --password DEMO_VALUE", "exit_code": 1,
             "command_output": "A test failed\nAPI_KEY=DEMO_VALUE\n" + "v" * 7000},
        ]
        payload = {"host_id": "example-host", "activity_enabled": True, "activity_roots": ["/work"],
                   "sessions":[{"session_id": "run-a", "harness": "codex", "agent_name": "example",
                                "workspace": "/work", "steps": steps, "capture_steps": steps}]}
        for _ in range(2):
            status, result, _ = self.req("POST", "/api/v1/ingest/activity", payload, headers=ingest, cookie=False)
            self.assertIn(status, (200, 201), result)
        _, page, _ = self.req("GET", "/api/v1/event-feed")
        work = [r for r in page["records"] if r["source"] == "observed_step"]
        self.assertEqual(len(work), 2)
        file_event = next(r for r in work if r["details"]["action"] == "file_read")
        self.assertEqual(file_event["details"]["files"], ["ui/tile.png"])
        for route in ("/api/v1/event-feed", "/api/v1/live-records", "/api/v1/events", "/api/v1/activity"):
            body = json.dumps(self.req("GET", route)[1])
            self.assertNotIn(PNG, body)
            self.assertNotIn("A test failed", body)
            self.assertNotIn("DEMO_VALUE", body)
        file_url = f"{BASE}/{file_event['id']}/evidence"
        status, detail, headers = self.req("GET", file_url, headers=reader, cookie=False)
        self.assertEqual((status, headers["cache-control"]), (200, "no-store"))
        self.assertEqual(detail["files"], ["ui/tile.png"])
        self.assertIsNone(detail["command_output"])
        entry, = detail["images"]
        self.assertEqual(entry["sha256"], hashlib.sha256(base64.b64decode(PNG)).hexdigest())
        self.assertEqual(entry["source"], "tool_result")
        binary = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        binary.request("GET", entry["url"], headers=reader)
        response = binary.getresponse()
        self.assertEqual((response.status, response.getheader("Content-Type"), response.getheader("Cache-Control")),
                         (200, "image/png", "no-store"))
        self.assertEqual(response.read(), base64.b64decode(PNG))
        binary.close()
        exec_id = next(r["id"] for r in work if r["details"]["action"] == "shell")
        status, execution, _ = self.req("GET", f"{BASE}/{exec_id}/evidence")
        self.assertEqual(status, 200)
        self.assertEqual(execution["exit_code"], 1)
        self.assertTrue(execution["output_truncated"])
        self.assertLessEqual(len(execution["command_output"]), 4096)
        self.assertIn("A test failed\n", execution["command_output"])
        self.assertIn("pytest -q", execution["command_input"])
        self.assertNotIn("DEMO_VALUE", json.dumps(execution))
        self.assertEqual(self.req("GET", f"{BASE}/{exec_id}/images/{entry['sha256']}")[0], 404)
        self.assertEqual(self.req("GET", file_url, cookie=False)[0], 401)
        self.assertEqual(self.req("GET", entry["url"], headers=ingest, cookie=False)[0], 401)
        self.assertEqual(self.req("GET", file_url+"?organization_id=999")[0], 409)
        status, _, header = self.req("POST", "/api/v1/auth/register", {"organization":"Another team",
                                    "username":"reviewer-b", "password":secrets.token_urlsafe(22)}, cookie=False)
        self.assertEqual(status, 201)
        self.cookie = header["set-cookie"].split(";")[0]
        self.assertEqual(self.req("GET", file_url)[0], 404)
        self.assertEqual(self.req("GET", entry["url"].split("?")[0])[0], 404)
        self.assertEqual(self.req("GET", entry["url"])[0], 409)
        with self.ctx.db.transaction() as conn:
            conn.execute("DELETE FROM events WHERE id IN (?,?)", (file_event["id"], exec_id))
            for table in ("event_images", "event_execution", "event_texts"):
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM "+table).fetchone()[0], 0)

    def test_large_unrelated_metadata_retains_files_and_legacy_details_are_explicitly_absent(self):
        self.login()
        with self.ctx.db.transaction() as conn:
            event = conn.execute("INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at)"
                 " VALUES('demo','codex','agent','observed_step','INFO','Read a file',?,?)",
                 (json.dumps({"workspace":"docs", "files":["guide.md"], "unrelated":"x"*20000}), time.time())).lastrowid
        for route, key, name in (("event-feed","details","records"), ("live-records","work","records")):
            data = self.req("GET", "/api/v1/"+route)[1][name]
            row = next(r for r in data if r["id"]==event)
            self.assertEqual(row[key]["files"], ["guide.md"])
            self.assertNotIn("unrelated",row[key])
        detail = self.req("GET", f"{BASE}/{event}/evidence")[1]
        self.assertEqual(detail["images"], [])
        self.assertIsNone(detail["command_output"])
        self.assertIsNone(detail["exit_code"])

    def test_only_approved_recorded_paths_and_raster_types(self):
        root = Path(self.tmp.name).resolve()
        directory = root / "docs"
        directory.mkdir()
        files = ["chart.png", "../private.jpg", "C:secret", "~/.ssh/id", ".env"]
        self.assertEqual(step_journal.journal_files(files, root, None, str(directory))[0], ["docs/chart.png"])
        self.assertEqual(step_journal.journal_files(files, root, None, "")[0], [])
        windows = step_journal.build_root_index(["C:/work"])
        self.assertEqual(step_journal.resolve_step_files(files, windows, "C:/work/docs")[0], ["docs/chart.png"])
        self.assertEqual(step_journal.resolve_step_files(files, windows, "C:/outside")[0], [])
        self.assertIsNone(event_evidence.image_type(b"<svg></svg>"))
        self.assertIsNone(event_evidence.image_type(base64.b64decode(PNG)[:-1]))


class SourceEvidenceTests(CaptureHarness):
    def test_workspace_snapshot_is_versioned_and_never_follows_a_link(self):
        root = self.roots["codex-team"]
        file = root / "src/tile.png"
        data = base64.b64decode(PNG)
        file.write_bytes(data)
        scope = inspector.Scope([root])
        after = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
        before = (datetime.now(timezone.utc) - timedelta(seconds=2)).isoformat()
        snap = inspector._workspace_image(str(file), after, scope)
        self.assertEqual(base64.b64decode(snap["data_base64"]), data)
        self.assertEqual(snap["source"], "workspace_snapshot")
        self.assertIsNone(inspector._workspace_image(str(file), before, scope))
        link = root / "src/shortcut.png"
        link.symlink_to(file)
        self.assertIsNone(inspector._workspace_image(str(link), after, scope))

    def test_claude_pairs_tool_id_and_preserves_its_relative_path(self):
        root = self.roots["claude-team"]
        records = []
        for i, (number, cmd) in enumerate((("first", "pytest -q"), ("second", "git status"))):
            records.append({"type":"assistant", "timestamp":stamp(i), "cwd":str(root),
                            "message":{"content":[{"type":"tool_use","name":"Bash",
                                                   "id":number,"input":{"command":cmd}}]}})
        for i, (number, out) in enumerate((("second", "clean tree"), ("first", "5 passed"))):
            records.append({"type":"user", "timestamp":stamp(i+2), "cwd":str(root),
                            "message":{"content":[{"type":"tool_result","tool_use_id":number,"content":out}]}})
        records.append({"type":"assistant","timestamp":stamp(4),"cwd":str(root/"src"),
                        "message":{"content":[{"type":"tool_use","name":"Read","id":"r","input":{"file_path":"icon.png"}}]}})
        records.append({"type":"user","timestamp":stamp(5),"cwd":str(root/"src"),
                        "message":{"content":[{"type":"tool_result","tool_use_id":"r",
                            "content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":PNG}}]}]}})
        records.append({"type":"assistant","timestamp":stamp(6),"cwd":str(root/"src"),
                        "message":{"content":[{"type":"tool_use","name":"Read","id":"t","input":{"file_path":"app.py"}}]}})
        records.append({"type":"user","timestamp":stamp(7),"cwd":str(root/"src"),"message":{"content":[
                        {"type":"tool_result","tool_use_id":"t","content":"def main():\n  api_key=TEST_SECRET_VALUE"}]}})
        self.claude(0, extra=records)
        with patch.dict(os.environ, {"SWARMCONTROL_SHARE_COMMAND_OUTPUT":"1", "SWARMCONTROL_SHARE_FILE_PREVIEWS":"1"}):
            self.scan()
        rows = self.dbo.query_all("SELECT id FROM events WHERE event_type='observed_step'")
        details = [event_evidence.detail(self.dbo, 1, row["id"]) for row in rows]
        outputs = {row["program"]:row["command_output"] for row in details if row["program"]}
        self.assertEqual(outputs, {"pytest":"5 passed","git":"clean tree"})
        image, = [row for row in details if row["images"]]
        self.assertTrue(image["files"][0].endswith("src/icon.png"))
        self.assertEqual(image["images"][0]["source"], "tool_result")
        snippet, = [row["text_previews"][0] for row in details if row["text_previews"]]
        self.assertTrue(snippet["path"].endswith("src/app.py"))
        self.assertIn("def main():\n  api_key=", snippet["text"])
        self.assertNotIn("TEST_SECRET_VALUE", snippet["text"])

    def test_typed_tool_result_and_command_output_survive_real_journal(self):
        rollout = self.codex(0)
        read = {"type":"DynamicToolCall", "tool":"tool_call", "arguments":{"name":"openbot.read_image",
                "arguments":{"path":"src/tile.png"}}, "success":True,
                "content_items":[{"type":"image","mimeType":"image/png","data":PNG}]}
        shell = {"type":"CommandExecution", "cwd":str(self.roots["codex-team"]),
                 "command":["bash","-lc","pytest -q"],"parsed_cmd":[{"type":"unknown","cmd":"pytest"}],
                 "aggregated_output":"first line\nsecond line","exit_code":3}
        def write(item,n):
            append(rollout,[{"timestamp":stamp(n),"payload":{"type":"item_completed","item":item}}])
        for name, expected in (("0", False), ("1", True)):
            env = {"SWARMCONTROL_SHARE_COMMANDS":name, "SWARMCONTROL_SHARE_COMMAND_OUTPUT":name,
                   "SWARMCONTROL_SHARE_FILE_PREVIEWS":name}
            with patch.dict(os.environ, env):
                write(read,1 if expected else 0)
                write(shell,3 if expected else 2)
                self.scan()
            records = self.dbo.query_all("SELECT id,message FROM events WHERE event_type='observed_step' ORDER BY id DESC LIMIT 2")
            details = [event_evidence.detail(self.dbo, 1, row["id"]) for row in records]
            image = next(x for x in details if x["files"])
            command = next(x for x in details if x["program"] == "pytest")
            self.assertTrue(image["files"][0].endswith("src/tile.png"))
            self.assertEqual(bool(image["images"]), expected)
            self.assertEqual(command["exit_code"], 3)
            self.assertEqual(command["command_input"], "pytest -q" if expected else None)
            self.assertEqual(command["command_output"], "first line\nsecond line" if expected else None)
