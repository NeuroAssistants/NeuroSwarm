"""Pi v3 sessions through both journal paths and the same HTTP endpoints used by Live Events."""
import base64
from contextlib import ExitStack
import hashlib
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "agent")]

import activity_inspector as inspector
import activity_shipper
from db import Database
from live_history import history
import work_journal

try:
    from .test_security import ServerHarness
except ImportError:
    from test_security import ServerHarness


SID = "00000000-0000-4000-a000-000000000001"
STAMP = datetime.now(timezone.utc).isoformat()
PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGOwmPngPwAFbwKxEfU0EQAAAABJRU5ErkJggg=="


def header(cwd, sid=SID, version=3):
    return {"type": "session", "id": sid, "version": version, "cwd": str(cwd), "timestamp": STAMP}


def message(node, parent, role, **fields):
    return {"type": "message", "id": node, "parentId": parent, "timestamp": STAMP,
            "message": {"role": role, **fields}}


def call(call_id, tool, **arguments):
    return {"type": "toolCall", "id": call_id, "name": tool, "arguments": arguments}


def result(node, parent, call_id, tool, error=False, text=""):
    return message(node, parent, "toolResult", toolCallId=call_id, toolName=tool, isError=error,
                   content=[{"type": "text", "text": text}])


def append(path, *rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


def collect(project, **options):
    payload, offsets, _ = activity_shipper.collect_incremental_activity(
        raw_roots=[str(project)], home_dir=project.parent / "home", host_id="pi-host",
        use_core=True, **options)
    return payload, offsets


class PiActivityTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.project = self.base / "project"
        self.project.mkdir()
        self.home = self.base / "home"
        self.log = self.home / ".pi/agent/sessions/--project--/session.jsonl"
        self.patches = ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(patch.object(inspector, "HOME", self.home))
        self.patches.enter_context(patch.object(inspector, "harnesses", return_value=[]))
        self.patches.enter_context(patch.dict(os.environ, PI_CODING_AGENT_DIR="", PI_CODING_AGENT_SESSION_DIR="",
                                    SWARMCONTROL_SHARE_COMMANDS="0", SWARMCONTROL_SHARE_COMMAND_OUTPUT="0",
                                    SWARMCONTROL_SHARE_FILE_PREVIEWS="0"))

    def test_forks_parallel_results_and_privacy(self):
        calls = [call("same", "write", path="left.py", content="PRIVATE_CONTENT"),
                 call("read", "read", path="@notes.txt"), call("pending", "edit", path="never-ran.py")]
        append(self.log, header(self.project),
               message("a", None, "assistant", content=calls, model="demo"),
               message("b", None, "assistant", content=[call("same", "edit", path="right.py")]),
               result("rb", "b", "same", "edit", error=True, text="PRIVATE_CONTENT"),
               result("bad", "a", "same", "read"),
               result("orphan", "absent", "same", "write"),
               result("ra", "a", "same", "write"),
               result("rr", "ra", "read", "read"),
               message("user", "ra", "user", content="PRIVATE_PROMPT"),
               result("late", "user", "pending", "edit"),
               message("c", "rr", "assistant", content=[
                   call("private", "read", path=".env"), call("other", "write", path="../private.py"),
                   call("cmd", "bash", command="echo PRIVATE_ARG")]),
               result("rc", "c", "private", "read", text="PRIVATE_CONTENT"),
               result("rd", "rc", "other", "write"),
               result("re", "rd", "cmd", "bash", text="PRIVATE_SHELL_OUTPUT"))
        session, = collect(self.project)[0]["sessions"]
        self.assertEqual(session["files_edited"], [str(self.project / "left.py")])
        self.assertEqual(session["files_read"], [str(self.project / "notes.txt")])
        self.assertEqual(session["how"], {"file_edit": 3, "file_read": 2, "shell": 1})
        first = session["capture_steps"][0]
        self.assertEqual((first["status"], first["file_basis"]), ("error", "recorded"))
        self.assertEqual(first["files"], [str(self.project / "right.py")])
        self.assertEqual(session["steps"][1]["file_basis"], "confirmed")
        self.assertEqual(len({s["src"] for s in session["capture_steps"]}), 6)
        for hidden in ("PRIVATE_", ".env", "never-ran", "private.py"):
            self.assertNotIn(hidden, json.dumps(session))

    def test_directory_overrides_scope_versions_and_links(self):
        outside = self.base / "private"
        outside.mkdir()
        profile_log = self.base / "profile/sessions/--project--/x.jsonl"
        direct = self.base / "sessions"
        for path, cwd, sid, version in [
            (self.log, self.project, SID, 3), (profile_log, self.project, "profile", 3),
            (direct / "x.jsonl", self.project, "sensitive user-defined session name", 3),
            (direct / "elsewhere.jsonl", outside, "foreign", 3),
            (direct / "future.jsonl", self.project, "future", 4),
            (direct / "invalid.jsonl", chr(0), "invalid", 3),
        ]:
            append(path, header(cwd, sid, version))
        (direct / "broken.jsonl").write_text("not JSON\n")
        (direct / "link.jsonl").symlink_to(self.log)
        (direct / "linked-folder").symlink_to(profile_log.parent, target_is_directory=True)
        self.assertEqual(collect(self.project)[0]["sessions"][0]["session_id"], "pi:" + SID)
        with patch.dict(os.environ, PI_CODING_AGENT_DIR=str(profile_log.parents[2])):
            session, = collect(self.project)[0]["sessions"]
            self.assertNotEqual(session["session_id"], "pi:" + SID)
            with patch.dict(os.environ, PI_CODING_AGENT_SESSION_DIR=str(direct)):
                direct_session, = collect(self.project)[0]["sessions"]
                self.assertNotEqual(direct_session["session_id"], session["session_id"])
                self.assertNotIn("sensitive user-defined", json.dumps(direct_session))
                self.assertIsNone(activity_shipper.collect_incremental_activity(raw_roots=[])[0])

    def test_rotation_between_header_and_tail_does_not_attribute_foreign_events(self):
        outside = self.base / "other"
        outside.mkdir()
        append(self.log, header(self.project))
        replacement = self.base / "replacement"
        append(replacement, header(outside, "outside"),
               {"padding": "x" * (inspector.CAPTURE_FIRST_SIGHT + 1024)},
               message("one", None, "assistant", content=[call("k", "edit", path="foreign.py")]),
               result("done", "one", "k", "edit"))
        original = inspector._lines
        def rotate(path):
            replacement.replace(path)
            yield from original(path)
        with patch.object(inspector, "_lines", side_effect=rotate):
            payload, offsets = collect(self.project)
        self.assertFalse(payload["sessions"])
        self.assertNotIn(inspector._file_key(self.log), offsets)
        self.assertFalse(collect(self.project, offsets=offsets)[0]["sessions"])

    def test_append_resume_and_local_journal(self):
        append(self.log, header(self.project),
               message("one", None, "assistant", content=[call("k", "edit", path="src/demo.py")]))
        db = Database(self.base / "local.db")
        self.addCleanup(db.close)
        with sqlite3.connect(db.db_path) as conn:
            scope = inspector.Scope([self.project], {}, "pi-host")
            def scan():
                return work_journal.capture_once(conn, {self.project.name}, self.project, scope=scope).get("inserted", 0)
            self.assertEqual(scan(), 0)
            append(self.log, result("done", "one", "k", "edit"))
            self.assertEqual(scan(), 1)
            self.assertEqual(scan(), 0)
        record, = history(db, 1, {"runtime": ["pi"]})["records"]
        self.assertEqual(record["work"]["files"], ["src/demo.py"])
        self.assertEqual(record["work"]["basis"], "confirmed")


class PiLiveTests(ServerHarness):
    def test_observer_to_live_map_and_evidence(self):
        project = Path(self.tmp.name) / "project"
        project.mkdir()
        log = project.parent / "sessions/demo.jsonl"
        append(log, header(project),
               message("a", None, "assistant", content=[call("write", "write", path="demo.py", content="PRIVATE_SOURCE")]),
               result("b", "a", "write", "write", text="PRIVATE_SOURCE"),
               message("c", "b", "assistant", content=[call("test", "bash", command="python3 -m unittest")]),
               result("d", "c", "test", "bash", text="one test passed\nAPI_KEY=FAKE_PRIVATE_VALUE"),
               message("e", "d", "assistant", content=[
                   call("image", "read", path="ui/tile.png"), call("source", "read", path="notes.txt")]),
               message("f", "e", "toolResult", toolCallId="image", toolName="read", isError=False,
                       content=[{"type": "image", "mimeType": "image/png", "data": PNG}]),
               result("g", "f", "source", "read", text="shared excerpt\nAPI_KEY=FAKE_PRIVATE_VALUE"))
        with patch.dict(os.environ, PI_CODING_AGENT_SESSION_DIR=str(log.parent),
                        SWARMCONTROL_SHARE_COMMANDS="1", SWARMCONTROL_SHARE_COMMAND_OUTPUT="1",
                        SWARMCONTROL_SHARE_FILE_PREVIEWS="1"):
            payload, offsets = collect(project)
            after, _ = collect(project, offsets=offsets)
        self.assertEqual(after["capture_metrics"]["steps_seen"], 0)
        self.assertEqual(self.login()[0], 200)
        token = self.bearer(self.token("pi"))
        for _ in range(2):
            status, info, _ = self.req("POST", "/api/v1/ingest/activity", payload, headers=token, cookie=False)
            self.assertEqual(status, 200, info)
        status, view, _ = self.req("GET", "/api/v1/activity")
        self.assertEqual(status, 200)
        session, = [s for s in view["sessions"] if s["harness"] == "pi"]
        status, feed, _ = self.req("GET", "/api/v1/event-feed")
        self.assertEqual(status, 200)
        records = [r for r in feed["records"] if r.get("source") == "observed_step"]
        self.assertEqual(len(records), 4)
        edit = next(r for r in records if r["details"]["action"] == "file_edit")
        command = next(r for r in records if r["details"]["action"] == "shell")
        self.assertEqual(edit["details"]["files"], ["demo.py"])
        self.assertEqual({s["event_id"] for s in session["steps"]}, {r["id"] for r in records})
        status, evidence, _ = self.req("GET", f"/api/v1/events/{command['id']}/evidence")
        self.assertEqual(status, 200)
        self.assertEqual(evidence["command_input"], "python3 -m unittest")
        self.assertIn("one test passed", evidence["command_output"])
        self.assertIsNone(evidence["exit_code"])
        by_file = {path: r["id"] for r in records for path in r["details"]["files"]}
        _, image, _ = self.req("GET", f"/api/v1/events/{by_file['ui/tile.png']}/evidence")
        preview, = image["images"]
        self.assertEqual(preview["sha256"], hashlib.sha256(base64.b64decode(PNG)).hexdigest())
        self.assertEqual(preview["source"], "tool_result")
        _, file, _ = self.req("GET", f"/api/v1/events/{by_file['notes.txt']}/evidence")
        excerpt, = file["text_previews"]
        self.assertIn("shared excerpt", excerpt["text"])
        self.assertNotIn("shared excerpt", json.dumps([feed, view]))
        for marker in ("PRIVATE_SOURCE", "FAKE_PRIVATE_VALUE"):
            self.assertNotIn(marker, json.dumps([feed, evidence, file, view]))
