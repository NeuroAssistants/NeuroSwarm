import datetime
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"backend"))
from db import Database
from activity_inspector import Scope
from live_history import history
from work_journal import record


class WorkJournalTests(unittest.TestCase):
    def test_optional_folder_and_command_history(self):
        now = time.time()
        stamp = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).isoformat()
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp, "product")
            secondary = Path(tmp, "examples")
            project.mkdir()
            secondary.mkdir()
            (secondary / "escape").symlink_to(Path(tmp))
            db = Database(Path(tmp, "journal.db"))
            self.addCleanup(db.close)
            scope = Scope([secondary])
            step = {"category": "shell", "tool": "exec_command", "time": stamp, "label": "Run tests",
                    "program": "python3", "command": "python3 -m unittest discover -k private_marker",
                    "files": [str(secondary/"sample.py"), str(secondary/".env"), str(secondary/"escape/private.txt")]}
            snapshot = {"sessions": [{"agent_name": "worker", "host_id": "host", "harness": "local",
                                      "workspace": str(project), "session_id": "s", "steps": [step]}]}
            writer = sqlite3.connect(db.db_path)
            self.addCleanup(writer.close)
            with patch.dict(os.environ, SWARMCONTROL_SHARE_COMMANDS="0"):
                record(writer, snapshot, {"worker"}, project, now)
            first = history(db, 1, {})["records"][0]["work"]
            self.assertEqual(first["files"], [])
            self.assertNotIn("command", first)
            with patch.dict(os.environ, SWARMCONTROL_SHARE_COMMANDS="1"):
                record(writer, snapshot, {"worker"}, project, now, scope)
                self.assertEqual(len(history(db, 1, {})["records"]), 1)
                snapshot["sessions"][0]["session_id"] = "new-session"
                record(writer, snapshot, {"worker"}, project, now, scope)
            rows = history(db, 1, {})["records"]
            self.assertEqual(len(rows), 2)
            work = rows[0]["work"]
            self.assertEqual(work["files"], ["examples/sample.py"])
            self.assertEqual(work["workspace"], "examples")
            self.assertEqual(work["command"], "python3 -m unittest discover")
            stored = json.dumps(db.query_all("SELECT * FROM events"))
            for excluded in ("private_marker", ".env", "private.txt", tmp):
                self.assertNotIn(excluded, stored)

    def test_safe_attribution_replay_and_history(self):
        now = time.time()
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)/"sample"
            project.mkdir()
            db = Database(Path(tmp)/"sample.db")
            self.addCleanup(db.close)
            stamp = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).isoformat()
            session = {"agent_name":"worker","workspace":str(project),"host_id":"h","harness":"codex",
                       "session_id":"s","steps":[{"category":"file_edit","time":stamp,"tool":"apply_patch",
                       "label":"raw private text","file_basis":"confirmed","files":[str(project/"file.py"),
                       str(project/".env"),str(project.parent/"unshared.txt")]}]}
            snap = {"sessions":[session,{**session,"agent_name":"outside"}]}
            with sqlite3.connect(db.db_path) as writer:
                for _ in range(2):
                    record(writer,snap,{"worker"},project,now)
            page = history(db,1,{})
            self.assertEqual(len(page["records"]),1)
            r = page["records"][0]
            self.assertEqual(r["work"]["files"],["file.py"])
            for private in ("unshared.txt",".env","raw private text",tmp,"outside"):
                self.assertNotIn(private,json.dumps(page))
            params={"session":["s"],"host":["h"],"agent":["worker"],"runtime":["codex"]}
            self.assertEqual(history(db,1,params)["records"],[r])
            self.assertFalse(history(db,1,{**params,"host":["elsewhere"]})["records"])
            with db.transaction() as conn:
                conn.executemany("""INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,created_at)
                                 VALUES('h','codex','w','info','INFO','note',?)""", [(now,)]*300)
            head=history(db,1,{})
            tail=history(db,1,{"before":[head["next"]]})
            self.assertEqual(len({r["id"] for r in head["records"]+tail["records"]}),301)
