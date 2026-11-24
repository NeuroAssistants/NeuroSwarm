"""Local OpenBot collaboration projection and authenticated work-board contract."""

from contextlib import closing
import http.client
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from adapters import openbot_collaboration as source
from server import create_server


class WorkCollaborationTests(unittest.TestCase):
    A, B = "channel-alpha", "channel-beta"

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.config = Path(temp.name) / "OpenBot #test?"
        self.config.mkdir()
        self.path = self.config / "openbot.db"
        env = patch.dict(os.environ, {
            "SWARMCONTROL_OPENBOT_CONFIG": str(self.config),
            "SWARMCONTROL_OPENBOT_CHANNEL_ID": self.A,
            "SWARMCONTROL_ACTIVITY_ADAPTERS": "",
            "SWARMCONTROL_ACTIVITY_ROOTS": "",
            "SWARMCONTROL_PUBLIC_URL": "",
            "SWARMCONTROL_REGISTRATION": "open",
            "SWARMCONTROL_QUIET": "1",
        })
        env.start()
        self.addCleanup(env.stop)
        self.db = sqlite3.connect(self.path, isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.executescript("""
            CREATE TABLE projection_channel_tasks(task_id TEXT PRIMARY KEY, channel_id TEXT, task_json TEXT);
            CREATE TABLE projection_channel_messages(channel_id TEXT, message_id TEXT, sequence INTEGER,
                message_json TEXT, PRIMARY KEY(channel_id, message_id));
            CREATE TABLE projection_agents(agent_id TEXT PRIMARY KEY, agent_json TEXT);
            CREATE TABLE projection_channel_assignments(assignment_id TEXT PRIMARY KEY, channel_id TEXT,
                task_id TEXT, assignment_json TEXT);
        """)
        self.sequence = 0
        self.agent("lead", "Release team")
        self.agent("builder", "dev-team-api")
        self.agent("reviewer", "Revisión técnica")
        self.seed(self.A, "rA", "Add a weekly billing digest")
        self.seed(self.B, "rB", "Review the warehouse ledger")

    def agent(self, agent, name):
        self.db.execute("INSERT OR REPLACE INTO projection_agents VALUES (?,?)", (agent, json.dumps({
            "name": name, "description": "PROFILE_PRIVATE_SENTINEL", "workspacePath": "/hidden/location"})))

    def message(self, channel, mid, task, text, when, *, who="lead", superseded=False):
        self.sequence += 1
        data = {"taskId": task, "author": {"kind": "agent", "id": who}, "superseded": superseded,
                "message": {"author": "assistant", "text": text, "createdAt": when, "status": "completed",
                            "attachments": [{"name": "ATTACHMENT_PRIVATE_SENTINEL"}]}}
        self.db.execute("INSERT INTO projection_channel_messages VALUES (?,?,?,?)",
                        (channel, mid, self.sequence, json.dumps(data)))

    def task(self, channel, tid, root, parent, owner, title, state, *, objective="", rev=0):
        record = {"rootTaskId": root, "parentTaskId": parent, "ownerAgentId": owner, "requestMessageId": "request",
                  "instruction": title, "expectedResult": objective, "state": state, "revision": rev,
                  "resources": ["PRIVATE_RESOURCE_SENTINEL"], "error": "PRIVATE_ERROR_SENTINEL"}
        self.db.execute("INSERT OR REPLACE INTO projection_channel_tasks VALUES (?,?,?)",
                        (tid, channel, json.dumps(record)))

    def formal(self, channel, aid, tid, owner, summary, when, *, rev=0, superseded=False, author=None):
        self.db.execute("INSERT INTO projection_channel_assignments VALUES (?,?,?,?)",
                        (aid, channel, tid, json.dumps({"agentId": owner, "taskRevision": rev})))
        self.message(channel, f"channel-result-{aid}-revision-{rev}", tid, summary, when,
                     who=author or owner, superseded=superseded)

    def seed(self, channel, root, name):
        self.message(channel, "request", root, "REQUEST_PRIVATE_SENTINEL", "2026-01-01T00:00:00.999Z")
        self.task(channel, root, root, None, "lead", name, "waiting")
        self.task(channel, root+"-api", root, root, "builder", "Implement the monthly totals.", "completed")
        self.task(channel, root+"-qa", root, root+"-api", "reviewer", "Verify invoice rounding.", "running")
        self.formal(channel, "delivery-"+root, root+"-api", "builder",
                    "Los totales coinciden con el resumen mensual.\nDetails and PRIVATE_EXTRA_SENTINEL",
                    "2026-01-01T00:05:00Z")
        self.message(channel, "turn-post", root+"-qa", "TRANSCRIPT_PRIVATE_SENTINEL", "2026-01-01T00:08:02Z")

    def test_real_shape_links_owner_state_latest_formal_result_and_clock(self):
        before = self.path.read_bytes()
        changes = source.collaboration(1)["changes"]
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(len(changes), 1)
        change = changes[0]
        self.assertEqual(set(change), {"id", "title", "status", "updated_at", "tasks"})
        self.assertEqual((change["id"], change["title"], change["status"]),
                         ("rA", "Add a weekly billing digest", "waiting"))
        lead, api, qa = change["tasks"]
        self.assertEqual(set(api), {"id", "parent_id", "agent", "title", "status", "result", "updated_at"})
        self.assertIsNone(lead["parent_id"])
        self.assertEqual((api["agent"], api["parent_id"], qa["parent_id"]), ("dev-team-api", "rA", "rA-api"))
        self.assertEqual((qa["status"], qa["agent"], qa["result"]), ("running", "Revisión técnica", ""))
        self.assertEqual(api["result"], "Los totales coinciden con el resumen mensual.")
        self.assertEqual(api["updated_at"], 1767225900)
        self.assertEqual(change["updated_at"], qa["updated_at"])
        self.assertEqual(qa["updated_at"], 1767226082)
        public = json.dumps(change)
        self.assertNotIn("SENTINEL", public)
        self.assertNotIn("warehouse", public)

    def test_result_requires_current_owner_revision_unsuperseded_and_matching_assignment(self):
        self.formal(self.A, "old", "rA-qa", "reviewer", "Former private result", "2026-01-01T01:00:00Z",
                    rev=2)
        self.formal(self.A, "withdrawn", "rA-qa", "reviewer", "Withdrawn private result",
                    "2026-01-01T01:04:00Z", superseded=True)
        self.formal(self.A, "wrong-person", "rA-qa", "reviewer", "Another person's result",
                    "2026-01-01T01:05:00Z", author="builder")
        self.message(self.A, "channel-result-unassigned-revision-0", "rA-qa", "Invented result",
                     "2026-01-01T01:06:00Z", who="reviewer")
        self.assertEqual(source.collaboration(1)["changes"][0]["tasks"][2]["result"], "")
        self.formal(self.A, "accepted", "rA-qa", "reviewer", "El redondeo quedó documentado.",
                    "2026-01-01T01:07:00Z")
        self.assertEqual(source.collaboration(1)["changes"][0]["tasks"][2]["result"],
                         "El redondeo quedó documentado.")
        self.task(self.A, "rA-qa", "rA", "rA-api", "reviewer", "Revisar la siguiente moneda", "queued", rev=1)
        qa = source.collaboration(1)["changes"][0]["tasks"][2]
        self.assertEqual((qa["status"], qa["result"]), ("queued", ""))

    def test_channel_selection_missing_parents_cycles_and_change_bound(self):
        self.task(self.A, "cross-family", "rA", "rB", "builder", "Cross channel confidential", "running")
        self.task(self.A, "orphan", "rA", "absent", "builder", "Missing parent", "running")
        self.task(self.A, "cycle1", "rA", "cycle2", "builder", "Invalid cycle", "running")
        self.task(self.A, "cycle2", "rA", "cycle1", "builder", "Invalid cycle", "running")
        self.task(self.A, "solo", "solo", None, "builder", "Unrelated solo request", "running")
        self.assertEqual(len(source.collaboration(1)["changes"][0]["tasks"]), 3)
        with patch.dict(os.environ, SWARMCONTROL_OPENBOT_CHANNEL_ID=self.B):
            changes = source.collaboration(1)["changes"]
            self.assertEqual([c["id"] for c in changes], ["rB"])
            self.assertNotIn("billing", json.dumps(changes))
        with patch.object(source, "MAX_TASKS", 2):
            self.assertEqual([t["id"] for t in source.collaboration(1)["changes"][0]["tasks"]], ["rA", "rA-api"])
        self.task(self.A, "old-root", "old-root", None, "lead", "Earlier completed change", "completed")
        self.task(self.A, "old-child", "old-root", "old-root", "builder", "Prepare release note", "completed")
        with patch.object(source, "MAX_CHANGES", 1):
            self.assertEqual([c["id"] for c in source.collaboration(1)["changes"]], ["rA"])

    def test_text_is_bounded_and_omits_private_material(self):
        # All values below are synthetic test markers.
        for raw in ["Check file /home/example/private/QDFXT.csv", r"Read C:\Users\example\QDFXT.xlsx",
                    "Check relative finance/QDFXT", "Visit https://host.invalid/private/QDFXT",
                    "password: 'QDFXT sample phrase'", "Bearer QDFXT0123456789abcdefgh",
                    "authorization: Basic UURGWFRodW50", "secret=QDFXT", "OTP: QDFXT", "sc_ro_t1_QDFXT",
                    "Open [private QDFXT](file:///tmp/QDFXT)", "```text\nQDFXT\n```", "User: private QDFXT",
                    "Run `echo QDFXT`", "TOKEN=QDFXT", "> QDFXT transcript",
                    "QDFXT is the password", "Check '.QDFXT' locally", "Said «QDFXT private quote»"]:
            with self.subTest(raw=raw):
                self.assertNotIn("QDFXT", source._summary(raw, 160))
        self.agent("builder", "/home/private/QDFXT")
        self.task(self.A, "rA-api", "rA", "rA", "builder", "Visit /users/QDFXT",
                  "completed", objective="Preparar el resumen contable.")
        api = source.collaboration(1)["changes"][0]["tasks"][1]
        self.assertEqual((api["title"], api["agent"]), ("Preparar el resumen contable.", "Agent"))
        self.assertLessEqual(len(source._summary("Measure " + "sample "*100, 160)), 160)

    def test_only_typed_summaries_and_committed_wal_records_are_visible(self):
        self.assertEqual(self.db.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        self.db.execute("PRAGMA wal_autocheckpoint=0")
        self.task(self.A, "rA-qa", "rA", "rA-api", "reviewer", ["PRIVATE CHAT ARRAY"], "running",
                  objective="Confirmar la fecha de corte.")
        self.formal(self.A, "bad-type", "rA-qa", "reviewer", ["PRIVATE TRANSCRIPT"], "2026-01-01T02:00:00Z")
        self.db.execute("BEGIN")
        self.task(self.A, "rA-qa", "rA", "rA-api", "reviewer", "Presentar el informe.", "completed", rev=1)
        try:
            qa = source.collaboration(1)["changes"][0]["tasks"][2]
            self.assertEqual((qa["title"], qa["status"], qa["result"]), ("Confirmar la fecha de corte.", "running", ""))
        finally:
            self.db.commit()
        qa = source.collaboration(1)["changes"][0]["tasks"][2]
        self.assertEqual((qa["title"], qa["status"]), ("Presentar el informe.", "completed"))

    def test_disabled_or_other_org_never_opens_source_and_missing_source_creates_nothing(self):
        with patch.object(source.sqlite3, "connect", side_effect=AssertionError("unexpected source access")):
            self.assertEqual(source.collaboration(2), {"changes": []})
            for setting in ("", "   ", "*", self.A + "," + self.B, "' OR 1=1 --"):
                with patch.dict(os.environ, SWARMCONTROL_OPENBOT_CHANNEL_ID=setting):
                    self.assertEqual(source.collaboration(1), {"changes": []})
        with patch.dict(os.environ, SWARMCONTROL_OPENBOT_CONFIG=str(self.config / "absent")):
            self.assertEqual(source.collaboration(1), {"changes": []})
            self.assertFalse((self.config / "absent").exists())
        self.db.execute("DROP TABLE projection_channel_tasks")
        self.assertEqual(source.collaboration(1), {"changes": []})

    def test_authenticated_http_org_and_channel_cannot_be_overridden(self):
        password = secrets.token_urlsafe(18)
        server, _ = create_server(port=0, db_path=str(self.config.parent / "app.db"), admin_pass=password)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.shutdown)

        def request(method, path, data=None, headers=None, *, status=200):
            with closing(http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)) as client:
                client.request(method, "/api/v1/"+path, json.dumps(data) if data is not None else None,
                               {"Content-Type": "application/json", **(headers or {})})
                res = client.getresponse()
                self.assertEqual(res.status, status)
                return json.loads(res.read()), res.getheader("Set-Cookie", "").split(";")[0]

        request("GET", "work-board", status=401)
        _, legacy = request("POST", "auth/login", {"username": "admin", "password": password})
        _, other = request("POST", "auth/register", {"username": "tenant-b", "password": password,
                                                     "organization": "Other team"}, status=201)
        for cookie, expected in ((legacy, ["rA"]), (other, [])):
            headers = {"Cookie": cookie}
            token, _ = request("POST", "tokens", {"name": "service", "scope": "read"}, headers, status=201)
            for auth in (headers, {"Authorization": "Bearer " + token["token"]}):
                board, _ = request("GET", "work-board?include=activity&channel_id=channel-beta&org_id=1",
                                   headers={**auth, "X-Organization-ID": "1", "X-OpenBot-Channel": self.B})
                self.assertEqual([c["id"] for c in board["collaboration"]["changes"]], expected)
                self.assertIn("reports", board)
                self.assertIn("activity", board)
        with patch.dict(os.environ, SWARMCONTROL_OPENBOT_CONFIG=str(self.config / "absent")):
            board, _ = request("GET", "work-board", headers={"Cookie": legacy})
            self.assertEqual(board["collaboration"], {"changes": []})
            self.assertIn("reports", board)


if __name__ == "__main__":
    unittest.main()
