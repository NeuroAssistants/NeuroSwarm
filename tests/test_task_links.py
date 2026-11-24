#!/usr/bin/env python3
"""Tests for Paso 4 explicit task <-> session <-> step <-> confirmed file correlation.

Covers LINK-CONTRACT v1:
- Explicit task_id attribution on observed steps (never heuristic by agent/time).
- Simultaneous tasks for the same agent: only the explicitly linked task resolves.
- Confirmed files only (mentioned-only plan paths are never promoted to confirmed_file).
- OpenBot orchestrator turn -> provider session links (unambiguous, ambiguous concurrent, no-steps, missing tables, Org 1 only).
- HTTP endpoints: /api/v1/ingest/activity (with task_id), /api/v1/work-board (`links`),
  /api/v1/links, /api/v1/live-records?task_id=..., and multi-tenant isolation.
"""

from __future__ import annotations

from datetime import datetime, timezone
import http.cookiejar
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from adapters.openbot_collaboration import task_session_links  # noqa: E402
from correlation import resolve_links  # noqa: E402
from db import Database  # noqa: E402
from remote_activity import ingest_remote_activity  # noqa: E402
from server import create_server  # noqa: E402


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_req(opener, url: str, payload: dict | None = None, headers: dict | None = None, method: str | None = None):
    hdrs = dict(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = Request(url, data=data, headers=hdrs, method=method or ("POST" if payload is not None else "GET"))
    with opener.open(req, timeout=5) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


class TestCorrelationUnit(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.db_path = Path(self._td.name) / "tenant1.db"
        self.db = Database(str(self.db_path))

    def tearDown(self) -> None:
        self._td.cleanup()

    def test_simultaneous_same_agent_only_explicit_task_links(self) -> None:
        """Two simultaneous tasks of the same agent, one step linked
        explicitly to task-alpha and one unlinked step. Only task-alpha may be attributed."""
        now = time.time()
        collab = {
            "source": "openbot",
            "available": True,
            "changes": [
                {
                    "id": "change-root-1",
                    "title": "Parallel work by builder",
                    "status": "in_progress",
                    "updated_at": now,
                    "tasks": [
                        {
                            "id": "task-alpha",
                            "parent_id": "change-root-1",
                            "agent": "builder",
                            "title": "Fix billing tax rounding",
                            "status": "in_progress",
                            "result": "",
                            "updated_at": now,
                        },
                        {
                            "id": "task-beta",
                            "parent_id": "change-root-1",
                            "agent": "builder",
                            "title": "Audit invoice exports",
                            "status": "in_progress",
                            "result": "",
                            "updated_at": now,
                        },
                    ],
                }
            ],
        }

        payload = {
            "host_id": "node-1",
            "hostname": "node-1",
            "activity_enabled": True,
            "activity_roots": ["/srv/billing-api"],
            "sessions": [
                {
                    "session_id": "codex:sess-alpha-001",
                    "harness": "codex",
                    "agent_name": "builder",
                    "workspace": "/srv/billing-api",
                    "updated_at": now,
                    "steps": [
                        {
                            "time": _iso(now - 5),
                            "tool": "edit_file",
                            "category": "file_edit",
                            "label": "Updated tax rounding in src/billing.py",
                            "files": ["/srv/billing-api/src/billing.py"],
                            "file_basis": "confirmed",
                            "task_id": "task-alpha",
                        },
                        {
                            "time": _iso(now - 2),
                            "tool": "edit_file",
                            "category": "file_edit",
                            "label": "Edited src/unlinked.py without task_id",
                            "files": ["/srv/billing-api/src/unlinked.py"],
                            "file_basis": "confirmed",
                            # No task_id! Must NOT be attributed to task-beta or task-alpha.
                        },
                    ],
                }
            ],
        }
        res = ingest_remote_activity(self.db, payload)
        self.assertEqual(res["steps_persisted"], 2)

        links = resolve_links(self.db, org_id=1, collaboration_data=collab, reports=[], now=now)
        self.assertEqual(links["version"], "1")
        self.assertEqual(links["organization"], 1)

        alpha = links["by_task"]["task-alpha"]
        self.assertEqual(alpha["status"], "linked")
        self.assertEqual(alpha["basis"], "explicit_task_id")
        self.assertEqual(alpha["session_id"], "codex:sess-alpha-001")
        self.assertEqual(alpha["step_count"], 1)
        self.assertEqual(alpha["confirmed_file"], "src/billing.py")
        self.assertEqual(alpha["confirmed_files"], ["src/billing.py"])
        self.assertIsNotNone(alpha["confirmed_file_event_id"])
        self.assertEqual(alpha["last_step"]["file"], "src/billing.py")
        self.assertNotIn("src/unlinked.py", alpha["confirmed_files"])

        beta = links["by_task"]["task-beta"]
        self.assertEqual(beta["status"], "unknown")
        self.assertEqual(beta["basis"], "none")
        self.assertEqual(beta["session_id"], "")
        self.assertEqual(beta["step_count"], 0)
        self.assertIsNone(beta["last_step"])
        self.assertEqual(beta["confirmed_file"], "")
        self.assertEqual(beta["confirmed_files"], [])
        self.assertIsNone(beta["confirmed_file_event_id"])

        # Reverse index by_session contains ONLY task-alpha
        sess_links = links["by_session"]["codex:sess-alpha-001"]
        self.assertEqual(len(sess_links), 1)
        self.assertEqual(sess_links[0]["task_id"], "task-alpha")

    def test_mentioned_only_file_is_never_confirmed_file(self) -> None:
        now = time.time()
        payload = {
            "host_id": "node-1",
            "hostname": "node-1",
            "activity_enabled": True,
            "activity_roots": ["/srv/repo"],
            "sessions": [
                {
                    "session_id": "codex:sess-plan-001",
                    "harness": "codex",
                    "agent_name": "planner",
                    "workspace": "/srv/repo",
                    "updated_at": now,
                    "steps": [
                        {
                            "time": _iso(now - 10),
                            "tool": "plan",
                            "category": "plan",
                            "label": "Plan mentions src/mentioned_only.py",
                            "files": ["/srv/repo/src/mentioned_only.py"],
                            "file_basis": "mentioned",
                            "task_id": "task-plan-only",
                        }
                    ],
                }
            ],
        }
        ingest_remote_activity(self.db, payload)
        links = resolve_links(self.db, org_id=1, now=now)
        entry = links["by_task"]["task-plan-only"]
        self.assertEqual(entry["status"], "linked")
        self.assertEqual(entry["step_count"], 1)
        self.assertEqual(entry["confirmed_file"], "")
        self.assertEqual(entry["confirmed_files"], [])
        self.assertIsNone(entry["confirmed_file_event_id"])

        # Add a confirmed file edit on the same task
        payload2 = {
            "host_id": "node-1",
            "hostname": "node-1",
            "activity_enabled": True,
            "activity_roots": ["/srv/repo"],
            "sessions": [
                {
                    "session_id": "codex:sess-plan-001",
                    "harness": "codex",
                    "agent_name": "planner",
                    "workspace": "/srv/repo",
                    "updated_at": now,
                    "steps": [
                        {
                            "time": _iso(now - 1),
                            "tool": "edit_file",
                            "category": "file_edit",
                            "label": "Applied edit to src/real_change.py",
                            "files": ["/srv/repo/src/real_change.py"],
                            "file_basis": "confirmed",
                            "task_id": "task-plan-only",
                        }
                    ],
                }
            ],
        }
        ingest_remote_activity(self.db, payload2)
        links2 = resolve_links(self.db, org_id=1, now=now)
        entry2 = links2["by_task"]["task-plan-only"]
        self.assertEqual(entry2["confirmed_file"], "src/real_change.py")
        self.assertEqual(entry2["confirmed_files"], ["src/real_change.py"])
        self.assertIsNotNone(entry2["confirmed_file_event_id"])

    def test_openbot_turn_session_links_unambiguous_ambiguous_and_missing_tables(self) -> None:
        now_s = int(time.time())
        ob_dir = Path(self._td.name) / "openbot_cfg"
        ob_dir.mkdir()
        ob_db = ob_dir / "openbot.db"
        con = sqlite3.connect(str(ob_db))
        con.executescript(
            """
            CREATE TABLE projection_channel_assignments (
                channel_id TEXT,
                task_id TEXT,
                assignment_json TEXT
            );
            CREATE TABLE projection_turns (
                turn_id TEXT PRIMARY KEY,
                provider_session_id TEXT,
                started_at INTEGER,
                completed_at INTEGER
            );
            CREATE TABLE projection_provider_sessions (
                id TEXT PRIMARY KEY,
                provider TEXT,
                external_session_id TEXT
            );
            """
        )
        # Clean non-overlapping turn for task-turn-clean -> ps-clean
        con.execute("INSERT INTO projection_provider_sessions VALUES ('ps-clean', 'codex', 'extclean0001')")
        con.execute("INSERT INTO projection_turns VALUES ('turn-clean', 'ps-clean', ?, ?)", (now_s - 60, now_s - 30))
        con.execute(
            "INSERT INTO projection_channel_assignments VALUES ('ch-1', 'task-turn-clean', ?)",
            (json.dumps({"turnId": "turn-clean"}),),
        )

        # Two overlapping turns on the SAME provider session ps-shared -> BOTH must be ambiguous
        con.execute("INSERT INTO projection_provider_sessions VALUES ('ps-shared', 'codex', 'extshared002')")
        con.execute("INSERT INTO projection_turns VALUES ('turn-ov-1', 'ps-shared', ?, ?)", (now_s - 50, now_s - 10))
        con.execute("INSERT INTO projection_turns VALUES ('turn-ov-2', 'ps-shared', ?, ?)", (now_s - 40, now_s - 5))
        con.execute(
            "INSERT INTO projection_channel_assignments VALUES ('ch-1', 'task-ov-1', ?)",
            (json.dumps({"turnId": "turn-ov-1"}),),
        )
        con.execute(
            "INSERT INTO projection_channel_assignments VALUES ('ch-1', 'task-ov-2', ?)",
            (json.dumps({"turnId": "turn-ov-2"}),),
        )

        # Turn with no observed steps captured -> session_recorded_no_steps
        con.execute("INSERT INTO projection_provider_sessions VALUES ('ps-empty', 'codex', 'extempty0003')")
        con.execute("INSERT INTO projection_turns VALUES ('turn-empty', 'ps-empty', ?, ?)", (now_s - 20, now_s - 15))
        con.execute(
            "INSERT INTO projection_channel_assignments VALUES ('ch-1', 'task-empty', ?)",
            (json.dumps({"turnId": "turn-empty"}),),
        )
        con.commit()
        con.close()

        task_ids = ["task-turn-clean", "task-ov-1", "task-ov-2", "task-empty"]
        env = {"SWARMCONTROL_OPENBOT_CONFIG": str(ob_dir), "SWARMCONTROL_OPENBOT_CHANNEL_ID": "ch-1"}
        with mock.patch.dict(os.environ, env, clear=False):
            # Org 2 must receive empty dict
            self.assertEqual(task_session_links(2, task_ids), {})
            tlinks = task_session_links(1, task_ids)

        self.assertFalse(tlinks["task-turn-clean"]["ambiguous"])
        self.assertEqual(tlinks["task-turn-clean"]["session_id"], "codex:extclean0001")
        self.assertTrue(tlinks["task-ov-1"]["ambiguous"])
        self.assertTrue(tlinks["task-ov-2"]["ambiguous"])
        self.assertFalse(tlinks["task-empty"]["ambiguous"])

        # Seed a step inside task-turn-clean's turn window (no explicit task_id on the step)
        t_clean = float(now_s - 45)
        ingest_remote_activity(
            self.db,
            {
                "host_id": "node-1",
                "hostname": "node-1",
                "activity_enabled": True,
                "activity_roots": ["/srv/app"],
                "sessions": [
                    {
                        "session_id": "codex:extclean0001",
                        "harness": "codex",
                        "agent_name": "worker",
                        "workspace": "/srv/app",
                        "updated_at": t_clean,
                        "steps": [
                            {
                                "time": _iso(t_clean),
                                "tool": "edit_file",
                                "category": "file_edit",
                                "label": "Edited src/turn_clean.py",
                                "files": ["/srv/app/src/turn_clean.py"],
                                "file_basis": "confirmed",
                            }
                        ],
                    }
                ],
            },
        )

        collab = {
            "changes": [
                {
                    "id": "ch-root",
                    "tasks": [
                        {"id": "task-turn-clean", "agent": "worker", "title": "Clean turn", "status": "done"},
                        {"id": "task-ov-1", "agent": "worker", "title": "Overlap 1", "status": "done"},
                        {"id": "task-ov-2", "agent": "worker", "title": "Overlap 2", "status": "done"},
                        {"id": "task-empty", "agent": "worker", "title": "No steps", "status": "done"},
                    ],
                }
            ]
        }
        resolved = resolve_links(self.db, org_id=1, collaboration_data=collab, openbot_turn_links=tlinks)
        self.assertEqual(resolved["by_task"]["task-turn-clean"]["status"], "linked")
        self.assertEqual(resolved["by_task"]["task-turn-clean"]["basis"], "explicit_turn_session")
        self.assertEqual(resolved["by_task"]["task-turn-clean"]["confirmed_file"], "src/turn_clean.py")

        self.assertEqual(resolved["by_task"]["task-ov-1"]["status"], "unknown")
        self.assertEqual(resolved["by_task"]["task-ov-1"]["basis"], "ambiguous_concurrent_turn")
        self.assertEqual(resolved["by_task"]["task-ov-2"]["status"], "unknown")
        self.assertEqual(resolved["by_task"]["task-ov-2"]["basis"], "ambiguous_concurrent_turn")

        self.assertEqual(resolved["by_task"]["task-empty"]["status"], "unknown")
        self.assertEqual(resolved["by_task"]["task-empty"]["basis"], "session_recorded_no_steps")
        self.assertEqual(resolved["by_task"]["task-empty"]["session_id"], "codex:extempty0003")

        # Missing projection_turns table degrades cleanly to {}
        minimal_dir = Path(self._td.name) / "minimal_cfg"
        minimal_dir.mkdir()
        c2 = sqlite3.connect(str(minimal_dir / "openbot.db"))
        c2.execute("CREATE TABLE projection_channel_assignments (channel_id TEXT, task_id TEXT, assignment_json TEXT)")
        c2.commit()
        c2.close()
        with mock.patch.dict(
            os.environ,
            {"SWARMCONTROL_OPENBOT_CONFIG": str(minimal_dir), "SWARMCONTROL_OPENBOT_CHANNEL_ID": "ch-1"},
            clear=False,
        ):
            self.assertEqual(task_session_links(1, task_ids), {})


class TestLinksHTTPAndMultiTenant(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.httpd, _ = create_server(
            "127.0.0.1",
            0,
            db_path=str(Path(self._td.name) / "swarm.db"),
            admin_user="org1_admin",
            admin_pass="StrongPass1234!",
        )
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self._th = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._th.start()

        self.org1_opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        status, data = _json_req(
            self.org1_opener,
            f"{self.base}/api/v1/auth/login",
            {"username": "org1_admin", "password": "StrongPass1234!"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(data["authenticated"])

        # Create ingest token for Org 1
        st, tok = _json_req(self.org1_opener, f"{self.base}/api/v1/tokens", {"label": "ingest-1"})
        self.assertEqual(st, 201)
        self.org1_token = tok["token"]

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self._th.join(timeout=2)
        self._td.cleanup()

    def test_ingest_work_board_links_live_records_and_multitenant_isolation(self) -> None:
        now = time.time()
        # 1. Ingest activity with explicit task_id on one step and none on a concurrent step
        ingest_payload = {
            "host_id": "worker-node-a",
            "hostname": "worker-node-a",
            "activity_enabled": True,
            "activity_roots": ["/srv/payments"],
            "sessions": [
                {
                    "session_id": "codex:http-sess-01",
                    "harness": "codex",
                    "agent_name": "builder",
                    "workspace": "/srv/payments",
                    "status": "active",
                    "updated_at": now,
                    "steps": [
                        {
                            "time": _iso(now - 6),
                            "tool": "edit_file",
                            "category": "file_edit",
                            "label": "Fixed tax rate in src/payments/tax.py",
                            "files": ["/srv/payments/src/payments/tax.py"],
                            "file_basis": "confirmed",
                            "task_id": "task-http-linked",
                        },
                        {
                            "time": _iso(now - 3),
                            "tool": "run_command",
                            "category": "shell",
                            "label": "Run tests",
                            "command": "python3 -m unittest",
                            "program": "python3",
                            "file_basis": "confirmed",
                        },
                    ],
                }
            ],
        }
        st, ing = _json_req(
            self.org1_opener,
            f"{self.base}/api/v1/ingest/activity",
            ingest_payload,
            headers={"Authorization": f"Bearer {self.org1_token}"},
        )
        self.assertEqual(st, 200)
        self.assertEqual(ing["steps_persisted"], 2)

        # 2. Record two simultaneous work reports for the same agent: one linked, one unlinked
        _json_req(
            self.org1_opener,
            f"{self.base}/api/v1/ingest/event",
            {
                "host_id": "worker-node-a",
                "agent_name": "builder",
                "event_type": "work_done",
                "message": "Completed tax fix",
                "metadata": {"task_id": "task-http-linked"},
            },
            headers={"Authorization": f"Bearer {self.org1_token}"},
        )
        _json_req(
            self.org1_opener,
            f"{self.base}/api/v1/ingest/event",
            {
                "host_id": "worker-node-a",
                "agent_name": "builder",
                "event_type": "work_done",
                "message": "Audit report without step link",
                "metadata": {"task_id": "task-http-unlinked"},
            },
            headers={"Authorization": f"Bearer {self.org1_token}"},
        )

        # 3. Verify GET /api/v1/work-board includes `links`
        st, board = _json_req(self.org1_opener, f"{self.base}/api/v1/work-board")
        self.assertEqual(st, 200)
        self.assertIn("links", board)
        linked = board["links"]["by_task"]["task-http-linked"]
        unlinked = board["links"]["by_task"]["task-http-unlinked"]
        self.assertEqual(linked["status"], "linked")
        self.assertEqual(linked["confirmed_file"], "src/payments/tax.py")
        self.assertEqual(linked["session_id"], "codex:http-sess-01")
        self.assertEqual(unlinked["status"], "unknown")
        self.assertEqual(unlinked["basis"], "none")

        # 4. Verify GET /api/v1/links with & without filters + 400 on invalid task_id
        st, l_all = _json_req(self.org1_opener, f"{self.base}/api/v1/links?task_id=task-http-linked")
        self.assertEqual(st, 200)
        self.assertEqual(list(l_all["by_task"].keys()), ["task-http-linked"])
        with self.assertRaises(HTTPError) as ctx:
            _json_req(self.org1_opener, f"{self.base}/api/v1/links?task_id=bad%20id!!")
        self.assertEqual(ctx.exception.code, 400)

        # 5. Verify GET /api/v1/live-records?task_id= returns ONLY the linked step
        st, recs = _json_req(self.org1_opener, f"{self.base}/api/v1/live-records?task_id=task-http-linked")
        self.assertEqual(st, 200)
        self.assertEqual(len(recs["records"]), 1)
        self.assertEqual(recs["records"][0]["work"]["task_id"], "task-http-linked")
        self.assertEqual(recs["records"][0]["work"]["files"], ["src/payments/tax.py"])

        st, recs_unlinked = _json_req(self.org1_opener, f"{self.base}/api/v1/live-records?task_id=task-http-unlinked")
        self.assertEqual(st, 200)
        self.assertEqual(recs_unlinked["records"], [])

        with self.assertRaises(HTTPError) as ctx2:
            _json_req(self.org1_opener, f"{self.base}/api/v1/live-records?task_id=../evil")
        self.assertEqual(ctx2.exception.code, 400)

        # 6. Multi-tenant isolation: Register Org 2 and verify ZERO visibility into Org 1 links/records
        org2_opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))
        st, reg2 = _json_req(
            org2_opener,
            f"{self.base}/api/v1/auth/register",
            {
                "organization": "Beta Tenant",
                "username": "beta_admin",
                "password": "BetaPassword1234!",
            },
        )
        self.assertEqual(st, 201)
        self.assertNotEqual(reg2["organization"]["id"], 1)

        st, board2 = _json_req(org2_opener, f"{self.base}/api/v1/work-board")
        self.assertEqual(st, 200)
        self.assertEqual(board2["links"]["by_task"], {})
        self.assertEqual(board2["links"]["by_session"], {})

        st, links2 = _json_req(org2_opener, f"{self.base}/api/v1/links?task_id=task-http-linked")
        self.assertEqual(st, 200)
        self.assertEqual(links2["by_task"]["task-http-linked"]["status"], "unknown")
        self.assertEqual(links2["by_session"], {})

        st, recs2 = _json_req(org2_opener, f"{self.base}/api/v1/live-records?task_id=task-http-linked")
        self.assertEqual(st, 200)
        self.assertEqual(recs2["records"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
