"""Independent black-box acceptance QA for the multi-agent Collaboration view.

Tests GET /api/v1/work-board (collaboration.changes) against real spawned
console servers with disposable SQLite databases:
1. Two+ agents contributing to the same change with readable assignments,
   distinct agent names, parent/child hierarchy, statuses, timestamps and results,
   without GitHub.
2. Configured channel enforcement (SWARMCONTROL_OPENBOT_CHANNEL_ID) and strict
   organization isolation (legacy org 1 only; org 2+ always receives changes=[]).
3. Privacy redaction (no secrets, private paths, ordinary chatter transcripts,
   or superseded results).
4. Graceful operation with opt-in disabled, without OpenBot installed, or with
   a corrupt OpenBot database.
5. Read-only contrast against an explicitly configured OpenBot channel.
"""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

try:
    from .test_acceptance_blackbox import HttpClient, SpawnedConsole
except ImportError:
    from test_acceptance_blackbox import HttpClient, SpawnedConsole

REAL_CHANNEL_ID = os.getenv("TEST_OPENBOT_CHANNEL_ID")


def _create_synthetic_openbot_db(config_dir: Path) -> Path:
    """Create a minimal read-only-compatible OpenBot SQLite projection DB."""
    config_dir.mkdir(parents=True, exist_ok=True)
    db_path = config_dir / "openbot.db"
    with sqlite3.connect(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE projection_agents (
                agent_id TEXT PRIMARY KEY,
                thread_id TEXT,
                model TEXT NOT NULL,
                updated_at TEXT,
                sort_order INTEGER NOT NULL,
                agent_json TEXT NOT NULL,
                last_event_sequence INTEGER NOT NULL
            );
            CREATE TABLE projection_channels (
                channel_id TEXT PRIMARY KEY,
                channel_json TEXT NOT NULL
            );
            CREATE TABLE projection_channel_tasks (
                task_id TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                task_json TEXT NOT NULL
            );
            CREATE TABLE projection_channel_assignments (
                assignment_id TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                delivery_id TEXT UNIQUE,
                assignment_json TEXT NOT NULL
            );
            CREATE TABLE projection_channel_messages (
                channel_id TEXT NOT NULL,
                message_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                message_json TEXT NOT NULL,
                PRIMARY KEY(channel_id, message_id)
            );
            """
        )

        agents = [
            ("agent-lead", "demo-team-lead"),
            ("agent-builder", "demo-team-builder"),
            ("agent-frontend", "demo-team-frontend"),
            ("agent-reviewer", "demo-team-reviewer"),
        ]
        for idx, (aid, name) in enumerate(agents, 1):
            conn.execute(
                "INSERT INTO projection_agents VALUES (?,?,?,?,?,?,?)",
                (aid, f"thr-{idx}", "test-model", "2026-11-23T16:40:00Z", idx, json.dumps({"id": aid, "name": name}), idx),
            )

        for cid, cname in (("chan-alpha-01", "alpha-team"), ("chan-beta-02", "beta-secret")):
            conn.execute("INSERT INTO projection_channels VALUES (?,?)", (cid, json.dumps({"id": cid, "name": cname})))

        # Request messages
        conn.execute(
            "INSERT INTO projection_channel_messages VALUES (?,?,?,?)",
            (
                "chan-alpha-01",
                "req-alpha-1",
                10,
                json.dumps(
                    {
                        "id": "req-alpha-1",
                        "author": {"kind": "member", "id": "user-1", "name": "Operator"},
                        "message": {"createdAt": "2026-11-23T16:40:00Z", "text": "Seguimiento colaborativo"},
                    }
                ),
            ),
        )
        conn.execute(
            "INSERT INTO projection_channel_messages VALUES (?,?,?,?)",
            (
                "chan-beta-02",
                "req-beta-1",
                10,
                json.dumps(
                    {
                        "id": "req-beta-1",
                        "author": {"kind": "member", "id": "user-2", "name": "Other"},
                        "message": {"createdAt": "2026-11-23T16:40:00Z", "text": "Secreto de otro canal"},
                    }
                ),
            ),
        )

        # Channel A: 1 root + 2 children + 1 grandchild + 1 standalone (must be excluded)
        alpha_tasks = [
            (
                "root-change-1",
                {
                    "id": "root-change-1",
                    "channelId": "chan-alpha-01",
                    "parentTaskId": None,
                    "rootTaskId": "root-change-1",
                    "ownerAgentId": "agent-lead",
                    "requestMessageId": "req-alpha-1",
                    "instruction": "Mejorar la consola para seguir cambios colaborativos de varios agentes sin depender de GitHub.",
                    "expectedResult": "Vista colaborativa verificada.",
                    "state": "waiting",
                    "revision": 0,
                    "updatedAt": "2026-11-23T16:41:00Z",
                },
            ),
            (
                "child-backend-1",
                {
                    "id": "child-backend-1",
                    "channelId": "chan-alpha-01",
                    "parentTaskId": "root-change-1",
                    "rootTaskId": "root-change-1",
                    "ownerAgentId": "agent-builder",
                    "requestMessageId": "req-alpha-1",
                    "instruction": "Implementar fuente local de colaboracion en modo lectura para la organizacion legada.",
                    "expectedResult": "API integrada y probada.",
                    "state": "completed",
                    "revision": 0,
                    "updatedAt": "2026-11-23T16:44:00Z",
                },
            ),
            (
                "child-frontend-1",
                {
                    "id": "child-frontend-1",
                    "channelId": "chan-alpha-01",
                    "parentTaskId": "root-change-1",
                    "rootTaskId": "root-change-1",
                    "ownerAgentId": "agent-frontend",
                    "requestMessageId": "req-alpha-1",
                    "instruction": "Construir el arbol visual de tareas y resultados recientes en el tablero de agentes.",
                    "expectedResult": "Interfaz integrada y accesible.",
                    "state": "completed",
                    "revision": 0,
                    "updatedAt": "2026-11-23T16:46:00Z",
                },
            ),
            (
                "grandchild-qa-1",
                {
                    "id": "grandchild-qa-1",
                    "channelId": "chan-alpha-01",
                    "parentTaskId": "child-frontend-1",
                    "rootTaskId": "root-change-1",
                    "ownerAgentId": "agent-reviewer",
                    "requestMessageId": "req-alpha-1",
                    "instruction": "Ejecutar aceptacion independiente con dos organizaciones y revisar navegacion.",
                    "expectedResult": "Veredicto independiente reproducible.",
                    "state": "running",
                    "revision": 0,
                    "updatedAt": "2026-11-23T16:48:00Z",
                },
            ),
            (
                "standalone-task-9",
                {
                    "id": "standalone-task-9",
                    "channelId": "chan-alpha-01",
                    "parentTaskId": None,
                    "rootTaskId": "standalone-task-9",
                    "ownerAgentId": "agent-lead",
                    "requestMessageId": "req-alpha-1",
                    "instruction": "Tarea individual sin subtareas que no debe aparecer como cambio colaborativo.",
                    "expectedResult": "Informe simple.",
                    "state": "completed",
                    "revision": 0,
                    "updatedAt": "2026-11-23T16:49:00Z",
                },
            ),
        ]
        for tid, payload in alpha_tasks:
            conn.execute("INSERT INTO projection_channel_tasks VALUES (?,?,?)", (tid, "chan-alpha-01", json.dumps(payload)))

        # Formal assignments & completed results for the builder and the reviewer
        assignments = [
            (
                "assign-builder-1",
                "child-backend-1",
                "agent-builder",
                0,
                21,
                "2026-11-23T16:45:00Z",
                "Fuente local de colaboracion integrada y validada con aislamiento entre organizaciones.",
            ),
            (
                "assign-reviewer-1",
                "child-frontend-1",
                "agent-frontend",
                0,
                22,
                "2026-11-23T16:47:00Z",
                "Vista colaborativa por cambio publicada en el tablero con refresco en vivo y sin GitHub.",
            ),
        ]
        for aid, tid, owner, rev, seq, ts, text in assignments:
            conn.execute(
                "INSERT INTO projection_channel_assignments VALUES (?,?,?,?,?)",
                (aid, "chan-alpha-01", tid, f"deliv-{aid}", json.dumps({"assignmentId": aid, "agentId": owner, "taskRevision": rev})),
            )
            mid = f"channel-result-{aid}-revision-{rev}"
            conn.execute(
                "INSERT INTO projection_channel_messages VALUES (?,?,?,?)",
                (
                    "chan-alpha-01",
                    mid,
                    seq,
                    json.dumps(
                        {
                            "id": mid,
                            "taskId": tid,
                            "superseded": False,
                            "author": {"kind": "agent", "id": owner, "name": owner},
                            "message": {"createdAt": ts, "status": "completed", "text": text},
                        }
                    ),
                ),
            )

        # Channel B: must NEVER leak when channel A is configured
        beta_tasks = [
            (
                "beta-root-1",
                {
                    "id": "beta-root-1",
                    "channelId": "chan-beta-02",
                    "parentTaskId": None,
                    "rootTaskId": "beta-root-1",
                    "ownerAgentId": "agent-lead",
                    "requestMessageId": "req-beta-1",
                    "instruction": "Secreto de otro canal no autorizado para Alpha.",
                    "expectedResult": "Confidencial.",
                    "state": "running",
                    "revision": 0,
                    "updatedAt": "2026-11-23T16:45:00Z",
                },
            ),
            (
                "beta-child-1",
                {
                    "id": "beta-child-1",
                    "channelId": "chan-beta-02",
                    "parentTaskId": "beta-root-1",
                    "rootTaskId": "beta-root-1",
                    "ownerAgentId": "agent-builder",
                    "requestMessageId": "req-beta-1",
                    "instruction": "Subtarea privada de otro canal.",
                    "expectedResult": "No visible.",
                    "state": "completed",
                    "revision": 0,
                    "updatedAt": "2026-11-23T16:46:00Z",
                },
            ),
        ]
        for tid, payload in beta_tasks:
            conn.execute("INSERT INTO projection_channel_tasks VALUES (?,?,?)", (tid, "chan-beta-02", json.dumps(payload)))
    return db_path


class CollaborationAcceptanceTests(unittest.TestCase):
    """Independent black-box acceptance tests for work-board.collaboration."""

    def _spawn(self, extra_env: dict[str, str] | None = None) -> tuple[SpawnedConsole, Path]:
        tmp = tempfile.TemporaryDirectory(prefix="swarm-collab-qa-")
        self.addCleanup(tmp.cleanup)
        state_dir = Path(tmp.name)
        srv = SpawnedConsole(state_dir, extra_env=extra_env)
        self.addCleanup(srv.stop)
        return srv, state_dir

    def test_01_two_agents_same_change_readable_names_hierarchy_and_results(self):
        with tempfile.TemporaryDirectory(prefix="openbot-synth-") as ob_tmp:
            ob_dir = Path(ob_tmp)
            _create_synthetic_openbot_db(ob_dir)
            srv, _ = self._spawn(
                {
                    "SWARMCONTROL_OPENBOT_CHANNEL_ID": "chan-alpha-01",
                    "SWARMCONTROL_OPENBOT_CONFIG": str(ob_dir),
                }
            )

            org1 = HttpClient(srv.base_url)
            st, _, login = org1.json(
                "POST",
                "/api/v1/auth/login",
                {"username": "bootstrap_admin", "password": "BootstrapPass!2026#QA"},
            )
            self.assertEqual(st, 200, login)

            st, _, board = org1.json("GET", "/api/v1/work-board")
            self.assertEqual(st, 200)
            collab = board.get("collaboration")
            self.assertIsInstance(collab, dict)
            changes = collab.get("changes", [])
            self.assertEqual(len(changes), 1, f"Expected exactly 1 multi-agent change, got {changes}")

            ch = changes[0]
            self.assertEqual(ch["id"], "root-change-1")
            self.assertIn("colaborativos", ch["title"].lower())
            self.assertEqual(ch["status"], "waiting")
            self.assertIsInstance(ch["updated_at"], int)
            self.assertGreater(ch["updated_at"], 1_700_000_000)

            tasks = {t["id"]: t for t in ch["tasks"]}
            self.assertEqual(set(tasks.keys()), {"root-change-1", "child-backend-1", "child-frontend-1", "grandchild-qa-1"})
            self.assertNotIn("standalone-task-9", json.dumps(board), "Standalone task without children must be omitted")

            # Parent/child hierarchy including grandchild
            self.assertIsNone(tasks["root-change-1"]["parent_id"])
            self.assertEqual(tasks["child-backend-1"]["parent_id"], "root-change-1")
            self.assertEqual(tasks["child-frontend-1"]["parent_id"], "root-change-1")
            self.assertEqual(tasks["grandchild-qa-1"]["parent_id"], "child-frontend-1")

            # Distinct readable agent names (hyphenated OpenBot agent names must NOT collapse to generic 'Agent')
            self.assertEqual(
                tasks["root-change-1"]["agent"],
                "demo-team-lead",
                "BLOCKER: Hyphenated agent name collapsed to generic fallback",
            )
            self.assertEqual(tasks["child-backend-1"]["agent"], "demo-team-builder")
            self.assertEqual(tasks["child-frontend-1"]["agent"], "demo-team-frontend")
            self.assertEqual(tasks["grandchild-qa-1"]["agent"], "demo-team-reviewer")

            # Readable results for completed tasks, empty string for running task
            self.assertIn("aislamiento", tasks["child-backend-1"]["result"].lower())
            self.assertIn("sin github", tasks["child-frontend-1"]["result"].lower())
            self.assertEqual(tasks["grandchild-qa-1"]["result"], "")

            # Channel isolation: chan-beta-02 never leaks even with query/header spoofing
            st2, _, board_spoof = org1.json(
                "GET",
                "/api/v1/work-board?channel_id=chan-beta-02&include=activity",
                headers={"X-Channel-Id": "chan-beta-02"},
            )
            self.assertEqual(st2, 200)
            self.assertNotIn("beta-root-1", json.dumps(board_spoof))
            self.assertNotIn("Secreto de otro canal", json.dumps(board_spoof))
            self.assertEqual(len(board_spoof["collaboration"]["changes"]), 1)

            # Authorized Org 1 read token also receives collaboration changes
            st_t, _, ro_tok = org1.json("POST", "/api/v1/tokens", {"name": "org1-reader", "scope": "read"})
            self.assertEqual(st_t, 201, ro_tok)
            anon = HttpClient(srv.base_url)
            st_r, _, ro_board = anon.json(
                "GET",
                "/api/v1/work-board",
                headers={"Authorization": f"Bearer {ro_tok['token']}"},
            )
            self.assertEqual(st_r, 200)
            self.assertEqual([c["id"] for c in ro_board["collaboration"]["changes"]], ["root-change-1"])

    def test_02_organization_isolation_org2_receives_empty_changes(self):
        with tempfile.TemporaryDirectory(prefix="openbot-iso-") as ob_tmp:
            ob_dir = Path(ob_tmp)
            _create_synthetic_openbot_db(ob_dir)
            srv, _ = self._spawn(
                {
                    "SWARMCONTROL_OPENBOT_CHANNEL_ID": "chan-alpha-01",
                    "SWARMCONTROL_OPENBOT_CONFIG": str(ob_dir),
                }
            )

            org1 = HttpClient(srv.base_url)
            org2 = HttpClient(srv.base_url)
            shared_user = HttpClient(srv.base_url)

            st, _, _ = org1.json("POST", "/api/v1/auth/login", {"username": "bootstrap_admin", "password": "BootstrapPass!2026#QA"})
            self.assertEqual(st, 200)

            st, _, reg2 = org2.json(
                "POST",
                "/api/v1/auth/register",
                {"username": "org2_admin", "password": "Org2StrongPass!2026", "organization": "External Corp"},
            )
            self.assertEqual(st, 201, reg2)
            org2_id = reg2["organization"]["id"]

            # Org 2 admin + Org 2 read token must ALWAYS see {"changes": []}
            for url in ("/api/v1/work-board", "/api/v1/work-board?include=activity", "/api/v1/work-board?channel_id=chan-alpha-01"):
                st, _, b2 = org2.json("GET", url, headers={"X-Organization-Id": "1", "X-Channel-Id": "chan-alpha-01"})
                self.assertEqual(st, 200)
                self.assertEqual(b2.get("collaboration"), {"changes": []}, f"Org 2 leaked collaboration on {url}")

            st, _, ro2 = org2.json("POST", "/api/v1/tokens", {"name": "org1-reader", "scope": "read"})
            self.assertEqual(st, 201)
            anon = HttpClient(srv.base_url)
            st, _, b2_tok = anon.json("GET", "/api/v1/work-board", headers={"Authorization": f"Bearer {ro2['token']}"})
            self.assertEqual(st, 200)
            self.assertEqual(b2_tok.get("collaboration"), {"changes": []})

            # Viewer invited to Org 1 sees collaboration; after switching to Org 2 sees {"changes": []}
            st, _, inv1 = org1.json("POST", "/api/v1/invitations", {"username": "dual_viewer", "role": "viewer"})
            self.assertEqual(st, 201)
            st, _, _ = shared_user.json(
                "POST",
                "/api/v1/auth/accept-invitation",
                {"token": inv1["token"], "username": "dual_viewer", "password": "DualViewerPass!2026"},
            )
            self.assertEqual(st, 200)
            st, _, v1 = shared_user.json("GET", "/api/v1/work-board")
            self.assertEqual(st, 200)
            self.assertEqual(len(v1["collaboration"]["changes"]), 1)

            st, _, inv2 = org2.json("POST", "/api/v1/invitations", {"username": "dual_viewer", "role": "admin"})
            self.assertEqual(st, 201)
            st, _, _ = shared_user.json(
                "POST",
                "/api/v1/auth/accept-invitation",
                {"token": inv2["token"], "username": "dual_viewer", "password": "DualViewerPass!2026"},
            )
            self.assertEqual(st, 200)
            st, _, v2 = shared_user.json("GET", "/api/v1/work-board")
            self.assertEqual(st, 200)
            self.assertEqual(v2.get("collaboration"), {"changes": []}, f"Switched user in Org {org2_id} must not see Org 1 channel")

    def test_03_privacy_redaction_no_secrets_private_paths_or_transcripts(self):
        with tempfile.TemporaryDirectory(prefix="openbot-priv-") as ob_tmp:
            ob_dir = Path(ob_tmp)
            db_path = _create_synthetic_openbot_db(ob_dir)
            with sqlite3.connect(db_path) as conn:
                # Inject sensitive content into a new assignment result + chatter + superseded message
                conn.execute(
                    "INSERT INTO projection_channel_assignments VALUES (?,?,?,?,?)",
                    ("assign-priv", "grandchild-qa-1", "grandchild-qa-1", "deliv-priv", json.dumps({"assignmentId": "assign-priv", "agentId": "agent-reviewer", "taskRevision": 0})),
                )
                # Superseded old result (must be ignored)
                conn.execute(
                    "INSERT INTO projection_channel_messages VALUES (?,?,?,?)",
                    (
                        "chan-alpha-01",
                        "channel-result-assign-priv-revision-0",
                        30,
                        json.dumps(
                            {
                                "id": "channel-result-assign-priv-revision-0",
                                "taskId": "grandchild-qa-1",
                                "superseded": True,
                                "author": {"kind": "agent", "id": "agent-reviewer"},
                                "message": {"createdAt": "2026-11-23T16:48:30Z", "status": "completed", "text": "SUPERSEDED OLD RESULT"},
                            }
                        ),
                    ),
                )
                # Ordinary chatter message (must NOT be used as task result)
                conn.execute(
                    "INSERT INTO projection_channel_messages VALUES (?,?,?,?)",
                    (
                        "chan-alpha-01",
                        "msg-chatter-99",
                        31,
                        json.dumps(
                            {
                                "id": "msg-chatter-99",
                                "taskId": "grandchild-qa-1",
                                "superseded": False,
                                "author": {"kind": "agent", "id": "agent-reviewer"},
                                "message": {"createdAt": "2026-11-23T16:48:40Z", "status": "completed", "text": "CHATTER PRIVATE TRANSCRIPT DO NOT SHOW"},
                            }
                        ),
                    ),
                )
                # Replace the builder result with one containing secrets & private paths after a safe sentence
                conn.execute(
                    "UPDATE projection_channel_messages SET message_json=? WHERE message_id='channel-result-assign-builder-1-revision-0'",
                    (
                        json.dumps(
                            {
                                "id": "channel-result-assign-builder-1-revision-0",
                                "taskId": "child-backend-1",
                                "superseded": False,
                                "author": {"kind": "agent", "id": "agent-builder"},
                                "message": {
                                    "createdAt": "2026-11-23T16:45:00Z",
                                    "status": "completed",
                                    "text": (
                                        "Integracion verificada en pruebas locales. "
                                        "No exponer /srv/example-private/.env ni sk-ant-api03-SECRET1234567890abcd "
                                        "ni sc_tok_t1_ABCDE12345678901234567890123456 ni password=SuperSecret99."
                                    ),
                                },
                            }
                        ),
                    ),
                )

            srv, _ = self._spawn(
                {
                    "SWARMCONTROL_OPENBOT_CHANNEL_ID": "chan-alpha-01",
                    "SWARMCONTROL_OPENBOT_CONFIG": str(ob_dir),
                }
            )
            org1 = HttpClient(srv.base_url)
            st, _, _ = org1.json("POST", "/api/v1/auth/login", {"username": "bootstrap_admin", "password": "BootstrapPass!2026#QA"})
            self.assertEqual(st, 200)
            st, _, board = org1.json("GET", "/api/v1/work-board")
            self.assertEqual(st, 200)
            blob = json.dumps(board)
            for forbidden in (
                "SUPERSEDED OLD RESULT",
                "CHATTER PRIVATE TRANSCRIPT",
                "/srv/example-private",
                ".env",
                "sk-ant-api03",
                "sc_tok_t1_",
                "SuperSecret99",
            ):
                self.assertNotIn(forbidden, blob, f"Sensitive/private content leaked in work-board: {forbidden}")

    def test_04_opt_in_disabled_no_openbot_and_corrupt_db_degrade_gracefully(self):
        # Case A: channel ID unset -> disabled
        srv_off, _ = self._spawn({"SWARMCONTROL_OPENBOT_CHANNEL_ID": ""})
        c_off = HttpClient(srv_off.base_url)
        st, _, _ = c_off.json("POST", "/api/v1/auth/login", {"username": "bootstrap_admin", "password": "BootstrapPass!2026#QA"})
        self.assertEqual(st, 200)
        st, _, b_off = c_off.json("GET", "/api/v1/work-board")
        self.assertEqual(st, 200)
        self.assertEqual(b_off.get("collaboration"), {"changes": []})
        self.assertIn("reports", b_off)

        # Case B: channel ID set, but OpenBot is NOT installed (empty dir)
        with tempfile.TemporaryDirectory(prefix="no-openbot-") as empty_dir:
            srv_none, _ = self._spawn(
                {
                    "SWARMCONTROL_OPENBOT_CHANNEL_ID": "chan-alpha-01",
                    "SWARMCONTROL_OPENBOT_CONFIG": empty_dir,
                }
            )
            c_none = HttpClient(srv_none.base_url)
            st, _, _ = c_none.json("POST", "/api/v1/auth/login", {"username": "bootstrap_admin", "password": "BootstrapPass!2026#QA"})
            self.assertEqual(st, 200)
            st, _, b_none = c_none.json("GET", "/api/v1/work-board")
            self.assertEqual(st, 200)
            self.assertEqual(b_none.get("collaboration"), {"changes": []})
            st_ov, _, _ = c_none.json("GET", "/api/v1/overview")
            self.assertEqual(st_ov, 200)

        # Case C: corrupt openbot.db -> graceful empty collaboration, no path or SQL error leak
        with tempfile.TemporaryDirectory(prefix="corrupt-openbot-") as bad_dir:
            (Path(bad_dir) / "openbot.db").write_bytes(b"NOT A VALID SQLITE DATABASE!!!")
            srv_bad, _ = self._spawn(
                {
                    "SWARMCONTROL_OPENBOT_CHANNEL_ID": "chan-alpha-01",
                    "SWARMCONTROL_OPENBOT_CONFIG": bad_dir,
                }
            )
            c_bad = HttpClient(srv_bad.base_url)
            st, _, _ = c_bad.json("POST", "/api/v1/auth/login", {"username": "bootstrap_admin", "password": "BootstrapPass!2026#QA"})
            self.assertEqual(st, 200)
            st, _, b_bad = c_bad.json("GET", "/api/v1/work-board")
            self.assertEqual(st, 200)
            self.assertEqual(b_bad.get("collaboration"), {"changes": []})
            self.assertNotIn(bad_dir, json.dumps(b_bad))

    def test_05_real_channel_contrast_read_only(self):
        real_ob_dir = Path(os.environ.get("TEST_OPENBOT_CONFIG_DIR", Path.home() / ".config/OpenBot"))
        if not REAL_CHANNEL_ID or not (real_ob_dir / "openbot.db").is_file():
            self.skipTest("Optional test requires TEST_OPENBOT_CHANNEL_ID and its local OpenBot database")

        srv, _ = self._spawn(
            {
                "SWARMCONTROL_OPENBOT_CHANNEL_ID": REAL_CHANNEL_ID,
                "SWARMCONTROL_OPENBOT_CONFIG": str(real_ob_dir),
            }
        )
        org1 = HttpClient(srv.base_url)
        org2 = HttpClient(srv.base_url)

        st, _, _ = org1.json("POST", "/api/v1/auth/login", {"username": "bootstrap_admin", "password": "BootstrapPass!2026#QA"})
        self.assertEqual(st, 200)
        st, _, board1 = org1.json("GET", "/api/v1/work-board")
        self.assertEqual(st, 200)

        # Org 2 isolation against the configured channel
        st, _, _ = org2.json(
            "POST",
            "/api/v1/auth/register",
            {"username": "ext_admin", "password": "ExternalAdmin!2026", "organization": "Other Org"},
        )
        self.assertEqual(st, 201)
        st, _, board2 = org2.json("GET", "/api/v1/work-board")
        self.assertEqual(st, 200)
        self.assertEqual(board2.get("collaboration"), {"changes": []})

        changes = board1.get("collaboration", {}).get("changes", [])
        self.assertGreaterEqual(len(changes), 1, "Expected real collaborative changes from this channel")
        named_agents = {t["agent"] for c in changes for t in c["tasks"] if t["agent"] and t["agent"] != "Agent"}
        self.assertGreaterEqual(
            len(named_agents),
            2,
            f"BLOCKER: Operator cannot tell who is doing what; real channel agents collapsed to {named_agents}",
        )
        # No secrets or server paths leaked from real channel
        blob = json.dumps(board1["collaboration"])
        for secret in ("/srv/example-private", "sk-ant-", "sk-proj-", "sc_tok_", "sc_inv_", "ghp_"):
            self.assertNotIn(secret, blob)


if __name__ == "__main__":
    unittest.main()
