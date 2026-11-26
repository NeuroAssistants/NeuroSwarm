"""Independently verify mission grouping, attribution, privacy and original evidence."""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from unittest.mock import patch

try:
    from .test_security import ServerHarness
except ImportError:
    from test_security import ServerHarness


CHANNEL = "qa-shared-channel"
OTHER_CHANNEL = "qa-private-channel"
ROUTE = "/api/v1/missions"
RAW_REASONING = "Raw thinking must remain private"
SUPERSEDED = "Withdrawn update must remain private"
PRIVATE_OTHER_CHANNEL = "Content from another channel"
FIXTURE_SECRET = "sk-proj-" + "A" * 26


class MissionReleaseAcceptanceTests(ServerHarness):
    def mission(self, payload, mission_id):
        return next(entry for entry in payload["missions"] if entry["id"] == mission_id)

    def register_other_org(self):
        status, _, headers = self.req("POST", "/api/v1/auth/register", {
            "username": "second-team", "organization": "Second team", "password": secrets.token_urlsafe(24),
        }, cookie=False)
        self.assertEqual(status, 201)
        self.cookie = headers["set-cookie"].split(";")[0]

    def publish(self, key, kind, message, agent, **metadata):
        status, result, _ = self.req("POST", "/api/v1/ingest/event", {
            "event_type": kind, "host_id": "same-machine", "harness": "qa",
            "agent_name": agent, "message": message, "metadata": metadata,
        }, headers=self.bearer(key), cookie=False)
        self.assertEqual(status, 200)
        self.assertTrue(result["ok"])
        return result["event_id"]

    def test_reported_mission_links_original_evidence_and_isolates_orgs(self):
        self.assertEqual(self.req("GET", ROUTE, cookie=False)[0], 401)
        self.assertEqual(self.login()[0], 200)
        key = self.token()
        shared = {"mission_id": "reconcile", "task_id": "inspect"}
        original = self.publish(key, "agent_message", "Please confirm that the totals match.",
                                "Coordinator", to_agent="Verifier", **shared)
        self.publish(key, "decision", "Compare independent totals.", "Verifier",
                     reason="Both batches use the same cutoff date.", reasoning=RAW_REASONING, **shared)
        self.publish(key, "blocker", "Waiting for the final receipt.", "Verifier", **shared)
        self.publish(key, "memory_saved", "The cutoff uses local business time.", "Verifier", **shared)
        self.publish(key, "agent_message", "Switch to the other queue.", "Coordinator",
                     mission_id="another-mission", task_id="inspect")
        self.publish(key, "decision", f"Use the shared report. API key: {FIXTURE_SECRET}", "Verifier", **shared)

        status, result, headers = self.req("GET", ROUTE)
        self.assertEqual(status, 200)
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertNotIn(RAW_REASONING, json.dumps(result))
        self.assertNotIn(FIXTURE_SECRET, json.dumps(result))
        mission = self.mission(result, "reconcile")
        self.assertEqual(len(mission["events"]), 5)
        event = next(e for e in mission["events"] if e.get("event_id") == original)
        self.assertEqual((event["agent"], event["to"], event["task_id"]), ("Coordinator", "Verifier", "inspect"))
        self.assertEqual(event["text"], "Confirm that the totals match.")
        self.assertTrue(any(e.get("reason") == "Both batches use the same cutoff date." for e in mission["events"]))
        self.assertNotIn("Switch to the other queue", json.dumps(mission))
        status, evidence, _ = self.req("GET", f"/api/v1/events/{original}/evidence")
        self.assertEqual(status, 200)
        self.assertEqual(evidence["event_id"], original)
        self.assertEqual(evidence["record"]["details"]["to_agent"], "Verifier")

        self.register_other_org()
        self.publish(self.token(), "decision", "Second team made an independent decision.",
                     "Coordinator", **shared)
        status, result, _ = self.req("GET", ROUTE + "?organization=1&channel_id=" + CHANNEL)
        self.assertEqual(status, 200)
        self.assertNotEqual(result["organization"], 1)
        events = self.mission(result, "reconcile")["events"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["text"], "Second team made an independent decision.")


    def test_public_records_allow_only_shared_fields_even_for_older_rows(self):
        self.assertEqual(self.login()[0], 200)
        fresh = self.publish(self.token(), "decision", "Use the independent report.", "Verifier",
                             mission_id="verify", reason="Two sources agree.", reasoning=RAW_REASONING)
        old = self.ctx.db.execute("""INSERT INTO events
            (host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at)
            VALUES ('same-machine','qa','Verifier','decision','INFO','Use the earlier report.',?,?)""",
            (json.dumps({"mission_id": "verify", "reason": "The estimate includes all results.",
                         "reasoning": RAW_REASONING, "private_context": {"thoughts": RAW_REASONING}}), time.time() - 60))
        fresh_row = self.ctx.db.query_one("SELECT metadata_json FROM events WHERE id=?", (fresh,))
        self.assertNotIn(RAW_REASONING, fresh_row["metadata_json"])
        for route in ("/api/v1/event-feed", "/api/v1/live-records", "/api/v1/events", "/api/v1/overview",
                      f"/api/v1/events/{old}/evidence"):
            with self.subTest(route=route):
                status, result, _ = self.req("GET", route)
                self.assertEqual(status, 200)
                self.assertNotIn(RAW_REASONING, json.dumps(result))
                self.assertIn("The estimate includes all results.", json.dumps(result))

    def seed_channel(self, path: Path):
        with closing(sqlite3.connect(path)) as db, db:
            db.executescript("""
                CREATE TABLE projection_channel_tasks (channel_id TEXT, task_id TEXT, task_json TEXT);
                CREATE TABLE projection_channel_messages (channel_id TEXT, message_id TEXT, sequence INTEGER, message_json TEXT);
                CREATE TABLE projection_agents (agent_id TEXT, agent_json TEXT);
                CREATE TABLE projection_channel_assignments (assignment_id TEXT, channel_id TEXT,
                    task_id TEXT, assignment_json TEXT);
                CREATE TABLE projection_channel_memories (memory_id TEXT, channel_id TEXT, text TEXT,
                    updated_at TEXT, source_turn_id TEXT, last_event_sequence INTEGER);
            """)
            db.executemany("INSERT INTO projection_agents VALUES (?, ?)",
                           [(key, json.dumps({"name": name})) for key, name in
                            (("lead", "Coordinator"), ("qa", "Verifier"))])
            tasks = ((CHANNEL, "alpha", "alpha", "request-alpha", "lead", "Reconcile the invoices."),
                     (CHANNEL, "alpha-qa", "alpha", "request-alpha-qa", "qa", "Verify monthly totals."),
                     (CHANNEL, "beta", "beta", "request-beta", "lead", "Check the other queue."),
                     (OTHER_CHANNEL, "outside", "outside", "outside-request", "lead", "Review the vault."))
            for channel, task, root, request, owner, title in tasks:
                db.execute("INSERT INTO projection_channel_tasks VALUES (?, ?, ?)", (channel, task, json.dumps({
                    "rootTaskId": root, "ownerAgentId": owner, "requestMessageId": request, "instruction": title,
                    "state": "running", "parentTaskId": None if task == root else root,
                })))

            def update(channel, task, key, text, number, *, agent="Coordinator", parent=None,
                       item_type="commentary", superseded=False):
                message = {"taskId": task, "superseded": superseded, "author": {"kind": "agent", "name": agent},
                           "message": {"text": text, "status": "completed", "itemType": item_type,
                                       "createdAt": f"2026-11-26T11:00:{number:02d}Z", "replyToMessageId": parent}}
                db.execute("INSERT INTO projection_channel_messages VALUES (?, ?, ?, ?)",
                           (channel, key, number, json.dumps(message)))

            update(CHANNEL, "alpha", "msg_parent", "Compare both invoice batches.", 1)
            update(CHANNEL, "alpha-qa", "channel-reply-actual", "The monthly totals match.", 2,
                   agent="Verifier", parent="msg_parent")
            update(CHANNEL, "alpha-qa", "msg_internal", RAW_REASONING, 3, item_type="reasoning")
            update(CHANNEL, "alpha-qa", "msg_replaced", SUPERSEDED, 4, superseded=True)
            update(CHANNEL, "alpha-qa", "msg_sensitive", f"Audit completed. API key: {FIXTURE_SECRET}", 5)
            update(OTHER_CHANNEL, "outside", "msg_outside", PRIVATE_OTHER_CHANNEL, 6)
            update(CHANNEL, "beta", "msg_beta", "Different mission uses a separate ledger.", 7, agent="Analyst")
            update(CHANNEL, "alpha-qa", "channel-reply-other-mission", "See the coordination note.", 8,
                   agent="Verifier", parent="msg_beta")
            db.execute("INSERT INTO projection_channel_assignments VALUES ('assign', ?, 'alpha-qa', ?)",
                       (CHANNEL, json.dumps({"turnId": "turn-qa", "agentId": "qa"})))
            db.execute("INSERT INTO projection_channel_memories VALUES ('memory', ?, ?, ?, 'turn-qa', 9)",
                       (CHANNEL, "The team closed the review.", "2026-11-26T11:00:09Z"))
            db.execute("INSERT INTO projection_channel_memories VALUES ('private-memory', ?, ?, ?, 'unmatched-turn', 10)",
                       (CHANNEL, "Memory has no recorded assignment.", "2026-11-26T11:00:10Z"))

    def test_shared_channel_is_opt_in_and_messages_use_stored_reply_edges(self):
        self.assertEqual(self.login()[0], 200)
        self.seed_channel(Path(self.tmp.name) / "openbot.db")
        settings = {"SWARMCONTROL_OPENBOT_CHANNEL_ID": CHANNEL, "SWARMCONTROL_OPENBOT_CONFIG": self.tmp.name}
        with patch.dict(os.environ, {**settings, "SWARMCONTROL_SHARE_MISSION_UPDATES": "0"}):
            status, data, _ = self.req("GET", ROUTE)
            self.assertEqual(status, 200)
            self.assertEqual(data["shared_channel"], "disabled")
            self.assertEqual(data["missions"], [])
        with patch.dict(os.environ, {**settings, "SWARMCONTROL_SHARE_MISSION_UPDATES": "1"}):
            status, data, _ = self.req("GET", ROUTE + "?channel_id=" + OTHER_CHANNEL)
            self.assertEqual(status, 200)
            self.assertEqual(data["shared_channel"], "connected")
            payload = json.dumps(data)
            for item in (RAW_REASONING, SUPERSEDED, FIXTURE_SECRET, PRIVATE_OTHER_CHANNEL, "unmatched-turn"):
                self.assertNotIn(item, payload)
            events = {e["id"]: e for e in self.mission(data, "request-alpha")["events"]}
            original = events["channel-reply-actual"]
            self.assertEqual((original["agent"], original["to"], original["reply"], original["task_id"]),
                             ("Verifier", "Coordinator", "msg_parent", "alpha-qa"))
            self.assertEqual(original["parent_text"], "Compare both invoice batches.")
            self.assertEqual(events["memory"]["text"], "The team closed the review.")
            self.assertEqual(events["memory"]["agent"], "Verifier")
            self.assertNotIn("private-memory", events)

            self.register_other_org()
            status, data, _ = self.req("GET", ROUTE + "?organization=1&channel_id=" + CHANNEL)
            self.assertEqual(status, 200)
            self.assertEqual(data["missions"], [])
            self.assertEqual(data["shared_channel"], "disabled")
