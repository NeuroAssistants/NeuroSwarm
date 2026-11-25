import datetime
import time
import json
from pathlib import Path
from test_security import ServerHarness
import incidents
def _iso(offset_sec: float = -10.0) -> str:
    return (
        datetime.datetime.fromtimestamp(time.time() + offset_sec, datetime.timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.000Z")
    )


class AlertOriginAndReloadTests(ServerHarness):
    env_overrides = {"SWARMCONTROL_SHARE_COMMANDS": "1", "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "1"}

    def test_two_alerts_same_session_preserve_originals_after_disk_change_and_host_last_step(self) -> None:
        self.login()
        tok = self.token("sensor-1")
        auth = self.bearer(tok)
        self.assertEqual(self.req("POST", "/api/v1/ingest/heartbeat", self.hb("host-1"), headers=auth)[0], 200)

        workspace = Path(self.tmp.name) / "shared-proj"
        (workspace / "jobs").mkdir(parents=True)
        (workspace / "logs").mkdir(parents=True)
        alpha_file = workspace / "jobs" / "alpha.py"
        beta_file = workspace / "logs" / "beta.log"
        settled_file = workspace / "settled.py"
        alpha_file.write_text("alpha v1\n", encoding="utf-8")
        beta_file.write_text("original-beta-v1\n", encoding="utf-8")
        settled_file.write_text("settled\n", encoding="utf-8")

        shared_session = "codex:shared-alert-sess"
        snap = {
            "host_id": "host-1",
            "activity_enabled": True,
            "activity_roots": [str(workspace)],
            "capture_policy": {"share_commands": True, "share_output": True, "share_files": True},
            "sessions": [{
                "session_id": shared_session,
                "agent_name": "shared-proj",
                "harness": "codex",
                "workspace": str(workspace),
                "capture_steps": [
                    {
                        "tool": "exec_command", "category": "shell", "label": "Run a Python script", "program": "python3",
                        "time": _iso(-40), "status": "error", "files": ["jobs/alpha.py"], "file_basis": "confirmed",
                        "command_input": "python3 jobs/alpha.py", "command_output": "ValueError: alpha boom\n", "exit_code": 2,
                        "src": "alt:1:0",
                    },
                    {
                        "tool": "exec_command", "category": "file_read", "label": "Read beta.log", "program": "tail",
                        "time": _iso(-30), "status": "completed", "files": ["logs/beta.log"], "file_basis": "confirmed",
                        "command_input": "tail -n 5 logs/beta.log", "command_output": "original-beta-v1\n", "exit_code": 0,
                        "src": "alt:2:0",
                    },
                ],
            }],
        }
        st, _, _ = self.req("POST", "/api/v1/ingest/activity", snap, headers=auth)
        self.assertEqual(st, 200)

        ev_rows = self.ctx.db.query_all("SELECT id, metadata_json FROM events WHERE event_type='observed_step' ORDER BY id")
        self.assertEqual(len(ev_rows), 2)
        e1_id = ev_rows[0]["id"]
        e2_id = ev_rows[1]["id"]

        a1_id = incidents.observe(
            self.ctx.db, "host-1", "LOOP_SUSPECTED", "WARNING",
            "Repeated alpha failure", "Loop suspected on alpha",
            {"source_event_id": e1_id, "event_id": e1_id, "session": shared_session, "agent_name": "shared-proj", "harness": "codex"},
        )
        a2_id = incidents.observe(
            self.ctx.db, "host-1", "QUOTA_EXHAUSTION_BURST", "CRITICAL",
            "Quota burst on beta step", "Hit provider rate limit",
            {"source_event_id": e2_id, "event_id": e2_id, "session": shared_session, "agent_name": "shared-proj", "harness": "codex"},
        )

        # Mutate & delete workspace files on disk and advance host `last_step` to a third file `settled.py`
        alpha_file.write_text("alpha mutated v2\n", encoding="utf-8")
        beta_file.unlink()
        snap_later = {
            "host_id": "host-1",
            "activity_enabled": True,
            "activity_roots": [str(workspace)],
            "capture_policy": {"share_commands": True, "share_output": True, "share_files": True},
            "sessions": [{
                "session_id": "claude-code:other-sess",
                "agent_name": "other-agent",
                "harness": "claude-code",
                "workspace": str(workspace),
                "capture_steps": [{
                    "tool": "Edit", "category": "file_edit", "label": "Edit settled.py",
                    "time": _iso(-5), "status": "completed", "files": ["settled.py"], "file_basis": "confirmed",
                    "src": "alt:3:0",
                }],
            }],
        }
        self.assertEqual(self.req("POST", "/api/v1/ingest/activity", snap_later, headers=auth)[0], 200)
        e3_id = self.ctx.db.query_one("SELECT max(id) AS m FROM events WHERE event_type='observed_step'")["m"]
        self.assertNotEqual(e3_id, e2_id)

        # Repeating Alert 1 without an event_id must NOT drop its original source_event_id
        incidents.observe(self.ctx.db, "host-1", "LOOP_SUSPECTED", "WARNING", "Repeated alpha failure", "Still looping", {"count": 5})

        # Host-level RUNAWAY_CPU carries last_step hint (`e3_id`) WITHOUT setting causal source_event_id
        cpu_alert_id = incidents.observe(
            self.ctx.db, "host-1", "RUNAWAY_CPU", "WARNING",
            "High agent CPU", "Reached 93%", {"max_cpu_pct": 93.0, "process": {"pid": 4242, "comm": "python3"}},
        )

        # Verify `/api/v1/alerts/<id>`
        _, d1, _ = self.req("GET", f"/api/v1/alerts/{a1_id}")
        _, d2, _ = self.req("GET", f"/api/v1/alerts/{a2_id}")
        _, dcpu, _ = self.req("GET", f"/api/v1/alerts/{cpu_alert_id}")
        self.assertEqual(d1["alert"]["source_event_id"], e1_id)
        self.assertEqual(d2["alert"]["source_event_id"], e2_id)
        self.assertNotIn("source_event_id", dcpu["alert"])
        self.assertEqual(dcpu["alert"]["last_step"]["event_id"], e3_id)
        self.assertEqual(dcpu["alert"]["last_step"]["basis"], "last_observed_on_host")

        # Verify reload via `/api/v1/live-records` and `/api/v1/event-feed`
        _, hist, _ = self.req("GET", "/api/v1/live-records")
        hist_alerts = {r["id"]: r for r in hist["records"] if r["kind"] == "Alert"}
        self.assertEqual(hist_alerts[a1_id]["source_event_id"], e1_id)
        self.assertEqual(hist_alerts[a2_id]["source_event_id"], e2_id)
        self.assertNotIn("source_event_id", hist_alerts[cpu_alert_id])
        self.assertEqual(hist_alerts[cpu_alert_id]["last_step"]["event_id"], e3_id)

        _, ef, _ = self.req("GET", "/api/v1/event-feed")
        ef_alerts = {r["id"]: r for r in ef["records"] if r["kind"] == "alert"}
        self.assertEqual(ef_alerts[a1_id]["source_event_id"], e1_id)
        self.assertEqual(ef_alerts[a2_id]["source_event_id"], e2_id)
        self.assertNotIn("source_event_id", ef_alerts[cpu_alert_id])
        self.assertEqual(ef_alerts[cpu_alert_id]["last_step"]["event_id"], e3_id)

        # Fetch each alert's original event evidence -> exact command, file, and immutable output preserved!
        _, ev1, _ = self.req("GET", f"/api/v1/events/{hist_alerts[a1_id]['source_event_id']}/evidence")
        _, ev2, _ = self.req("GET", f"/api/v1/events/{hist_alerts[a2_id]['source_event_id']}/evidence")
        self.assertEqual((ev1["files"], ev1["command_input"], ev1["command_output"], ev1["exit_code"]), (["jobs/alpha.py"], "python3 jobs/alpha.py", "ValueError: alpha boom\n", 2))
        self.assertEqual((ev2["files"], ev2["command_input"], ev2["command_output"], ev2["exit_code"]), (["logs/beta.log"], "tail -n 5 logs/beta.log", "original-beta-v1\n", 0))

        # Verify list endpoints never expose command_output or response_excerpt
        _, act, _ = self.req("GET", "/api/v1/activity")
        for blob in (json.dumps(hist), json.dumps(ef), json.dumps(act)):
            self.assertNotIn("ValueError: alpha boom", blob)
            self.assertNotIn("original-beta-v1", blob)
            self.assertNotIn("response_excerpt", blob)

        # Multi-tenant isolation: Org 2 sees none of Org 1's alerts or evidence
        st, _, hdrs = self.req(
            "POST", "/api/v1/auth/register",
            {"username": "org2_user", "organization": "Other Org", "password": "SecondOrgPass!2026"},
            cookie=False,
        )
        self.assertEqual(st, 201)
        org2_cookie = hdrs["set-cookie"].split(";")[0]
        self.assertEqual(self.req("GET", f"/api/v1/alerts/{a1_id}", headers={"Cookie": org2_cookie}, cookie=False)[0], 404)
        self.assertEqual(self.req("GET", f"/api/v1/events/{e1_id}/evidence", headers={"Cookie": org2_cookie}, cookie=False)[0], 404)
        self.assertEqual(self.req("GET", "/api/v1/live-records", headers={"Cookie": org2_cookie}, cookie=False)[1]["records"], [])
        self.assertEqual(self.req("GET", "/api/v1/event-feed", headers={"Cookie": org2_cookie}, cookie=False)[1]["records"], [])
