"""Coverage counts and drilldowns must agree for the exact window, tenant and evidence revision."""
import json
import secrets
from urllib.parse import urlencode

from test_security import ServerHarness


PATH = "/api/v1/output-coverage"


def step(conn, *, program="grep", outcome="completed", reason=None, output=None, ts=100,
         exit_code=None, host="worker-01", event_type="observed_step", tool="exec_command"):
    meta = {"tool": tool, "action": "shell", "outcome": outcome}
    if program is not None:
        meta["program"] = program
    if reason:
        meta["output_reason"] = reason
    ident = conn.execute(
        "INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at) "
        "VALUES(?, 'codex','tester',?,'INFO','Recorded call',?,?)",
        (host, event_type, json.dumps(meta), ts),
    ).lastrowid
    if output is not None or exit_code is not None:
        conn.execute("INSERT INTO event_execution VALUES(?, 'private-input-fixture', ?, ?, 0)",
                     (ident, output, exit_code))
    return ident


class OutputCoverageHTTPTests(ServerHarness):
    def get(self, **params):
        return self.req("GET", PATH + "?" + urlencode({"from_ts": 100, "to_ts": 200, **params}))

    def test_membership_for_every_count_and_fixed_half_open_window(self):
        self.login()
        with self.ctx.db.transaction() as conn:
            pending = step(conn, outcome="in_progress", reason="capture_disabled")
            empty = step(conn, output="", exit_code=0)
            disabled = step(conn, reason="capture_disabled")
            error = step(conn, outcome="error", output="private-output-fixture", reason="not_recorded")
            unknown = step(conn, outcome="recorded", reason="old_or_unknown_code")
            before = step(conn, ts=99.9)
            after = step(conn, ts=200)
            heartbeat = step(conn, event_type="heartbeat")
            web = step(conn, program=None, tool="snapshot", reason="protected", ts=199.99)
            # One event with multiple previews still counts once.
            conn.executemany("INSERT INTO event_texts VALUES(?, ?, 'private-preview-fixture', 0)",
                             [(web, "a.md"), (web, "b.md")])
        status, data, _ = self.get()
        self.assertEqual(status, 200)
        self.assertEqual((data["from_ts"], data["to_ts"]), (100, 200))
        rows = {item["program"]: item for item in data["programs"]}
        self.assertEqual(set(rows), {"grep", "snapshot"})
        membership = {
            "grep": {"pending": [pending], "completed": [error, disabled, empty], "capture_disabled": [disabled],
                     "recorded_output": [error, empty], "empty_output": [empty], "unconfirmed": [unknown],
                     "missing_output": [unknown, disabled], "not_recorded": [unknown]},
            "snapshot": {"completed": [web], "missing_output": [web], "protected": [web], "file_preview": [web]},
        }
        for name, buckets in membership.items():
            self.assertEqual(rows[name]["counts"], {k: len(v) for k, v in buckets.items()})
            for bucket, ids in buckets.items():
                with self.subTest(program=name, bucket=bucket):
                    status, detail, _ = self.get(program=name, bucket=bucket, version=rows[name]["version"])
                    self.assertEqual(status, 200)
                    self.assertEqual((detail["count"], [item["id"] for item in detail["events"]]), (len(ids), ids))
                    self.assertNotIn("private-", json.dumps(detail))
        self.assertEqual(data["total"]["counts"]["completed"], 4)
        _, detail, _ = self.get(bucket="missing_output", version=data["total"]["version"])
        self.assertEqual([e["id"] for e in detail["events"]], [web, unknown, disabled])
        self.assertFalse({after, before, heartbeat} & {e["id"] for e in detail["events"]})
        self.assertNotIn("private-", json.dumps(data))

    def test_keyset_pages_and_late_evidence_cannot_change_membership_silently(self):
        self.login()
        with self.ctx.db.transaction() as conn:
            ids = [step(conn, reason="capture_disabled") for _ in range(54)]
            other = step(conn, output="original")
        _, data, _ = self.get()
        args = {"program": "grep", "bucket": "capture_disabled", "version": data["programs"][0]["version"]}
        _, first, _ = self.get(**args)
        _, last, _ = self.get(**args, before=first["next_before"])
        self.assertIsNone(last["next_before"])
        self.assertEqual([e["id"] for e in first["events"] + last["events"]], list(reversed(ids)))
        with self.ctx.db.transaction() as conn:
            conn.execute("INSERT INTO event_execution VALUES(?,NULL,'arrived late',0,0)", (ids[0],))
            # Same count, different members. The old version must still be rejected.
            conn.execute("UPDATE event_execution SET command_output=NULL WHERE event_id=?", (other,))
            conn.execute("UPDATE events SET metadata_json=json_set(metadata_json,'$.output_reason','capture_disabled') "
                         "WHERE id=?", (other,))
        self.assertEqual(self.get(**args)[0], 409)
        _, fresh, _ = self.get()
        args["version"] = fresh["programs"][0]["version"]
        _, page, _ = self.get(**args)
        self.assertEqual((page["count"], page["events"][0]["id"]), (54, other))

    def test_tenant_and_read_scope_and_bad_window(self):
        self.assertEqual(self.req("GET", PATH, cookie=False)[0], 401)
        self.login()
        with self.ctx.db.transaction() as conn:
            step(conn, reason="outside_scope")
        self.assertEqual(self.get(organization_id=999)[0], 409)
        self.assertEqual(self.req("GET", PATH, headers=self.bearer(self.token()), cookie=False)[0], 401)
        _, token, _ = self.req("POST", "/api/v1/tokens", {"name": "report-reader", "scope": "read"})
        self.assertEqual(self.req("GET", PATH, headers=self.bearer(token), cookie=False)[0], 200)
        for query in ("from_ts=abc", "from_ts=50&to_ts=40", "from_ts=0&to_ts=3000000", "bucket=arbitrary"):
            self.assertEqual(self.req("GET", PATH + "?" + query)[0], 400)
        status, _, headers = self.req("POST", "/api/v1/auth/register",
                                     {"organization": "Second tenant", "username": "reader-b",
                                      "password": secrets.token_urlsafe(24)}, cookie=False)
        self.assertEqual(status, 201)
        self.cookie = headers["set-cookie"].split(";")[0]
        self.assertEqual(self.get(organization_id=1)[0], 409)
        _, own, _ = self.get()
        self.assertNotEqual(own["organization"], 1)
        self.assertEqual(own["programs"], [])
