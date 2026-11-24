"""End-to-end tests for Needs attention: normal ingestion (permissions, failed tests,
exhausted quotas, resolutions, age, exact links), heartbeat-only No signal without
inferring cause, auth/multi-tenant isolation, CSP safety, and desktop/mobile browser UX."""
from __future__ import annotations

import json
import re
import sqlite3
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ROOT_DIR = TESTS_DIR.parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))
QA_DIR = TESTS_DIR / "product_qa"
if str(QA_DIR) not in sys.path:
    sys.path.insert(0, str(QA_DIR))
if str(ROOT_DIR / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT_DIR / "backend"))

import browser_cdp as bc
import needs_attention
from test_acceptance_blackbox import HttpClient, SpawnedConsole

ORG_A = ("bootstrap_admin", "BootstrapPass!2026#QA")
ORG_B = ("orgb_na_user", "OrgBNeedsAttn!2026", "Beta Attention Org")


def _iso_offset(seconds_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


def _heartbeat(host_id: str, hostname: str | None = None) -> dict:
    return {
        "host_id": host_id,
        "hostname": hostname or host_id,
        "os_name": "linux",
        "arch": "x86_64",
        "agent_version": "0.3.0",
        "cpu_count": 4,
        "load_1m": 0.4,
        "mem_total_mb": 8192,
        "mem_used_mb": 2048,
        "agent_rss_mb": 24.0,
        "scan_duration_ms": 12.0,
        "harnesses": [{"id": "codex", "name": "Codex", "status": "running", "process_count": 1}],
        "processes": [],
    }


class NeedsAttentionAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ns-na-api-")
        self.srv = SpawnedConsole(Path(self.tmp.name))
        self.admin = HttpClient(self.srv.base_url)
        st, _, _ = self.admin.json("POST", "/api/v1/auth/login", {"username": ORG_A[0], "password": ORG_A[1]})
        self.assertEqual(st, 200)

    def tearDown(self):
        self.srv.stop()
        self.tmp.cleanup()

    def _create_token(self, client: HttpClient, name: str, scope: str = "ingest") -> str:
        st, _, body = client.json("POST", "/api/v1/tokens", {"name": name, "scope": scope})
        self.assertEqual(st, 201, body)
        return body["token"]

    def _ingest_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def test_explicit_permission_lifecycle_and_idle_session_no_false_positive(self):
        tok = self._create_token(self.admin, "host-perm")
        hdr = self._ingest_headers(tok)

        # 1) Normal idle session with an older file edit must NOT raise a permission item.
        st, _, body = self.admin.json(
            "POST",
            "/api/v1/ingest/activity",
            {
                "host_id": "host-perm",
                "activity_enabled": True,
                "activity_roots": ["/work/app"],
                "sessions": [
                    {
                        "session_id": "codex:idle-sess",
                        "harness": "codex",
                        "agent_name": "idle-agent",
                        "workspace": "/work/app",
                        "steps": [
                            {
                                "tool": "edit_file",
                                "category": "file_edit",
                                "label": "Edit readme",
                                "status": "completed",
                                "time": _iso_offset(1800),
                                "files": ["README.md"],
                            }
                        ],
                    }
                ],
            },
            headers=hdr,
        )
        self.assertIn(st, (200, 201), body)

        st, _, na = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(st, 200)
        self.assertEqual(na["items"], [], "Idle session without explicit permission must not trigger Needs attention")

        # 2) Explicit permission request via normal event ingestion -> active permission item with age & exact link.
        st, _, ev = self.admin.json(
            "POST",
            "/api/v1/ingest/event",
            {
                "host_id": "host-perm",
                "harness": "claude",
                "agent_name": "builder-1",
                "event_type": "permission_request",
                "severity": "WARNING",
                "message": "Allow running database migration script?",
                "metadata": {"session": "claude:perm-1", "workspace": "app", "waiting_for": "permission"},
            },
            headers=hdr,
        )
        self.assertEqual(st, 200, ev)
        perm_event_id = ev["event_id"]

        st, _, na = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(st, 200)
        self.assertEqual(na["counts"]["permission"], 1)
        item = na["items"][0]
        self.assertEqual(item["category"], "permission")
        self.assertEqual(item["event_id"], perm_event_id)
        self.assertEqual(item["event_key"], f"event:{perm_event_id}")
        self.assertIn(f"event=event%3A{perm_event_id}", item["link"])
        self.assertIn("host=host-perm", item["link"])
        for forbidden in ("session=", "agent=", "runtime="):
            self.assertNotIn(forbidden, item["link"])
        self.assertGreaterEqual(item["age_seconds"], 0)
        self.assertEqual(item["session"], "claude:perm-1")

        # 3) Explicit permission granted resolves the item and records resolution metadata.
        st, _, res_ev = self.admin.json(
            "POST",
            "/api/v1/ingest/event",
            {
                "host_id": "host-perm",
                "harness": "claude",
                "agent_name": "builder-1",
                "event_type": "permission_granted",
                "severity": "INFO",
                "message": "Operator granted permission for migration script",
                "metadata": {"session": "claude:perm-1", "workspace": "app"},
            },
            headers=hdr,
        )
        self.assertEqual(st, 200, res_ev)

        st, _, na = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(st, 200)
        self.assertEqual(na["counts"]["permission"], 0)
        self.assertEqual(len(na["resolved"]), 1)
        self.assertEqual(na["resolved"][0]["event_id"], perm_event_id)
        self.assertEqual(na["resolved"][0]["resolved_by_event_id"], res_ev["event_id"])
        self.assertEqual(na["resolved"][0]["resolution_reason"], "Permission granted")
        for link_field in ("link", "resolved_link"):
            for forbidden in ("session=", "agent=", "runtime="):
                self.assertNotIn(forbidden, na["resolved"][0][link_field])

    def test_failed_test_not_cleared_by_non_test_command_and_resolved_by_passing_test(self):
        tok = self._create_token(self.admin, "host-tests")
        hdr = self._ingest_headers(tok)

        # 1) Failed pytest step via normal activity ingestion.
        fail_step = {
            "tool": "exec_command",
            "category": "shell",
            "label": "Run pytest",
            "program": "pytest",
            "status": "failed",
            "time": _iso_offset(60),
            "command_input": "pytest -q tests/test_core.py",
            "command_output": "1 failed in 0.4s",
            "exit_code": 1,
        }
        st, _, body = self.admin.json(
            "POST",
            "/api/v1/ingest/activity",
            {
                "host_id": "host-tests",
                "activity_enabled": True,
                "activity_roots": ["/work/repo"],
                "sessions": [
                    {
                        "session_id": "codex:test-sess",
                        "harness": "codex",
                        "agent_name": "qa-agent",
                        "workspace": "/work/repo",
                        "steps": [fail_step],
                        "capture_steps": [fail_step],
                    }
                ],
            },
            headers=hdr,
        )
        self.assertIn(st, (200, 201), body)

        st, _, na = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(st, 200)
        self.assertEqual(na["counts"]["failed_test"], 1)
        ft = na["items"][0]
        self.assertEqual(ft["category"], "failed_test")
        self.assertEqual(ft["exit_code"], 1)
        self.assertEqual(ft["program"], "pytest")
        self.assertIn(f"event=event%3A{ft['event_id']}", ft["link"])
        self.assertGreaterEqual(ft["age_seconds"], 50)

        # 2) Non-test command succeeding (git status exit 0) must NOT resolve the failed test.
        non_test = {
            "tool": "exec_command",
            "category": "shell",
            "label": "Check git status",
            "program": "git",
            "status": "completed",
            "time": _iso_offset(30),
            "command_input": "git status",
            "command_output": "On branch main",
            "exit_code": 0,
        }
        st, _, body = self.admin.json(
            "POST",
            "/api/v1/ingest/activity",
            {
                "host_id": "host-tests",
                "activity_enabled": True,
                "activity_roots": ["/work/repo"],
                "sessions": [
                    {
                        "session_id": "codex:test-sess",
                        "harness": "codex",
                        "agent_name": "qa-agent",
                        "workspace": "/work/repo",
                        "steps": [fail_step, non_test],
                        "capture_steps": [fail_step, non_test],
                    }
                ],
            },
            headers=hdr,
        )
        self.assertIn(st, (200, 201), body)

        st, _, na = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(na["counts"]["failed_test"], 1, "Non-test command must not resolve failed test")

        # 3) Passing pytest (exit 0) resolves the failed test and links to resolving event.
        pass_step = {
            "tool": "exec_command",
            "category": "shell",
            "label": "Run pytest",
            "program": "pytest",
            "status": "completed",
            "time": _iso_offset(5),
            "command_input": "pytest -q tests/test_core.py",
            "command_output": "4 passed in 0.3s",
            "exit_code": 0,
        }
        st, _, body = self.admin.json(
            "POST",
            "/api/v1/ingest/activity",
            {
                "host_id": "host-tests",
                "activity_enabled": True,
                "activity_roots": ["/work/repo"],
                "sessions": [
                    {
                        "session_id": "codex:test-sess",
                        "harness": "codex",
                        "agent_name": "qa-agent",
                        "workspace": "/work/repo",
                        "steps": [fail_step, non_test, pass_step],
                        "capture_steps": [fail_step, non_test, pass_step],
                    }
                ],
            },
            headers=hdr,
        )
        self.assertIn(st, (200, 201), body)

        st, _, na = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(na["counts"]["failed_test"], 0)
        self.assertEqual(len(na["resolved"]), 1)
        self.assertEqual(na["resolved"][0]["category"], "failed_test")
        self.assertIn("Tests passed", na["resolved"][0]["resolution_reason"])
        self.assertIn("event=event%3A", na["resolved"][0]["resolved_link"])

    def test_quota_exhausted_and_resolution(self):
        tok = self._create_token(self.admin, "host-quota")
        hdr = self._ingest_headers(tok)

        st, _, ev = self.admin.json(
            "POST",
            "/api/v1/ingest/event",
            {
                "host_id": "host-quota",
                "harness": "codex",
                "agent_name": "worker-q",
                "event_type": "quota_429",
                "severity": "WARNING",
                "message": "HTTP 429 Too Many Requests: quota exceeded",
                "metadata": {"session": "codex:q1", "http_status": 429, "retry_after_sec": 45},
            },
            headers=hdr,
        )
        self.assertEqual(st, 200, ev)

        st, _, na = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(na["counts"]["quota_exhausted"], 1)
        q_item = na["items"][0]
        self.assertEqual(q_item["category"], "quota_exhausted")
        self.assertEqual(q_item["event_id"], ev["event_id"])
        self.assertIn("retry after 45s", q_item["detail"])
        self.assertIn(f"event=event%3A{ev['event_id']}", q_item["link"])
        for forbidden in ("session=", "agent=", "runtime="):
            self.assertNotIn(forbidden, q_item["link"])

        # Resolve with explicit quota_recovered event
        st, _, rec = self.admin.json(
            "POST",
            "/api/v1/ingest/event",
            {
                "host_id": "host-quota",
                "harness": "codex",
                "agent_name": "worker-q",
                "event_type": "quota_recovered",
                "severity": "INFO",
                "message": "Quota window reset; requests succeeding",
                "metadata": {"session": "codex:q1"},
            },
            headers=hdr,
        )
        self.assertEqual(st, 200, rec)

        st, _, na = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(na["counts"]["quota_exhausted"], 0)
        self.assertEqual(na["resolved"][0]["resolution_reason"], "Quota recovered")
        self.assertIn(f"event=event%3A{rec['event_id']}", na["resolved"][0]["resolved_link"])
        for forbidden in ("session=", "agent=", "runtime="):
            self.assertNotIn(forbidden, na["resolved"][0]["resolved_link"])

    def test_no_signal_by_heartbeat_without_inferring_cause_and_recovery(self):
        tok = self._create_token(self.admin, "host-hb")
        hdr = self._ingest_headers(tok)

        st, _, body = self.admin.json("POST", "/api/v1/ingest/heartbeat", _heartbeat("host-hb", "build-node-01"), headers=hdr)
        self.assertEqual(st, 200, body)

        # Fresh heartbeat -> zero No signal hosts
        st, _, na = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(st, 200)
        self.assertEqual(na["no_signal"], [])
        self.assertEqual(na["items"], [])

        # Age heartbeat past threshold (90s) to simulate silence without inferring cause
        with sqlite3.connect(self.srv.db_path) as conn:
            conn.execute("UPDATE hosts SET last_seen_at = ? WHERE host_id = ?", (time.time() - 240, "host-hb"))
            conn.commit()

        st, _, na = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(st, 200)
        self.assertEqual(na["items"], [], "No signal host must stay strictly separate from session attention items")
        self.assertEqual(len(na["no_signal"]), 1)
        ns = na["no_signal"][0]
        self.assertEqual(ns["host_id"], "host-hb")
        self.assertEqual(ns["status"], "no_signal")
        self.assertFalse(ns["cause_inferred"])
        self.assertGreaterEqual(ns["age_seconds"], 230)
        summary_low = ns["summary"].lower()
        self.assertIn("no heartbeat", summary_low)
        self.assertIn("not inferred", summary_low)
        for forbidden_inference in ("crashed", "rebooted", "network failure", "agent hung", "out of memory"):
            self.assertNotIn(forbidden_inference, summary_low)

        # New normal heartbeat immediately clears No signal
        st, _, body = self.admin.json("POST", "/api/v1/ingest/heartbeat", _heartbeat("host-hb", "build-node-01"), headers=hdr)
        self.assertEqual(st, 200, body)
        st, _, na = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(na["no_signal"], [])

    def test_auth_read_token_org_mismatch_409_and_two_org_isolation(self):
        tok_a = self._create_token(self.admin, "host-org-a")
        read_a = self._create_token(self.admin, "reader-org-a", scope="read")

        # Seed attention item + stale host in Org A
        self.admin.json("POST", "/api/v1/ingest/heartbeat", _heartbeat("host-org-a"), headers=self._ingest_headers(tok_a))
        self.admin.json(
            "POST",
            "/api/v1/ingest/event",
            {
                "host_id": "host-org-a",
                "harness": "codex",
                "agent_name": "secret-org-a-agent",
                "event_type": "permission_request",
                "severity": "WARNING",
                "message": "Org A private approval prompt",
                "metadata": {"session": "codex:org-a-only"},
            },
            headers=self._ingest_headers(tok_a),
        )
        with sqlite3.connect(self.srv.db_path) as conn:
            conn.execute("UPDATE hosts SET last_seen_at = ? WHERE host_id = ?", (time.time() - 300, "host-org-a"))
            conn.commit()

        # Unauthenticated -> 401
        anon = HttpClient(self.srv.base_url)
        self.assertEqual(anon.json("GET", "/api/v1/needs-attention")[0], 401)
        # Ingest token cannot read monitoring route -> 401
        self.assertEqual(anon.json("GET", "/api/v1/needs-attention", headers=self._ingest_headers(tok_a))[0], 401)
        # Read token -> 200 with Org A data
        st, hdrs, data_a = anon.json("GET", "/api/v1/needs-attention", headers=self._ingest_headers(read_a))
        self.assertEqual(st, 200)
        self.assertEqual(hdrs.get("cache-control"), "no-store")
        self.assertEqual(data_a["counts"]["permission"], 1)
        self.assertEqual(data_a["counts"]["no_signal"], 1)

        # Mismatched explicit organization_id -> 409
        self.assertEqual(self.admin.json("GET", "/api/v1/needs-attention?organization_id=99999")[0], 409)

        # Register Org B -> strictly empty, zero leak from Org A
        org_b = HttpClient(self.srv.base_url)
        st, _, reg_b = org_b.json(
            "POST",
            "/api/v1/auth/register",
            {"username": ORG_B[0], "password": ORG_B[1], "organization": ORG_B[2]},
        )
        self.assertEqual(st, 201, reg_b)
        st, _, data_b = org_b.json("GET", "/api/v1/needs-attention")
        self.assertEqual(st, 200)
        self.assertEqual(data_b["items"], [])
        self.assertEqual(data_b["no_signal"], [])
        self.assertEqual(data_b["resolved"], [])
        self.assertNotIn("secret-org-a-agent", json.dumps(data_b))
        self.assertNotIn("host-org-a", json.dumps(data_b))
        # Org B trying Org A's org_id -> 409
        self.assertEqual(org_b.json("GET", f"/api/v1/needs-attention?organization_id={data_a['organization']}")[0], 409)

    def test_activity_step_permission_and_quota_and_resolution(self):
        tok = self._create_token(self.admin, "host-act-na")
        hdr = self._ingest_headers(tok)

        perm_step = {
            "tool": "exec_command",
            "category": "shell",
            "label": "Run deploy script",
            "program": "bash",
            "status": "awaiting_permission",
            "time": _iso_offset(40),
            "command_input": "bash deploy.sh",
        }
        quota_step = {
            "tool": "exec_command",
            "category": "shell",
            "label": "Call model API",
            "program": "python3",
            "status": "failed",
            "time": _iso_offset(35),
            "command_input": "python3 run_batch.py",
            "command_output": "Error: HTTP 429 Too Many Requests - quota exceeded",
            "exit_code": 1,
        }
        st, _, body = self.admin.json(
            "POST",
            "/api/v1/ingest/activity",
            {
                "host_id": "host-act-na",
                "activity_enabled": True,
                "activity_roots": ["/work/app"],
                "sessions": [
                    {
                        "session_id": "codex:act-perm",
                        "harness": "codex",
                        "agent_name": "act-agent-1",
                        "workspace": "/work/app",
                        "steps": [perm_step],
                        "capture_steps": [perm_step],
                    },
                    {
                        "session_id": "codex:act-quota",
                        "harness": "codex",
                        "agent_name": "act-agent-2",
                        "workspace": "/work/app",
                        "steps": [quota_step],
                        "capture_steps": [quota_step],
                    },
                ],
            },
            headers=hdr,
        )
        self.assertIn(st, (200, 201), body)

        st, _, na = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(st, 200)
        self.assertEqual(na["counts"]["permission"], 1)
        self.assertEqual(na["counts"]["quota_exhausted"], 1)

        # Substantive completed steps in each session resolve both conditions automatically.
        ok_step_1 = {
            "tool": "edit_file",
            "category": "file_edit",
            "label": "Update release note",
            "status": "completed",
            "time": _iso_offset(5),
            "files": ["CHANGELOG.md"],
        }
        ok_step_2 = {
            "tool": "exec_command",
            "category": "shell",
            "label": "Retry batch",
            "program": "python3",
            "status": "completed",
            "time": _iso_offset(4),
            "command_input": "python3 run_batch.py",
            "command_output": "Batch finished",
            "exit_code": 0,
        }
        st, _, body = self.admin.json(
            "POST",
            "/api/v1/ingest/activity",
            {
                "host_id": "host-act-na",
                "activity_enabled": True,
                "activity_roots": ["/work/app"],
                "sessions": [
                    {
                        "session_id": "codex:act-perm",
                        "harness": "codex",
                        "agent_name": "act-agent-1",
                        "workspace": "/work/app",
                        "steps": [perm_step, ok_step_1],
                        "capture_steps": [perm_step, ok_step_1],
                    },
                    {
                        "session_id": "codex:act-quota",
                        "harness": "codex",
                        "agent_name": "act-agent-2",
                        "workspace": "/work/app",
                        "steps": [quota_step, ok_step_2],
                        "capture_steps": [quota_step, ok_step_2],
                    },
                ],
            },
            headers=hdr,
        )
        self.assertIn(st, (200, 201), body)

        st, _, na = self.admin.json("GET", "/api/v1/needs-attention")
        self.assertEqual(na["counts"]["total"], 0)
        self.assertEqual(na["counts"]["resolved"], 2)

    def test_csp_and_static_assets(self):
        js = (ROOT_DIR / "frontend/needs-attention.js").read_text(encoding="utf-8")
        css = (ROOT_DIR / "frontend/needs-attention.css").read_text(encoding="utf-8")
        inline_handler = re.compile(r"\bon(?:click|change|submit|input|keydown|keyup|load|error|focus|blur)\s*=", re.I)
        self.assertIsNone(inline_handler.search(js))
        self.assertNotIn("http://", js)
        self.assertNotIn("https://", js)
        self.assertNotIn("http://", css)
        self.assertNotIn("https://", css)
        for asset in ("/needs-attention.js", "/needs-attention.css"):
            st, _, _ = self.admin.request("GET", asset)
            self.assertEqual(st, 200, f"Static asset {asset} failed")


class NeedsAttentionBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chrome = bc.find_browser()
        cls.tmp = tempfile.TemporaryDirectory(prefix="ns-na-browser-")
        cls.srv = SpawnedConsole(Path(cls.tmp.name))
        cls.admin = HttpClient(cls.srv.base_url)
        st, _, _ = cls.admin.json("POST", "/api/v1/auth/login", {"username": ORG_A[0], "password": ORG_A[1]})
        assert st == 200
        st, _, tok = cls.admin.json("POST", "/api/v1/tokens", {"name": "na-host-1", "scope": "ingest"})
        assert st == 201
        hdr = {"Authorization": f"Bearer {tok['token']}"}

        # 1) Enroll host-active (fresh) and host-silent (stale No signal)
        st, _, _ = cls.admin.json("POST", "/api/v1/ingest/heartbeat", _heartbeat("na-host-1", "worker-east"), headers=hdr)
        assert st == 200
        st, _, tok2 = cls.admin.json("POST", "/api/v1/tokens", {"name": "na-host-silent", "scope": "ingest"})
        assert st == 201
        hdr2 = {"Authorization": f"Bearer {tok2['token']}"}
        st, _, _ = cls.admin.json("POST", "/api/v1/ingest/heartbeat", _heartbeat("na-host-silent", "worker-silent"), headers=hdr2)
        assert st == 200
        with sqlite3.connect(cls.srv.db_path) as conn:
            conn.execute("UPDATE hosts SET last_seen_at = ? WHERE host_id = ?", (time.time() - 260, "na-host-silent"))
            conn.commit()

        # 2) Seed earlier observed_step activity on the same sessions used by permission, quota,
        #    and failed_test items so any accidental session= scoping on non-observed_step events
        #    would visibly select the wrong observed_step row in /live.
        prior_perm_step = {
            "tool": "edit_file",
            "category": "file_edit",
            "label": "Prepare migration script",
            "status": "completed",
            "time": _iso_offset(120),
            "files": ["migrations/001.sql"],
        }
        prior_quota_step = {
            "tool": "edit_file",
            "category": "file_edit",
            "label": "Edit batch runner",
            "status": "completed",
            "time": _iso_offset(110),
            "files": ["batch.py"],
        }
        fail_step = {
            "tool": "exec_command",
            "category": "shell",
            "label": "Run tests",
            "program": "pytest",
            "status": "failed",
            "time": _iso_offset(45),
            "command_input": "pytest -q tests/test_checkout.py",
            "command_output": "AssertionError in test_checkout.py",
            "exit_code": 1,
        }
        st, _, _ = cls.admin.json(
            "POST",
            "/api/v1/ingest/activity",
            {
                "host_id": "na-host-1",
                "activity_enabled": True,
                "activity_roots": ["/work/demo"],
                "sessions": [
                    {
                        "session_id": "claude:perm-ui",
                        "harness": "claude",
                        "agent_name": "deploy-bot",
                        "workspace": "/work/demo",
                        "steps": [prior_perm_step],
                        "capture_steps": [prior_perm_step],
                    },
                    {
                        "session_id": "codex:quota-ui",
                        "harness": "codex",
                        "agent_name": "quota-bot",
                        "workspace": "/work/demo",
                        "steps": [prior_quota_step],
                        "capture_steps": [prior_quota_step],
                    },
                    {
                        "session_id": "codex:fail-ui",
                        "harness": "codex",
                        "agent_name": "test-bot",
                        "workspace": "/work/demo",
                        "steps": [fail_step],
                        "capture_steps": [fail_step],
                    },
                ],
            },
            headers=hdr,
        )
        assert st in (200, 201)

        # 3) Explicit permission with XSS probe (via /api/v1/ingest/event on session with prior observed_step)
        cls.xss = '<img src=x onerror="window.__na_xss=1">'
        st, _, perm_ev = cls.admin.json(
            "POST",
            "/api/v1/ingest/event",
            {
                "host_id": "na-host-1",
                "harness": "claude",
                "agent_name": "deploy-bot",
                "event_type": "permission_request",
                "severity": "WARNING",
                "message": f"Approve deployment command {cls.xss}",
                "metadata": {"session": "claude:perm-ui", "workspace": "demo"},
            },
            headers=hdr,
        )
        assert st == 200, perm_ev
        cls.perm_event_id = perm_ev["event_id"]

        # 4) Exhausted quota event (via /api/v1/ingest/event on session with prior observed_step)
        st, _, quota_ev = cls.admin.json(
            "POST",
            "/api/v1/ingest/event",
            {
                "host_id": "na-host-1",
                "harness": "codex",
                "agent_name": "quota-bot",
                "event_type": "quota_429",
                "severity": "WARNING",
                "message": "HTTP 429 rate limit exceeded on provider",
                "metadata": {"session": "codex:quota-ui", "http_status": 429},
            },
            headers=hdr,
        )
        assert st == 200, quota_ev
        cls.quota_event_id = quota_ev["event_id"]

        # 5) One resolved permission so Recently resolved disclosure appears with both trigger & resolution links
        st, _, res_trig = cls.admin.json(
            "POST",
            "/api/v1/ingest/event",
            {
                "host_id": "na-host-1",
                "harness": "claude",
                "agent_name": "resolved-bot",
                "event_type": "permission_request",
                "severity": "WARNING",
                "message": "Approve config read",
                "metadata": {"session": "claude:done-ui"},
            },
            headers=hdr,
        )
        assert st == 200, res_trig
        cls.resolved_trigger_event_id = res_trig["event_id"]

        st, _, res_done = cls.admin.json(
            "POST",
            "/api/v1/ingest/event",
            {
                "host_id": "na-host-1",
                "harness": "claude",
                "agent_name": "resolved-bot",
                "event_type": "permission_granted",
                "severity": "INFO",
                "message": "Approved config read",
                "metadata": {"session": "claude:done-ui"},
            },
            headers=hdr,
        )
        assert st == 200, res_done
        cls.resolved_by_event_id = res_done["event_id"]

        # 6) Second organization for browser isolation check
        beta = HttpClient(cls.srv.base_url)
        st, _, reg = beta.json(
            "POST",
            "/api/v1/auth/register",
            {"username": ORG_B[0], "password": ORG_B[1], "organization": ORG_B[2]},
        )
        assert st == 201, reg

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()
        cls.tmp.cleanup()

    def _login(self, page, user, pw):
        page.goto(self.srv.base_url + "/")
        page.settled("#login-form button[type=submit]", 15)
        page.type("#username", user)
        page.type("#password", pw)
        page.click("#login-form button[type=submit]")
        page.wait(
            "getComputedStyle(document.querySelector('#app-view')).display!=='none'"
            " && !document.querySelector('#app-view').hidden",
            15,
        )

    def test_desktop_and_mobile_dashboard_exact_link_xss_and_org_isolation(self):
        b = bc.Browser(self.chrome)
        try:
            # Desktop 1440x900 — Org A
            p = b.new_page(1440, 900)
            self._login(p, ORG_A[0], ORG_A[1])
            p.wait("document.querySelectorAll('#na-items-list .na-item').length === 3", 15)
            p.wait("document.querySelectorAll('#na-no-signal-list .na-item').length === 1", 10)

            # Verify XSS payload escaped as literal text
            self.assertIsNone(p.eval("window.__na_xss ?? null"))
            self.assertIn("<img src=x", p.eval("document.getElementById('na-items-list').textContent"))

            # Verify No signal panel is strictly separate and does not infer cause
            ns_text = p.eval("document.getElementById('na-no-signal-panel').textContent")
            self.assertIn("worker-silent", ns_text)
            self.assertIn("cause not inferred", ns_text.lower())

            # Verify Recently resolved fold exists and opens
            self.assertTrue(p.eval("Boolean(document.getElementById('na-resolved-fold'))"))
            p.click("#na-resolved-fold > summary")
            p.wait("document.getElementById('na-resolved-fold').open === true", 5)
            self.assertIn("Permission granted", p.eval("document.getElementById('na-resolved-list').textContent"))

            # Verify Expand all / Compact view toggle works without overflow
            compact_h = p.eval("Math.round(document.getElementById('needs-attention-body').getBoundingClientRect().height)")
            self.assertLessEqual(compact_h, 210)
            p.click("[data-na-toggle='expand']")
            p.wait("document.getElementById('needs-attention-body').classList.contains('is-expanded')", 5)
            expanded_h = p.eval("Math.round(document.getElementById('needs-attention-body').getBoundingClientRect().height)")
            self.assertGreater(expanded_h, compact_h)
            self.assertLessEqual(p.eval("document.documentElement.scrollWidth"), 1441)
            p.click("[data-na-toggle='expand']")
            p.wait("!document.getElementById('needs-attention-body').classList.contains('is-expanded')", 5)

            # Verify category filter works
            p.click("[data-na-filter='failed_test']")
            p.wait("document.querySelectorAll('#na-items-list .na-item').length === 1", 5)
            failed_ev_id = p.eval("document.querySelector('#na-items-list .na-item').dataset.naEventId")
            self.assertTrue(failed_ev_id.isdigit())

            # Zero horizontal overflow & zero JS errors on desktop dashboard
            self.assertLessEqual(p.eval("document.documentElement.scrollWidth"), 1441)
            self.assertEqual([e for e in p.errors if "/api/v1/auth/me" not in e], [])

            # Click exact event link for failed_test -> opens /live with that exact event selected!
            p.click("#na-items-list [data-na-link='event']")
            p.wait("window.location.pathname === '/live'", 10)
            p.wait(
                f"Boolean(document.querySelector('#rows tr[data-key=\"event:{failed_ev_id}\"][aria-selected=\"true\"]'))",
                15,
            )
            p.wait("document.getElementById('detail').textContent.includes('pytest')", 10)
            self.assertEqual([e for e in p.errors if "/api/v1/auth/me" not in e], [])

            # Verify exact /live selection for permission, quota_exhausted, and resolved-history links
            link_checks = [
                (
                    "#na-items-list .na-item[data-na-category='permission'] [data-na-link='event']",
                    f"event:{self.perm_event_id}",
                    "Approve deployment command",
                    False,
                ),
                (
                    "#na-items-list .na-item[data-na-category='quota_exhausted'] [data-na-link='event']",
                    f"event:{self.quota_event_id}",
                    "HTTP 429 rate limit exceeded on provider",
                    False,
                ),
                (
                    "#na-resolved-list .na-item [data-na-link='event']",
                    f"event:{self.resolved_trigger_event_id}",
                    "Approve config read",
                    True,
                ),
                (
                    "#na-resolved-list .na-item [data-na-link='resolution']",
                    f"event:{self.resolved_by_event_id}",
                    "Approved config read",
                    True,
                ),
            ]
            for selector, expected_key, expected_detail, open_resolved in link_checks:
                p.goto(self.srv.base_url + "/")
                p.wait("document.querySelectorAll('#na-items-list .na-item').length === 3", 15)
                if open_resolved:
                    p.click("#na-resolved-fold > summary")
                    p.wait("document.getElementById('na-resolved-fold').open === true", 5)
                p.click(selector)
                p.wait("window.location.pathname === '/live'", 10)
                p.wait(
                    f"(document.querySelector('#rows tr[aria-selected=\"true\"]') || {{}}).dataset?.key === {json.dumps(expected_key)}",
                    15,
                )
                p.wait(
                    f"Boolean(document.querySelector('#rows tr[data-key={json.dumps(expected_key)}].selected'))",
                    5,
                )
                p.wait(
                    f"document.getElementById('detail').textContent.includes({json.dumps(expected_detail)})",
                    10,
                )
                self.assertEqual([e for e in p.errors if "/api/v1/auth/me" not in e], [])

            # Mobile 390x844 — Org A
            pm = b.new_page(390, 844)
            self._login(pm, ORG_A[0], ORG_A[1])
            pm.wait("document.querySelectorAll('#na-items-list .na-item').length === 3", 15)
            pm.wait("document.querySelectorAll('#na-no-signal-list .na-item').length === 1", 10)
            self.assertLessEqual(pm.eval("document.documentElement.scrollWidth"), 391)
            self.assertEqual([e for e in pm.errors if "/api/v1/auth/me" not in e], [])

            # Desktop 1440x900 — Org B isolation
            pb = b.new_page(1440, 900)
            self._login(pb, ORG_B[0], ORG_B[1])
            pb.wait("document.getElementById('na-status-pill').textContent.trim() === 'CLEAR'", 15)
            na_b_text = pb.eval("document.getElementById('needs-attention').textContent")
            self.assertNotIn("worker-silent", na_b_text)
            self.assertNotIn("deploy-bot", na_b_text)
            self.assertNotIn("test_checkout.py", na_b_text)
            self.assertEqual([e for e in pb.errors if "/api/v1/auth/me" not in e], [])
        finally:
            b.close()

    def test_needs_attention_layout_shift_stays_under_50px_with_4_and_20_items(self):
        """Needs attention must reserve its height before data loads so #activity does not jump."""
        for count in (4, 20):
            with self.subTest(items=count), tempfile.TemporaryDirectory(prefix=f"ns-na-cls-{count}-") as tmp:
                srv = SpawnedConsole(Path(tmp))
                b = bc.Browser(self.chrome)
                try:
                    adm = HttpClient(srv.base_url)
                    st, _, _ = adm.json("POST", "/api/v1/auth/login", {"username": ORG_A[0], "password": ORG_A[1]})
                    self.assertEqual(st, 200)
                    st, _, tok = adm.json("POST", "/api/v1/tokens", {"name": "cls-host", "scope": "ingest"})
                    self.assertEqual(st, 201)
                    hdr = {"Authorization": f"Bearer {tok['token']}"}
                    st, _, _ = adm.json("POST", "/api/v1/ingest/heartbeat", _heartbeat("cls-host"), headers=hdr)
                    self.assertEqual(st, 200)
                    for idx in range(count):
                        st, _, _ = adm.json(
                            "POST",
                            "/api/v1/ingest/event",
                            {
                                "host_id": "cls-host",
                                "harness": "claude",
                                "agent_name": "cls-agent",
                                "event_type": "permission_request",
                                "severity": "WARNING",
                                "message": f"Allow migration step {idx}?",
                                "metadata": {"session": f"claude:cls-{idx}", "waiting_for": "permission"},
                            },
                            headers=hdr,
                        )
                        self.assertEqual(st, 200)

                    for vw, vh, mob in ((1440, 900, False), (390, 844, True)):
                        pg = b.new_page(vw, vh, mob)
                        pg.goto(srv.base_url + "/")
                        pg.settled("#login-form button[type=submit]", 15)
                        pg.type("#username", ORG_A[0])
                        pg.type("#password", ORG_A[1])
                        pg.click("#login-form button[type=submit]")
                        # Measure section height and exact #needs-attention -> #activity offset across load.
                        samples = []
                        t0 = time.monotonic()
                        while time.monotonic() - t0 < 3.0:
                            s = pg.eval(
                                """(() => {
                                    const app = document.querySelector('#app-view');
                                    if (!app || app.classList.contains('hidden')) return null;
                                    const na = document.querySelector('#needs-attention');
                                    const nb = document.querySelector('#needs-attention-body');
                                    const act = document.querySelector('#activity');
                                    const nr = na.getBoundingClientRect();
                                    const ar = act.getBoundingClientRect();
                                    return {
                                        naH: Math.round(nr.height),
                                        offset: Math.round(ar.top - nr.top),
                                        loaded: !nb.innerText.includes('Loading'),
                                        rendered: document.querySelectorAll('#na-items-list .na-item').length,
                                    };
                                })()"""
                            )
                            if s:
                                samples.append(s)
                                if s["loaded"] and s["rendered"] == count and len(samples) >= 3:
                                    break
                            time.sleep(0.05)
                        self.assertTrue(samples and samples[-1]["loaded"], f"Did not finish loading ({count}, {vw}x{vh})")
                        self.assertEqual(samples[-1]["rendered"], count)
                        na_shift = max(s["naH"] for s in samples) - min(s["naH"] for s in samples)
                        offset_shift = max(s["offset"] for s in samples) - min(s["offset"] for s in samples)
                        self.assertLess(na_shift, 50, f"naH shifted {na_shift}px for {count} items at {vw}x{vh}")
                        self.assertLess(offset_shift, 50, f"#activity offset shifted {offset_shift}px for {count} items at {vw}x{vh}")
                        self.assertLessEqual(pg.eval("document.documentElement.scrollWidth"), vw + 1)
                        self.assertEqual([e for e in pg.errors if "/api/v1/auth/me" not in e], [])
                        pg.close()
                finally:
                    b.close()
                    srv.stop()


if __name__ == "__main__":
    unittest.main()
