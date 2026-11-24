"""Comprehensive unit, API, security/RBAC, multi-tenant, privacy/non-execution,
and headless Chromium browser tests for Reproducible Cases."""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
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

import browser_cdp as bc  # noqa: E402
import repro_cases  # noqa: E402
from test_acceptance_blackbox import HttpClient, SpawnedConsole  # noqa: E402

ORG_A = ("bootstrap_admin", "BootstrapPass!2026#QA")
ORG_B = ("orgb_repro_user", "OrgBReproPass!2026", "Beta Repro Org")


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


def _planted_secrets() -> list[str]:
    return [
        "sk-proj-" + "AbCdEfGhIjKlMnOpQrStUvWx0123",
        "sk-ant-" + "ZxYwVuTsRqPoNmLkJiHgFeDc9876",
        "ghp_" + "1234567890abcdefghijklmnopqr",
        "AKIA" + "IOSFODNN7EXAMPLZ",
        "sc_live_" + "secretToken99887766",
        "mySecretPass123!",
        "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    ]


class ReproCasesUnitTests(unittest.TestCase):
    def test_backend_module_never_imports_or_calls_execution_primitives(self):
        src = (ROOT_DIR / "backend" / "repro_cases.py").read_text(encoding="utf-8")
        for forbidden in ("import subprocess", "from subprocess", "os.system", "os.popen", "pty.", "eval(", "exec("):
            self.assertNotIn(forbidden, src, f"repro_cases.py must never contain {forbidden!r}")

    def test_redaction_and_sensitive_path_stripping(self):
        secrets_list = _planted_secrets()
        raw = (
            f"OPENAI_API_KEY={secrets_list[0]}\n"
            f"ANTHROPIC_API_KEY={secrets_list[1]}\n"
            f"curl -H 'Authorization: Bearer {secrets_list[0]}'\n"
            f"gh={secrets_list[2]} aws={secrets_list[3]} tok={secrets_list[4]}\n"
            f"password={secrets_list[5]} jwt={secrets_list[6]}\n"
            f"https://alice:{secrets_list[5]}@git.example.invalid/repo.git\n"
            f"cat /home/dev/project/.env"
        )
        redacted, _ = repro_cases._redact_text(raw, 2048)
        assert redacted is not None
        for sec in secrets_list:
            self.assertNotIn(sec, redacted)
        self.assertNotIn(".env", redacted)
        self.assertIn("[protected file]", redacted)

        pem, _ = repro_cases._redact_text("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----", 1024)
        self.assertEqual(pem, "[protected content]")

        files = repro_cases._sanitize_files([
            "src/app.py",
            "tests/test_billing.py",
            ".env",
            ".env.local",
            "config/credentials.json",
            ".ssh/id_rsa",
            "../etc/passwd",
            "/etc/hosts",
            ".git/config",
        ])
        self.assertEqual(files, ["src/app.py", "tests/test_billing.py"])

    def test_markdown_fence_escaping(self):
        block = repro_cases._fence_block("line1\n~~~nested\nline2", "text")
        self.assertTrue(block.startswith("~~~~text\n"))
        self.assertTrue(block.endswith("\n~~~~"))

    def test_compare_run_verdicts_and_diff(self):
        baseline = {
            "status": "failed",
            "revision": "abc1234",
            "command_input": "pytest -q tests/test_math.py",
            "exit_code": 1,
            "observed_output": "FAILED tests/test_math.py::test_sum\nAssertionError: 3 != 4",
        }
        same = repro_cases.compare_run(
            baseline,
            {
                "run_number": 1,
                "status": "failed",
                "revision": "abc1234",
                "command_used": "pytest -q tests/test_math.py",
                "exit_code": 1,
                "observed_output": "FAILED tests/test_math.py::test_sum\nAssertionError: 3 != 4",
            },
        )
        self.assertEqual(same["verdict"], "still_failing")
        self.assertFalse(same["exit_code_changed"])
        self.assertFalse(same["output_changed"])

        changed = repro_cases.compare_run(
            baseline,
            {
                "run_number": 2,
                "status": "failed",
                "revision": "def5678",
                "command_used": "pytest -q tests/test_math.py",
                "exit_code": 2,
                "observed_output": "ImportError: missing dependency",
            },
        )
        self.assertEqual(changed["verdict"], "changed_failure")
        self.assertTrue(changed["exit_code_changed"])
        self.assertTrue(changed["revision_changed"])
        self.assertTrue(any(line.startswith("-FAILED") for line in changed["diff_lines"]))
        self.assertTrue(any(line.startswith("+ImportError") for line in changed["diff_lines"]))

        fixed = repro_cases.compare_run(
            baseline,
            {
                "run_number": 3,
                "status": "passed",
                "revision": "fed9999",
                "command_used": "pytest -q tests/test_math.py",
                "exit_code": 0,
                "observed_output": "1 passed in 0.08s",
            },
        )
        self.assertEqual(fixed["verdict"], "fixed")
        self.assertEqual(fixed["verdict_label"], "Fixed")
        self.assertTrue(any(line.startswith("+1 passed") for line in fixed["diff_lines"]))

        contradiction = repro_cases.compare_run(
            baseline,
            {"run_number": 4, "status": "passed", "revision": None, "command_used": None, "exit_code": 2, "observed_output": ""},
        )
        self.assertEqual(contradiction["verdict"], "inconclusive")


class ReproCasesAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ns-rc-api-")
        self.srv = SpawnedConsole(Path(self.tmp.name))
        self.admin = HttpClient(self.srv.base_url)
        st, _, _ = self.admin.json("POST", "/api/v1/auth/login", {"username": ORG_A[0], "password": ORG_A[1]})
        self.assertEqual(st, 200)

    def tearDown(self):
        self.srv.stop()
        self.tmp.cleanup()

    def _create_token(self, name: str, scope: str = "ingest") -> str:
        st, _, body = self.admin.json("POST", "/api/v1/tokens", {"name": name, "scope": scope})
        self.assertEqual(st, 201, body)
        return body["token"]

    def _invite_user(self, username: str, password: str, role: str) -> HttpClient:
        st, _, inv = self.admin.json("POST", "/api/v1/invitations", {"username": username, "role": role})
        self.assertEqual(st, 201, inv)
        client = HttpClient(self.srv.base_url)
        st, _, acc = client.json(
            "POST",
            "/api/v1/auth/accept-invitation",
            {"token": inv["token"], "username": username, "password": password},
        )
        self.assertEqual(st, 200, acc)
        return client

    def test_end_to_end_repro_lifecycle_redaction_and_non_execution(self):
        tok = self._create_token("host-repro")
        hdr = {"Authorization": f"Bearer {tok}"}
        secrets_list = _planted_secrets()
        pwn_marker = Path(self.tmp.name) / "must_never_be_executed.flag"

        # 1) Normal healthy session must NOT show up as a failed session candidate
        healthy_step = {
            "tool": "exec_command",
            "category": "shell",
            "label": "Run lint",
            "program": "ruff",
            "status": "completed",
            "time": _iso_offset(300),
            "command_input": "ruff check src",
            "command_output": "All checks passed!",
            "exit_code": 0,
        }
        st, _, body = self.admin.json(
            "POST",
            "/api/v1/ingest/activity",
            {
                "host_id": "host-repro",
                "activity_enabled": True,
                "activity_roots": ["/work/service"],
                "sessions": [
                    {
                        "session_id": "codex:ok-sess",
                        "harness": "codex",
                        "agent_name": "ok-agent",
                        "workspace": "/work/service",
                        "steps": [healthy_step],
                        "capture_steps": [healthy_step],
                    }
                ],
            },
            headers=hdr,
        )
        self.assertIn(st, (200, 201), body)

        # 2) Failed session via activity ingestion + preceding edit step + planted secrets + shell metacharacters
        edit_step = {
            "tool": "edit_file",
            "category": "file_edit",
            "label": "Edit src/billing.py",
            "status": "completed",
            "time": _iso_offset(90),
            "files": ["src/billing.py", ".env"],
        }
        fail_step = {
            "tool": "exec_command",
            "category": "shell",
            "label": "Run pytest",
            "program": "pytest",
            "status": "failed",
            "time": _iso_offset(45),
            "files": ["tests/test_billing.py", "credentials.json"],
            "command_input": f"pytest -q tests/test_billing.py; touch {pwn_marker}; $(touch {pwn_marker}.sub) # Bearer {secrets_list[0]}",
            "command_output": (
                f"FAILED tests/test_billing.py::test_charge - AssertionError: expected 200\n"
                f"env leak: gh={secrets_list[2]} aws={secrets_list[3]} password={secrets_list[5]} <script>alert(1)</script>"
            ),
            "exit_code": 1,
        }
        st, _, body = self.admin.json(
            "POST",
            "/api/v1/ingest/activity",
            {
                "host_id": "host-repro",
                "activity_enabled": True,
                "activity_roots": ["/work/service"],
                "sessions": [
                    {
                        "session_id": "codex:fail-billing",
                        "harness": "codex",
                        "agent_name": "billing-agent",
                        "workspace": "/work/service",
                        "steps": [edit_step, fail_step],
                        "capture_steps": [edit_step, fail_step],
                    }
                ],
            },
            headers=hdr,
        )
        self.assertIn(st, (200, 201), body)

        # 3) Also test /api/v1/ingest/event with explicit revision metadata + partial/legacy failed event without cmd/output
        st, _, ev_rev = self.admin.json(
            "POST",
            "/api/v1/ingest/event",
            {
                "host_id": "host-repro",
                "harness": "claude",
                "agent_name": "api-agent",
                "event_type": "test_failed",
                "severity": "ERROR",
                "message": "Contract suite failed on /invoices",
                "metadata": {
                    "session": "claude:invoice-fail",
                    "workspace": "billing-api",
                    "git_commit": "e4f9a12",
                    "files": ["api/invoices.py", ".ssh/id_ed25519"],
                    "command": f"pytest tests/test_invoices.py --token {secrets_list[1]}",
                    "expected_result": "HTTP 200 with invoice payload",
                    "observed_output": f"AssertionError: 500 returned\nAuthorization: Bearer {secrets_list[4]}",
                    "exit_code": 1,
                },
            },
            headers=hdr,
        )
        self.assertEqual(st, 200, ev_rev)

        st, _, ev_legacy = self.admin.json(
            "POST",
            "/api/v1/ingest/event",
            {
                "host_id": "host-repro",
                "harness": "generic",
                "agent_name": "legacy-agent",
                "event_type": "tool_error",
                "severity": "ERROR",
                "message": "Legacy runner exited unexpectedly",
                "metadata": {"session": "legacy:no-extras"},
            },
            headers=hdr,
        )
        self.assertEqual(st, 200, ev_legacy)

        # List overview
        st, _, ov = self.admin.json("GET", "/api/v1/repro-cases")
        self.assertEqual(st, 200)
        self.assertEqual(ov["execution_mode"], "manual_only")
        session_ids = [c["session_id"] for c in ov["failed_sessions"]]
        self.assertNotIn("codex:ok-sess", session_ids)
        self.assertIn("codex:fail-billing", session_ids)
        self.assertIn("claude:invoice-fail", session_ids)
        self.assertIn("legacy:no-extras", session_ids)

        billing_cand = next(c for c in ov["failed_sessions"] if c["session_id"] == "codex:fail-billing")
        self.assertEqual(billing_cand["files"], ["tests/test_billing.py", "src/billing.py"])
        self.assertEqual(billing_cand["workspace"], "service")
        self.assertEqual(billing_cand["observed_exit_code"], 1)
        self.assertTrue(billing_cand["has_command"])
        self.assertTrue(billing_cand["has_output"])

        # Convert billing failure to repro case with explicit operator revision & expected result
        st, _, created = self.admin.json(
            "POST",
            "/api/v1/repro-cases",
            {
                "source_event_id": billing_cand["source_event_id"],
                "title": "Billing tax rounding returns 500",
                "revision": "release-2026.11@rc1",
                "expected_result": "Charge endpoint returns HTTP 200",
                "notes": f"Reproduce with password={secrets_list[5]} scrubbed",
            },
        )
        self.assertEqual(st, 201, created)
        case_id = created["id"]
        self.assertEqual(created["revision"], "release-2026.11@rc1")
        self.assertEqual(created["files"], ["tests/test_billing.py", "src/billing.py"])
        self.assertEqual(created["execution_mode"], "manual_only")
        serialized_case = json.dumps(created)
        for sec in secrets_list:
            self.assertNotIn(sec, serialized_case)
        self.assertNotIn("credentials.json", serialized_case)
        self.assertNotIn(".env", serialized_case)

        # Convert partial/legacy event -> missing fields must stay explicitly None (not fabricated)
        st, _, leg_case = self.admin.json("POST", "/api/v1/repro-cases", {"source_event_id": ev_legacy["event_id"]})
        self.assertEqual(st, 201, leg_case)
        self.assertIsNone(leg_case["revision"])
        self.assertIsNone(leg_case["command_input"])
        self.assertIsNone(leg_case["observed_output"])
        self.assertIsNone(leg_case["observed_exit_code"])

        # Export JSON & Markdown bundles
        st, hdrs, raw_json = self.admin.request("GET", f"/api/v1/repro-cases/{case_id}/export?format=json")
        self.assertEqual(st, 200)
        self.assertEqual(hdrs.get("cache-control"), "no-store")
        self.assertEqual(hdrs.get("x-content-type-options"), "nosniff")
        self.assertIn("attachment", hdrs.get("content-disposition", ""))
        bundle = json.loads(raw_json.decode("utf-8"))
        self.assertEqual(bundle["execution_mode"], "manual_only")
        self.assertEqual(bundle["revision"], "release-2026.11@rc1")
        for sec in secrets_list:
            self.assertNotIn(sec, raw_json.decode("utf-8"))

        st, hdrs_md, raw_md = self.admin.request("GET", f"/api/v1/repro-cases/{case_id}/export?format=markdown")
        self.assertEqual(st, 200)
        self.assertIn("text/markdown", hdrs_md.get("content-type", ""))
        md_text = raw_md.decode("utf-8")
        self.assertIn("manual_only", md_text)
        for sec in secrets_list:
            self.assertNotIn(sec, md_text)

        # Record Run 1 (still failing, matching exit/output), Run 2 (changed failure), Run 3 (fixed)
        st, _, r1 = self.admin.json(
            "POST",
            f"/api/v1/repro-cases/{case_id}/runs",
            {
                "status": "failed",
                "exit_code": 1,
                "revision": "release-2026.11@rc1",
                "command_used": created["command_input"],
                "observed_output": created["observed_output"],
                "notes": "Reproduced failure cleanly on first try",
            },
        )
        self.assertEqual(st, 201, r1)
        self.assertEqual(r1["comparison"]["verdict"], "still_failing")

        st, _, r2 = self.admin.json(
            "POST",
            f"/api/v1/repro-cases/{case_id}/runs",
            {
                "status": "failed",
                "exit_code": 2,
                "revision": "fix-wip-1",
                "observed_output": f"TypeError: tax must be Decimal (leaked={secrets_list[0]})",
            },
        )
        self.assertEqual(st, 201, r2)
        self.assertEqual(r2["comparison"]["verdict"], "changed_failure")
        self.assertNotIn(secrets_list[0], json.dumps(r2))

        st, _, r3 = self.admin.json(
            "POST",
            f"/api/v1/repro-cases/{case_id}/runs",
            {
                "status": "passed",
                "exit_code": 0,
                "revision": "fix-final-42",
                "command_used": "pytest -q tests/test_billing.py",
                "observed_output": "1 passed in 0.11s",
                "notes": "Verified fix manually after rounding Decimal fix",
            },
        )
        self.assertEqual(st, 201, r3)
        self.assertEqual(r3["comparison"]["verdict"], "fixed")
        self.assertTrue(r3["comparison"]["exit_code_changed"])
        self.assertTrue(r3["comparison"]["revision_changed"])
        self.assertTrue(r3["comparison"]["diff_lines"])

        # Never automatically executed shell payload from logs!
        self.assertFalse(pwn_marker.exists(), "Shell command from log telemetry MUST NEVER be executed")
        self.assertFalse(Path(str(pwn_marker) + ".sub").exists(), "Command substitution from log telemetry MUST NEVER run")

        # Audit hash chain remains valid and includes repro actions
        st, _, audit_ok = self.admin.json("GET", "/api/v1/audit/verify")
        self.assertEqual(st, 200)
        self.assertTrue(audit_ok["ok"], audit_ok)
        st, _, audit_rows = self.admin.json("GET", "/api/v1/audit")
        actions = {a["action"] for a in audit_rows["audit"]}
        self.assertIn("repro_case_create", actions)
        self.assertIn("repro_run_record", actions)

    def test_protected_command_suppresses_output_even_in_repro_case(self):
        tok = self._create_token("host-prot")
        st, _, ev = self.admin.json(
            "POST",
            "/api/v1/ingest/event",
            {
                "host_id": "host-prot",
                "harness": "codex",
                "agent_name": "env-agent",
                "event_type": "command_failed",
                "severity": "ERROR",
                "message": "Reading env file failed",
                "metadata": {
                    "session": "codex:prot",
                    "command": "cat .env && printenv",
                    "observed_output": "SUPER_SECRET_DB_URL=postgres://u:p@host/db",
                    "exit_code": 1,
                },
            },
            headers={"Authorization": f"Bearer {tok}"},
        )
        self.assertEqual(st, 200, ev)
        st, _, case = self.admin.json("POST", "/api/v1/repro-cases", {"source_event_id": ev["event_id"]})
        self.assertEqual(st, 201, case)
        self.assertIsNone(case["observed_output"])
        self.assertEqual(case["context"]["output_suppressed_reason"], "protected_command")

    def test_rbac_csrf_and_multitenant_isolation(self):
        ingest_tok = self._create_token("host-sec", "ingest")
        read_tok = self._create_token("reader-sec", "read")

        # Seed failed event in Org A
        st, _, ev_a = self.admin.json(
            "POST",
            "/api/v1/ingest/event",
            {
                "host_id": "host-sec",
                "harness": "codex",
                "agent_name": "sec-agent",
                "event_type": "test_failed",
                "severity": "ERROR",
                "message": "Org A failure",
                "metadata": {"session": "codex:orga-fail", "exit_code": 1},
            },
            headers={"Authorization": f"Bearer {ingest_tok}"},
        )
        self.assertEqual(st, 200)

        st, _, case_a = self.admin.json("POST", "/api/v1/repro-cases", {"source_event_id": ev_a["event_id"]})
        self.assertEqual(st, 201)
        case_id = case_a["id"]

        viewer = self._invite_user("rc.viewer", "ViewerPass!2026", "viewer")
        operator = self._invite_user("rc.operator", "OperatorPass!2026", "operator")
        anon = HttpClient(self.srv.base_url)

        # 1) Anonymous denied everywhere
        for method, path in (
            ("GET", "/api/v1/repro-cases"),
            ("GET", f"/api/v1/repro-cases/{case_id}"),
            ("GET", f"/api/v1/repro-cases/{case_id}/export?format=json"),
            ("POST", "/api/v1/repro-cases"),
            ("POST", f"/api/v1/repro-cases/{case_id}/runs"),
        ):
            st, _, _ = anon.json(method, path, {} if method == "POST" else None)
            self.assertEqual(st, 401, (method, path, st))

        # 2) Ingest token denied on operator endpoints
        st, _, _ = anon.json("GET", "/api/v1/repro-cases", headers={"Authorization": f"Bearer {ingest_tok}"})
        self.assertEqual(st, 401)
        st, _, _ = anon.json("POST", "/api/v1/repro-cases", {"source_event_id": ev_a["event_id"]}, headers={"Authorization": f"Bearer {ingest_tok}"})
        self.assertEqual(st, 401)

        # 3) Read token can GET list, detail, export, CANNOT POST
        read_hdr = {"Authorization": f"Bearer {read_tok}"}
        st, _, r_ov = anon.json("GET", "/api/v1/repro-cases", headers=read_hdr)
        self.assertEqual(st, 200)
        self.assertFalse(r_ov["can_write"])
        st, _, _ = anon.json("GET", f"/api/v1/repro-cases/{case_id}", headers=read_hdr)
        self.assertEqual(st, 200)
        st, _, _ = anon.request("GET", f"/api/v1/repro-cases/{case_id}/export?format=markdown", headers=read_hdr)
        self.assertEqual(st, 200)
        st, _, _ = anon.json("POST", "/api/v1/repro-cases", {"source_event_id": ev_a["event_id"]}, headers=read_hdr)
        self.assertEqual(st, 403)
        st, _, _ = anon.json("POST", f"/api/v1/repro-cases/{case_id}/runs", {"status": "passed"}, headers=read_hdr)
        self.assertEqual(st, 403)

        # 4) Viewer role: GET allowed (can_write=False), POST forbidden (403)
        st, _, v_ov = viewer.json("GET", "/api/v1/repro-cases")
        self.assertEqual(st, 200)
        self.assertFalse(v_ov["can_write"])
        st, _, _ = viewer.json("GET", f"/api/v1/repro-cases/{case_id}")
        self.assertEqual(st, 200)
        st, _, _ = viewer.json("POST", "/api/v1/repro-cases", {"source_event_id": ev_a["event_id"]})
        self.assertEqual(st, 403)
        st, _, _ = viewer.json("POST", f"/api/v1/repro-cases/{case_id}/runs", {"status": "passed"})
        self.assertEqual(st, 403)

        # 5) Operator role: POST create and POST run allowed (201)
        st, _, op_ov = operator.json("GET", "/api/v1/repro-cases")
        self.assertEqual(st, 200)
        self.assertTrue(op_ov["can_write"])
        st, _, op_run = operator.json("POST", f"/api/v1/repro-cases/{case_id}/runs", {"status": "passed", "exit_code": 0})
        self.assertEqual(st, 201, op_run)

        # 6) CSRF Origin mismatch rejected (403)
        st, _, _ = self.admin.json(
            "POST",
            f"/api/v1/repro-cases/{case_id}/runs",
            {"status": "passed"},
            headers={"Origin": "https://evil.example.invalid"},
        )
        self.assertEqual(st, 403)

        # 7) Multi-tenant isolation with Org B
        org_b = HttpClient(self.srv.base_url)
        st, _, reg_b = org_b.json("POST", "/api/v1/auth/register", {"username": ORG_B[0], "password": ORG_B[1], "organization": ORG_B[2]})
        self.assertEqual(st, 201, reg_b)

        st, _, b_ov = org_b.json("GET", "/api/v1/repro-cases")
        self.assertEqual(st, 200)
        self.assertEqual(b_ov["failed_sessions"], [])
        self.assertEqual(b_ov["cases"], [])

        # Cross-tenant IDs return 404
        st, _, _ = org_b.json("GET", f"/api/v1/repro-cases/{case_id}")
        self.assertEqual(st, 404)
        st, _, _ = org_b.request("GET", f"/api/v1/repro-cases/{case_id}/export?format=json")
        self.assertEqual(st, 404)
        st, _, _ = org_b.json("POST", "/api/v1/repro-cases", {"source_event_id": ev_a["event_id"]})
        self.assertEqual(st, 404)
        st, _, _ = org_b.json("POST", f"/api/v1/repro-cases/{case_id}/runs", {"status": "passed"})
        self.assertEqual(st, 404)

        # Stale/mismatched organization_id returns 409
        st, _, _ = org_b.json("GET", f"/api/v1/repro-cases?organization_id={case_a['organization']}")
        self.assertEqual(st, 409)
        st, _, _ = org_b.json(
            "POST",
            "/api/v1/repro-cases",
            {"source_event_id": ev_a["event_id"], "organization_id": case_a["organization"]},
        )
        self.assertEqual(st, 409)

    def test_csp_and_static_assets(self):
        js = (ROOT_DIR / "frontend/repro-cases.js").read_text(encoding="utf-8")
        css = (ROOT_DIR / "frontend/repro-cases.css").read_text(encoding="utf-8")
        inline_handler = re.compile(r"\bon(?:click|change|submit|input|keydown|keyup|load|error|focus|blur)\s*=", re.I)
        self.assertIsNone(inline_handler.search(js))
        for text in (js, css):
            self.assertNotIn("http://", text)
            self.assertNotIn("https://", text)
        for asset in ("/repro-cases.js", "/repro-cases.css"):
            st, _, _ = self.admin.request("GET", asset)
            self.assertEqual(st, 200, asset)


class ReproCasesBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chrome = bc.find_browser()
        cls.tmp = tempfile.TemporaryDirectory(prefix="ns-rc-browser-")
        cls.srv = SpawnedConsole(Path(cls.tmp.name))
        cls.admin = HttpClient(cls.srv.base_url)
        st, _, _ = cls.admin.json("POST", "/api/v1/auth/login", {"username": ORG_A[0], "password": ORG_A[1]})
        assert st == 200

        st, _, tok = cls.admin.json("POST", "/api/v1/tokens", {"name": "rc-host-1", "scope": "ingest"})
        assert st == 201
        hdr = {"Authorization": f"Bearer {tok['token']}"}
        st, _, _ = cls.admin.json("POST", "/api/v1/ingest/heartbeat", _heartbeat("rc-host-1", "runner-west"), headers=hdr)
        assert st == 200

        sec = "sk-proj-" + "BrowserSecretTest999888777"
        xss = '<img src=x onerror="window.__rc_xss=1">'
        fail_step = {
            "tool": "exec_command",
            "category": "shell",
            "label": "Run checkout tests",
            "program": "pytest",
            "status": "failed",
            "time": _iso_offset(30),
            "files": ["tests/test_checkout.py", ".env"],
            "command_input": f"pytest -q tests/test_checkout.py --api-key={sec}",
            "command_output": f"FAILED test_total {xss}\nsecret={sec}",
            "exit_code": 1,
        }
        st, _, body = cls.admin.json(
            "POST",
            "/api/v1/ingest/activity",
            {
                "host_id": "rc-host-1",
                "activity_enabled": True,
                "activity_roots": ["/work/shop"],
                "sessions": [
                    {
                        "session_id": "codex:checkout-fail",
                        "harness": "codex",
                        "agent_name": "shop-bot",
                        "workspace": "/work/shop",
                        "steps": [fail_step],
                        "capture_steps": [fail_step],
                    }
                ],
            },
            headers=hdr,
        )
        assert st in (200, 201), body

        # Viewer user for UI RBAC verification
        st, _, inv = cls.admin.json("POST", "/api/v1/invitations", {"username": "rc.ui.viewer", "role": "viewer"})
        assert st == 201
        cls.viewer_pw = "ViewerUI!2026"
        vc = HttpClient(cls.srv.base_url)
        st, _, _ = vc.json(
            "POST",
            "/api/v1/auth/accept-invitation",
            {"token": inv["token"], "username": "rc.ui.viewer", "password": cls.viewer_pw},
        )
        assert st == 200

        # Org B for UI isolation verification
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

    def _login(self, page, user: str, pw: str):
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

    def test_convert_export_preview_run_compare_xss_mobile_viewer_and_org_isolation(self):
        b = bc.Browser(self.chrome)
        try:
            # 1) Desktop 1440x900 as Admin: convert -> preview redacted bundle -> record run -> compare
            p = b.new_page(1440, 900)
            self._login(p, ORG_A[0], ORG_A[1])
            p.wait("document.querySelectorAll('#rc-failed-list .rc-failed-item').length >= 1", 15)

            # XSS payload rendered as literal text, never executed
            self.assertIsNone(p.eval("window.__rc_xss ?? null"))
            self.assertIn("checkout", p.eval("document.getElementById('rc-failed-list').textContent").lower())

            # Click "Convert to repro case"
            p.click("#rc-failed-list [data-rc-convert]")
            p.wait("Boolean(document.getElementById('rc-convert-form'))", 5)
            p.type("#rc-conv-title", "Checkout tax precision mismatch")
            p.type("#rc-conv-revision", "c0ffee1")
            p.type("#rc-conv-expected", "Checkout total matches cent precision")
            p.click("#rc-conv-submit")

            p.wait("document.querySelectorAll('#rc-cases-list .rc-case-item').length === 1", 10)
            p.wait("Boolean(document.getElementById('rc-detail'))", 5)
            detail_text = p.eval("document.getElementById('rc-detail').textContent")
            self.assertIn("Checkout tax precision mismatch", detail_text)
            self.assertIn("c0ffee1", detail_text)
            self.assertNotIn("BrowserSecretTest999888777", detail_text)
            self.assertIn("<img src=x", detail_text)
            self.assertIsNone(p.eval("window.__rc_xss ?? null"))

            # Preview redacted JSON export inline
            p.click("[data-rc-preview]")
            p.wait("Boolean(document.getElementById('rc-export-preview'))", 5)
            preview_text = p.eval("document.getElementById('rc-export-preview').textContent")
            self.assertIn('"execution_mode": "manual_only"', preview_text)
            self.assertNotIn("BrowserSecretTest999888777", preview_text)

            # Record new passing verification run & verify comparison + diff
            p.click("#rc-toggle-run-form")
            p.wait("Boolean(document.getElementById('rc-run-form'))", 5)
            p.eval("document.getElementById('rc-run-status').value = 'passed'")
            p.type("#rc-run-exit", "0")
            p.type("#rc-run-revision", "c0ffee2")
            p.type("#rc-run-output", "1 passed in 0.09s")
            p.type("#rc-run-notes", "Fixed Decimal rounding in tax calculator")
            p.click("#rc-run-submit")

            p.wait("document.getElementById('rc-compare-verdict')?.textContent.trim().toLowerCase() === 'fixed'", 10)
            comp_text = p.eval("document.getElementById('rc-comparison').textContent")
            self.assertIn("c0ffee1", comp_text)
            self.assertIn("c0ffee2", comp_text)
            self.assertIn("+1 passed in 0.09s", p.eval("document.getElementById('rc-diff-view').textContent"))

            desktop_over = p.overflow()
            self.assertLessEqual(desktop_over["scrollWidth"], 1441, desktop_over)
            self.assertEqual([e for e in p.errors if "/api/v1/auth/me" not in e], [])

            # 2) Mobile 390x844 as Admin: zero horizontal overflow and readable comparison
            pm = b.new_page(390, 844)
            self._login(pm, ORG_A[0], ORG_A[1])
            pm.wait("Boolean(document.getElementById('rc-comparison'))", 15)
            mobile_over = pm.overflow()
            self.assertLessEqual(mobile_over["scrollWidth"], 391, mobile_over)
            self.assertEqual([e for e in pm.errors if "/api/v1/auth/me" not in e], [])

            # 3) Viewer UI: read-only notice visible, convert/record buttons absent
            pv = b.new_page(1440, 900)
            self._login(pv, "rc.ui.viewer", self.viewer_pw)
            pv.wait("Boolean(document.getElementById('rc-readonly-note'))", 15)
            self.assertIsNone(pv.eval("document.querySelector('[data-rc-convert]')"))
            self.assertIsNone(pv.eval("document.getElementById('rc-toggle-run-form')"))
            self.assertEqual([e for e in pv.errors if "/api/v1/auth/me" not in e], [])

            # 4) Org B isolation: sees zero Org A failed sessions or repro cases
            pb = b.new_page(1440, 900)
            self._login(pb, ORG_B[0], ORG_B[1])
            pb.wait("document.getElementById('rc-status-pill').textContent.trim() === 'NONE'", 15)
            org_b_text = pb.eval("document.getElementById('repro-cases').textContent")
            self.assertNotIn("Checkout tax precision mismatch", org_b_text)
            self.assertNotIn("shop-bot", org_b_text)
            self.assertEqual([e for e in pb.errors if "/api/v1/auth/me" not in e], [])
        finally:
            b.close()


if __name__ == "__main__":
    unittest.main()
