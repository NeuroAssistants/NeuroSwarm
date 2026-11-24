"""Independent black-box acceptance QA suite for the self-hosted console.

Exercises a real spawned server process against disposable state directories with:
- Two isolated organizations (same host_id, separate credentials, sessions, alerts, activity)
- Role-based access control (admin, operator, viewer), invitations, org switching, revocation
- Local TOTP 2FA setup, login challenge, replay rejection, and disable
- Real URL installation (`GET /install.sh` piped to `bash --no-service`) in clean HOME without OpenBot
- Generic non-OpenBot workspaces, local redacted preview (`--preview-activity`), confirmed edits,
  secret & out-of-scope file filtering, and token revocation isolation
- Security headers, HEAD support, invite URL fragment privacy contract, backup/restore of all tenants,
  portability hardcode check, and legacy single-org migration.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import http.client
import http.cookiejar
import json
import os
import re
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _totp_code(secret_b32: str, counter: int) -> str:
    padded = secret_b32.strip().upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code % 1_000_000:06d}"


class HttpClient:
    """Black-box cookie-aware HTTP client against a loopback server."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def request(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> tuple[int, dict[str, str], bytes]:
        hdrs = {"Accept-Encoding": "identity"}
        if headers:
            hdrs.update(headers)
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            hdrs.setdefault("Content-Type", "application/json")
        if method in {"POST", "DELETE", "PUT", "PATCH"}:
            hdrs.setdefault("Origin", self.base_url)
        req = urllib.request.Request(self.base_url + path, data=data, headers=hdrs, method=method)
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                raw = resp.read()
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                if resp_headers.get("content-encoding") == "gzip":
                    raw = gzip.decompress(raw)
                return resp.status, resp_headers, raw
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            resp_headers = {k.lower(): v for k, v in exc.headers.items()}
            if resp_headers.get("content-encoding") == "gzip":
                try:
                    raw = gzip.decompress(raw)
                except OSError:
                    pass
            exc.close()
            return exc.code, resp_headers, raw

    def json(
        self,
        method: str,
        path: str,
        body: dict | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], dict]:
        status, resp_headers, raw = self.request(method, path, body=body, headers=headers)
        parsed = json.loads(raw.decode("utf-8")) if raw else {}
        return status, resp_headers, parsed


class SpawnedConsole:
    """Runs the console as an external OS process against a disposable state directory."""

    def __init__(self, state_dir: Path, extra_env: dict[str, str] | None = None, use_launcher: bool = False) -> None:
        self.state_dir = state_dir
        self.port = _free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.db_path = state_dir / "swarmcontrol.db"
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(state_dir / "server-home"),
            "SWARMCONTROL_HOST": "127.0.0.1",
            "SWARMCONTROL_PORT": str(self.port),
            "SWARMCONTROL_DB": str(self.db_path),
            "SWARMCONTROL_STATE_DIR": str(state_dir),
            "SWARMCONTROL_ADMIN_USER": "bootstrap_admin",
            "SWARMCONTROL_ADMIN_PASS": "BootstrapPass!2026#QA",
            "SWARMCONTROL_SESSION_SECRET": "qa-session-secret-0123456789abcdef",
            "SWARMCONTROL_ACTIVITY_ROOTS": "",
            "SWARMCONTROL_ACTIVITY_ADAPTERS": "",
            "SWARMCONTROL_QUIET": "1",
        }
        (state_dir / "server-home").mkdir(parents=True, exist_ok=True)
        if use_launcher:
            # Let deploy/start_console.py generate session.key and initial-password
            env.pop("SWARMCONTROL_ADMIN_PASS", None)
            env.pop("SWARMCONTROL_SESSION_SECRET", None)
            env.pop("SWARMCONTROL_DB", None)
        if extra_env:
            env.update(extra_env)
        script = ROOT / ("deploy/start_console.py" if use_launcher else "backend/server.py")
        self.proc = subprocess.Popen(
            [sys.executable, str(script)],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._wait_ready()

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 12.0
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                out, err = self.proc.communicate(timeout=2)
                raise RuntimeError(f"Server exited early ({self.proc.returncode}): stdout={out!r} stderr={err!r}")
            try:
                with urllib.request.urlopen(f"{self.base_url}/health", timeout=1.0) as r:
                    if r.status == 200:
                        return
            except Exception:
                time.sleep(0.1)
        self.stop()
        raise TimeoutError(f"Server on {self.base_url} did not become healthy in time")

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=2)
        if self.proc.stdout:
            self.proc.stdout.close()
        if self.proc.stderr:
            self.proc.stderr.close()


def _seed_generic_agent_records(
    home_dir: Path,
    workspace_dir: Path,
    edited_rel: str,
    claude_rel: str,
    secret_dir: Path,
    secret_file_name: str = "salaries.csv",
) -> None:
    """Create synthetic Codex CLI + Claude Code records for a generic non-OpenBot workspace."""
    workspace_dir.mkdir(parents=True, exist_ok=True)
    secret_dir.mkdir(parents=True, exist_ok=True)
    edited_file = workspace_dir / edited_rel
    edited_file.parent.mkdir(parents=True, exist_ok=True)
    edited_file.write_text("def parse_invoice(row):\n    return {'ok': True}\n", encoding="utf-8")

    claude_file = workspace_dir / claude_rel
    claude_file.parent.mkdir(parents=True, exist_ok=True)
    claude_file.write_text("# Generic Workspace\nVerified build notes.\n", encoding="utf-8")

    # Sensitive files that MUST never leak
    (workspace_dir / ".env").write_text("OPENAI_API_KEY=sk-proj-AAAABBBBCCCCDDDDEEEEFFFF1111\n", encoding="utf-8")
    outside_file = secret_dir / secret_file_name
    outside_file.write_text("employee,salary\nalice,120000\n", encoding="utf-8")

    now = time.time()
    iso_now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    # 1) Codex CLI state_5.sqlite + rollout JSONL with confirmed FileChange + secret leakage traps
    codex_dir = home_dir / ".codex"
    codex_dir.mkdir(parents=True, exist_ok=True)
    rollout = codex_dir / f"rollout-{workspace_dir.name}.jsonl"
    codex_records = [
        {
            "timestamp": iso_now,
            "payload": {
                "type": "function_call",
                "name": "update_plan",
                "arguments": json.dumps(
                    {
                        "plan": [
                            {"step": f"Update {edited_rel} parser", "status": "completed"},
                            {"step": "Verify isolation tests", "status": "in_progress"},
                        ]
                    }
                ),
            },
        },
        {
            "timestamp": iso_now,
            "payload": {
                "type": "item_completed",
                "item": {
                    "id": "fc-1",
                    "type": "FileChange",
                    "status": "completed",
                    "changes": {
                        str(edited_file): {"type": "update", "unified_diff": "PRIVATE DIFF BODY"},
                        str(workspace_dir / ".env"): {"type": "update"},
                        str(outside_file): {"type": "update"},
                    },
                },
            },
        },
        {
            "timestamp": iso_now,
            "payload": {
                "type": "item_completed",
                "item": {
                    "id": "cmd-1",
                    "type": "CommandExecution",
                    "cwd": str(workspace_dir),
                    "parsed_cmd": [
                        {"type": "read", "path": ".env"},
                        {"type": "read", "path": str(edited_file)},
                    ],
                },
            },
        },
        {
            "timestamp": iso_now,
            "payload": {
                "type": "agent_message",
                "message": (
                    f"Completed update to {edited_rel}. "
                    "Never leak sk-ant-api03-SECRETTOKEN1234567890abcd or ghp_ABCDEFGHIJKLMNOPQRST123456."
                ),
            },
        },
    ]
    rollout.write_text("\n".join(json.dumps(r) for r in codex_records) + "\n", encoding="utf-8")
    with sqlite3.connect(codex_dir / "state_5.sqlite") as conn:
        conn.execute(
            "CREATE TABLE threads("
            "id TEXT, cwd TEXT, model TEXT, tokens_used INT, updated_at INT, rollout_path TEXT, model_provider TEXT)"
        )
        conn.execute(
            "INSERT INTO threads VALUES(?,?,?,?,?,?,?)",
            (f"codex-{workspace_dir.name}", str(workspace_dir), "gpt-5.4", 4200, int(now), str(rollout), "openai"),
        )

    # 2) Claude Code project JSONL editing claude_rel in same generic workspace
    claude_proj = home_dir / ".claude" / "projects" / f"proj-{workspace_dir.name}"
    claude_proj.mkdir(parents=True, exist_ok=True)
    claude_log = claude_proj / f"session-{workspace_dir.name}.jsonl"
    claude_records = [
        {
            "type": "assistant",
            "cwd": str(workspace_dir),
            "timestamp": iso_now,
            "message": {
                "model": "claude-sonnet-4-5",
                "content": [
                    {
                        "type": "tool_use",
                        "name": "Edit",
                        "input": {"file_path": str(claude_file), "old_string": "a", "new_string": "b"},
                    },
                    {
                        "type": "tool_use",
                        "name": "Read",
                        "input": {"file_path": str(workspace_dir / ".env")},
                    },
                    {
                        "type": "text",
                        "text": f"Updated {claude_rel} documentation cleanly.",
                    },
                ],
            },
        }
    ]
    claude_log.write_text("\n".join(json.dumps(r) for r in claude_records) + "\n", encoding="utf-8")


class ProductAcceptanceBlackBoxTests(unittest.TestCase):
    """Independent end-to-end black-box acceptance suite."""

    def _spawn(self, extra_env: dict[str, str] | None = None, use_launcher: bool = False) -> tuple[SpawnedConsole, Path]:
        tmp = tempfile.TemporaryDirectory(prefix="swarm-qa-")
        self.addCleanup(tmp.cleanup)
        state_dir = Path(tmp.name)
        srv = SpawnedConsole(state_dir, extra_env=extra_env, use_launcher=use_launcher)
        self.addCleanup(srv.stop)
        return srv, state_dir

    def test_01_two_orgs_roles_invitations_org_switch_and_revocation(self):
        srv, _ = self._spawn()
        anon = HttpClient(srv.base_url)

        # Anonymous requests must be denied on every private route
        for path in (
            "/api/v1/auth/me",
            "/api/v1/overview",
            "/api/v1/activity",
            "/api/v1/work-board",
            "/api/v1/work-board?include=activity",
            "/api/v1/hosts",
            "/api/v1/members",
            "/api/v1/invitations",
            "/api/v1/tokens",
            "/api/v1/audit",
            "/api/v1/audit/verify",
        ):
            st, _, _ = anon.request("GET", path)
            self.assertEqual(st, 401, f"Expected 401 for anonymous GET {path}, got {st}")

        alice = HttpClient(srv.base_url)
        bob = HttpClient(srv.base_url)
        carol = HttpClient(srv.base_url)

        # Short password must be rejected
        st, _, _ = alice.json(
            "POST",
            "/api/v1/auth/register",
            {"username": "alice_qa", "password": "short", "organization": "Alpha Labs"},
        )
        self.assertEqual(st, 400)

        # Register two separate organizations
        st, _, reg_a = alice.json(
            "POST",
            "/api/v1/auth/register",
            {"username": "alice_qa", "password": "AliceStrongPass!2026", "organization": "Alpha Labs"},
        )
        self.assertEqual(st, 201, reg_a)
        self.assertEqual(reg_a["user"]["role"], "admin")
        org_a_id = reg_a["organization"]["id"]

        st, _, reg_b = bob.json(
            "POST",
            "/api/v1/auth/register",
            {"username": "bob_qa", "password": "BobStrongPass!2026", "organization": "Beta Systems"},
        )
        self.assertEqual(st, 201, reg_b)
        self.assertEqual(reg_b["user"]["role"], "admin")
        org_b_id = reg_b["organization"]["id"]
        self.assertNotEqual(org_a_id, org_b_id)

        # Alice creates an alert in Org A via an ingest token so operator vs viewer ack can be tested
        st, _, tok_a = alice.json("POST", "/api/v1/tokens", {"name": "alpha-node"})
        self.assertEqual(st, 201, tok_a)
        st, _, _ = anon.json(
            "POST",
            "/api/v1/ingest/heartbeat",
            {
                "host_id": "alpha-alert-box",
                "hostname": "alpha-alert-box",
                "os_name": "linux",
                "arch": "x86_64",
                "cpu_count": 4,
                "load_1m": 0.5,
                "mem_total_mb": 4096,
                "mem_used_mb": 1024,
                "harnesses": [{"id": "codex", "name": "Codex CLI", "status": "running", "process_count": 1}],
                "processes": [
                    {"pid": 999, "user": "dev", "comm": "codex", "cpu_pct": 96.0, "rss_mb": 200.0, "uptime_sec": 300, "harness": "Codex CLI"}
                ],
            },
            headers={"Authorization": f"Bearer {tok_a['token']}"},
        )
        self.assertEqual(st, 200)
        st, _, alerts_a = alice.json("GET", "/api/v1/alerts?status=OPEN")
        self.assertEqual(st, 200)
        self.assertGreaterEqual(len(alerts_a.get("alerts", [])), 1, "Expected runaway CPU alert in Org A")
        alert_id = alerts_a["alerts"][0]["id"]

        # Alice invites Carol as viewer
        st, _, inv_a = alice.json("POST", "/api/v1/invitations", {"username": "carol_qa", "role": "viewer"})
        self.assertEqual(st, 201, inv_a)
        st, _, acc_a = carol.json(
            "POST",
            "/api/v1/auth/accept-invitation",
            {"token": inv_a["token"], "username": "carol_qa", "password": "CarolStrongPass!2026"},
        )
        self.assertEqual(st, 200, acc_a)
        self.assertEqual(acc_a["user"]["role"], "viewer")
        self.assertEqual(acc_a["organization"]["id"], org_a_id)

        # Invitation token must be single-use
        replay_client = HttpClient(srv.base_url)
        st, _, _ = replay_client.json(
            "POST",
            "/api/v1/auth/accept-invitation",
            {"token": inv_a["token"], "username": "carol_qa", "password": "CarolStrongPass!2026"},
        )
        self.assertIn(st, (400, 401, 404, 409))

        # Viewer permissions: read monitoring allowed, audit/admin/ack denied
        st, _, ov_c = carol.json("GET", "/api/v1/overview")
        self.assertEqual(st, 200)
        self.assertEqual(ov_c.get("audit"), [], "Viewer must not receive audit entries in overview")
        for read_path in ("/api/v1/activity", "/api/v1/hosts", "/api/v1/work-board"):
            st, _, _ = carol.json("GET", read_path)
            self.assertEqual(st, 200, f"Viewer should read {read_path}")
        for forbidden_method, forbidden_path, payload in (
            ("GET", "/api/v1/members", None),
            ("GET", "/api/v1/invitations", None),
            ("GET", "/api/v1/tokens", None),
            ("POST", "/api/v1/tokens", {"name": "escalate", "role": "admin"}),
            ("GET", "/api/v1/audit", None),
            ("GET", "/api/v1/audit/verify", None),
            ("POST", f"/api/v1/alerts/{alert_id}/ack", {}),
        ):
            st, _, _ = carol.json(
                forbidden_method,
                forbidden_path,
                payload,
                headers={"X-Organization-Id": str(org_b_id)},
            )
            self.assertEqual(st, 403, f"Viewer must get 403 on {forbidden_method} {forbidden_path}, got {st}")

        # Promote Carol to operator in Org A -> can ack alert, still cannot manage org/audit
        st, _, members_a = alice.json("GET", "/api/v1/members")
        self.assertEqual(st, 200)
        carol_id = next(m["id"] for m in members_a["members"] if m["username"] == "carol_qa")
        alice_id = next(m["id"] for m in members_a["members"] if m["username"] == "alice_qa")
        st, _, _ = alice.json("POST", f"/api/v1/members/{carol_id}/role", {"role": "operator"})
        self.assertEqual(st, 200)

        st, _, _ = carol.json("POST", f"/api/v1/alerts/{alert_id}/ack", {})
        self.assertEqual(st, 200, "Operator must be allowed to acknowledge alerts")
        st, _, _ = carol.json("POST", "/api/v1/tokens", {"name": "op-forbidden"})
        self.assertEqual(st, 403, "Operator must not create tokens")
        st, _, _ = carol.json("GET", "/api/v1/audit")
        self.assertEqual(st, 403, "Operator must not read audit log")

        # Bob invites Carol into Org B as admin -> Carol switches orgs and role follows membership
        st, _, inv_b = bob.json("POST", "/api/v1/invitations", {"username": "carol_qa", "role": "admin"})
        self.assertEqual(st, 201, inv_b)
        st, _, acc_b = carol.json(
            "POST",
            "/api/v1/auth/accept-invitation",
            {"token": inv_b["token"], "username": "carol_qa", "password": "CarolStrongPass!2026"},
        )
        self.assertEqual(st, 200, acc_b)
        self.assertEqual(acc_b["organization"]["id"], org_b_id)
        self.assertEqual(acc_b["user"]["role"], "admin")
        st, _, _ = carol.json("GET", "/api/v1/members")
        self.assertEqual(st, 200, "Carol as Org B admin must read Org B members")

        # Switch back to Org A -> drops back to operator
        st, _, sw = carol.json("POST", "/api/v1/auth/switch", {"organization_id": str(org_a_id)})
        self.assertEqual(st, 200, sw)
        self.assertEqual(sw["organization"]["id"], org_a_id)
        self.assertEqual(sw["user"]["role"], "operator")
        st, _, _ = carol.json("GET", "/api/v1/members")
        self.assertEqual(st, 403)

        # Last-admin protection in Org A
        st, _, _ = alice.json("DELETE", f"/api/v1/members/{alice_id}")
        self.assertIn(st, (400, 409), "Last admin deletion must be blocked")

        # Removing Carol from Org A revokes her active Org A session immediately
        st, _, _ = alice.json("DELETE", f"/api/v1/members/{carol_id}")
        self.assertEqual(st, 200)
        st, _, _ = carol.json("GET", "/api/v1/auth/me")
        self.assertEqual(st, 401, "Removed member's active org session must be revoked immediately")

    def test_02_local_2fa_enrollment_challenge_and_replay_rejection(self):
        srv, _ = self._spawn()
        client = HttpClient(srv.base_url)
        st, _, reg = client.json(
            "POST",
            "/api/v1/auth/register",
            {"username": "mfa_admin", "password": "MfaStrongPass!2026", "organization": "MFA Corp"},
        )
        self.assertEqual(st, 201, reg)
        self.assertFalse(reg["user"]["mfa_enabled"])

        st, _, setup = client.json("POST", "/api/v1/auth/2fa/setup", {"password": "MfaStrongPass!2026"})
        self.assertEqual(st, 200, setup)
        secret = setup["secret"]
        self.assertIn("otpauth://totp/", setup["otpauth_uri"])

        step = int(time.time() // 30)
        code_now = _totp_code(secret, step)
        st, _, confirmed = client.json(
            "POST", "/api/v1/auth/2fa/confirm", {"password": "MfaStrongPass!2026", "otp": code_now}
        )
        self.assertEqual(st, 200, confirmed)
        self.assertTrue(confirmed["user"]["mfa_enabled"])

        # Logout and verify login requires MFA
        st, _, _ = client.json("POST", "/api/v1/auth/logout", {})
        self.assertEqual(st, 200)
        st, _, no_otp = client.json(
            "POST", "/api/v1/auth/login", {"username": "mfa_admin", "password": "MfaStrongPass!2026"}
        )
        self.assertEqual(st, 401)
        self.assertEqual(no_otp.get("code"), "mfa_required")

        # Reusing the exact code already consumed by 2fa/confirm must be rejected
        st, _, _ = client.json(
            "POST",
            "/api/v1/auth/login",
            {"username": "mfa_admin", "password": "MfaStrongPass!2026", "otp": code_now},
        )
        self.assertEqual(st, 401, "Replayed TOTP code must be rejected")

        # Valid next counter within +/-1 clock offset succeeds
        code_next = _totp_code(secret, step + 1)
        st, _, logged_in = client.json(
            "POST",
            "/api/v1/auth/login",
            {"username": "mfa_admin", "password": "MfaStrongPass!2026", "otp": code_next},
        )
        self.assertEqual(st, 200, logged_in)
        self.assertTrue(logged_in["user"]["mfa_enabled"])

    def test_03_url_install_no_openbot_generic_workspace_preview_and_two_org_same_host_isolation(self):
        srv, state_dir = self._spawn()
        org_a = HttpClient(srv.base_url)
        org_b = HttpClient(srv.base_url)

        st, _, _ = org_a.json(
            "POST",
            "/api/v1/auth/register",
            {"username": "admin_a", "password": "OrgAStrongPass!2026", "organization": "Acme Robotics"},
        )
        self.assertEqual(st, 201)
        st, _, _ = org_b.json(
            "POST",
            "/api/v1/auth/register",
            {"username": "admin_b", "password": "OrgBStrongPass!2026", "organization": "Beta Analytics"},
        )
        self.assertEqual(st, 201)

        # Create ingest + read tokens in Org A and ingest token in Org B
        st, _, tok_a_ingest = org_a.json("POST", "/api/v1/tokens", {"name": "acme-laptop", "scope": "ingest"})
        self.assertEqual(st, 201, tok_a_ingest)
        self.assertIn("/install.sh", tok_a_ingest.get("install_command", ""))

        st, _, tok_a_read = org_a.json("POST", "/api/v1/tokens", {"name": "acme-reader", "scope": "read"})
        self.assertEqual(st, 201, tok_a_read)
        self.assertNotIn("install_command", tok_a_read)

        st, _, tok_b_ingest = org_b.json("POST", "/api/v1/tokens", {"name": "beta-laptop", "scope": "ingest"})
        self.assertEqual(st, 201, tok_b_ingest)

        # Verify read token scope: GET allowed, POST ingest denied
        anon = HttpClient(srv.base_url)
        st, _, _ = anon.json("GET", "/api/v1/activity", headers={"Authorization": f"Bearer {tok_a_read['token']}"})
        self.assertEqual(st, 200, "Read token must allow GET /api/v1/activity")
        st, _, _ = anon.json(
            "POST",
            "/api/v1/ingest/heartbeat",
            {"host_id": "bad-read-write"},
            headers={"Authorization": f"Bearer {tok_a_read['token']}"},
        )
        self.assertIn(st, (401, 403), "Read token must not ingest heartbeats")

        # Verify all public installer & agent download endpoints return 200
        for pub_path in (
            "/install.sh",
            "/install.ps1",
            "/agent/detector.py",
            "/agent/activity_shipper.py",
            "/agent/activity_core.py",
            "/agent/swarmcontrol_agent.py",
        ):
            st, _, raw = anon.request("GET", pub_path)
            self.assertEqual(st, 200, f"Public route {pub_path} returned {st}")
            self.assertGreater(len(raw), 100)

        # Download real /install.sh from server URL and execute it in a clean isolated HOME (ZERO OpenBot!)
        st, _, install_script_bytes = anon.request("GET", "/install.sh")
        self.assertEqual(st, 200)
        install_script = install_script_bytes.decode("utf-8")

        shared_host_id = "shared-dev-box-01"

        # --- Host A (Org A): clean HOME without OpenBot ---
        home_a = state_dir / "clean-home-a"
        install_dir_a = state_dir / "installed-agent-a"
        home_a.mkdir(parents=True, exist_ok=True)
        env_a = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(home_a),
            "SWARMCONTROL_TOKEN": tok_a_ingest["token"],
            "SWARMCONTROL_HOST_ID": shared_host_id,
            "SWARMCONTROL_INSTALL_DIR": str(install_dir_a),
        }
        proc_a = subprocess.run(
            ["bash", "-s", "--", "--no-service"],
            input=install_script,
            text=True,
            capture_output=True,
            env=env_a,
            timeout=25,
        )
        self.assertEqual(proc_a.returncode, 0, f"URL install failed:\nSTDOUT:\n{proc_a.stdout}\nSTDERR:\n{proc_a.stderr}")
        self.assertTrue((install_dir_a / "swarmcontrol_agent.py").is_file())
        self.assertTrue((install_dir_a / "activity_core.py").is_file())
        self.assertEqual(os.stat(install_dir_a / "agent.env").st_mode & 0o777, 0o600)

        # Health-only check (no folders selected yet): Org A sees host, 0 sessions; Org B sees 0 hosts
        st, _, hosts_a = org_a.json("GET", "/api/v1/hosts")
        self.assertEqual(st, 200)
        self.assertEqual([h["host_id"] for h in hosts_a["hosts"]], [shared_host_id])
        st, _, act_a0 = org_a.json("GET", "/api/v1/activity")
        self.assertEqual(st, 200)
        self.assertEqual(act_a0["sessions"], [])

        st, _, hosts_b0 = org_b.json("GET", "/api/v1/hosts")
        self.assertEqual(st, 200)
        self.assertEqual(hosts_b0["hosts"], [], "Org B must not see Org A's enrolled host")

        # Seed generic workspace for Org A (with confirmed edits + secrets + out-of-scope private folder)
        ws_a = home_a / "repos" / "acme-billing"
        priv_a = home_a / "private-hr"
        _seed_generic_agent_records(home_a, ws_a, "src/invoice_parser.py", "README.md", priv_a)

        # Run local preview BEFORE shipping (zero network) and verify redaction & scope
        prev_proc = subprocess.run(
            [
                sys.executable,
                str(install_dir_a / "swarmcontrol_agent.py"),
                "--preview-activity",
                "--host-id",
                shared_host_id,
                "--activity-roots",
                str(ws_a),
            ],
            env={"PATH": env_a["PATH"], "HOME": str(home_a)},
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(prev_proc.returncode, 0, prev_proc.stderr)
        preview = json.loads(prev_proc.stdout)
        preview_blob = json.dumps(preview)
        self.assertTrue(preview.get("activity_enabled", True))
        self.assertGreaterEqual(len(preview.get("sessions", [])), 2, f"Expected Codex + Claude sessions in preview: {preview}")
        self.assertIn("invoice_parser.py", preview_blob)
        self.assertIn("README.md", preview_blob)
        for forbidden in (
            ".env",
            "salaries.csv",
            "private-hr",
            "sk-proj-AAAABBBB",
            "sk-ant-api03-SECRET",
            "ghp_ABCDEFGHIJ",
            "PRIVATE DIFF BODY",
            "example-workspace",
            "/srv/example-private",
        ):
            self.assertNotIn(forbidden, preview_blob, f"Sensitive/coupled string leaked in preview: {forbidden}")

        # Ship Org A activity via the installed observer
        ship_a = subprocess.run(
            [
                sys.executable,
                str(install_dir_a / "swarmcontrol_agent.py"),
                "--server",
                srv.base_url,
                "--host-id",
                shared_host_id,
                "--activity-roots",
                str(ws_a),
                "--once",
            ],
            env=env_a,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(ship_a.returncode, 0, f"Org A ship failed:\n{ship_a.stdout}\n{ship_a.stderr}")

        # --- Host B (Org B): SAME host_id, different generic workspace, clean HOME without OpenBot ---
        home_b = state_dir / "clean-home-b"
        install_dir_b = state_dir / "installed-agent-b"
        ws_b = home_b / "repos" / "beta-search"
        priv_b = home_b / "private-legal"
        _seed_generic_agent_records(home_b, ws_b, "core/ranker.py", "NOTES.md", priv_b, secret_file_name="merger.txt")

        env_b = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(home_b),
            "SWARMCONTROL_TOKEN": tok_b_ingest["token"],
            "SWARMCONTROL_HOST_ID": shared_host_id,
            "SWARMCONTROL_ACTIVITY_ROOTS": str(ws_b),
            "SWARMCONTROL_INSTALL_DIR": str(install_dir_b),
        }
        proc_b = subprocess.run(
            ["bash", "-s", "--", "--no-service"],
            input=install_script,
            text=True,
            capture_output=True,
            env=env_b,
            timeout=25,
        )
        self.assertEqual(proc_b.returncode, 0, f"Org B URL install failed:\n{proc_b.stdout}\n{proc_b.stderr}")

        # Verify Org A sees ONLY acme-billing (with gzip + confirmed edit + latest_work) and ZERO Beta data
        st, hdrs_a, act_a = org_a.json("GET", "/api/v1/activity", headers={"Accept-Encoding": "gzip"})
        self.assertEqual(st, 200)
        blob_a = json.dumps(act_a)
        self.assertIn("acme-billing", blob_a)
        self.assertIn("invoice_parser.py", blob_a)
        self.assertNotIn("beta-search", blob_a, "Org A leaked Org B workspace!")
        self.assertNotIn("ranker.py", blob_a, "Org A leaked Org B file!")
        for secret_tok in (".env", "salaries.csv", "private-hr", "sk-ant-api03", "sk-proj-", "ghp_"):
            self.assertNotIn(secret_tok, blob_a, f"Org A activity leaked secret/private path: {secret_tok}")

        codex_a = [s for s in act_a["sessions"] if s.get("harness") == "codex"]
        self.assertEqual(len(codex_a), 1)
        self.assertTrue(any("invoice_parser.py" in p for p in codex_a[0].get("files_edited", [])))
        self.assertTrue(codex_a[0].get("latest_work"), "Expected latest_work field on remote Codex session")
        edit_steps = [st_i for st_i in codex_a[0].get("steps", []) if st_i.get("files")]
        self.assertTrue(any(st_i.get("file_basis") == "confirmed" for st_i in edit_steps))

        # Verify Org B sees ONLY beta-search and ZERO Acme data
        st, _, act_b = org_b.json("GET", "/api/v1/activity", headers={"Accept-Encoding": "gzip"})
        self.assertEqual(st, 200)
        blob_b = json.dumps(act_b)
        self.assertIn("beta-search", blob_b)
        self.assertIn("ranker.py", blob_b)
        self.assertNotIn("acme-billing", blob_b, "Org B leaked Org A workspace!")
        self.assertNotIn("invoice_parser.py", blob_b, "Org B leaked Org A file!")
        self.assertNotIn("merger.txt", blob_b)

        # Verify work-board?include=activity also isolates both tenants cleanly
        st, _, wb_a = org_a.json("GET", "/api/v1/work-board?include=activity")
        self.assertEqual(st, 200)
        self.assertIn("acme-billing", json.dumps(wb_a.get("activity", {})))
        self.assertNotIn("beta-search", json.dumps(wb_a.get("activity", {})))

        # Revoke Org A token -> Org A agent rejected, Org B agent with SAME host_id still accepted
        st, _, _ = org_a.json("DELETE", f"/api/v1/tokens/{tok_a_ingest['id']}")
        self.assertEqual(st, 200)
        revoked_run = subprocess.run(
            [
                sys.executable,
                str(install_dir_a / "swarmcontrol_agent.py"),
                "--server",
                srv.base_url,
                "--host-id",
                shared_host_id,
                "--once",
            ],
            env=env_a,
            capture_output=True,
            text=True,
            timeout=15,
        )
        # Heartbeat failure returns non-zero or logs 401; check direct POST as well
        st_rev, _, _ = anon.json(
            "POST",
            "/api/v1/ingest/heartbeat",
            {"host_id": shared_host_id, "harnesses": [], "processes": []},
            headers={"Authorization": f"Bearer {tok_a_ingest['token']}"},
        )
        self.assertEqual(st_rev, 401)
        st_b_ok, _, _ = anon.json(
            "POST",
            "/api/v1/ingest/heartbeat",
            {"host_id": shared_host_id, "harnesses": [], "processes": []},
            headers={"Authorization": f"Bearer {tok_b_ingest['token']}"},
        )
        self.assertEqual(st_b_ok, 200, "Revoking Org A token must not break Org B token for the same host_id")
        _ = revoked_run  # exercised above

    def test_04_security_headers_head_assets_and_invite_fragment_contract(self):
        srv, _ = self._spawn()
        c = HttpClient(srv.base_url)

        st, hdrs, body = c.request("HEAD", "/")
        self.assertEqual(st, 200)
        self.assertEqual(body, b"")
        self.assertEqual(hdrs.get("x-frame-options", "").upper(), "DENY")
        self.assertEqual(hdrs.get("x-content-type-options"), "nosniff")
        self.assertIn("script-src 'self'", hdrs.get("content-security-policy", ""))
        self.assertIn("no-store", hdrs.get("cache-control", ""))

        st, _, html_raw = c.request("GET", "/")
        self.assertEqual(st, 200)
        html = html_raw.decode("utf-8")
        # All 4 frontend assets must be version-hashed and served 200
        for asset in ("styles.css", "activity-product.css", "app.js", "activity.js"):
            m = re.search(rf"/{re.escape(asset)}\?v=([0-9a-f]{{12}})", html)
            self.assertIsNotNone(m, f"Expected content-hashed /{asset}?v=<hash> in index.html")
            st_a, _, raw_a = c.request("GET", m.group(0))
            self.assertEqual(st_a, 200, f"Asset {m.group(0)} returned {st_a}")
            self.assertGreater(len(raw_a), 200)

        # AUTH-CONTRACT.md: browser invite handoff must use URL fragment /#invite=<token>, never /?invite=<token>
        app_js = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
        self.assertNotIn(
            "/?invite=",
            app_js,
            "BLOCKER: frontend/app.js generates query-string '/?invite=' instead of fragment '/#invite=' (leaks token to proxies/logs)",
        )

    def test_05_backup_and_restore_preserves_both_organizations(self):
        # Start via deploy/start_console.py (real self-hosted launcher)
        srv, state_dir = self._spawn(use_launcher=True)
        org1 = HttpClient(srv.base_url)
        org2 = HttpClient(srv.base_url)

        initial_pw = (state_dir / "initial-password").read_text(encoding="utf-8").strip()
        st, _, login1 = org1.json("POST", "/api/v1/auth/login", {"username": "bootstrap_admin", "password": initial_pw})
        self.assertEqual(st, 200, login1)
        st, _, tok1 = org1.json("POST", "/api/v1/tokens", {"name": "org1-node"})
        self.assertEqual(st, 201)

        st, _, reg2 = org2.json(
            "POST",
            "/api/v1/auth/register",
            {"username": "org2_admin", "password": "Org2StrongPass!2026", "organization": "Second Org"},
        )
        self.assertEqual(st, 201, reg2)
        st, _, tok2 = org2.json("POST", "/api/v1/tokens", {"name": "org2-node"})
        self.assertEqual(st, 201)

        anon = HttpClient(srv.base_url)
        for tok, hid in ((tok1["token"], "org1-host"), (tok2["token"], "org2-host")):
            st, _, _ = anon.json(
                "POST",
                "/api/v1/ingest/heartbeat",
                {"host_id": hid, "hostname": hid, "harnesses": [], "processes": []},
                headers={"Authorization": f"Bearer {tok}"},
            )
            self.assertEqual(st, 200)

        # Quiesce server, take backup snapshot, restore into clean directory, restart on restored dir
        srv.stop()
        with tempfile.TemporaryDirectory(prefix="swarm-backup-") as btmp:
            backup_root = Path(btmp) / "backups"
            restore_dir = Path(btmp) / "restored-state"
            snap_res = subprocess.run(
                [sys.executable, str(ROOT / "deploy/backup.py"), "snapshot", str(state_dir), str(backup_root)],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(snap_res.returncode, 0, snap_res.stderr)
            snap_dir = Path(snap_res.stdout.strip().splitlines()[-1])

            rest_res = subprocess.run(
                [sys.executable, str(ROOT / "deploy/backup.py"), "restore", str(snap_dir), str(restore_dir)],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(rest_res.returncode, 0, rest_res.stderr)

            # Verify restored instance still has BOTH Org 1 and Org 2 hosts
            restored_srv = SpawnedConsole(restore_dir, use_launcher=True)
            self.addCleanup(restored_srv.stop)
            r1 = HttpClient(restored_srv.base_url)
            r2 = HttpClient(restored_srv.base_url)
            st, _, _ = r1.json("POST", "/api/v1/auth/login", {"username": "bootstrap_admin", "password": initial_pw})
            self.assertEqual(st, 200)
            st, _, h1 = r1.json("GET", "/api/v1/hosts")
            self.assertEqual([h["host_id"] for h in h1["hosts"]], ["org1-host"])

            st, _, _ = r2.json("POST", "/api/v1/auth/login", {"username": "org2_admin", "password": "Org2StrongPass!2026"})
            self.assertEqual(st, 200)
            st, _, h2 = r2.json("GET", "/api/v1/hosts")
            self.assertEqual(
                [h["host_id"] for h in h2["hosts"]],
                ["org2-host"],
                "BLOCKER: deploy/backup.py lost non-default tenant database (*.sqlite3 under swarmcontrol.db.tenants/)",
            )

    def test_06_portability_no_team_or_private_domain_hardcodes(self):
        forbidden_patterns = [
            (r"example-workspace", "team workspace name"),
            (r"agent-10000001|agent-10000002|agent-10000004|agent-10000005|agent-10000006|agent-10000003", "team UUID"),
            (r"/srv/example-private", "OpenBot server path"),
            (r"invalid\.private\.", "private domain reverse-DNS identifier"),
        ]
        scan_files = [
            *sorted((ROOT / "backend").glob("*.py")),
            *sorted((ROOT / "frontend").glob("*")),
            *sorted((ROOT / "agent").glob("*.py")),
            ROOT / "install.sh",
            ROOT / "install.ps1",
        ]
        hits = []
        for fp in scan_files:
            if not fp.is_file():
                continue
            text = fp.read_text(encoding="utf-8", errors="ignore")
            for lineno, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith('"""') or stripped.startswith("3. Zero hardcoded"):
                    continue
                for pat, desc in forbidden_patterns:
                    if re.search(pat, line):
                        hits.append(f"{fp.relative_to(ROOT)}:{lineno} ({desc}): {stripped[:100]}")
        self.assertEqual(hits, [], "Portability leaks found in core runtime/installer files:\n" + "\n".join(hits))

    def test_07_legacy_single_org_migration_preserves_user_history_and_token(self):
        tmp = tempfile.TemporaryDirectory(prefix="swarm-legacy-")
        self.addCleanup(tmp.cleanup)
        state_dir = Path(tmp.name)
        db_path = state_dir / "swarmcontrol.db"

        # Build an authentic pre-multitenant v0.1 SQLite DB (no organizations/memberships tables)
        salt = os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", b"LegacyAdmin!2026", salt, 120_000)
        pw_hash = f"pbkdf2_sha256$120000${salt.hex()}${dk.hex()}"
        raw_token = "sc_tok_LegacyToken1234567890abcdef12345"  # 32 chars after sc_tok_ (token_urlsafe(24))
        tok_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        now = time.time() - 60

        with sqlite3.connect(db_path) as conn:
            conn.executescript(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'admin',
                    created_at REAL NOT NULL
                );
                CREATE TABLE agent_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    token_hash TEXT UNIQUE NOT NULL,
                    token_prefix TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    last_used_at REAL,
                    revoked_at REAL,
                    bound_host_id TEXT
                );
                CREATE TABLE hosts (
                    host_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    os_name TEXT,
                    arch TEXT,
                    agent_version TEXT,
                    cpu_count INTEGER DEFAULT 1,
                    load_1m REAL DEFAULT 0,
                    mem_total_mb REAL DEFAULT 0,
                    mem_used_mb REAL DEFAULT 0,
                    agent_rss_mb REAL DEFAULT 0,
                    scan_duration_ms REAL DEFAULT 0,
                    harnesses_json TEXT DEFAULT '[]',
                    processes_json TEXT DEFAULT '[]',
                    status TEXT DEFAULT 'HEALTHY',
                    first_seen_at REAL NOT NULL,
                    last_seen_at REAL NOT NULL,
                    ip_hint TEXT
                );
                CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id TEXT NOT NULL,
                    harness TEXT,
                    agent_name TEXT,
                    event_type TEXT NOT NULL,
                    severity TEXT DEFAULT 'INFO',
                    message TEXT NOT NULL,
                    metadata_json TEXT DEFAULT '{}',
                    created_at REAL NOT NULL
                );
                CREATE TABLE alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id TEXT NOT NULL,
                    rule_code TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    evidence_json TEXT DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    acked_by TEXT,
                    acked_at REAL
                );
                CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    prev_hash TEXT,
                    entry_hash TEXT
                );
                """
            )
            conn.execute("INSERT INTO users(username, password_hash, role, created_at) VALUES (?,?,?,?)", ("legacy_ops", pw_hash, "admin", now))
            conn.execute(
                "INSERT INTO agent_tokens(name, token_hash, token_prefix, created_by, created_at, bound_host_id) VALUES (?,?,?,?,?,?)",
                ("legacy-box", tok_hash, raw_token[:14], "legacy_ops", now, "legacy-host-01"),
            )
            conn.execute(
                "INSERT INTO hosts(host_id, hostname, os_name, arch, agent_version, first_seen_at, last_seen_at) VALUES (?,?,?,?,?,?,?)",
                ("legacy-host-01", "legacy-host-01", "linux", "x86_64", "0.1.0", now, now),
            )
            conn.execute(
                "INSERT INTO events(host_id, harness, agent_name, event_type, severity, message, created_at) VALUES (?,?,?,?,?,?,?)",
                ("legacy-host-01", "codex", "worker", "work_done", "INFO", "Legacy migrated milestone", now),
            )

        # Boot the server against the legacy DB
        srv = SpawnedConsole(state_dir)
        self.addCleanup(srv.stop)
        client = HttpClient(srv.base_url)

        st, _, login = client.json("POST", "/api/v1/auth/login", {"username": "legacy_ops", "password": "LegacyAdmin!2026"})
        self.assertEqual(st, 200, login)
        self.assertEqual(login["user"]["role"], "admin")

        st, _, hosts = client.json("GET", "/api/v1/hosts")
        self.assertEqual(st, 200)
        self.assertIn("legacy-host-01", [h["host_id"] for h in hosts["hosts"]])

        st, _, evs = client.json("GET", "/api/v1/events")
        self.assertEqual(st, 200)
        self.assertIn("Legacy migrated milestone", json.dumps(evs))

        st, _, ver = client.json("GET", "/api/v1/audit/verify")
        self.assertEqual(st, 200)
        self.assertTrue(ver.get("ok"), ver)

        # Legacy observer token still ingests heartbeats for its bound host
        anon = HttpClient(srv.base_url)
        st, _, _ = anon.json(
            "POST",
            "/api/v1/ingest/heartbeat",
            {"host_id": "legacy-host-01", "hostname": "legacy-host-01", "harnesses": [], "processes": []},
            headers={"Authorization": f"Bearer {raw_token}"},
        )
        self.assertEqual(st, 200, "Legacy observer token must remain functional after migration")

    def test_08_privacy_codex_read_outside_roots_does_not_leak_filename(self):
        """Regression/blocker check: Codex CommandExecution read outside opted-in roots must not leak basename in label."""
        with tempfile.TemporaryDirectory(prefix="swarm-qa-priv-") as td:
            home = Path(td) / "home"
            ws = home / "repos" / "acme-billing"
            priv = home / "private-hr"
            ws.mkdir(parents=True)
            priv.mkdir(parents=True)
            outside = priv / "salaries.csv"
            outside.write_text("alice,120000\n", encoding="utf-8")
            codex_dir = home / ".codex"
            codex_dir.mkdir(parents=True)
            rollout = codex_dir / "rollout-priv.jsonl"
            now = time.time()
            iso_now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
            rollout.write_text(
                json.dumps(
                    {
                        "timestamp": iso_now,
                        "payload": {
                            "type": "item_completed",
                            "item": {
                                "id": "cmd-priv",
                                "type": "CommandExecution",
                                "cwd": str(ws),
                                "parsed_cmd": [{"type": "read", "path": str(outside)}],
                            },
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with sqlite3.connect(codex_dir / "state_5.sqlite") as conn:
                conn.execute(
                    "CREATE TABLE threads("
                    "id TEXT, cwd TEXT, model TEXT, tokens_used INT, updated_at INT, rollout_path TEXT, model_provider TEXT)"
                )
                conn.execute(
                    "INSERT INTO threads VALUES(?,?,?,?,?,?,?)",
                    ("codex-priv", str(ws), "gpt-5.4", 100, int(now), str(rollout), "openai"),
                )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "agent/swarmcontrol_agent.py"),
                    "--preview-activity",
                    "--host-id",
                    "priv-check-host",
                    "--activity-roots",
                    str(ws),
                ],
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home)},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn(
                "salaries.csv",
                proc.stdout,
                "BLOCKER: Codex CommandExecution read outside activity_roots leaked private filename 'salaries.csv' into step/latest_work label",
            )


if __name__ == "__main__":
    unittest.main()
