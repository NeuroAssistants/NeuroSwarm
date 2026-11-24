#!/usr/bin/env python3
"""Security & robustness regression tests for NeuroSwarm v0.2 hardening.

Covers: input validation, token<->host binding, login rate limiting, trusted-proxy handling,
server-side logout, security headers, CSRF/Origin checks, installer Host-header injection,
SHA-256 audit chain (incl. migration of v0.1 databases), stale-alert auto-resolution,
event retention and JSON 500 handling. Every test uses an ephemeral server and database.
"""

from __future__ import annotations

import http.client
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from db import Database  # noqa: E402
from server import create_server  # noqa: E402

ADMIN_PASS = "sec-test-pass-4711!"


class ServerHarness(unittest.TestCase):
    env_overrides: dict[str, str] = {}

    def setUp(self) -> None:
        self._saved_env = {k: os.environ.get(k) for k in [*self.env_overrides, "SWARMCONTROL_PUBLIC_URL"]}
        os.environ.pop("SWARMCONTROL_PUBLIC_URL", None)
        os.environ.update(self.env_overrides)
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "sec.db")
        self.httpd, _ = create_server(
            host="127.0.0.1", port=0, db_path=self.db_path, admin_user="admin",
            admin_pass=ADMIN_PASS, session_secret="sec-test-secret",
        )
        self.port = self.httpd.server_address[1]
        self.ctx = self.httpd.app_ctx  # type: ignore[attr-defined]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.cookie = ""

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.ctx.db.close()
        self.tmp.cleanup()
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # -- helpers ---------------------------------------------------------
    def req(self, method: str, path: str, body=None, headers=None, raw: bytes | None = None, cookie=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = dict(headers or {})
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        if cookie and self.cookie:
            hdrs.setdefault("Cookie", self.cookie)
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        payload = resp.read()
        headers_out = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        try:
            parsed = json.loads(payload) if payload else {}
        except ValueError:
            parsed = payload.decode("utf-8", "replace")
        return resp.status, parsed, headers_out

    def login(self, password: str = ADMIN_PASS, headers=None):
        status, body, hdrs = self.req("POST", "/api/v1/auth/login", {"username": "admin", "password": password},
                                      headers=headers, cookie=False)
        if status == 200:
            self.cookie = hdrs["set-cookie"].split(";")[0]
        return status, body, hdrs

    def token(self, name: str = "t") -> dict:
        status, tok, _ = self.req("POST", "/api/v1/tokens", {"name": name})
        self.assertEqual(status, 201)
        return tok

    @staticmethod
    def bearer(tok: dict) -> dict:
        return {"Authorization": f"Bearer {tok['token']}"}

    @staticmethod
    def hb(host_id: str, **extra) -> dict:
        return {"host_id": host_id, "hostname": host_id, "cpu_count": 2, "mem_total_mb": 1000, "mem_used_mb": 100,
                "harnesses": [], "processes": [], **extra}


class InputValidationTests(ServerHarness):
    def setUp(self) -> None:
        super().setUp()
        self.login()
        self.auth = self.bearer(self.token("val"))

    def test_malformed_heartbeats_return_400_not_500(self):
        cases = [
            self.hb("h1", cpu_count="abc"),
            self.hb("h1", processes="not-a-list"),
            self.hb("h1", processes=[1, 2, 3]),
            self.hb("h1", harnesses=[{"id": "x", "cpu_pct": {"nested": 1}}]),
            self.hb("h1", processes=[{"pid": 1, "comm": "x"}] * 201),
            self.hb("bad host id with spaces"),
            self.hb(""),
            {"hostname": "no-host-id"},
        ]
        for body in cases:
            status, resp, _ = self.req("POST", "/api/v1/ingest/heartbeat", body, headers=self.auth)
            self.assertEqual(status, 400, msg=f"{body!r:.120} -> {status} {resp}")
            self.assertIn("error", resp)

    def test_nan_and_infinity_literals_rejected(self):
        for literal in (b"NaN", b"Infinity", b"-Infinity"):
            raw = b'{"host_id":"h1","load_1m":' + literal + b"}"
            status, _, _ = self.req("POST", "/api/v1/ingest/heartbeat", raw=raw,
                                    headers={**self.auth, "Content-Type": "application/json"})
            self.assertEqual(status, 400)

    def test_values_are_clamped_and_unknown_keys_dropped(self):
        body = self.hb("h1", load_1m=-5, cpu_count=10**9, evil_key="x",
                       processes=[{"pid": 7, "comm": "codex\x00\x1b[31m", "cpu_pct": 1e12, "extra": "drop"}])
        status, _, _ = self.req("POST", "/api/v1/ingest/heartbeat", body, headers=self.auth)
        self.assertEqual(status, 200)
        _, hosts, _ = self.req("GET", "/api/v1/hosts")
        h = hosts["hosts"][0]
        self.assertEqual(h["load_1m"], 0.0)
        self.assertEqual(h["cpu_count"], 4096)
        proc = h["processes"][0]
        self.assertNotIn("extra", proc)
        self.assertEqual(proc["comm"], "codex[31m")  # control chars stripped
        self.assertLessEqual(proc["cpu_pct"], 100_000)

    def test_event_metadata_limits(self):
        big = {"blob": "x" * 9000}
        status, _, _ = self.req("POST", "/api/v1/ingest/event",
                                {"host_id": "h1", "event_type": "info", "metadata": big}, headers=self.auth)
        self.assertEqual(status, 400)
        status, _, _ = self.req("POST", "/api/v1/ingest/event",
                                {"host_id": "h1", "event_type": "info", "metadata": ["not", "dict"]}, headers=self.auth)
        self.assertEqual(status, 400)
        status, res, _ = self.req("POST", "/api/v1/ingest/event",
                                  {"host_id": "h1", "event_type": "info", "severity": "<script>", "message": "ok"},
                                  headers=self.auth)
        self.assertEqual(status, 200)
        _, ev, _ = self.req("GET", "/api/v1/events")
        self.assertEqual(ev["events"][0]["severity"], "INFO")

    def test_oversized_and_chunked_bodies(self):
        status, _, _ = self.req("POST", "/api/v1/ingest/heartbeat", raw=b"{}",
                                headers={**self.auth, "Content-Length": str(10 * 1024 * 1024)})
        self.assertEqual(status, 413)
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.putrequest("POST", "/api/v1/ingest/heartbeat")
        conn.putheader("Authorization", self.auth["Authorization"])
        conn.putheader("Transfer-Encoding", "chunked")
        conn.endheaders()
        conn.send(b"2\r\n{}\r\n0\r\n\r\n")
        self.assertEqual(conn.getresponse().status, 411)
        conn.close()

    def test_unexpected_error_returns_json_500(self):
        original = self.ctx.guardrails.evaluate_heartbeat

        def boom(_payload):
            raise RuntimeError("simulated failure")

        self.ctx.guardrails.evaluate_heartbeat = boom
        try:
            import contextlib
            import io

            with contextlib.redirect_stderr(io.StringIO()):
                status, body, _ = self.req("POST", "/api/v1/ingest/heartbeat", self.hb("h1"), headers=self.auth)
        finally:
            self.ctx.guardrails.evaluate_heartbeat = original
        self.assertEqual(status, 500)
        self.assertEqual(body, {"error": "Internal server error"})


class SecretClassificationTests(unittest.TestCase):
    def test_anthropic_keys_are_not_labelled_openai(self):
        from guardrails import redact_secrets

        text, found = redact_secrets("key sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv and sk-proj-AbCdEfGhIjKlMnOpQrStUvWx")
        self.assertEqual(sorted(found), ["anthropic_key", "openai_key"])
        self.assertNotIn("AbCdEf", text)


class TokenHostBindingTests(ServerHarness):
    def test_token_binds_to_first_host_and_blocks_impersonation(self):
        self.login()
        tok_a, tok_b = self.token("a"), self.token("b")
        self.assertEqual(self.req("POST", "/api/v1/ingest/heartbeat", self.hb("host-a"), headers=self.bearer(tok_a))[0], 200)
        # Same token cannot write another host
        self.assertEqual(self.req("POST", "/api/v1/ingest/heartbeat", self.hb("host-b"), headers=self.bearer(tok_a))[0], 403)
        self.assertEqual(self.req("POST", "/api/v1/ingest/event", {"host_id": "host-b"}, headers=self.bearer(tok_a))[0], 403)
        # Another token cannot hijack host-a while tok_a is active
        self.assertEqual(self.req("POST", "/api/v1/ingest/heartbeat", self.hb("host-a"), headers=self.bearer(tok_b))[0], 403)
        _, toks, _ = self.req("GET", "/api/v1/tokens")
        bound = {t["name"]: t["bound_host_id"] for t in toks["tokens"]}
        self.assertEqual(bound, {"a": "host-a", "b": None})
        # Re-enrolment: revoke tok_a, then tok_b may claim host-a
        self.assertEqual(self.req("DELETE", f"/api/v1/tokens/{tok_a['id']}")[0], 200)
        self.assertEqual(self.req("POST", "/api/v1/ingest/heartbeat", self.hb("host-a"), headers=self.bearer(tok_a))[0], 401)
        self.assertEqual(self.req("POST", "/api/v1/ingest/heartbeat", self.hb("host-a"), headers=self.bearer(tok_b))[0], 200)


class LoginRateLimitTests(ServerHarness):
    def test_bruteforce_is_throttled_even_for_correct_password(self):
        for _ in range(5):
            self.assertEqual(self.login("wrong")[0], 401)
        status, body, hdrs = self.login()
        self.assertEqual(status, 429)
        self.assertGreater(body["retry_after"], 0)
        self.assertEqual(hdrs["retry-after"], str(body["retry_after"]))

    def test_success_resets_user_bucket(self):
        for _ in range(4):
            self.login("wrong")
        self.assertEqual(self.login()[0], 200)
        for _ in range(4):
            self.assertEqual(self.login("wrong")[0], 401)

    def test_unknown_user_takes_comparable_time(self):
        t0 = time.perf_counter()
        self.req("POST", "/api/v1/auth/login", {"username": "nobody", "password": "x"}, cookie=False)
        unknown = time.perf_counter() - t0
        t0 = time.perf_counter()
        self.req("POST", "/api/v1/auth/login", {"username": "admin", "password": "x"}, cookie=False)
        known = time.perf_counter() - t0
        self.assertGreater(unknown, known * 0.3)  # PBKDF2 runs for unknown users too


class TrustedProxyDefaultTests(ServerHarness):
    """Loopback is a trusted proxy by default (cloudflared on the same host)."""

    def test_rotating_forwarded_ip_counts_per_client(self):
        for i in range(5):
            self.login("wrong", headers={"CF-Connecting-IP": "203.0.113.7"})
        self.assertEqual(self.login(headers={"CF-Connecting-IP": "203.0.113.7"})[0], 429)
        self.assertEqual(self.login(headers={"CF-Connecting-IP": "198.51.100.9"})[0], 200)


class UntrustedProxyTests(ServerHarness):
    env_overrides = {"SWARMCONTROL_TRUSTED_PROXIES": "10.255.255.254/32"}

    def test_spoofed_forwarded_ip_is_ignored(self):
        for i in range(5):
            self.login("wrong", headers={"CF-Connecting-IP": f"203.0.113.{i}"})
        self.assertEqual(self.login(headers={"CF-Connecting-IP": "198.51.100.9"})[0], 429)

    def test_spoofed_forwarded_proto_does_not_enable_hsts(self):
        _, _, hdrs = self.req("GET", "/health", headers={"X-Forwarded-Proto": "https"})
        self.assertNotIn("strict-transport-security", hdrs)


class SessionAndHeaderTests(ServerHarness):
    def test_logout_revokes_cookie_server_side(self):
        self.login()
        stolen = self.cookie
        status, me, _ = self.req("GET", "/api/v1/auth/me")
        self.assertEqual(status, 200)
        self.assertEqual(set(me["user"]), {"id", "username", "role", "mfa_enabled"})  # no credential or session fields
        self.assertEqual(self.req("POST", "/api/v1/auth/logout", {})[0], 200)
        self.assertEqual(self.req("GET", "/api/v1/overview", headers={"Cookie": stolen}, cookie=False)[0], 401)

    def test_concurrent_sessions_are_independent(self):
        self.login()
        first = self.cookie
        self.login()
        second = self.cookie
        self.assertNotEqual(first, second)
        self.assertEqual(self.req("POST", "/api/v1/auth/logout", {}, headers={"Cookie": first}, cookie=False)[0], 200)
        self.assertEqual(self.req("GET", "/api/v1/overview", headers={"Cookie": first}, cookie=False)[0], 401)
        self.assertEqual(self.req("GET", "/api/v1/overview", headers={"Cookie": second}, cookie=False)[0], 200)

    def test_forged_or_tampered_cookie_rejected(self):
        self.login()
        body, sig = self.cookie.split("=", 1)[1].rsplit(".", 1)
        forged = f"sc_session={body}.{'0' * len(sig)}"
        self.assertEqual(self.req("GET", "/api/v1/overview", headers={"Cookie": forged}, cookie=False)[0], 401)

    def test_security_headers(self):
        _, _, hdrs = self.req("GET", "/")
        self.assertIn("default-src 'self'", hdrs["content-security-policy"])
        self.assertIn("frame-ancestors 'none'", hdrs["content-security-policy"])
        self.assertEqual(hdrs["x-content-type-options"], "nosniff")
        self.assertEqual(hdrs["x-frame-options"], "DENY")
        self.assertNotIn("Python", hdrs.get("server", ""))
        self.login()
        _, _, api_hdrs = self.req("GET", "/api/v1/overview")
        self.assertEqual(api_hdrs["cache-control"], "no-store")

    def test_secure_cookie_and_hsts_behind_trusted_tls_proxy(self):
        _, _, hdrs = self.login(headers={"X-Forwarded-Proto": "https"})
        self.assertIn("Secure", hdrs["set-cookie"])
        self.assertIn("strict-transport-security", hdrs)

    def test_frontend_has_no_inline_script(self):
        _, html, _ = self.req("GET", "/")
        import re

        for tag in re.findall(r"<script[^>]*>", html):
            self.assertIn("src=", tag)


class CsrfOriginTests(ServerHarness):
    def setUp(self) -> None:
        super().setUp()
        self.login()

    def test_cross_origin_mutations_rejected(self):
        evil = {"Origin": "https://evil.example"}
        self.assertEqual(self.req("POST", "/api/v1/tokens", {"name": "x"}, headers=evil)[0], 403)
        self.assertEqual(self.req("POST", "/api/v1/tokens", {"name": "x"},
                                  headers={"Sec-Fetch-Site": "cross-site"})[0], 403)
        # A matching Origin does not override an explicit cross-site fetch marker
        self.assertEqual(self.req("POST", "/api/v1/tokens", {"name": "x"},
                                  headers={"Origin": f"http://127.0.0.1:{self.port}",
                                           "Sec-Fetch-Site": "cross-site"})[0], 403)
        tok = self.token("victim")
        self.assertEqual(self.req("DELETE", f"/api/v1/tokens/{tok['id']}", headers=evil)[0], 403)
        self.assertEqual(self.req("POST", "/api/v1/auth/login", {"username": "admin", "password": ADMIN_PASS},
                                  headers=evil, cookie=False)[0], 403)

    def test_cross_origin_logout_rejected_and_session_kept(self):
        for hdrs in ({"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"},
                     {"Origin": f"https://127.0.0.1:{self.port}"}):  # wrong scheme for a plain-HTTP origin
            self.assertEqual(self.req("POST", "/api/v1/auth/logout", {}, headers=hdrs)[0], 403, hdrs)
        self.assertEqual(self.req("GET", "/api/v1/overview")[0], 200)

    def test_same_origin_mutations_allowed(self):
        same = {"Origin": f"http://127.0.0.1:{self.port}", "Sec-Fetch-Site": "same-origin"}
        self.assertEqual(self.req("POST", "/api/v1/tokens", {"name": "ok"}, headers=same)[0], 201)

    def test_install_command_uses_env_token(self):
        tok = self.token("cmd")
        self.assertIn(f"SWARMCONTROL_TOKEN={tok['token']} bash", tok["install_command"])
        self.assertNotIn("--token", tok["install_command"])


class InstallerTests(ServerHarness):
    def test_host_header_injection_cannot_reach_script(self):
        status, script, _ = self.req("GET", "/install.sh", headers={"Host": 'evil"; touch /tmp/pwned; echo "'})
        self.assertEqual(status, 200)
        self.assertNotIn("pwned", script)
        self.assertIn(f'SERVER_URL="${{SWARMCONTROL_SERVER:-http://127.0.0.1:{self.port}}}"', script)
        check = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_env_token_install_keeps_token_out_of_argv_and_files_private(self):
        self.login()
        tok = self.token("env-install")
        install_dir = Path(self.tmp.name) / "agent-env"
        env = {**os.environ, "SWARMCONTROL_TOKEN": tok["token"]}
        cmd = (f"curl -fsSL 'http://127.0.0.1:{self.port}/install.sh' | "
               f"bash -s -- --host-id env-host --install-dir '{install_dir}' --no-service")
        run = subprocess.run(["bash", "-c", cmd], env=env, text=True, capture_output=True, timeout=60)
        self.assertEqual(run.returncode, 0, msg=run.stdout + run.stderr)
        self.assertEqual(stat.S_IMODE((install_dir / "agent.env").stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(install_dir.stat().st_mode), 0o700)
        self.assertNotIn(tok["token"], run.stdout + run.stderr)
        _, toks, _ = self.req("GET", "/api/v1/tokens")
        self.assertEqual({t["bound_host_id"] for t in toks["tokens"]}, {"env-host"})

    def test_installer_rejects_bad_inputs(self):
        _, script, _ = self.req("GET", "/install.sh")
        for env_extra, args in [({"SWARMCONTROL_TOKEN": "bad token;id"}, []),
                                ({"SWARMCONTROL_TOKEN": "sc_tok_goodtoken"}, ["--interval", "5;id"]),
                                ({"SWARMCONTROL_TOKEN": "sc_tok_goodtoken"}, ["--host-id", "$(id)"]),
                                ({}, [])]:
            env = {k: v for k, v in os.environ.items() if k != "SWARMCONTROL_TOKEN"}
            env.update(env_extra)
            run = subprocess.run(["bash", "-s", "--", *args, "--install-dir", str(Path(self.tmp.name) / "x")],
                                 input=script, env=env, text=True, capture_output=True, timeout=20)
            self.assertEqual(run.returncode, 2, msg=f"{env_extra} {args}: {run.stderr}")


class AuditChainTests(ServerHarness):
    def test_chain_verifies_and_detects_tampering(self):
        self.login()
        tok = self.token("audit")
        self.req("DELETE", f"/api/v1/tokens/{tok['id']}")
        status, res, _ = self.req("GET", "/api/v1/audit/verify")
        self.assertEqual(status, 200)
        self.assertTrue(res["ok"])
        self.assertGreaterEqual(res["entries"], 4)
        self.assertEqual(self.req("GET", "/api/v1/audit/verify", cookie=False)[0], 401)
        # Tamper with history directly in SQLite (simulates an attacker with DB access)
        self.ctx.db.execute("UPDATE audit_log SET actor = 'mallory' WHERE action = 'TOKEN_REVOKED'")
        _, res, _ = self.req("GET", "/api/v1/audit/verify")
        self.assertFalse(res["ok"])
        self.assertIsNotNone(res["broken_at"])
        self.assertIn("head", res)
        self.assertIsNone(res["head"])

    def test_deleted_middle_entry_detected(self):
        self.login()
        self.token("a")
        self.token("b")
        self.ctx.db.execute("DELETE FROM audit_log WHERE id = 2")
        self.assertFalse(self.ctx.db.verify_audit_chain()["ok"])

    def test_concurrent_appends_keep_chain_valid(self):
        def worker(n):
            for i in range(25):
                self.ctx.db.log_audit(f"w{n}", "STRESS", "t", str(i))

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        res = self.ctx.db.verify_audit_chain()
        self.assertTrue(res["ok"], res)


class MigrationTests(unittest.TestCase):
    def test_v01_database_is_upgraded_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.db"
            conn = sqlite3.connect(path)
            conn.executescript(
                """
                CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
                    target TEXT NOT NULL, detail TEXT NOT NULL, created_at REAL NOT NULL);
                CREATE TABLE agent_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
                    token_prefix TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL, created_by TEXT NOT NULL,
                    created_at REAL NOT NULL, last_used_at REAL, revoked_at REAL);
                INSERT INTO audit_log(actor, action, target, detail, created_at) VALUES
                    ('system','USER_BOOTSTRAP','admin','init',1.5), ('admin','LOGIN_OK','auth','in',2.25);
                INSERT INTO agent_tokens(name, token_prefix, token_hash, created_by, created_at)
                    VALUES ('old','sc_tok_x','abc','admin',1.0);
                """
            )
            conn.commit()
            conn.close()
            db = Database(path)
            try:
                self.assertTrue(db.verify_audit_chain()["ok"])
                db.log_audit("admin", "AFTER_UPGRADE", "x", "y")
                res = db.verify_audit_chain()
                self.assertTrue(res["ok"])
                self.assertEqual(res["entries"], 3)
                self.assertIsNone(db.query_one("SELECT bound_host_id FROM agent_tokens")["bound_host_id"])
            finally:
                db.close()
            # Re-opening is idempotent
            Database(path).close()


class LifecycleTests(ServerHarness):
    def test_stale_alert_auto_resolves_on_heartbeat(self):
        self.login()
        auth = self.bearer(self.token("stale"))
        self.req("POST", "/api/v1/ingest/heartbeat", self.hb("stale-host"), headers=auth)
        self.ctx.db.execute("UPDATE hosts SET last_seen_at = ? WHERE host_id = 'stale-host'", (time.time() - 600,))
        _, digest, _ = self.req("GET", "/api/v1/digest")
        self.assertEqual(digest["fleet_status"], "WARNING")
        status, hb, _ = self.req("POST", "/api/v1/ingest/heartbeat", self.hb("stale-host"), headers=auth)
        self.assertEqual(hb["status"], "HEALTHY")
        _, alerts, _ = self.req("GET", "/api/v1/alerts?status=RESOLVED")
        self.assertEqual([a["rule_code"] for a in alerts["alerts"]], ["STALE_HOST_HEARTBEAT"])
        _, digest, _ = self.req("GET", "/api/v1/digest")
        self.assertEqual(digest["fleet_status"], "HEALTHY")

    def test_old_events_are_pruned(self):
        self.login()
        auth = self.bearer(self.token("prune"))
        self.req("POST", "/api/v1/ingest/event", {"host_id": "p", "message": "fresh"}, headers=auth)
        self.ctx.db.execute(
            "INSERT INTO events(host_id, harness, agent_name, event_type, severity, message, metadata_json, created_at)"
            " VALUES ('p','h','a','info','INFO','ancient','{}',?)", (time.time() - 400 * 86400,))
        self.ctx.last_prune = 0.0
        self.req("GET", "/api/v1/overview")
        msgs = [r["message"] for r in self.ctx.db.query_all("SELECT message FROM events")]
        self.assertEqual(msgs, ["fresh"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
