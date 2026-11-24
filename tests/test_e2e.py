#!/usr/bin/env python3
"""End-to-end integration tests for NeuroSwarm MVP (including live VM harness detection)."""

from __future__ import annotations

import http.cookiejar
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "agent"))

from server import create_server  # noqa: E402


class SwarmControlE2ETest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "test.db")
        self.admin_pass = "test-operator-pass-987!"
        self.httpd, _ = create_server(
            host="127.0.0.1",
            port=0,
            db_path=self.db_path,
            admin_user="admin",
            admin_pass=self.admin_pass,
            session_secret="test-session-secret-for-ci",
        )
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.httpd.app_ctx.db.close()  # type: ignore[attr-defined]
        self.tmpdir.cleanup()

    def _req(self, method: str, path: str, body: dict | None = None, headers: dict | None = None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(f"{self.base}{path}", data=data, method=method)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with self.opener.open(req, timeout=8) as r:
                raw = r.read().decode("utf-8", errors="replace")
                ct = r.headers.get("Content-Type", "")
                return r.status, json.loads(raw) if "application/json" in ct else raw
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", errors="replace")
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw

    def _login(self) -> None:
        status, data = self._req("POST", "/api/v1/auth/login", {"username": "admin", "password": self.admin_pass})
        self.assertEqual(status, 200)
        self.assertTrue(data["authenticated"])

    def test_01_auth_and_static_ui(self) -> None:
        status, health = self._req("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(health["status"], "ok")

        status, html = self._req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("NeuroSwarm", html)

        # Unauthenticated operator endpoint must return 401
        status, _ = self._req("GET", "/api/v1/overview")
        self.assertEqual(status, 401)

        # Wrong password rejected
        status, _ = self._req("POST", "/api/v1/auth/login", {"username": "admin", "password": "wrong"})
        self.assertEqual(status, 401)

        # Correct login works
        self._login()
        status, me = self._req("GET", "/api/v1/auth/me")
        self.assertEqual(status, 200)
        self.assertEqual(me["user"]["username"], "admin")

    def test_02_installer_script_and_cloudflare_headers(self) -> None:
        status, script = self._req(
            "GET",
            "/install.sh",
            headers={"Host": "console.example.org", "X-Forwarded-Proto": "https"},
        )
        self.assertEqual(status, 200)
        self.assertIn('SERVER_URL="${SWARMCONTROL_SERVER:-https://console.example.org}"', script)
        # Validate bash syntax of generated installer
        check = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True)
        self.assertEqual(check.returncode, 0, msg=check.stderr)

        # End-to-end live curl | bash installer test into an isolated temp directory (--no-service)
        self._login()
        status, tok = self._req("POST", "/api/v1/tokens", {"name": "curl-install-test"})
        self.assertEqual(status, 201)
        install_dir = Path(self.tmpdir.name) / "agent-install"
        cmd = (
            f"curl -fsSL '{self.base}/install.sh' | "
            f"bash -s -- --token '{tok['token']}' --host-id curl-e2e-host --install-dir '{install_dir}' --no-service"
        )
        run = subprocess.run(["bash", "-c", cmd], text=True, capture_output=True, timeout=15)
        self.assertEqual(run.returncode, 0, msg=f"stdout={run.stdout}\nstderr={run.stderr}")
        self.assertTrue((install_dir / "swarmcontrol_agent.py").is_file())
        self.assertTrue((install_dir / "detector.py").is_file())
        self.assertTrue((install_dir / "agent.env").is_file())
        status, hosts_resp = self._req("GET", "/api/v1/hosts")
        self.assertEqual(status, 200)
        self.assertIn("curl-e2e-host", {h["host_id"] for h in hosts_resp["hosts"]})

    def test_03_live_vm_agent_autodetect_and_heartbeat(self) -> None:
        self._login()
        status, tok = self._req("POST", "/api/v1/tokens", {"name": "live-vm-test"})
        self.assertEqual(status, 201)
        raw_token = tok["token"]

        # Provide a discoverable tool even on a clean runner.
        tool = Path(self.tmpdir.name) / "openbot"
        tool.write_text("#!/bin/sh\nexit 0\n")
        tool.chmod(0o700)
        env = dict(os.environ, PATH=self.tmpdir.name + os.pathsep + os.environ["PATH"])
        run = subprocess.run(
            [
                sys.executable,
                str(ROOT / "agent" / "swarmcontrol_agent.py"),
                "--server",
                self.base,
                "--token",
                raw_token,
                "--once",
            ],
            env=env,
            text=True,
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(run.returncode, 0, msg=f"stdout={run.stdout} stderr={run.stderr}")
        resp = json.loads(run.stdout)
        self.assertTrue(resp["ok"])

        status, hosts_resp = self._req("GET", "/api/v1/hosts")
        self.assertEqual(status, 200)
        self.assertEqual(len(hosts_resp["hosts"]), 1)
        host = hosts_resp["hosts"][0]
        harness_ids = {h["id"] for h in host["harnesses"]}
        self.assertIn("openbot", harness_ids)
        self.assertLess(host["scan_duration_ms"], 3000.0)

        # Revoking token must immediately block subsequent heartbeats
        status, _ = self._req("DELETE", f"/api/v1/tokens/{tok['id']}")
        self.assertEqual(status, 200)
        status, _ = self._req(
            "POST",
            "/api/v1/ingest/heartbeat",
            {"host_id": "revoked-host", "hostname": "revoked-host"},
            headers={"Authorization": f"Bearer {raw_token}"},
        )
        self.assertEqual(status, 401)

    def test_04_guardrails_secret_redaction_loops_quota_and_ack(self) -> None:
        self._login()
        _, tok = self._req("POST", "/api/v1/tokens", {"name": "guardrail-sim"})
        hdr = {"Authorization": f"Bearer {tok['token']}"}

        # Synthetic heartbeat triggering RUNAWAY_CPU and PROCESS_STORM
        storm_procs = [
            {"pid": 5000 + i, "user": "openbot", "comm": "codex", "cpu_pct": 92.0 if i == 0 else 4.0, "rss_mb": 210.0, "harness": "codex"}
            for i in range(42)
        ]
        status, hb = self._req(
            "POST",
            "/api/v1/ingest/heartbeat",
            {
                "host_id": "sim-node-1",
                "hostname": "sim-node-1",
                "os_name": "linux",
                "arch": "x86_64",
                "cpu_count": 4,
                "load_1m": 5.2,
                "mem_total_mb": 8192.0,
                "mem_used_mb": 4200.0,
                "agent_rss_mb": 18.4,
                "scan_duration_ms": 22.1,
                "harnesses": [{"id": "codex", "name": "Codex CLI", "status": "running", "process_count": 25, "cpu_pct": 188.0, "rss_mb": 5250.0}],
                "processes": storm_procs,
            },
            headers=hdr,
        )
        self.assertEqual(status, 200)
        codes = {a["rule_code"] for a in hb["alerts_triggered"]}
        self.assertIn("RUNAWAY_CPU", codes)
        self.assertIn("PROCESS_STORM", codes)

        # Secret exposure test: raw key must NEVER appear in stored events
        fake_secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456"
        status, ev_res = self._req(
            "POST",
            "/api/v1/ingest/event",
            {
                "host_id": "sim-node-1",
                "harness": "openclaw",
                "agent_name": "worker-alpha",
                "event_type": "log_warning",
                "severity": "WARNING",
                "message": f"Leaked credential {fake_secret} in stdout",
            },
            headers=hdr,
        )
        self.assertEqual(status, 200)
        self.assertIn("openai_key", ev_res["redacted_patterns"])
        _, events_data = self._req("GET", "/api/v1/events")
        stored_msgs = " ".join(e["message"] for e in events_data["events"])
        self.assertNotIn(fake_secret, stored_msgs)
        self.assertIn("[REDACTED:openai_key]", stored_msgs)

        # Loop detection test (4 identical tool_error events)
        for _ in range(4):
            status, loop_res = self._req(
                "POST",
                "/api/v1/ingest/event",
                {
                    "host_id": "sim-node-1",
                    "harness": "codex",
                    "agent_name": "worker-beta",
                    "event_type": "tool_error",
                    "severity": "WARNING",
                    "message": "Tool edit_file failed: target mismatch",
                },
                headers=hdr,
            )
            self.assertEqual(status, 200)
        self.assertIn("LOOP_SUSPECTED", {a["rule_code"] for a in loop_res["alerts_triggered"]})

        # Quota 429 burst test (3 events)
        for idx in range(3):
            status, q_res = self._req(
                "POST",
                "/api/v1/ingest/event",
                {
                    "host_id": "sim-node-1",
                    "harness": "claude-code",
                    "agent_name": f"worker-{idx}",
                    "event_type": "quota_429",
                    "severity": "WARNING",
                    "message": "HTTP 429 rate limit exceeded",
                },
                headers=hdr,
            )
            self.assertEqual(status, 200)
        self.assertIn("QUOTA_EXHAUSTION_BURST", {a["rule_code"] for a in q_res["alerts_triggered"]})

        # Digest reflects CRITICAL fleet status and open alerts
        status, digest = self._req("GET", "/api/v1/digest")
        self.assertEqual(status, 200)
        self.assertEqual(digest["fleet_status"], "CRITICAL")
        self.assertGreaterEqual(digest["metrics"]["open_alerts"], 5)

        # Acknowledgement clears the unhandled queue; unresolved conditions still affect fleet health.
        _, alerts_data = self._req("GET", "/api/v1/alerts?status=OPEN")
        for a in alerts_data["alerts"]:
            s_ack, ack_res = self._req("POST", f"/api/v1/alerts/{a['id']}/ack", {})
            self.assertEqual(s_ack, 200)
            self.assertTrue(ack_res["ok"])
        _, digest_after = self._req("GET", "/api/v1/digest")
        self.assertEqual(digest_after["metrics"]["open_alerts"], 0)
        self.assertGreater(digest_after["metrics"]["active_incidents"], 0)
        self.assertEqual(digest_after["fleet_status"], "CRITICAL")


if __name__ == "__main__":
    unittest.main(verbosity=2)
