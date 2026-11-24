#!/usr/bin/env python3
"""Unit and live ephemeral-server integration tests for NeuroSwarm event emitters."""

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

ROOT = Path(__file__).resolve().parents[2]
INTEGRATIONS_DIR = ROOT / "integrations"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from integrations.client import (  # noqa: E402
    ClientConfig,
    SwarmEventClient,
    detect_rate_limit,
    extract_http_status,
    load_config,
    normalize_error_signature,
    parse_env_file,
    redact_secrets,
)
from server import create_server  # noqa: E402


class ClientUnitTests(unittest.TestCase):
    def test_rate_limit_detection_and_false_positives(self) -> None:
        positives = [
            "HTTP 429 Too Many Requests",
            "Received HTTP/2 429 from api.anthropic.com",
            "status_code=429 retry-after: 12s",
            "Error: rate_limit_error: tokens per minute exceeded",
            "429 Too Many Requests",
            "google.api_core.exceptions.ResourceExhausted: RESOURCE_EXHAUSTED",
        ]
        for text in positives:
            self.assertTrue(detect_rate_limit(text), msg=f"Should detect rate limit: {text}")
            self.assertEqual(extract_http_status(text), 429, msg=f"Should map to 429: {text}")

        negatives = [
            "Batch 42980 completed",
            "429 rows saved",
            "HTTP 4299 custom code",
            "Record 429 delivered successfully",
            "Processed 1429 items in 3.2s",
        ]
        for text in negatives:
            self.assertFalse(detect_rate_limit(text), msg=f"False positive on: {text}")
            self.assertNotEqual(extract_http_status(text), 429, msg=f"False 429 on: {text}")

        self.assertEqual(extract_http_status("Upstream returned HTTP/1.1 503 Service Unavailable"), 503)

    def test_normalize_error_signature_collapses_volatile_tokens(self) -> None:
        a = "2026-11-22T14:01:02.123Z req_id=abc1234567 UUID 550e8400-e29b-41d4-a716-446655440000 retry-after: 12s timeout"
        b = "2026-11-22T14:02:59.999Z req_id=zzz9876543 UUID 11111111-2222-3333-4444-555555555555 retry-after: 45s timeout"
        self.assertEqual(normalize_error_signature(a), normalize_error_signature(b))

    def test_redact_secrets_recursive(self) -> None:
        fake_oa = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz123456"
        fake_gh = "ghp_1234567890abcdefghij1234567890"
        cleaned, found = redact_secrets({"msg": f"key={fake_oa}", "nested": [f"gh={fake_gh}"]})
        self.assertNotIn(fake_oa, json.dumps(cleaned))
        self.assertNotIn(fake_gh, json.dumps(cleaned))
        self.assertEqual(found, ["github_token", "openai_key"])

    def test_env_file_parsing_and_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "agent.env"
            env_path.write_text(
                "# comment\n"
                "SWARMCONTROL_SERVER=http://127.0.0.1:9999/\n"
                "SWARMCONTROL_TOKEN='tok-from-file'\n"
                "SWARMCONTROL_HOST_ID=host-from-file\n",
                encoding="utf-8",
            )
            parsed = parse_env_file(env_path)
            self.assertEqual(parsed["SWARMCONTROL_TOKEN"], "tok-from-file")

            old_env = {k: os.environ.pop(k, None) for k in ("SWARMCONTROL_SERVER", "SWARMCONTROL_TOKEN", "SWARMCONTROL_HOST_ID")}
            try:
                cfg = load_config(env_file=env_path)
                self.assertEqual(cfg.server, "http://127.0.0.1:9999")
                self.assertEqual(cfg.token, "tok-from-file")
                self.assertEqual(cfg.host_id, "host-from-file")

                os.environ["SWARMCONTROL_HOST_ID"] = "host-from-env"
                cfg2 = load_config(env_file=env_path, server="http://127.0.0.1:8888")
                self.assertEqual(cfg2.server, "http://127.0.0.1:8888")
                self.assertEqual(cfg2.host_id, "host-from-env")
            finally:
                for k, v in old_env.items():
                    if v is not None:
                        os.environ[k] = v
                    else:
                        os.environ.pop(k, None)


class LiveServerIntegrationTests(unittest.TestCase):
    """End-to-end tests against an ephemeral NeuroSwarm server (port=0, temp SQLite DB)."""

    def setUp(self) -> None:
        self._prev_quiet = os.environ.get("SWARMCONTROL_QUIET")
        os.environ["SWARMCONTROL_QUIET"] = "1"
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "integrations_test.db")
        self.admin_pass = "test-integrations-pass-456!"
        self.httpd, _ = create_server(
            host="127.0.0.1",
            port=0,
            db_path=self.db_path,
            admin_user="admin",
            admin_pass=self.admin_pass,
            session_secret="test-integrations-session-secret",
        )
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self._login()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.httpd.app_ctx.db.close()  # type: ignore[attr-defined]
        self.tmpdir.cleanup()
        if self._prev_quiet is None:
            os.environ.pop("SWARMCONTROL_QUIET", None)
        else:
            os.environ["SWARMCONTROL_QUIET"] = self._prev_quiet

    def _req(self, method: str, path: str, body: dict | None = None, headers: dict | None = None):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(f"{self.base}{path}", data=data, method=method)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            req.add_header("Origin", self.base)
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

    def _create_token(self, name: str) -> dict:
        status, tok = self._req("POST", "/api/v1/tokens", {"name": name})
        self.assertEqual(status, 201)
        return tok

    def _subproc_env(self, token: str, host_id: str, extra: dict[str, str] | None = None) -> dict[str, str]:
        env = os.environ.copy()
        env["SWARMCONTROL_SERVER"] = self.base
        env["SWARMCONTROL_TOKEN"] = token
        env["SWARMCONTROL_HOST_ID"] = host_id
        env["SWARMCONTROL_ENV_FILE"] = str(Path(self.tmpdir.name) / "nonexistent.env")
        if extra:
            env.update(extra)
        return env

    def _run_claude_hook(
        self,
        payload: dict,
        *,
        env: dict[str, str],
        extra_args: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        cmd = [sys.executable, str(INTEGRATIONS_DIR / "claude_code_hook.py"), *(extra_args or [])]
        return subprocess.run(
            cmd,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            env=env,
            timeout=10,
        )

    def _open_alert_codes(self, host_id: str) -> set[str]:
        status, data = self._req("GET", "/api/v1/alerts?status=OPEN")
        self.assertEqual(status, 200)
        return {a["rule_code"] for a in data["alerts"] if a["host_id"] == host_id}

    def test_01_claude_hook_triggers_loop_suspected_despite_volatile_ids(self) -> None:
        tok = self._create_token("claude-loop")
        host_id = "claude-host-loop"
        env = self._subproc_env(tok["token"], host_id)

        for i in range(4):
            payload = {
                "hook_event_name": "PostToolUseFailure",
                "session_id": "sess-loop-001",
                "tool_name": "Edit",
                "error": (
                    f"2026-11-22T14:0{i}:10.000Z req_id=req00000{i} "
                    "File target string not found in backend/app.py"
                ),
            }
            res = self._run_claude_hook(payload, env=env, extra_args=["--strict"])
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            self.assertEqual(res.stdout, "", msg="Claude Code hook must keep stdout clean")

            codes = self._open_alert_codes(host_id)
            if i < 3:
                self.assertNotIn("LOOP_SUSPECTED", codes)
            else:
                self.assertIn("LOOP_SUSPECTED", codes)

        _, evs = self._req("GET", "/api/v1/events")
        host_evs = [e for e in evs["events"] if e["host_id"] == host_id]
        self.assertEqual(len(host_evs), 4)
        self.assertTrue(all(e["metadata"].get("task_id") == "sess-loop-001" for e in host_evs))

    def test_02_claude_hook_task_id_isolation_interrupt_and_recovery(self) -> None:
        tok = self._create_token("claude-scope")
        host_id = "claude-host-scope"
        env = self._subproc_env(tok["token"], host_id)

        def fail(task_id: str) -> None:
            r = self._run_claude_hook(
                {
                    "hook_event_name": "PostToolUseFailure",
                    "session_id": "sess-shared",
                    "task_id": task_id,
                    "tool_name": "Bash",
                    "error": "pytest exited with code 1",
                },
                env=env,
                extra_args=["--strict"],
            )
            self.assertEqual(r.returncode, 0, msg=r.stderr)

        # 3 failures on task-A + 1 on task-B must not cross-contaminate
        for _ in range(3):
            fail("task-A")
        fail("task-B")
        self.assertNotIn("LOOP_SUSPECTED", self._open_alert_codes(host_id))

        # Manual user interrupt on task-A resets streak without firing a loop
        r_int = self._run_claude_hook(
            {
                "hook_event_name": "PostToolUseFailure",
                "session_id": "sess-shared",
                "task_id": "task-A",
                "tool_name": "Bash",
                "is_interrupt": True,
                "error": "Interrupted by user",
            },
            env=env,
            extra_args=["--strict"],
        )
        self.assertEqual(r_int.returncode, 0)
        self.assertNotIn("LOOP_SUSPECTED", self._open_alert_codes(host_id))

        # 3 failures + PostToolUse success on task-A resets streak again
        for _ in range(3):
            fail("task-A")
        r_ok = self._run_claude_hook(
            {
                "hook_event_name": "PostToolUse",
                "session_id": "sess-shared",
                "task_id": "task-A",
                "tool_name": "Bash",
                "tool_response": {"exit_code": 0, "stdout": "all passed"},
            },
            env=env,
            extra_args=["--strict"],
        )
        self.assertEqual(r_ok.returncode, 0)

        # Now 3 failures still quiet, 4th trips LOOP_SUSPECTED
        for _ in range(3):
            fail("task-A")
        self.assertNotIn("LOOP_SUSPECTED", self._open_alert_codes(host_id))
        fail("task-A")
        self.assertIn("LOOP_SUSPECTED", self._open_alert_codes(host_id))

    def test_03_claude_hook_quota_429_burst_and_no_false_positives(self) -> None:
        tok = self._create_token("claude-quota")
        host_id = "claude-host-quota"
        env = self._subproc_env(tok["token"], host_id)

        # Ordinary numbers containing 429 must NOT trip QUOTA_EXHAUSTION_BURST
        for msg in ("Batch 42980 failed validation", "429 rows rejected", "Record 429 missing column"):
            r = self._run_claude_hook(
                {
                    "hook_event_name": "PostToolUseFailure",
                    "session_id": "sess-q1",
                    "tool_name": "Bash",
                    "error": msg,
                },
                env=env,
                extra_args=["--strict"],
            )
            self.assertEqual(r.returncode, 0)
        self.assertNotIn("QUOTA_EXHAUSTION_BURST", self._open_alert_codes(host_id))

        # Now emit 3 genuine rate-limit signals via PostToolUseFailure, PostToolUse error, and Notification
        quota_payloads = [
            {
                "hook_event_name": "PostToolUseFailure",
                "session_id": "sess-q1",
                "tool_name": "WebFetch",
                "error": "HTTP/2 429 Too Many Requests from provider",
            },
            {
                "hook_event_name": "PostToolUse",
                "session_id": "sess-q2",
                "tool_name": "Bash",
                "tool_response": {"is_error": True, "stderr": "Anthropic API rate_limit_error (status_code=429)"},
            },
            {
                "hook_event_name": "Notification",
                "session_id": "sess-q3",
                "notification_type": "rate_limit",
                "message": "Rate limit reached: too many requests",
            },
        ]
        for idx, p in enumerate(quota_payloads):
            r = self._run_claude_hook(p, env=env, extra_args=["--strict"])
            self.assertEqual(r.returncode, 0, msg=r.stderr)
            codes = self._open_alert_codes(host_id)
            if idx < 2:
                self.assertNotIn("QUOTA_EXHAUSTION_BURST", codes)
            else:
                self.assertIn("QUOTA_EXHAUSTION_BURST", codes)

        _, evs = self._req("GET", "/api/v1/events")
        q_evs = [e for e in evs["events"] if e["host_id"] == host_id and e["metadata"].get("http_status") == 429]
        self.assertEqual(len(q_evs), 3)

    def test_04_cli_wrapper_loop_suspected_exit_code_and_recovery(self) -> None:
        tok = self._create_token("cli-loop")
        host_id = "cli-host-loop"
        env = self._subproc_env(tok["token"], host_id)

        for i in range(4):
            child_code = (
                "import sys; "
                f"print('stdout-ok-{i}'); "
                f"print('2026-11-22T15:0{i}:00Z req_id=abcd000{i} fatal: merge conflict', file=sys.stderr); "
                "sys.exit(7)"
            )
            run = subprocess.run(
                [
                    sys.executable,
                    str(INTEGRATIONS_DIR / "cli_wrapper.py"),
                    "--harness",
                    "codex",
                    "--agent-name",
                    "codex-worker-1",
                    "--task-id",
                    "pr-101",
                    "--strict",
                    "--",
                    sys.executable,
                    "-c",
                    child_code,
                ],
                text=True,
                capture_output=True,
                env=env,
                timeout=10,
            )
            self.assertEqual(run.returncode, 7)
            self.assertIn(f"stdout-ok-{i}", run.stdout)
            self.assertIn("fatal: merge conflict", run.stderr)

            codes = self._open_alert_codes(host_id)
            if i < 3:
                self.assertNotIn("LOOP_SUSPECTED", codes)
            else:
                self.assertIn("LOOP_SUSPECTED", codes)

        # Successful command emits success and preserves exit code 0
        ok_run = subprocess.run(
            [
                sys.executable,
                str(INTEGRATIONS_DIR / "cli_wrapper.py"),
                "--harness",
                "codex",
                "--agent-name",
                "codex-worker-1",
                "--task-id",
                "pr-101",
                "--strict",
                "--",
                sys.executable,
                "-c",
                "print('recovered-cleanly')",
            ],
            text=True,
            capture_output=True,
            env=env,
            timeout=10,
        )
        self.assertEqual(ok_run.returncode, 0)
        self.assertIn("recovered-cleanly", ok_run.stdout)

        _, evs = self._req("GET", "/api/v1/events")
        latest = next(e for e in evs["events"] if e["host_id"] == host_id)
        self.assertEqual(latest["event_type"], "success")
        self.assertTrue(latest["metadata"].get("progress"))

    def test_05_cli_wrapper_quota_429_burst_across_and_within_runs(self) -> None:
        # Case A: 3 failing runs emitting HTTP 429
        tok_a = self._create_token("cli-quota-a")
        host_a = "cli-host-quota-a"
        env_a = self._subproc_env(tok_a["token"], host_a)

        for idx in range(3):
            run = subprocess.run(
                [
                    sys.executable,
                    str(INTEGRATIONS_DIR / "cli_wrapper.py"),
                    "--harness",
                    "opencode",
                    "--agent-name",
                    f"worker-{idx}",
                    "--strict",
                    "--",
                    sys.executable,
                    "-c",
                    "import sys; print('Error: HTTP/2 429 Too Many Requests', file=sys.stderr); sys.exit(1)",
                ],
                text=True,
                capture_output=True,
                env=env_a,
                timeout=10,
            )
            self.assertEqual(run.returncode, 1)
        self.assertIn("QUOTA_EXHAUSTION_BURST", self._open_alert_codes(host_a))

        # Case B: Single command that retries internally 3 times on 429 then succeeds
        tok_b = self._create_token("cli-quota-b")
        host_b = "cli-host-quota-b"
        env_b = self._subproc_env(tok_b["token"], host_b)
        retry_script = (
            "import sys\n"
            "for n in range(3):\n"
            "    print(f'attempt {n}: HTTP 429 Too Many Requests, retrying', file=sys.stderr)\n"
            "print('done')\n"
        )
        run_b = subprocess.run(
            [
                sys.executable,
                str(INTEGRATIONS_DIR / "cli_wrapper.py"),
                "--harness",
                "codex",
                "--agent-name",
                "retry-worker",
                "--strict",
                "--",
                sys.executable,
                "-c",
                retry_script,
            ],
            text=True,
            capture_output=True,
            env=env_b,
            timeout=10,
        )
        self.assertEqual(run_b.returncode, 0)
        self.assertIn("done", run_b.stdout)
        self.assertIn("QUOTA_EXHAUSTION_BURST", self._open_alert_codes(host_b))

    def test_06_secret_redaction_before_transmission(self) -> None:
        tok = self._create_token("secret-test")
        host_id = "secret-host-1"
        env = self._subproc_env(tok["token"], host_id)

        fake_ant = "sk-ant-AbCdEfGhIjKlMnOpQrStUvWxYz987654"
        fake_oa = "sk-proj-ZyXwVuTsRqPoNmLkJiHgFeDcBa123456"

        # Via Claude Code hook
        r1 = self._run_claude_hook(
            {
                "hook_event_name": "PostToolUseFailure",
                "session_id": "sess-sec",
                "tool_name": "Bash",
                "error": f"Auth failed with key {fake_ant}",
            },
            env=env,
            extra_args=["--strict"],
        )
        self.assertEqual(r1.returncode, 0)

        # Via CLI wrapper
        r2 = subprocess.run(
            [
                sys.executable,
                str(INTEGRATIONS_DIR / "cli_wrapper.py"),
                "--harness",
                "cli",
                "--agent-name",
                "sec-worker",
                "--strict",
                "--",
                sys.executable,
                "-c",
                f"import sys; print('leaked {fake_oa}', file=sys.stderr); sys.exit(2)",
            ],
            text=True,
            capture_output=True,
            env=env,
            timeout=10,
        )
        self.assertEqual(r2.returncode, 2)

        _, evs = self._req("GET", "/api/v1/events")
        host_evs = [e for e in evs["events"] if e["host_id"] == host_id]
        serialized = json.dumps(host_evs)
        self.assertNotIn(fake_ant, serialized)
        self.assertNotIn(fake_oa, serialized)
        self.assertIn("[REDACTED_LOCAL:anthropic_key]", serialized)
        self.assertIn("[REDACTED_LOCAL:openai_key]", serialized)

    def test_07_fail_open_strict_and_agent_env_file_loading(self) -> None:
        # 1. Fail-open when server is unreachable
        bad_env = self._subproc_env("dummy-token", "offline-host")
        bad_env["SWARMCONTROL_SERVER"] = "http://127.0.0.1:1"
        bad_env["SWARMCONTROL_TIMEOUT"] = "0.3"

        r_hook = self._run_claude_hook(
            {"hook_event_name": "PostToolUseFailure", "tool_name": "Bash", "error": "boom"},
            env=bad_env,
        )
        self.assertEqual(r_hook.returncode, 0)
        self.assertEqual(r_hook.stdout, "")

        r_hook_strict = self._run_claude_hook(
            {"hook_event_name": "PostToolUseFailure", "tool_name": "Bash", "error": "boom"},
            env=bad_env,
            extra_args=["--strict"],
        )
        self.assertNotEqual(r_hook_strict.returncode, 0)

        r_wrap = subprocess.run(
            [
                sys.executable,
                str(INTEGRATIONS_DIR / "cli_wrapper.py"),
                "--",
                sys.executable,
                "-c",
                "import sys; sys.exit(5)",
            ],
            text=True,
            capture_output=True,
            env=bad_env,
            timeout=10,
        )
        self.assertEqual(r_wrap.returncode, 5)

        # 2. Loading credentials purely from agent.env (no token in env or argv)
        tok = self._create_token("env-file-test")
        env_file = Path(self.tmpdir.name) / "agent.env"
        env_file.write_text(
            f"SWARMCONTROL_SERVER={self.base}\n"
            f"SWARMCONTROL_TOKEN={tok['token']}\n"
            f"SWARMCONTROL_HOST_ID=env-file-host\n",
            encoding="utf-8",
        )
        clean_env = os.environ.copy()
        for k in ("SWARMCONTROL_SERVER", "SWARMCONTROL_TOKEN", "SWARMCONTROL_HOST_ID"):
            clean_env.pop(k, None)
        clean_env["SWARMCONTROL_ENV_FILE"] = str(env_file)

        r_env_ok = self._run_claude_hook(
            {"hook_event_name": "PostToolUseFailure", "session_id": "s-env", "tool_name": "Read", "error": "ENOENT"},
            env=clean_env,
            extra_args=["--strict"],
        )
        self.assertEqual(r_env_ok.returncode, 0, msg=r_env_ok.stderr)
        _, evs = self._req("GET", "/api/v1/events")
        self.assertTrue(any(e["host_id"] == "env-file-host" for e in evs["events"]))

    def test_08_print_settings_and_dry_run(self) -> None:
        r_cfg = subprocess.run(
            [sys.executable, str(INTEGRATIONS_DIR / "claude_code_hook.py"), "--print-settings"],
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(r_cfg.returncode, 0)
        parsed = json.loads(r_cfg.stdout)
        self.assertIn("PostToolUseFailure", parsed["hooks"])
        self.assertIn("PostToolUse", parsed["hooks"])

        r_dry = subprocess.run(
            [
                sys.executable,
                str(INTEGRATIONS_DIR / "cli_wrapper.py"),
                "--dry-run",
                "--harness",
                "codex",
                "--",
                sys.executable,
                "-c",
                "print('hello')",
            ],
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(r_dry.returncode, 0)
        self.assertIn("hello", r_dry.stdout)
        dry_events = json.loads(r_dry.stderr)
        self.assertEqual(dry_events[0]["event_type"], "success")

    def test_09_host_bound_token_rejects_mismatched_host_id(self) -> None:
        tok = self._create_token("bound-host-test")
        env_ok = self._subproc_env(tok["token"], "bound-host-1")
        r_bind = self._run_claude_hook(
            {"hook_event_name": "PostToolUseFailure", "session_id": "s-bind", "tool_name": "Read", "error": "ENOENT"},
            env=env_ok,
            extra_args=["--strict"],
        )
        self.assertEqual(r_bind.returncode, 0, msg=r_bind.stderr)

        # Same token with a different host_id must get HTTP 403 from the hardened backend
        env_other = self._subproc_env(tok["token"], "impostor-host")
        r_fail_open = self._run_claude_hook(
            {"hook_event_name": "PostToolUseFailure", "session_id": "s-bind", "tool_name": "Read", "error": "ENOENT"},
            env=env_other,
        )
        self.assertEqual(r_fail_open.returncode, 0)
        self.assertEqual(r_fail_open.stdout, "")

        r_strict = self._run_claude_hook(
            {"hook_event_name": "PostToolUseFailure", "session_id": "s-bind", "tool_name": "Read", "error": "ENOENT"},
            env=env_other,
            extra_args=["--strict"],
        )
        self.assertNotEqual(r_strict.returncode, 0)
        self.assertIn("403", r_strict.stderr)

    def test_10_validation_guardrails_metadata_cap_nan_and_severity(self) -> None:
        tok = self._create_token("validation-safe")
        client = SwarmEventClient(
            ClientConfig(server=self.base, token=tok["token"], host_id="val-safe-host", timeout=5.0)
        )
        big_meta = {
            "task_id": "t-cap",
            "http_status": 429,
            "bad_nan": float("nan"),
            "bad_inf": float("inf"),
            "huge_blob": "x" * 16000,
            **{f"extra_{i}": "y" * 200 for i in range(60)},
        }
        res = client.emit(
            harness="claude-code",
            agent_name="cap-worker",
            event_type="rate_limit",
            severity="BOGUS_LEVEL",
            message="HTTP 429 Too Many Requests",
            metadata=big_meta,
            raise_on_error=True,
        )
        self.assertTrue(res.ok)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.payload["severity"], "INFO")
        self.assertEqual(res.payload["metadata"]["task_id"], "t-cap")
        self.assertEqual(res.payload["metadata"]["http_status"], 429)
        self.assertTrue(res.payload["metadata"]["metadata_truncated"])
        self.assertLessEqual(len(json.dumps(res.payload["metadata"], allow_nan=False).encode("utf-8")), 8192)


if __name__ == "__main__":
    unittest.main(verbosity=2)
