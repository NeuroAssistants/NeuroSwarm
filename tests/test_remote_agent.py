"""Tests for cross-platform detector, opt-in folder activity shipper, remote ingestion & installers.

See REMOTE-CONTRACT.md for the observer protocol.
Verifies:
1. Cross-platform detector parsers (Linux, WSL, macOS vm_stat/ps/launchctl, Windows tasklist/ctypes).
2. Opt-in privacy by default (None when no activity roots configured).
3. Folder-scoped activity collection on two external generic folders (`equipo-demo` and `cliente-alfa`)
   outside OpenBot without hardcoded team UUIDs.
4. Local 14-pattern secret redaction and sensitive file exclusion before network transmission.
5. Tenant-scoped `ingest_remote_activity` and `build_tenant_activity_map` isolation across two databases.
6. Shell (`install.sh`) and PowerShell (`install.ps1`) installer rendering and live `--from-repo --no-service` execution.
"""

from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "agent"), str(ROOT / "backend")]

import activity_shipper  # noqa: E402
import detector  # noqa: E402
import event_feed  # noqa: E402
import installer  # noqa: E402
import live_history  # noqa: E402
import remote_activity  # noqa: E402
import swarmcontrol_agent  # noqa: E402
from db import Database  # noqa: E402


class CrossPlatformDetectorTests(unittest.TestCase):
    def test_macos_memory_and_etime_parsers(self):
        vm_sample = (
            "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n"
            "Pages free:                               10000.\n"
            "Pages active:                             20000.\n"
            "Pages wired down:                         10000.\n"
            "Pages occupied by compressor:              5000.\n"
        )
        with patch("subprocess.check_output", side_effect=["17179869184\n", vm_sample]):
            total_mb, used_mb = detector._read_macos_mem_mb()
            self.assertEqual(total_mb, 16384.0)
            self.assertGreater(used_mb, 500.0)

        self.assertEqual(detector._parse_etime("05:30"), 330)
        self.assertEqual(detector._parse_etime("01:02:03"), 3723)
        self.assertEqual(detector._parse_etime("2-00:00:10"), 172810)

    def test_windows_tasklist_parser(self):
        csv_sample = (
            '"codex.exe","4120","Console","1","84,480 K"\n'
            '"claude.exe","5192","Console","1","102,400 K"\n'
        )
        with patch("subprocess.check_output", return_value=csv_sample):
            procs = detector._list_windows_processes()
            self.assertEqual(len(procs), 2)
            self.assertEqual(procs[0]["comm"], "codex.exe")
            self.assertEqual(procs[0]["pid"], 4120)
            self.assertEqual(procs[0]["rss_mb"], 82.5)

    def test_generic_workspace_label_without_openbot(self):
        root = Path("/home/alice/equipo-demo")
        cwd = Path("/home/alice/equipo-demo/backend")
        self.assertEqual(detector._workspace_label(cwd, root), "equipo-demo/backend")
        self.assertEqual(detector._workspace_label(root, root), "equipo-demo")


class OptInActivityShipperTests(unittest.TestCase):
    def test_opt_in_disabled_by_default(self):
        with patch.dict(os.environ, {"SWARMCONTROL_ACTIVITY_ROOTS": ""}, clear=False):
            self.assertIsNone(activity_shipper.collect_remote_activity_payload(""))

    def test_generic_folders_collection_and_local_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            home = base / "home"
            proj_a = base / "equipo-demo"
            proj_b = base / "cliente-alfa"
            unapproved = base / "private-notes"
            for d in (home, proj_a, proj_b, unapproved):
                d.mkdir(parents=True)

            # Create legitimate files and sensitive files inside proj_a and proj_b
            (proj_a / "parser.py").write_text("print('ok')\n", encoding="utf-8")
            (proj_a / "brand-tokens.css").write_text(":root { --c: #000; }\n", encoding="utf-8")
            (proj_a / ".env").write_text("OPENAI_API_KEY=sk-proj-1234567890abcdefghijklmnop\n", encoding="utf-8")
            (proj_b / "invoice.py").write_text("print('invoice')\n", encoding="utf-8")
            (unapproved / "secret_plan.md").write_text("top secret\n", encoding="utf-8")

            # Create synthetic Codex rollout for proj_a and Claude transcript for proj_b
            codex_sessions_dir = home / ".codex" / "sessions" / "2026" / "11" / "23"
            codex_sessions_dir.mkdir(parents=True)
            rollout_a = codex_sessions_dir / "rollout-2026-11-23T15-00-00-equipodemo01.jsonl"
            rollout_a.write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"cwd": str(proj_a)}}),
                        json.dumps(
                            {
                                "timestamp": "2026-11-23T15:01:00Z",
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "update_plan",
                                    "arguments": json.dumps(
                                        {"plan": [{"step": "Implement parser.py with key sk-ant-api03-1234567890abcdefghij", "status": "completed"}]}
                                    ),
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "timestamp": "2026-11-23T15:02:00Z",
                                "type": "event_msg",
                                "payload": {
                                    "type": "patch_apply_end",
                                    "changes": {str(proj_a / "parser.py"): {"type": "update"}},
                                },
                            }
                        ),
                        json.dumps(
                            {
                                "timestamp": "2026-11-23T15:03:00Z",
                                "type": "response_item",
                                "payload": {
                                    "type": "message",
                                    "role": "assistant",
                                    "content": [{"text": "Finished parser.py using token sc_live_secretToken123456789 and password=supersecretvalue"}],
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            claude_proj_dir = home / ".claude" / "projects" / "cliente-alfa"
            claude_proj_dir.mkdir(parents=True)
            claude_b = claude_proj_dir / "session-alfa-01.jsonl"
            claude_b.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "timestamp": "2026-11-23T15:04:00Z",
                                "cwd": str(proj_b),
                                "type": "assistant",
                                "message": {
                                    "model": "claude-sonnet-4-20250514",
                                    "content": [
                                        {
                                            "type": "tool_use",
                                            "name": "Edit",
                                            "input": {"file_path": str(proj_b / "invoice.py")},
                                        },
                                        {
                                            "type": "text",
                                            "text": "- [x] Updated invoice.py for cliente-alfa",
                                        },
                                    ],
                                },
                            }
                        )
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            payload = activity_shipper.collect_remote_activity_payload(
                raw_roots=[str(proj_a), str(proj_b)],
                host_id="external-node-01",
                home_dir=home,
            )
            self.assertIsNotNone(payload)
            assert payload is not None
            raw_json = json.dumps(payload)

            # 1. Verify secrets and .env are completely absent
            self.assertNotIn("sk-ant-api03", raw_json)
            self.assertNotIn("sc_live_secretToken", raw_json)
            self.assertNotIn("supersecretvalue", raw_json)
            self.assertNotIn(".env", raw_json)
            self.assertNotIn("private-notes", raw_json)

            # 2. Verify brand-tokens.css was NOT falsely hidden
            self.assertIn("brand-tokens.css", raw_json)

            # 3. Verify both external folders and sessions were captured without OpenBot UUIDs
            ws_labels = {w["label"] for w in payload["workspaces"]}
            self.assertEqual(ws_labels, {"equipo-demo", "cliente-alfa"})
            agent_names = {s["agent_name"] for s in payload["sessions"]}
            self.assertEqual(agent_names, {"equipo-demo", "cliente-alfa"})

            # 4. Verify tenant ingestion and multi-tenant isolation in remote_activity.py
            db_tenant_1 = Database(":memory:")
            db_tenant_2 = Database(":memory:")
            try:
                res = remote_activity.ingest_remote_activity(db_tenant_1, payload)
                self.assertTrue(res["ok"])
                self.assertEqual(res["sessions_ingested"], 2)

                map_t1 = remote_activity.build_tenant_activity_map(db_tenant_1)
                map_t2 = remote_activity.build_tenant_activity_map(db_tenant_2)

                self.assertEqual(map_t1["summary"]["sessions"], 2)
                self.assertEqual(map_t1["summary"]["workspaces"], 2)
                self.assertEqual(map_t2["summary"]["sessions"], 0)
                self.assertEqual(map_t2["summary"]["workspaces"], 0)
            finally:
                db_tenant_1.close()
                db_tenant_2.close()

    def test_v1_1_commands_claude_launch_owner_and_cli_redaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            home = base / "home"
            proj_a = base / "equipo-demo"
            proj_b = base / "cliente-alfa"
            for d in (home, proj_a, proj_b):
                d.mkdir(parents=True)

            now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            codex_dir = home / ".codex" / "sessions" / "2026" / "11" / "23"
            codex_dir.mkdir(parents=True)
            (codex_dir / "rollout-cmd-test01.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps({"type": "session_meta", "payload": {"cwd": str(proj_a)}}),
                        json.dumps(
                            {
                                "timestamp": now_iso,
                                "type": "response_item",
                                "payload": {
                                    "type": "function_call",
                                    "name": "exec_command",
                                    "arguments": json.dumps({"cmd": f"cd {proj_a} && python3 -m unittest discover -k secret"}),
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            claude_dir = home / ".claude" / "projects" / "cliente-alfa"
            claude_dir.mkdir(parents=True)
            pad_line = json.dumps({"type": "user", "cwd": str(proj_b), "message": {"role": "user", "content": "x" * 1024}})
            (claude_dir / "session-moved-01.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps({"timestamp": now_iso, "cwd": str(proj_b), "type": "user", "message": {"role": "user", "content": "start"}}),
                        *([pad_line] * 140),
                        json.dumps(
                            {
                                "timestamp": now_iso,
                                "cwd": str(proj_a),
                                "type": "assistant",
                                "message": {
                                    "model": "claude-sonnet-4-20250514",
                                    "content": [
                                        {
                                            "type": "tool_use",
                                            "name": "Bash",
                                            "input": {"command": "sudo -n git diff --password=topsecret -u alice:s3cr3t .env"},
                                        }
                                    ],
                                },
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            with patch.dict(os.environ, {"SWARMCONTROL_SHARE_COMMANDS": "0"}, clear=False):
                off_payload = activity_shipper.collect_remote_activity_payload(
                    raw_roots=[str(proj_a), str(proj_b)],
                    host_id="v11-node",
                    home_dir=home,
                )
            assert off_payload is not None
            by_harness = {s["harness"]: s for s in off_payload["sessions"]}
            self.assertEqual(by_harness["codex"]["steps"][0]["program"], "python3")
            self.assertNotIn("command", by_harness["codex"]["steps"][0])

            claude_sess = by_harness["claude-code"]
            self.assertEqual(claude_sess["agent_name"], "cliente-alfa")
            self.assertEqual(claude_sess["workspace"], str(proj_b))
            self.assertEqual(claude_sess["current_folder"], str(proj_a))
            self.assertEqual(claude_sess["steps"][0]["program"], "git")
            self.assertNotIn("command", claude_sess["steps"][0])

            with patch.dict(os.environ, {"SWARMCONTROL_SHARE_COMMANDS": "1"}, clear=False):
                on_payload = activity_shipper.collect_remote_activity_payload(
                    raw_roots=[str(proj_a), str(proj_b)],
                    host_id="v11-node",
                    home_dir=home,
                )
            assert on_payload is not None
            on_claude = next(s for s in on_payload["sessions"] if s["harness"] == "claude-code")
            cmd_text = on_claude["steps"][0].get("command", "")
            self.assertTrue(cmd_text)
            self.assertLessEqual(len(cmd_text), 160)
            self.assertIn("[protected file]", cmd_text)
            for leaked in ("topsecret", "s3cr3t", ".env"):
                self.assertNotIn(leaked, cmd_text)

    def test_remote_activity_persists_observed_steps_for_feed_history_and_correlation(self):
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        t1 = (now_dt - datetime.timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        t2 = (now_dt - datetime.timedelta(seconds=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
        t3 = (now_dt - datetime.timedelta(seconds=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        payload = {
            "schema_version": "1.0",
            "host_id": "remote-worker-01",
            "hostname": "remote-worker-01",
            "activity_roots": ["/home/dev/equipo-demo", "/home/dev/cliente-alfa"],
            "sessions": [
                {
                    "session_id": "codex:sess-remote-1",
                    "harness": "codex",
                    "harness_name": "Codex CLI",
                    "agent_id": "equipo-demo",
                    "agent_name": "equipo-demo",
                    "workspace": "/home/dev/equipo-demo",
                    "current_folder": "/home/dev/cliente-alfa",
                    "updated_at": now_dt.timestamp(),
                    "status": "active",
                    "steps": [
                        {
                            "tool": "apply_patch",
                            "category": "file_edit",
                            "label": "SECRET_USER_PROMPT_TEXT",
                            "time": t1,
                            "status": "completed",
                            "file_basis": "confirmed",
                            "files": [
                                "/home/dev/equipo-demo/parser.py",
                                "/home/dev/cliente-alfa/billing.py",
                                "/home/dev/private-hr/salaries.csv",
                                "/home/dev/equipo-demo/.env",
                            ],
                        },
                        {
                            "tool": "exec_command",
                            "category": "shell_exec",
                            "label": "Run tests",
                            "time": t2,
                            "status": "completed",
                            "program": "python3",
                            "command": "python3 -m unittest discover -k private_marker",
                            "files": [],
                        },
                        {
                            "tool": "exec_command",
                            "category": "shell",
                            "label": "SECRET_FAILED_CMD_TEXT",
                            "time": t3,
                            "status": "error",
                            "program": "pytest",
                            "command": "pytest --token secret123456",
                            "files": [],
                        },
                    ],
                }
            ],
            "workspaces": [],
            "harnesses": [],
        }

        db_t1 = Database(":memory:")
        db_t2 = Database(":memory:")
        try:
            res1 = remote_activity.ingest_remote_activity(db_t1, payload)
            self.assertEqual(res1["steps_persisted"], 3)
            res2 = remote_activity.ingest_remote_activity(db_t1, payload)
            self.assertEqual(res2["steps_persisted"], 0, "Repeated snapshots must not duplicate observed_step rows")

            feed_t1 = event_feed.feed(db_t1)
            self.assertEqual(len(feed_t1["records"]), 3)
            blob = json.dumps(feed_t1)
            self.assertIn("parser.py", blob)
            self.assertIn("cliente-alfa/billing.py", blob)
            for forbidden in ("SECRET_USER_PROMPT_TEXT", "SECRET_FAILED_CMD_TEXT", "salaries.csv", ".env", "private_marker", "secret123456", "/home/dev"):
                self.assertNotIn(forbidden, blob)

            hist = live_history.history(db_t1, 1, {})
            self.assertEqual(len(hist["records"]), 3)
            by_sev = {r["severity"]: r for r in hist["records"]}
            self.assertIn("ERROR", by_sev)
            self.assertEqual(by_sev["ERROR"]["work"]["program"], "pytest")
            self.assertNotIn("command", by_sev["ERROR"]["work"])

            test_row = next(r for r in hist["records"] if r["work"].get("program") == "python3")
            self.assertEqual(test_row["work"]["command"], "python3 -m unittest discover")

            corr = live_history.history(
                db_t1,
                1,
                {
                    "session": ["codex:sess-remote-1"],
                    "host": ["remote-worker-01"],
                    "agent": ["equipo-demo"],
                    "runtime": ["codex"],
                },
            )
            self.assertEqual(len(corr["records"]), 3)
            self.assertEqual(event_feed.feed(db_t2)["records"], [])
            self.assertEqual(live_history.history(db_t2, 2, {})["records"], [])
        finally:
            db_t1.close()
            db_t2.close()


class HeartbeatReceiptTests(unittest.TestCase):
    def test_once_rejects_unconfirmed_host_before_shipping_activity(self):
        import threading

        requests = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append((self.path, payload.get("host_id")))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(receipt)

        receipts = (
            b"", b"null", b'{"ok":true}', b'{"ok":true,"host_id":"other-host"}',
            b'{"ok":false,"host_id":"win-qa"}', b'{"ok":1,"host_id":"win-qa"}',
            b'{"ok":"true","host_id":"win-qa"}',
        )
        with tempfile.TemporaryDirectory() as tmp, ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for receipt in receipts:
                    with self.subTest(receipt=receipt):
                        requests.clear()
                        run = subprocess.run(
                            [sys.executable, str(ROOT / "agent" / "swarmcontrol_agent.py"), "--once",
                             "--server", f"http://127.0.0.1:{server.server_port}", "--host-id", "win-qa",
                             "--activity-roots", tmp, "--state-dir", str(Path(tmp) / "state")],
                            env=dict(os.environ, HOME=tmp, USERPROFILE=tmp, SWARMCONTROL_TOKEN="receipt-test-only"),
                            capture_output=True, text=True, timeout=20,
                        )
                        self.assertEqual(run.returncode, 1, run.stdout)
                        self.assertIn("heartbeat", run.stderr.lower())
                        self.assertEqual(requests, [("/api/v1/ingest/heartbeat", "win-qa")])
            finally:
                server.shutdown()
                thread.join()


class AgentTransitionTests(unittest.TestCase):
    def test_build_harness_transition_events(self):
        prev: dict[str, tuple[str, int]] = {}
        snap1 = {
            "host_id": "node-1",
            "harnesses": [
                {"id": "codex", "name": "Codex CLI", "status": "not_found", "process_count": 0},
                {"id": "claude-code", "name": "Claude Code CLI", "status": "running", "process_count": 2},
            ],
        }
        self.assertEqual(swarmcontrol_agent.build_harness_transition_events(snap1, prev), [])

        snap2 = {
            "host_id": "node-1",
            "harnesses": [
                {"id": "codex", "name": "Codex CLI", "status": "running", "process_count": 1},
                {"id": "claude-code", "name": "Claude Code CLI", "status": "installed", "process_count": 0},
            ],
        }
        evs = swarmcontrol_agent.build_harness_transition_events(snap2, prev)
        self.assertEqual([(e["harness"], e["event_type"]) for e in evs], [("codex", "harness_started"), ("claude-code", "harness_stopped")])
        self.assertEqual(swarmcontrol_agent.build_harness_transition_events(snap2, prev), [])

        # Non-running transitions (not_found -> installed) must not emit harness_stopped
        prev2 = {"opencode": ("not_found", 0)}
        snap3 = {"host_id": "node-1", "harnesses": [{"id": "opencode", "name": "OpenCode", "status": "installed", "process_count": 0}]}
        self.assertEqual(swarmcontrol_agent.build_harness_transition_events(snap3, prev2), [])


class InstallerEndToEndTests(unittest.TestCase):
    def test_shell_and_powershell_installers_and_url_flow(self):
        sh_script = installer.render_install_script("https://console.example.org")
        ps1_script = installer.render_powershell_install_script("https://console.example.org")
        self.assertIn("org.swarmcontrol.agent.plist", sh_script)
        self.assertIn("swarmcontrol-agent.service", sh_script)
        self.assertIn("SWARMCONTROL_ACTIVITY_ROOTS", sh_script)
        self.assertIn("SWARMCONTROL_SHARE_COMMAND_OUTPUT", sh_script)
        self.assertIn("SWARMCONTROL_SHARE_FILE_PREVIEWS", sh_script)
        self.assertIn("Register-ScheduledTask", ps1_script)
        self.assertIn("SWARMCONTROL_ACTIVITY_ROOTS", ps1_script)
        self.assertIn("SWARMCONTROL_SHARE_COMMAND_OUTPUT", ps1_script)
        self.assertIn("SWARMCONTROL_SHARE_FILE_PREVIEWS", ps1_script)
        self.assertIn('$ErrorActionPreference = "Continue"', ps1_script)
        self.assertIn('if ($ActivityRoots)', ps1_script)
        self.assertNotIn('--activity-roots $ActivityRoots', ps1_script)

        # Spin up an ephemeral HTTP server serving /agent/* and /api/v1/ingest/*
        received_heartbeats: list[dict] = []
        received_activities: list[dict] = []

        class MockHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                sources = {
                    "/agent/detector.py": ROOT / "agent" / "detector.py",
                    "/agent/activity_shipper.py": ROOT / "agent" / "activity_shipper.py",
                    "/agent/activity_core.py": ROOT / "backend" / "activity_inspector.py",
                    "/agent/swarmcontrol_agent.py": ROOT / "agent" / "swarmcontrol_agent.py",
                }
                src = sources.get(self.path)
                if src is not None:
                    data = src.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/x-python; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                response = {"ok": True}
                if self.path == "/api/v1/ingest/heartbeat":
                    received_heartbeats.append(body)
                    response["host_id"] = body["host_id"]
                elif self.path == "/api/v1/ingest/activity":
                    received_activities.append(body)
                out = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
        import threading

        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        base_url = f"http://127.0.0.1:{httpd.server_port}"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                install_dir = tmp_path / "installed-agent"
                work_dir = tmp_path / "equipo-demo"
                work_dir.mkdir()
                (work_dir / "main.py").write_text("print('demo')\n", encoding="utf-8")

                script_body = installer.render_install_script(base_url)
                env = dict(
                    os.environ,
                    SWARMCONTROL_TOKEN="sc_tok_testtoken1234567890",
                    SWARMCONTROL_HOST_ID="clean-linux-node",
                    SWARMCONTROL_ACTIVITY_ROOTS=str(work_dir),
                    SWARMCONTROL_INSTALL_DIR=str(install_dir),
                )
                proc = subprocess.run(
                    ["bash", "-s", "--", "--no-service"],
                    input=script_body,
                    text=True,
                    env=env,
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertTrue((install_dir / "activity_core.py").is_file())
                self.assertEqual(len(received_heartbeats), 1)
                self.assertEqual(received_heartbeats[0]["host_id"], "clean-linux-node")
                self.assertEqual(received_heartbeats[0]["capture_reader"], "core")
                self.assertEqual(len(received_activities), 1)
                self.assertEqual(received_activities[0]["host_id"], "clean-linux-node")
                self.assertEqual(received_activities[0]["workspaces"][0]["label"], "equipo-demo")
                default_env = (install_dir / "agent.env").read_text(encoding="utf-8")
                self.assertIn("SWARMCONTROL_SHARE_COMMANDS=0", default_env)
                self.assertIn("SWARMCONTROL_SHARE_COMMAND_OUTPUT=0", default_env)
                self.assertIn("SWARMCONTROL_SHARE_FILE_PREVIEWS=0", default_env)

                # Verify repo install.sh & install.ps1 match rendered installers and persist optional flags
                self.assertEqual((ROOT / "install.sh").read_text(encoding="utf-8"), installer.render_install_script())
                self.assertEqual((ROOT / "install.ps1").read_text(encoding="utf-8"), installer.render_powershell_install_script())

                for bad_var in (
                    {"SWARMCONTROL_SHARE_COMMANDS": "yes"},
                    {"SWARMCONTROL_SHARE_COMMAND_OUTPUT": "yes"},
                    {"SWARMCONTROL_SHARE_FILE_PREVIEWS": "2"},
                ):
                    bad_proc = subprocess.run(
                        ["bash", "-s", "--", "--no-service"],
                        input=script_body,
                        text=True,
                        env={**env, **bad_var},
                        capture_output=True,
                        timeout=10,
                    )
                    self.assertEqual(bad_proc.returncode, 2, bad_var)

                opt_dir = tmp_path / "installed-agent-opts"
                opt_proc = subprocess.run(
                    [
                        "bash",
                        "-s",
                        "--",
                        "--no-service",
                        "--share-commands",
                        "--share-command-output",
                        "--share-file-previews",
                        "--agent-labels",
                        "equipo-demo=Demo Team",
                    ],
                    input=script_body,
                    text=True,
                    env={**env, "SWARMCONTROL_INSTALL_DIR": str(opt_dir)},
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(opt_proc.returncode, 0, opt_proc.stderr)
                agent_env = (opt_dir / "agent.env").read_text(encoding="utf-8")
                self.assertIn("SWARMCONTROL_SHARE_COMMANDS=1", agent_env)
                self.assertIn("SWARMCONTROL_SHARE_COMMAND_OUTPUT=1", agent_env)
                self.assertIn("SWARMCONTROL_SHARE_FILE_PREVIEWS=1", agent_env)
                self.assertIn("SWARMCONTROL_AGENT_LABELS=equipo-demo=Demo Team", agent_env)

                # --diagnose surfaces opt-in sharing booleans without leaking tokens
                diag_env = {
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "HOME": str(tmp_path),
                    "SWARMCONTROL_SHARE_COMMANDS": "1",
                    "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "1",
                    "SWARMCONTROL_SHARE_FILE_PREVIEWS": "1",
                }
                diag_proc = subprocess.run(
                    [sys.executable, str(opt_dir / "swarmcontrol_agent.py"), "--diagnose", "--activity-roots", str(work_dir)],
                    env=diag_env,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                self.assertEqual(diag_proc.returncode, 0, diag_proc.stderr)
                diag_data = json.loads(diag_proc.stdout)
                self.assertTrue(diag_data["share_commands"])
                self.assertTrue(diag_data["share_command_output"])
                self.assertTrue(diag_data["share_file_previews"])

                # Upgrading with an unrelated override preserves saved evidence flags
                up_keep = subprocess.run(
                    ["bash", "-s", "--", "--upgrade", "--install-dir", str(opt_dir), "--no-service", "--interval", "25"],
                    input=script_body,
                    text=True,
                    env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp_path)},
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(up_keep.returncode, 0, up_keep.stderr)
                kept_env = (opt_dir / "agent.env").read_text(encoding="utf-8")
                self.assertIn("SWARMCONTROL_INTERVAL=25", kept_env)
                self.assertIn("SWARMCONTROL_SHARE_COMMANDS=1", kept_env)
                self.assertIn("SWARMCONTROL_SHARE_COMMAND_OUTPUT=1", kept_env)
                self.assertIn("SWARMCONTROL_SHARE_FILE_PREVIEWS=1", kept_env)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_installer_refuses_missing_activity_core_without_touching_existing(self):
        import shutil
        import threading

        class MissingCoreHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                sources = {
                    "/agent/detector.py": ROOT / "agent" / "detector.py",
                    "/agent/activity_shipper.py": ROOT / "agent" / "activity_shipper.py",
                    "/agent/swarmcontrol_agent.py": ROOT / "agent" / "swarmcontrol_agent.py",
                }
                src = sources.get(self.path)
                if src is not None:
                    data = src.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/x-python; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                self.send_response(404)
                self.end_headers()

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), MissingCoreHandler)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        base_url = f"http://127.0.0.1:{httpd.server_port}"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                install_dir = tmp_path / "existing-observer"
                install_dir.mkdir()
                orig_env = (
                    f"SWARMCONTROL_SERVER={base_url}\n"
                    "SWARMCONTROL_TOKEN=sc_tok_existing_987654321\n"
                    "SWARMCONTROL_INTERVAL=15\n"
                    "SWARMCONTROL_HOST_ID=existing-box\n"
                    "SWARMCONTROL_ACTIVITY_ROOTS=\n"
                    "SWARMCONTROL_AGENT_LABELS=\n"
                    "SWARMCONTROL_SHARE_COMMANDS=0\n"
                )
                orig_agent = "# v0.1.0 untouched\n"
                (install_dir / "agent.env").write_text(orig_env, encoding="utf-8")
                os.chmod(install_dir / "agent.env", 0o600)
                (install_dir / "swarmcontrol_agent.py").write_text(orig_agent, encoding="utf-8")

                # 1. URL upgrade when /agent/activity_core.py returns 404 -> exit 4, zero mutations
                url_proc = subprocess.run(
                    ["bash", str(ROOT / "install.sh"), "--upgrade", "--install-dir", str(install_dir), "--no-service"],
                    text=True,
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(url_proc.returncode, 4, url_proc.stderr)
                self.assertEqual((install_dir / "agent.env").read_text(encoding="utf-8"), orig_env)
                self.assertEqual((install_dir / "swarmcontrol_agent.py").read_text(encoding="utf-8"), orig_agent)
                self.assertFalse((install_dir / "activity_core.py").exists())

                # 2. --from-repo missing backend/activity_inspector.py -> exit 4, zero mutations
                bad_repo = tmp_path / "partial-repo"
                (bad_repo / "agent").mkdir(parents=True)
                for fn in ("detector.py", "activity_shipper.py", "swarmcontrol_agent.py"):
                    shutil.copy2(ROOT / "agent" / fn, bad_repo / "agent" / fn)
                repo_proc = subprocess.run(
                    [
                        "bash",
                        str(ROOT / "install.sh"),
                        "--upgrade",
                        "--from-repo",
                        str(bad_repo),
                        "--install-dir",
                        str(install_dir),
                        "--no-service",
                    ],
                    text=True,
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(repo_proc.returncode, 4, repo_proc.stderr)
                self.assertEqual((install_dir / "agent.env").read_text(encoding="utf-8"), orig_env)
                self.assertEqual((install_dir / "swarmcontrol_agent.py").read_text(encoding="utf-8"), orig_agent)
                self.assertFalse((install_dir / "activity_core.py").exists())
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_installer_upgrade_preserves_env_offsets_and_rolls_back(self):
        import threading

        state = {"fail_heartbeat": False, "heartbeats": []}

        class UpgradeMockHandler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                sources = {
                    "/agent/detector.py": ROOT / "agent" / "detector.py",
                    "/agent/activity_shipper.py": ROOT / "agent" / "activity_shipper.py",
                    "/agent/activity_core.py": ROOT / "backend" / "activity_inspector.py",
                    "/agent/swarmcontrol_agent.py": ROOT / "agent" / "swarmcontrol_agent.py",
                }
                src = sources.get(self.path)
                if src is not None:
                    data = src.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/x-python; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                self.send_response(404)
                self.end_headers()

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                response = {"ok": True, "commit_offsets": True}
                if self.path == "/api/v1/ingest/heartbeat":
                    state["heartbeats"].append(body)
                    response["host_id"] = body["host_id"]
                    if state["fail_heartbeat"]:
                        err = b'{"error": "injected upgrade failure"}'
                        self.send_response(500)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(err)))
                        self.end_headers()
                        self.wfile.write(err)
                        return
                out = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        httpd = ThreadingHTTPServer(("127.0.0.1", 0), UpgradeMockHandler)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        base_url = f"http://127.0.0.1:{httpd.server_port}"
        script_body = installer.render_install_script(base_url)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                work_dir = tmp_path / "repo-a"
                work_dir.mkdir()

                # 1. Upgrade simulated v0.1.0 install (only agent.env + detector.py + swarmcontrol_agent.py)
                v01_dir = tmp_path / "obs-v01"
                v01_dir.mkdir()
                v01_env = (
                    f"SWARMCONTROL_SERVER={base_url}\n"
                    "SWARMCONTROL_TOKEN=sc_tok_v010_secret_12345\n"
                    "SWARMCONTROL_INTERVAL=25\n"
                    "SWARMCONTROL_HOST_ID=legacy-v01-box\n"
                    f"SWARMCONTROL_ACTIVITY_ROOTS={work_dir}\n"
                    "SWARMCONTROL_AGENT_LABELS=repo-a=Team Alpha\n"
                    "SWARMCONTROL_SHARE_COMMANDS=0\n"
                )
                (v01_dir / "agent.env").write_text(v01_env, encoding="utf-8")
                os.chmod(v01_dir / "agent.env", 0o600)
                (v01_dir / "detector.py").write_text("# v0.1.0 detector\n", encoding="utf-8")
                (v01_dir / "swarmcontrol_agent.py").write_text("# v0.1.0 agent\n", encoding="utf-8")

                clean_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp_path)}
                up1 = subprocess.run(
                    ["bash", "-s", "--", "--upgrade", "--install-dir", str(v01_dir), "--no-service"],
                    input=script_body,
                    text=True,
                    env=clean_env,
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(up1.returncode, 0, up1.stderr)
                self.assertTrue((v01_dir / "activity_core.py").is_file())
                self.assertTrue((v01_dir / "activity_shipper.py").is_file())
                self.assertEqual((v01_dir / "agent.env").read_text(encoding="utf-8"), v01_env)
                self.assertEqual(os.stat(v01_dir / "agent.env").st_mode & 0o777, 0o600)
                baks = list(tmp_path.glob("obs-v01.bak.*"))
                self.assertEqual(len(baks), 1)
                self.assertEqual((baks[0] / "swarmcontrol_agent.py").read_text(encoding="utf-8"), "# v0.1.0 agent\n")
                self.assertEqual(state["heartbeats"][-1]["host_id"], "legacy-v01-box")
                self.assertEqual(state["heartbeats"][-1]["capture_reader"], "core")

                # 2. Upgrade simulated v0.2.0 install with custom SWARMCONTROL_STATE_DIR + capture_offsets.json
                v02_dir = tmp_path / "obs-v02"
                v02_state = tmp_path / "v02-state"
                v02_dir.mkdir()
                v02_state.mkdir()
                orig_offsets = {
                    "offsets": {"deadbeef01": {"offset": 4096, "inode": 12345, "legacy_until": 2048}},
                    "last_metrics": None,
                    "last_error": "",
                    "last_ship_ok_at": 1795400000.0,
                }
                (v02_state / "capture_offsets.json").write_text(json.dumps(orig_offsets), encoding="utf-8")
                v02_env = (
                    f"SWARMCONTROL_SERVER={base_url}\n"
                    "SWARMCONTROL_TOKEN=sc_tok_v020_secret_67890\n"
                    "SWARMCONTROL_INTERVAL=15\n"
                    "SWARMCONTROL_HOST_ID=legacy-v02-box\n"
                    f"SWARMCONTROL_ACTIVITY_ROOTS={work_dir}\n"
                    "SWARMCONTROL_AGENT_LABELS=\n"
                    "SWARMCONTROL_SHARE_COMMANDS=1\n"
                    f"SWARMCONTROL_STATE_DIR={v02_state}\n"
                )
                (v02_dir / "agent.env").write_text(v02_env, encoding="utf-8")
                os.chmod(v02_dir / "agent.env", 0o600)
                (v02_dir / "swarmcontrol_agent.py").write_text("# v0.2.0 agent\n", encoding="utf-8")

                up2 = subprocess.run(
                    ["bash", "-s", "--", "--upgrade", "--install-dir", str(v02_dir), "--no-service"],
                    input=script_body,
                    text=True,
                    env=clean_env,
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(up2.returncode, 0, up2.stderr)
                self.assertEqual((v02_dir / "agent.env").read_text(encoding="utf-8"), v02_env)
                saved_offsets = json.loads((v02_state / "capture_offsets.json").read_text(encoding="utf-8"))
                self.assertEqual(
                    saved_offsets["offsets"],
                    {"deadbeef01": {"offset": 4096, "inode": 12345, "legacy_until": 2048}},
                )

                # 3. Failed verification during --upgrade rolls back automatically and removes new files
                rb_dir = tmp_path / "obs-rollback"
                rb_dir.mkdir()
                rb_env = (
                    f"SWARMCONTROL_SERVER={base_url}\n"
                    "SWARMCONTROL_TOKEN=sc_tok_rollback_999999\n"
                    "SWARMCONTROL_INTERVAL=15\n"
                    "SWARMCONTROL_HOST_ID=rollback-box\n"
                    f"SWARMCONTROL_ACTIVITY_ROOTS={work_dir}\n"
                    "SWARMCONTROL_AGENT_LABELS=\n"
                    "SWARMCONTROL_SHARE_COMMANDS=0\n"
                )
                (rb_dir / "agent.env").write_text(rb_env, encoding="utf-8")
                os.chmod(rb_dir / "agent.env", 0o600)
                (rb_dir / "detector.py").write_text("# old detector\n", encoding="utf-8")
                (rb_dir / "swarmcontrol_agent.py").write_text("# old v0.1.0 agent\n", encoding="utf-8")

                state["fail_heartbeat"] = True
                rb_proc = subprocess.run(
                    ["bash", "-s", "--", "--upgrade", "--install-dir", str(rb_dir), "--no-service"],
                    input=script_body,
                    text=True,
                    env=clean_env,
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(rb_proc.returncode, 1, rb_proc.stderr)
                self.assertIn("restored previous observer", rb_proc.stderr)
                self.assertEqual((rb_dir / "swarmcontrol_agent.py").read_text(encoding="utf-8"), "# old v0.1.0 agent\n")
                self.assertEqual((rb_dir / "detector.py").read_text(encoding="utf-8"), "# old detector\n")
                self.assertEqual((rb_dir / "agent.env").read_text(encoding="utf-8"), rb_env)
                self.assertEqual(os.stat(rb_dir / "agent.env").st_mode & 0o777, 0o600)
                self.assertFalse((rb_dir / "activity_core.py").exists())
                self.assertFalse((rb_dir / "activity_shipper.py").exists())
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
