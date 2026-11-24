"""Paso 8 · unified local/remote incremental step capture regression suite."""

from __future__ import annotations

import datetime
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "agent")]

import activity_inspector as ai  # noqa: E402
import activity_shipper  # noqa: E402
import remote_activity  # noqa: E402
import step_journal  # noqa: E402
import swarmcontrol_agent  # noqa: E402
import work_journal  # noqa: E402
from db import Database  # noqa: E402
from live_history import history  # noqa: E402
from server import create_server  # noqa: E402

SYNTH_SECRET = "sk-ant-api03-" + "T" * 24


def _ts(offset: float = 0.0) -> str:
    return datetime.datetime.fromtimestamp(
        time.time() - 3600 + offset, datetime.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _append(path: Path, rows: list[dict | str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for row in rows:
            fh.write((row if isinstance(row, str) else json.dumps(row)) + "\n")


class _RuntimeFixtureBuilder:
    def __init__(self, base: Path):
        self.base = base
        self.home = base / "home"
        self.work = base / "work"
        (self.work / "src").mkdir(parents=True, exist_ok=True)
        self.outside = base / "outside-private"
        self.outside.mkdir(parents=True, exist_ok=True)
        (self.work / ".env").write_text(f"API_KEY={SYNTH_SECRET}\n", encoding="utf-8")
        (self.outside / "secret_notes.txt").write_text("confidential\n", encoding="utf-8")

    def claude(self, n: int, start: int = 0, name: str = "c1", include_edit: bool = False) -> Path:
        jf = self.home / f".claude/projects/work/{name}.jsonl"
        if not jf.exists():
            _append(
                jf,
                [{"type": "user", "cwd": str(self.work), "message": {"role": "user", "content": "start"}}],
            )
        rows: list[dict] = []
        if include_edit and start == 0:
            rows.append(
                {
                    "type": "assistant",
                    "cwd": str(self.work),
                    "timestamp": _ts(-1),
                    "message": {
                        "model": "claude-x",
                        "content": [
                            {"type": "tool_use", "name": "Edit", "input": {"file_path": str(self.work / "src/app.py")}},
                            {"type": "tool_use", "name": "Read", "input": {"file_path": str(self.work / ".env")}},
                            {"type": "tool_use", "name": "Read", "input": {"file_path": str(self.outside / "secret_notes.txt")}},
                        ],
                    },
                }
            )
        for i in range(start, start + n):
            rows.append(
                {
                    "type": "assistant",
                    "cwd": str(self.work),
                    "timestamp": _ts(i),
                    "message": {
                        "model": "claude-x",
                        "content": [
                            {
                                "type": "tool_use",
                                "name": "Bash",
                                "input": {
                                    "command": f"pytest -q --token {SYNTH_SECRET}",
                                    "description": f"run step {i}",
                                },
                            }
                        ],
                    },
                }
            )
        _append(jf, rows)
        return jf

    def codex(self, n: int, start: int = 0) -> Path:
        rollout = self.home / ".codex/sessions/2026/11/rollout-u1.jsonl"
        rows = [
            {
                "timestamp": _ts(i),
                "payload": {
                    "type": "item_completed",
                    "item": {
                        "type": "CommandExecution",
                        "cwd": str(self.work),
                        "command": ["bash", "-lc", f"rg pattern{i}"],
                        "parsed_cmd": [{"type": "unknown", "cmd": f"rg pattern{i}"}],
                    },
                },
            }
            for i in range(start, start + n)
        ]
        if start == 0:
            rows.insert(
                0,
                {
                    "timestamp": _ts(-2),
                    "payload": {
                        "type": "item_completed",
                        "item": {
                            "type": "FileChange",
                            "status": "completed",
                            "changes": {str(self.work / "src/worker.py"): {"kind": "update"}},
                        },
                    },
                },
            )
        _append(rollout, rows)
        db = self.home / ".codex/state_5.sqlite"
        db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS threads (id TEXT, cwd TEXT, model TEXT, tokens_used INT, updated_at INT,"
                " rollout_path TEXT, model_provider TEXT)"
            )
            conn.execute("DELETE FROM threads")
            conn.execute(
                "INSERT INTO threads VALUES ('t1', ?, 'gpt-x', 10, ?, ?, 'openai')",
                (str(self.work), int(time.time()), str(rollout)),
            )
        return rollout

    def antigravity(self, n: int, start: int = 0) -> Path:
        conv = "c0ffee00-0000-4000-8000-0000000000bb"
        tr = self.home / ".gemini/antigravity-acp/brain" / conv / ".system_generated/logs/transcript.jsonl"
        _append(
            tr,
            [
                {
                    "type": "PLANNER_RESPONSE",
                    "content": "working",
                    "created_at": _ts(i),
                    "model": "gemini-x",
                    "tool_calls": [
                        {
                            "name": "run_command",
                            "args": {
                                "CommandLine": json.dumps(f"python3 job{i}.py --token {SYNTH_SECRET}"),
                                "toolSummary": f"ag step {i}",
                            },
                        }
                    ],
                }
                for i in range(start, start + n)
            ],
        )
        convdb = self.home / ".gemini/antigravity-acp/conversations" / f"{conv}.db"
        if not convdb.exists():
            convdb.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(convdb) as conn:
                conn.execute("CREATE TABLE trajectory_metadata_blob (id TEXT, data BLOB)")
                conn.execute(
                    "INSERT INTO trajectory_metadata_blob VALUES ('main', ?)",
                    (b"\x0a\x10file://" + str(self.work).encode() + b"\x12:",),
                )
        return tr

    def opencode(self, n: int, start: int = 0) -> Path:
        db = self.home / ".local/share/opencode/opencode.db"
        db.parent.mkdir(parents=True, exist_ok=True)
        now_ms = int(time.time() * 1000)
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS session_v2(id TEXT PRIMARY KEY, directory TEXT, time_updated INTEGER, model TEXT, title TEXT)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS session_message(session_id TEXT, type TEXT, seq INTEGER, time_created INTEGER, data TEXT)"
            )
            conn.execute(
                "INSERT INTO session_v2 VALUES ('oc1', ?, ?, 'glm-x', 'Fix') "
                "ON CONFLICT(id) DO UPDATE SET time_updated=excluded.time_updated",
                (str(self.work), now_ms + start),
            )
            for i in range(start, start + n):
                part = {
                    "type": "tool",
                    "name": "bash",
                    "state": {"status": "completed", "input": {"command": f"npm test {i}"}},
                }
                conn.execute(
                    "INSERT INTO session_message VALUES ('oc1', 'assistant', ?, ?, ?)",
                    (i, now_ms - 60_000 + i, json.dumps({"content": [part]})),
                )
        return db


class UnifiedCaptureTests(unittest.TestCase):
    def _event_signature(self, conn: sqlite3.Connection) -> tuple[list[tuple], set[str]]:
        events = conn.execute(
            """
            SELECT host_id, harness, agent_name, event_type, severity, message, metadata_json, created_at
            FROM events WHERE event_type IN ('observed_step', 'capture_gap')
            ORDER BY created_at, harness, message, metadata_json
            """
        ).fetchall()
        digests = {
            r[0]
            for r in conn.execute("SELECT digest FROM observed_step_keys").fetchall()
        }
        return events, digests

    def test_01_local_vs_remote_parity_all_four_runtimes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fx = _RuntimeFixtureBuilder(root)
            fx.claude(4, include_edit=True)
            fx.codex(4)
            fx.antigravity(4)
            fx.opencode(4)

            local_db = Database(root / "local.db")
            remote_db = Database(root / "remote.db")
            self.addCleanup(local_db.close)
            self.addCleanup(remote_db.close)

            host_id = "parity-host"
            with patch.object(ai, "HOME", fx.home), patch.object(ai, "harnesses", return_value=[]):
                scope = ai.Scope([fx.work], {}, host_id)
                local_conn = sqlite3.connect(local_db.db_path)
                self.addCleanup(local_conn.close)
                res_local = work_journal.capture_once(
                    local_conn,
                    {fx.work.name},
                    fx.work,
                    now=time.time(),
                    scope=scope,
                )

                payload, _, _ = activity_shipper.collect_incremental_activity(
                    raw_roots=[str(fx.work)],
                    host_id=host_id,
                    home_dir=fx.home,
                    use_core=True,
                )
                assert payload is not None
                res_remote = remote_activity.ingest_remote_activity(remote_db, payload)

            self.assertGreaterEqual(res_local["inserted"], 16)
            self.assertEqual(res_remote["steps_persisted"], res_local["inserted"])

            with sqlite3.connect(local_db.db_path) as lc, sqlite3.connect(remote_db.db_path) as rc:
                l_events, l_digests = self._event_signature(lc)
                r_events, r_digests = self._event_signature(rc)

            self.assertEqual(len({e[1] for e in r_events}), 4, "All 4 runtimes persisted remotely")
            self.assertEqual(l_events, r_events, "Local and remote projections must produce identical rows")
            self.assertEqual(l_digests, r_digests, "Local and remote position dedup digests must match")

            # Privacy sanity
            blob = json.dumps(r_events)
            for secret in (SYNTH_SECRET, ".env", "secret_notes.txt"):
                self.assertNotIn(secret, blob)

    def test_02_http_burst_over_20_outage_restart_retry_and_lean_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fx = _RuntimeFixtureBuilder(root)
            fx.claude(35, name="burst", include_edit=False)

            httpd, admin_pw = create_server(
                host="127.0.0.1",
                port=0,
                db_path=str(root / "console.db"),
                admin_user="admin",
                admin_pass="StrongPass123!",
            )
            port = httpd.server_address[1]
            t = threading.Thread(target=httpd.serve_forever, daemon=True)
            t.start()
            self.addCleanup(httpd.server_close)
            self.addCleanup(httpd.shutdown)

            base_url = f"http://127.0.0.1:{port}"
            tok = httpd.app_ctx.stores.primary.auth.create_agent_token("remote-ci", "admin", "ingest")["token"]
            state_dir = root / "state"

            # 1. Simulate HTTP 500 server outage on initial ship -> offsets MUST NOT advance
            def failing_poster(*_args, **_kwargs):
                raise RuntimeError("HTTP 500 temporary outage")

            with patch.object(ai, "harnesses", return_value=[]):
                with self.assertRaises(RuntimeError):
                    swarmcontrol_agent.ship_activity_once(
                        server=base_url,
                        token=tok,
                        raw_roots=str(fx.work),
                        host_id="win-burst-01",
                        state_dir=state_dir,
                        home_dir=fx.home,
                        poster=failing_poster,
                        use_core=True,
                    )

                st_after_fail = swarmcontrol_agent.load_capture_state(state_dir)
                self.assertEqual(st_after_fail["offsets"], {}, "Offsets must remain uncommitted during outage")
                self.assertEqual(len(swarmcontrol_agent.load_pending_queue(state_dir)), 1)

                # 2. Server recovers, simulate agent restart -> drains queue + commits offsets, 35/35 persisted
                res_ok = swarmcontrol_agent.ship_activity_once(
                    server=base_url,
                    token=tok,
                    raw_roots=str(fx.work),
                    host_id="win-burst-01",
                    state_dir=state_dir,
                    home_dir=fx.home,
                    use_core=True,
                )
                self.assertEqual(res_ok["steps_persisted"], 35)
                self.assertEqual(len(swarmcontrol_agent.load_pending_queue(state_dir)), 0)
                self.assertTrue(swarmcontrol_agent.load_capture_state(state_dir)["offsets"])

                # 3. Repeat poll -> 0 duplicates
                res_again = swarmcontrol_agent.ship_activity_once(
                    server=base_url,
                    token=tok,
                    raw_roots=str(fx.work),
                    host_id="win-burst-01",
                    state_dir=state_dir,
                    home_dir=fx.home,
                    use_core=True,
                )
                self.assertEqual(res_again["steps_persisted"], 0)

            # Verify live-records has all 35 while host_activity map keeps <= 10 recent steps
            db = httpd.app_ctx.stores.primary.db
            recs = history(db, 1, {})
            self.assertEqual(len(recs["records"]), 35)
            act_map = remote_activity.build_tenant_activity_map(db)
            self.assertLessEqual(len(act_map["sessions"][0]["steps"]), 10)
            raw_host_row = db.query_one("SELECT payload_json FROM host_activity WHERE host_id='win-burst-01'")
            self.assertNotIn("capture_steps", raw_host_row["payload_json"])

    def test_03_rotation_gap_and_capture_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fx = _RuntimeFixtureBuilder(root)
            jf = fx.claude(5, name="rot")
            db = Database(root / "rot.db")
            self.addCleanup(db.close)
            state_dir = root / "state"

            def db_poster(_url, _tok, chunk):
                return remote_activity.ingest_remote_activity(db, chunk)

            r1 = swarmcontrol_agent.ship_activity_once(
                "http://127.0.0.1:0", "tok", str(fx.work), "rot-host", state_dir, home_dir=fx.home, poster=db_poster, use_core=False
            )
            self.assertEqual(r1["steps_persisted"], 5)

            # Truncate/rotate log with smaller replacement -> triggers gap WARNING + metrics
            jf.write_text("", encoding="utf-8")
            fx.claude(2, start=100, name="rot")

            r2 = swarmcontrol_agent.ship_activity_once(
                "http://127.0.0.1:0", "tok", str(fx.work), "rot-host", state_dir, home_dir=fx.home, poster=db_poster, use_core=False
            )
            self.assertEqual(r2["steps_persisted"], 2)

            gap_rows = db.query_all("SELECT severity, message FROM events WHERE event_type='capture_gap'")
            self.assertEqual(len(gap_rows), 1)
            self.assertEqual(gap_rows[0]["severity"], "WARNING")
            metric_rows = db.query_all("SELECT steps_seen, inserted, gaps, files_read, bytes_read FROM capture_metrics ORDER BY ts")
            self.assertGreaterEqual(len(metric_rows), 2)
            self.assertEqual(metric_rows[-1]["gaps"], 1)
            self.assertEqual(metric_rows[-1]["inserted"], 2)

    def test_04_backlog_and_payload_chunking_under_320_kib(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fx = _RuntimeFixtureBuilder(root)
            db = Database(root / "chunk.db")
            self.addCleanup(db.close)
            sent_sizes: list[int] = []

            def measuring_poster(_url, _tok, chunk):
                sz = len(json.dumps(chunk).encode("utf-8"))
                sent_sizes.append(sz)
                self.assertLessEqual(sz, 48_000)
                return remote_activity.ingest_remote_activity(db, chunk)

            orig_chunker = activity_shipper.chunk_activity_payload
            with (
                patch.object(ai, "harnesses", return_value=[]),
                patch.object(
                    swarmcontrol_agent,
                    "chunk_activity_payload",
                    lambda p: orig_chunker(p, max_bytes=48_000),
                ),
            ):
                state_dir = root / "state"
                # Initial baseline scan (like a running agent) before a 410-step burst arrives
                jf = fx.claude(10, name="big")
                r0 = swarmcontrol_agent.ship_activity_once(
                    "http://127.0.0.1:0",
                    "tok",
                    str(fx.work),
                    "big-host",
                    state_dir,
                    home_dir=fx.home,
                    ceiling=45_000,
                    poster=measuring_poster,
                    use_core=True,
                )
                total = r0["steps_persisted"]

                extra_rows = []
                for i in range(10, 420):
                    extra_rows.append(
                        {
                            "type": "assistant",
                            "cwd": str(fx.work),
                            "timestamp": _ts(i),
                            "message": {
                                "model": "claude-x",
                                "content": [
                                    {
                                        "type": "tool_use",
                                        "name": "Edit",
                                        "input": {"file_path": str(fx.work / "src" / f"mod_{i % 20}.py")},
                                    }
                                ],
                            },
                        }
                    )
                _append(jf, extra_rows)

                for _ in range(10):
                    r = swarmcontrol_agent.ship_activity_once(
                        "http://127.0.0.1:0",
                        "tok",
                        str(fx.work),
                        "big-host",
                        state_dir,
                        home_dir=fx.home,
                        ceiling=45_000,
                        poster=measuring_poster,
                        use_core=True,
                    )
                    total += r["steps_persisted"]
                    if not r["has_backlog"]:
                        break

            self.assertEqual(total, 420)
            self.assertGreater(len(sent_sizes), 3, "Backlog + size chunking should produce multiple chunks")
            page1 = history(db, 1, {"limit": ["250"]})
            page2 = history(db, 1, {"limit": ["250"], "before": [page1["next"]]})
            self.assertEqual(len({r["id"] for r in page1["records"] + page2["records"]}), 420)

    def test_05_upgrade_dedup_from_legacy_remote_table_and_tenant_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_t1 = Database(root / "t1.db")
            db_t2 = Database(root / "t2.db")
            self.addCleanup(db_t1.close)
            self.addCleanup(db_t2.close)

            stamp_iso = _ts(0)
            stamp_ts = step_journal.parse_step_ts(stamp_iso, time.time())
            assert stamp_ts is not None

            # Seed pre-Paso-8 remote_observed_step_keys table directly
            legacy_digest = step_journal.legacy_remote_v1_key(
                host_id="upg-host",
                session_id="claude:upg",
                harness="claude-code",
                agent_name="work",
                timestamp=stamp_ts,
                category="shell",
                tool="Bash",
                rel_files=[],
                program="pytest",
                outcome="completed",
                occurrence=1,
            )
            with db_t1.transaction() as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS remote_observed_step_keys (digest TEXT PRIMARY KEY, ts REAL NOT NULL)"
                )
                conn.execute("INSERT INTO remote_observed_step_keys VALUES (?, ?)", (legacy_digest, stamp_ts))
                conn.execute(
                    """INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at)
                       VALUES ('upg-host','claude-code','work','observed_step','INFO','Run tests · pytest','{}',?)""",
                    (stamp_ts,),
                )

            # Now send Paso-8 payload with src + capture_legacy_until covering the migrated step + 1 brand-new step
            stamp_new = _ts(5)
            payload = {
                "host_id": "upg-host",
                "hostname": "upg-host",
                "activity_enabled": True,
                "activity_roots": ["/tmp/work"],
                "capture_legacy_until": {"abc12345abc12345abcd": 500},
                "sessions": [
                    {
                        "session_id": "claude:upg",
                        "harness": "claude-code",
                        "harness_name": "Claude Code",
                        "agent_id": "work",
                        "agent_name": "work",
                        "workspace": "/tmp/work",
                        "steps": [],
                        "capture_steps": [
                            {
                                "tool": "Bash",
                                "category": "shell",
                                "label": "Run tests",
                                "time": stamp_iso,
                                "status": "completed",
                                "program": "pytest",
                                "src": "abc12345abc12345abcd:120:0",
                            },
                            {
                                "tool": "Bash",
                                "category": "shell",
                                "label": "Run tests",
                                "time": stamp_new,
                                "status": "completed",
                                "program": "pytest",
                                "src": "abc12345abc12345abcd:520:0",
                            },
                        ],
                    }
                ],
                "workspaces": [],
                "harnesses": [],
            }

            res = remote_activity.ingest_remote_activity(db_t1, payload)
            self.assertEqual(res["steps_persisted"], 1, "Legacy step must deduplicate; only new step inserts")
            self.assertEqual(res["steps_duplicates"], 1)
            self.assertEqual(len(db_t1.query_all("SELECT id FROM events WHERE event_type='observed_step'")), 2)
            # Tenant 2 remains completely isolated
            self.assertEqual(len(history(db_t2, 2, {})["records"]), 0)
            self.assertEqual(remote_activity.build_tenant_activity_map(db_t2)["sessions"], [])

    def test_06_diagnose_cli_is_read_only_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fx = _RuntimeFixtureBuilder(root)
            fx.claude(3, include_edit=True)
            state_dir = root / "state"
            state_dir.mkdir()
            offsets_before = state_dir / "capture_offsets.json"
            self.assertFalse(offsets_before.exists())

            proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "agent/swarmcontrol_agent.py"),
                    "--diagnose",
                    "--host-id",
                    "diag-host",
                    "--state-dir",
                    str(state_dir),
                    "--activity-roots",
                    str(fx.work),
                ],
                env={**os.environ, "HOME": str(fx.home), "SWARMCONTROL_ACTIVITY_HOME": str(fx.home)},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(proc.stdout)
            self.assertEqual(report["host_id"], "diag-host")
            self.assertEqual(report["offsets_count"], 0)
            self.assertEqual(report["pending_queue_batches"], 0)
            self.assertIsNotNone(report["dry_scan"])
            self.assertFalse(offsets_before.exists(), "--diagnose must not mutate capture_offsets.json")
            for forbidden in (SYNTH_SECRET, ".env", "secret_notes.txt"):
                self.assertNotIn(forbidden, proc.stdout)

    def _d3_payload(
        self,
        *,
        host_id: str,
        session_id: str,
        steps: list[dict],
        collected_at: float | None = None,
        capture_reader: str = "core",
        fallback_reason: str = "",
    ) -> dict:
        payload = {
            "host_id": host_id,
            "hostname": host_id,
            "activity_enabled": True,
            "activity_roots": ["/tmp/work"],
            "capture_reader": capture_reader,
            "sessions": [
                {
                    "session_id": session_id,
                    "harness": "claude-code",
                    "harness_name": "Claude Code",
                    "agent_id": "work",
                    "agent_name": "work",
                    "workspace": "/tmp/work",
                    "steps": [],
                    "capture_steps": steps,
                }
            ],
            "workspaces": [],
            "harnesses": [],
        }
        if collected_at is not None:
            payload["collected_at"] = collected_at
        if fallback_reason:
            payload["fallback_reason"] = fallback_reason
        return payload

    def test_07_d3_forward_clock_skew_normalization_ntp_fix_and_rate_limit(self):
        def _iso_at(ts: float) -> str:
            return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = Database(str(root / "d3.db"))
            remote_activity.ensure_remote_activity_table(db)
            base = time.time()

            # 1. Forward skew via collected_at (+120s): normalizes and preserves 10s intra-batch interval
            p1 = self._d3_payload(
                host_id="skew-host",
                session_id="claude:skew1",
                collected_at=base + 120.0,
                steps=[
                    {
                        "tool": "Bash",
                        "category": "shell",
                        "label": "Run pytest A",
                        "time": _iso_at(base + 110.0),
                        "status": "completed",
                        "program": "pytest",
                        "src": "skewfk1:100:0",
                    },
                    {
                        "tool": "Bash",
                        "category": "shell",
                        "label": "Run pytest B",
                        "time": _iso_at(base + 120.0),
                        "status": "completed",
                        "program": "pytest",
                        "src": "skewfk1:200:0",
                    },
                ],
            )
            r1 = remote_activity.ingest_remote_activity(db, p1)
            self.assertTrue(r1["ok"])
            self.assertTrue(r1["commit_offsets"])
            self.assertEqual(r1["steps_persisted"], 2)
            self.assertEqual(r1["steps_rejected"], 0)
            self.assertEqual(r1["steps_clock_adjusted"], 2)
            self.assertGreater(r1["clock_skew_sec"], 60.0)
            self.assertLess(r1["clock_skew_sec"], 130.0)
            self.assertIn("server_time", r1)
            self.assertTrue(any(w.startswith("clock_skew:") for w in (r1.get("warnings") or [])), r1.get("warnings"))

            rows = db.query_all(
                "SELECT message, created_at FROM events WHERE host_id='skew-host' AND event_type='observed_step' ORDER BY id ASC"
            )
            self.assertEqual(len(rows), 2)
            self.assertAlmostEqual(float(rows[1]["created_at"]) - float(rows[0]["created_at"]), 10.0, delta=0.2)

            # 2. Rescan same src produces 0 duplicates
            r1_dup = remote_activity.ingest_remote_activity(db, p1)
            self.assertEqual(r1_dup["steps_persisted"], 0)
            self.assertEqual(r1_dup["steps_duplicates"], 2)
            self.assertEqual(r1_dup["steps_rejected"], 0)

            # 3. Forward skew via log timestamps only (collected_at accurate, logs +110s/+125s)
            base2 = time.time()
            p2 = self._d3_payload(
                host_id="skew-host",
                session_id="claude:skew1",
                collected_at=base2,
                steps=[
                    {
                        "tool": "Bash",
                        "category": "shell",
                        "label": "Run pytest C",
                        "time": _iso_at(base2 + 110.0),
                        "status": "completed",
                        "program": "pytest",
                        "src": "skewfk1:300:0",
                    },
                    {
                        "tool": "Bash",
                        "category": "shell",
                        "label": "Run pytest D",
                        "time": _iso_at(base2 + 125.0),
                        "status": "completed",
                        "program": "pytest",
                        "src": "skewfk1:400:0",
                    },
                ],
            )
            r2 = remote_activity.ingest_remote_activity(db, p2)
            self.assertTrue(r2["commit_offsets"])
            self.assertEqual(r2["steps_persisted"], 2)
            self.assertEqual(r2["steps_clock_adjusted"], 2)
            rows_after = db.query_all(
                "SELECT message, created_at FROM events WHERE host_id='skew-host' AND event_type='observed_step' ORDER BY id ASC"
            )
            self.assertEqual(len(rows_after), 4)
            self.assertAlmostEqual(
                float(rows_after[3]["created_at"]) - float(rows_after[2]["created_at"]),
                15.0,
                delta=0.2,
            )

            # Warning rate-limited to 1 per host per hour while no rejections occur
            skew_warnings = db.query_all(
                "SELECT id, severity FROM events WHERE host_id='skew-host' AND event_type='clock_skew'"
            )
            self.assertEqual(len(skew_warnings), 1)
            self.assertEqual(skew_warnings[0]["severity"], "WARNING")

            # 4. NTP corrects clock mid-session (+120s -> 0s) and old src re-ships -> 0 duplicates via position_key
            base3 = time.time()
            p_ntp = self._d3_payload(
                host_id="skew-host",
                session_id="claude:skew1",
                collected_at=base3,
                steps=[
                    {
                        "tool": "Bash",
                        "category": "shell",
                        "label": "Run pytest A",
                        "time": _iso_at(base3 - 5.0),
                        "status": "completed",
                        "program": "pytest",
                        "src": "skewfk1:100:0",
                    }
                ],
            )
            r_ntp = remote_activity.ingest_remote_activity(db, p_ntp)
            self.assertEqual(r_ntp["steps_persisted"], 0)
            self.assertEqual(r_ntp["steps_duplicates"], 1)

    def test_08_d3_negative_skew_expired_and_delayed_queued_batch(self):
        def _iso_at(ts: float) -> str:
            return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = Database(str(root / "neg.db"))
            remote_activity.ensure_remote_activity_table(db)
            now = time.time()

            # 1. Negative skew (-120s) must persist verbatim without shifting
            neg_ts = now - 120.0
            r_neg = remote_activity.ingest_remote_activity(
                db,
                self._d3_payload(
                    host_id="neg-host",
                    session_id="claude:neg",
                    collected_at=neg_ts,
                    steps=[
                        {
                            "tool": "Bash",
                            "category": "shell",
                            "label": "Negative skew step",
                            "time": _iso_at(neg_ts),
                            "status": "completed",
                            "program": "pytest",
                            "src": "negfk:10:0",
                        }
                    ],
                ),
            )
            self.assertTrue(r_neg["commit_offsets"])
            self.assertEqual(r_neg["steps_persisted"], 1)
            self.assertEqual(r_neg["steps_clock_adjusted"], 0)
            self.assertEqual(r_neg["clock_skew_sec"], 0.0)
            stored_neg = db.query_one("SELECT created_at FROM events WHERE host_id='neg-host' AND event_type='observed_step'")
            self.assertIsNotNone(stored_neg)
            self.assertAlmostEqual(float(stored_neg["created_at"]), neg_ts, delta=0.5)

            # 2. Expired step (-8 days) -> steps_expired == 1, commit_offsets == True, steps_rejected == 0
            old_ts = now - (8 * 86400.0)
            r_exp = remote_activity.ingest_remote_activity(
                db,
                self._d3_payload(
                    host_id="neg-host",
                    session_id="claude:neg",
                    collected_at=now,
                    steps=[
                        {
                            "tool": "Bash",
                            "category": "shell",
                            "label": "Expired old step",
                            "time": _iso_at(old_ts),
                            "status": "completed",
                            "program": "pytest",
                            "src": "negfk:20:0",
                        }
                    ],
                ),
            )
            self.assertTrue(r_exp["ok"])
            self.assertTrue(r_exp["commit_offsets"])
            self.assertEqual(r_exp["steps_expired"], 1)
            self.assertEqual(r_exp["steps_persisted"], 0)
            self.assertEqual(r_exp["steps_rejected"], 0)

            # 3. Queued delayed batch (collected_at 1h ago, steps 1h+5s ago) -> NEVER false-shifted
            q_ts = now - 3605.0
            r_q = remote_activity.ingest_remote_activity(
                db,
                self._d3_payload(
                    host_id="neg-host",
                    session_id="claude:neg",
                    collected_at=now - 3600.0,
                    steps=[
                        {
                            "tool": "Bash",
                            "category": "shell",
                            "label": "Queued past batch",
                            "time": _iso_at(q_ts),
                            "status": "completed",
                            "program": "pytest",
                            "src": "negfk:30:0",
                        }
                    ],
                ),
            )
            self.assertTrue(r_q["commit_offsets"])
            self.assertEqual(r_q["steps_persisted"], 1)
            self.assertEqual(r_q["steps_clock_adjusted"], 0)
            self.assertEqual(r_q["clock_skew_sec"], 0.0)
            stored_q = db.query_all(
                "SELECT created_at FROM events WHERE host_id='neg-host' AND event_type='observed_step' ORDER BY id ASC"
            )[-1]
            self.assertAlmostEqual(float(stored_q["created_at"]), q_ts, delta=0.5)

    def test_09_d3_permanent_rejection_http_422_retry_hold_and_escape_hatch(self):
        def _iso_at(ts: float) -> str:
            return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            httpd, _ = create_server(
                host="127.0.0.1",
                port=0,
                db_path=str(root / "reject.db"),
                admin_user="admin",
                admin_pass="StrongPass123!",
            )
            port = httpd.server_address[1]
            t = threading.Thread(target=httpd.serve_forever, daemon=True)
            t.start()
            self.addCleanup(httpd.server_close)
            self.addCleanup(httpd.shutdown)

            base_url = f"http://127.0.0.1:{port}"
            tok_http = httpd.app_ctx.stores.primary.auth.create_agent_token("skew-reject-host", "admin", "ingest")["token"]

            def post_act(payload: dict) -> tuple[int, dict]:
                req = urllib.request.Request(
                    f"{base_url}/api/v1/ingest/activity",
                    data=json.dumps(payload).encode("utf-8"),
                    method="POST",
                    headers={"Content-Type": "application/json", "Authorization": f"Bearer {tok_http}"},
                )
                try:
                    with urllib.request.urlopen(req, timeout=8) as resp:
                        return resp.status, json.loads(resp.read().decode("utf-8"))
                except urllib.error.HTTPError as exc:
                    return exc.code, json.loads(exc.read().decode("utf-8"))

            now = time.time()
            # 1. +48h future skew -> HTTP 422, commit_offsets=False, steps_rejected=1
            st1, b1 = post_act(
                self._d3_payload(
                    host_id="skew-reject-host",
                    session_id="claude:r1",
                    collected_at=now + 48 * 3600.0,
                    steps=[
                        {
                            "tool": "Bash",
                            "category": "shell",
                            "label": "Extreme future",
                            "time": _iso_at(now + 48 * 3600.0),
                            "status": "completed",
                            "program": "pytest",
                            "src": "rfk:10:0",
                        }
                    ],
                )
            )
            self.assertEqual(st1, 422)
            self.assertFalse(b1["ok"])
            self.assertFalse(b1["commit_offsets"])
            self.assertEqual(b1["steps_rejected"], 1)
            self.assertIn("steps_rejected:1", b1.get("warnings") or [])

            # 2. Invalid timestamp string -> HTTP 422
            st2, b2 = post_act(
                self._d3_payload(
                    host_id="skew-reject-host",
                    session_id="claude:r1",
                    collected_at=now,
                    steps=[
                        {
                            "tool": "Bash",
                            "category": "shell",
                            "label": "Bad ts",
                            "time": "not-a-timestamp",
                            "status": "completed",
                            "program": "pytest",
                            "src": "rfk:20:0",
                        }
                    ],
                )
            )
            self.assertEqual(st2, 422)
            self.assertFalse(b2["commit_offsets"])
            self.assertEqual(b2["steps_rejected"], 1)

            # 3. Legacy payload WITHOUT collected_at and +120s step -> HTTP 422 (never silently dropped)
            st3, b3 = post_act(
                self._d3_payload(
                    host_id="skew-reject-host",
                    session_id="claude:r1",
                    collected_at=None,
                    steps=[
                        {
                            "tool": "Bash",
                            "category": "shell",
                            "label": "Legacy agent +120s",
                            "time": _iso_at(now + 120.0),
                            "status": "completed",
                            "program": "pytest",
                            "src": "rfk:30:0",
                        }
                    ],
                )
            )
            self.assertEqual(st3, 422)
            self.assertFalse(b3["commit_offsets"])
            self.assertEqual(b3["steps_rejected"], 1)

            primary_db = httpd.app_ctx.stores.primary.db
            w_events = primary_db.query_all(
                "SELECT severity FROM events WHERE host_id='skew-reject-host' AND event_type='clock_skew'"
            )
            self.assertTrue(any(r["severity"] == "WARNING" for r in w_events))
            m_row = primary_db.query_one("SELECT SUM(gaps) AS total_gaps FROM capture_metrics")
            self.assertGreaterEqual(int((m_row or {}).get("total_gaps") or 0), 1)

            # 4. End-to-end client retry hold (attempts 1 & 2) + escape hatch on attempt 3
            fx = _RuntimeFixtureBuilder(root)
            jf = fx.home / ".claude/projects/work/poison.jsonl"
            _append(
                jf,
                [
                    {"type": "user", "cwd": str(fx.work), "message": {"role": "user", "content": "start"}},
                    {
                        "type": "assistant",
                        "cwd": str(fx.work),
                        "timestamp": _iso_at(now + 48 * 3600.0),
                        "message": {
                            "model": "claude-x",
                            "content": [{"type": "tool_use", "name": "Bash", "input": {"command": "pytest poisoned"}}],
                        },
                    },
                ],
            )
            state_dir = root / "retry-state"
            tok_agent = httpd.app_ctx.stores.primary.auth.create_agent_token("retry-host", "admin", "ingest")["token"]

            with patch.object(ai, "HOME", fx.home), patch.object(ai, "harnesses", return_value=[]):
                # Attempt 1: holds offsets, raises RejectedStepsError
                with self.assertRaises(swarmcontrol_agent.RejectedStepsError) as cm1:
                    swarmcontrol_agent.ship_activity_once(
                        server=base_url,
                        token=tok_agent,
                        raw_roots=str(fx.work),
                        host_id="retry-host",
                        home_dir=fx.home,
                        state_dir=state_dir,
                    )
                self.assertEqual(cm1.exception.status_code, 422)
                self.assertEqual(swarmcontrol_agent.load_capture_state(state_dir)["offsets"], {})
                self.assertEqual(swarmcontrol_agent.load_pending_queue(state_dir)[0]["reject_retries"], 1)

                # Attempt 2: still holds offsets, reject_retries -> 2
                with self.assertRaises(swarmcontrol_agent.RejectedStepsError):
                    swarmcontrol_agent.ship_activity_once(
                        server=base_url,
                        token=tok_agent,
                        raw_roots=str(fx.work),
                        host_id="retry-host",
                        home_dir=fx.home,
                        state_dir=state_dir,
                    )
                self.assertEqual(swarmcontrol_agent.load_capture_state(state_dir)["offsets"], {})
                self.assertEqual(swarmcontrol_agent.load_pending_queue(state_dir)[0]["reject_retries"], 2)

                # Attempt 3: reaches DEFAULT_MAX_REJECT_RETRIES (3) -> emits capture_gap WARNING and advances past poison
                res3 = swarmcontrol_agent.ship_activity_once(
                    server=base_url,
                    token=tok_agent,
                    raw_roots=str(fx.work),
                    host_id="retry-host",
                    home_dir=fx.home,
                    state_dir=state_dir,
                )
                self.assertTrue(res3["ok"])
                self.assertTrue(swarmcontrol_agent.load_capture_state(state_dir)["offsets"])
                self.assertEqual(swarmcontrol_agent.load_pending_queue(state_dir), [])
                gap_ev = primary_db.query_one(
                    "SELECT severity, message FROM events WHERE host_id='retry-host' AND event_type='capture_gap'"
                )
                self.assertIsNotNone(gap_ev)
                self.assertEqual(gap_ev["severity"], "WARNING")

                # Subsequent valid step after poisoned record persists cleanly!
                _append(
                    jf,
                    [
                        {
                            "type": "assistant",
                            "cwd": str(fx.work),
                            "timestamp": _iso_at(now - 5.0),
                            "message": {
                                "model": "claude-x",
                                "content": [{"type": "tool_use", "name": "Bash", "input": {"command": "pytest recovered"}}],
                            },
                        }
                    ],
                )
                res4 = swarmcontrol_agent.ship_activity_once(
                    server=base_url,
                    token=tok_agent,
                    raw_roots=str(fx.work),
                    host_id="retry-host",
                    home_dir=fx.home,
                    state_dir=state_dir,
                )
                self.assertEqual(res4["steps_persisted"], 1)

    def test_10_d3_and_d6_multi_org_isolation_across_same_host_id(self):
        def _iso_at(ts: float) -> str:
            return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db1 = Database(str(root / "org1.db"))
            db2 = Database(str(root / "org2.db"))
            remote_activity.ensure_remote_activity_table(db1)
            remote_activity.ensure_remote_activity_table(db2)
            now = time.time()

            r1 = remote_activity.ingest_remote_activity(
                db1,
                self._d3_payload(
                    host_id="shared-worker-99",
                    session_id="claude:o1",
                    collected_at=now + 48 * 3600.0,
                    capture_reader="fallback",
                    fallback_reason="explicit_override",
                    steps=[
                        {
                            "tool": "Bash",
                            "category": "shell",
                            "label": "Org1 rejected",
                            "time": _iso_at(now + 48 * 3600.0),
                            "status": "completed",
                            "program": "pytest",
                            "src": "iso:1:0",
                        }
                    ],
                ),
            )
            self.assertFalse(r1["commit_offsets"])

            r2 = remote_activity.ingest_remote_activity(
                db2,
                self._d3_payload(
                    host_id="shared-worker-99",
                    session_id="claude:o2",
                    collected_at=now,
                    capture_reader="core",
                    steps=[
                        {
                            "tool": "Bash",
                            "category": "shell",
                            "label": "Org2 clean step",
                            "time": _iso_at(now - 5.0),
                            "status": "completed",
                            "program": "pytest",
                            "src": "iso:2:0",
                        }
                    ],
                ),
            )
            self.assertTrue(r2["commit_offsets"])
            self.assertEqual(r2["steps_persisted"], 1)

            org1_warns = db1.query_all("SELECT event_type FROM events WHERE host_id='shared-worker-99'")
            self.assertEqual({r["event_type"] for r in org1_warns}, {"clock_skew", "reader_fallback"})
            org2_warns = db2.query_all(
                "SELECT event_type FROM events WHERE host_id='shared-worker-99' AND event_type IN ('clock_skew','reader_fallback')"
            )
            self.assertEqual(org2_warns, [])
            self.assertEqual(remote_activity.build_tenant_activity_map(db1)["hosts"][0]["capture_reader"], "fallback")
            self.assertEqual(remote_activity.build_tenant_activity_map(db2)["hosts"][0]["capture_reader"], "core")

    def test_11_d6_no_silent_fallback_and_core_crash_holds_offsets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fx = _RuntimeFixtureBuilder(root)
            fx.claude(2, name="nosilent")
            state_dir = root / "state"

            # 1. Missing activity_core without SWARMCONTROL_ALLOW_FALLBACK raises and holds offsets
            with (
                patch.object(activity_shipper, "_load_activity_core", return_value=None),
                patch.dict(os.environ, {}, clear=False),
            ):
                os.environ.pop("SWARMCONTROL_ALLOW_FALLBACK", None)
                with self.assertRaises(RuntimeError) as cm:
                    activity_shipper.collect_incremental_activity(
                        raw_roots=[str(fx.work)],
                        host_id="no-silent-host",
                        home_dir=fx.home,
                    )
                self.assertIn("activity_core.py", str(cm.exception))

            with (
                patch.object(swarmcontrol_agent, "_load_activity_core", return_value=None),
                patch.object(activity_shipper, "_load_activity_core", return_value=None),
            ):
                with self.assertRaises(RuntimeError):
                    swarmcontrol_agent.ship_activity_once(
                        server="http://127.0.0.1:1",
                        token="tok",
                        raw_roots=str(fx.work),
                        host_id="no-silent-host",
                        home_dir=fx.home,
                        state_dir=state_dir,
                        poster=lambda *_a: {"ok": True},
                    )
                self.assertEqual(swarmcontrol_agent.load_capture_state(state_dir)["offsets"], {})

            # 2. Crashing core reader raises instead of silently falling back to _FallbackCapture
            class _BrokenCapture:
                def __init__(self, *_a, **_kw):
                    pass

                def collect(self):
                    raise RuntimeError("boom inside core")

            fake_core = type(sys)("fake_core")
            fake_core.Scope = lambda **_kw: object()
            fake_core.Capture = _BrokenCapture
            fake_core.collect_activity = lambda _scope, cap: cap.collect()
            fake_core.HOME = fx.home
            fake_core.harnesses = lambda: []
            with patch.object(activity_shipper, "_load_activity_core", return_value=fake_core):
                with self.assertRaises(RuntimeError) as cm2:
                    activity_shipper.collect_incremental_activity(
                        raw_roots=[str(fx.work)],
                        host_id="crash-host",
                        home_dir=fx.home,
                    )
                self.assertIn("boom inside core", str(cm2.exception))

    def test_12_d6_explicit_fallback_visible_in_payload_diagnose_heartbeat_and_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fx = _RuntimeFixtureBuilder(root)
            fx.claude(4, name="fb_claude", include_edit=True)
            fx.opencode(4)

            payload, _, _ = activity_shipper.collect_incremental_activity(
                raw_roots=[str(fx.work)],
                host_id="fb-host",
                home_dir=fx.home,
                use_core=False,
            )
            assert payload is not None
            self.assertEqual(payload.get("capture_reader"), "fallback")
            self.assertEqual(payload.get("fallback_reason"), "explicit_fallback")

            chunks = activity_shipper.chunk_activity_payload(payload, max_bytes=1024)
            self.assertGreaterEqual(len(chunks), 2)
            for ch in chunks:
                self.assertEqual(ch.get("capture_reader"), "fallback")

            db = Database(str(root / "fb.db"))
            remote_activity.ensure_remote_activity_table(db)
            res = remote_activity.ingest_remote_activity(db, chunks[0])
            self.assertEqual(res["capture_reader"], "fallback")
            self.assertIn("reader_fallback:explicit_fallback", res.get("warnings") or [])

            # Also verify fallback activation when activity_core is missing and SWARMCONTROL_ALLOW_FALLBACK=1
            with (
                patch.object(activity_shipper, "_load_activity_core", return_value=None),
                patch.dict(os.environ, {"SWARMCONTROL_ALLOW_FALLBACK": "1"}),
            ):
                p_env, _, _ = activity_shipper.collect_incremental_activity(
                    raw_roots=[str(fx.work)],
                    host_id="fb-env-host",
                    home_dir=fx.home,
                )
                assert p_env is not None
                self.assertEqual(p_env.get("capture_reader"), "fallback")
                self.assertEqual(p_env.get("fallback_reason"), "activity_core_missing")

            # Second fallback ingest stays rate-limited to 1 WARNING/hour
            remote_activity.ingest_remote_activity(db, chunks[-1])
            fb_warns = db.query_all(
                "SELECT severity FROM events WHERE host_id='fb-host' AND event_type='reader_fallback'"
            )
            self.assertEqual(len(fb_warns), 1)
            self.assertEqual(fb_warns[0]["severity"], "WARNING")
            self.assertEqual(remote_activity.build_tenant_activity_map(db)["hosts"][0]["capture_reader"], "fallback")

            # Heartbeat telemetry surfaces capture_reader="fallback" + clock_skew WARNINGs too
            with db.transaction() as conn:
                hb_res = remote_activity.inspect_heartbeat_telemetry(
                    conn,
                    "hb-fb-host",
                    {
                        "capture_reader": "fallback",
                        "fallback_reason": "activity_core_missing",
                        "collected_at": time.time() + 130.0,
                    },
                    time.time(),
                )
            self.assertIn("server_time", hb_res)
            self.assertGreater(hb_res["clock_skew_sec"], 60.0)
            self.assertTrue(any(w.startswith("reader_fallback:") for w in hb_res["warnings"]), hb_res["warnings"])
            self.assertTrue(any(w.startswith("clock_skew:") for w in hb_res["warnings"]), hb_res["warnings"])

            # --diagnose without activity_core reports activity_core_loaded=False + dry_scan_error
            import shutil

            isolated_agent_dir = root / "broken-agent"
            isolated_agent_dir.mkdir()
            for fn in ("detector.py", "activity_shipper.py", "swarmcontrol_agent.py"):
                shutil.copy2(ROOT / "agent" / fn, isolated_agent_dir / fn)
            diag_env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(fx.home),
                "SWARMCONTROL_ACTIVITY_HOME": str(fx.home),
            }
            diag_proc = subprocess.run(
                [
                    sys.executable,
                    str(isolated_agent_dir / "swarmcontrol_agent.py"),
                    "--diagnose",
                    "--host-id",
                    "missing-core-diag",
                    "--state-dir",
                    str(root / "diag-state"),
                    "--activity-roots",
                    str(fx.work),
                ],
                env=diag_env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(diag_proc.returncode, 0, diag_proc.stderr)
            diag_report = json.loads(diag_proc.stdout)
            self.assertFalse(diag_report["activity_core_loaded"])
            self.assertEqual(diag_report["capture_reader"], "fallback")
            self.assertIn("activity_core.py", diag_report.get("dry_scan_error", ""))


if __name__ == "__main__":
    unittest.main()
