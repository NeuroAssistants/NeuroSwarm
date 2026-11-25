"""Hermes session capture and incremental journal regression tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "agent"), str(ROOT / "backend"), str(Path(__file__).resolve().parent)]

import activity_inspector as ai  # noqa: E402
import activity_shipper  # noqa: E402
import step_journal  # noqa: E402
import work_journal  # noqa: E402
from db import Database  # noqa: E402
from event_evidence import SOURCE_POSITION  # noqa: E402

SECRET_ANTHROPIC = "sk-ant-" + "A" * 30
SECRET_GITHUB = "ghp_" + "Z" * 24


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _init_hermes_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        CREATE TABLE sessions (
            id TEXT PRIMARY KEY,
            title TEXT,
            source TEXT,
            model TEXT,
            model_config TEXT,
            parent_session_id TEXT,
            started_at REAL,
            last_activity_at REAL,
            ended_at REAL,
            cwd TEXT,
            input_tokens INTEGER,
            output_tokens INTEGER,
            billing_provider TEXT,
            profile_name TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            role TEXT NOT NULL,
            content TEXT,
            tool_calls TEXT,
            tool_call_id TEXT,
            tool_name TEXT,
            timestamp REAL
        )
        """
    )
    conn.commit()
    return conn


class HermesSessionsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="hermes-test-")
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.home = self.root / "home"
        self.proj = self.root / "work" / "proj-hermes"
        self.outside = self.root / "private" / "personal-notes"
        (self.proj / "src").mkdir(parents=True)
        self.outside.mkdir(parents=True)
        (self.proj / "src" / "main.py").write_text("print('ok')\n", encoding="utf-8")
        (self.proj / "src" / "broken.py").write_text("print('old')\n", encoding="utf-8")
        (self.proj / ".env").write_text(f"API_KEY={SECRET_ANTHROPIC}\n", encoding="utf-8")
        (self.outside / "diary.txt").write_text("do not leak\n", encoding="utf-8")

    def _scope(self) -> ai.Scope:
        return ai.Scope([self.proj], {}, "host-hermes")

    def _seed_hermes_db(self, db_path: Path, profile_label: str = "") -> None:
        now = time.time()
        conn = _init_hermes_db(db_path)
        try:
            # Parent in-scope session (OpenAI + native tool_calls, secrets, .env, failed edit)
            conn.execute(
                """INSERT INTO sessions(id, title, source, model, model_config, parent_session_id,
                   started_at, last_activity_at, ended_at, cwd, input_tokens, output_tokens, billing_provider, profile_name)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "hermes-main-1",
                    f"Implement feature with {SECRET_ANTHROPIC}",
                    "cli",
                    "gpt-4.1",
                    json.dumps({"cwd": str(self.proj)}),
                    None,
                    now - 120,
                    now - 10,
                    None,
                    str(self.proj),
                    320,
                    180,
                    "openai",
                    profile_label,
                ),
            )
            calls_openai = [
                {
                    "id": "call_plan",
                    "type": "function",
                    "function": {
                        "name": "todo",
                        "arguments": json.dumps({"todos": [{"content": f"Check token {SECRET_GITHUB}", "status": "completed"}]}),
                    },
                },
                {
                    "id": "call_write_ok",
                    "type": "function",
                    "function": {"name": "write_file", "arguments": json.dumps({"path": "src/main.py"})},
                },
                {
                    "id": "call_read_secret",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": json.dumps({"path": str(self.proj / ".env")})},
                },
                {
                    "id": "call_search",
                    "type": "function",
                    "function": {"name": "search_files", "arguments": json.dumps({"directory": str(self.proj / "src"), "query": "main"})},
                },
            ]
            conn.execute(
                "INSERT INTO messages(session_id, role, content, tool_calls, timestamp) VALUES(?,?,?,?,?)",
                ("hermes-main-1", "assistant", f"Updated files with password=TopSecret123", json.dumps(calls_openai), now - 90),
            )
            conn.execute(
                "INSERT INTO messages(session_id, role, content, tool_call_id, tool_name, timestamp) VALUES(?,?,?,?,?,?)",
                ("hermes-main-1", "tool", json.dumps({"output": "wrote ok", "exit_code": 0}), "call_write_ok", "write_file", now - 85),
            )
            conn.execute(
                "INSERT INTO messages(session_id, role, content, tool_call_id, tool_name, timestamp) VALUES(?,?,?,?,?,?)",
                ("hermes-main-1", "tool", json.dumps({"output": f"API_KEY={SECRET_ANTHROPIC}"}), "call_read_secret", "read_file", now - 84),
            )
            conn.execute(
                "INSERT INTO messages(session_id, role, content, tool_call_id, tool_name, timestamp) VALUES(?,?,?,?,?,?)",
                ("hermes-main-1", "tool", json.dumps({"output": "src/main.py matched"}), "call_search", "search_files", now - 83),
            )

            # Second message: native Hermes tool_calls format with failed patch, terminal, protected cmd, and MCP coordination
            calls_native = [
                {"id": "call_patch_err", "name": "patch", "arguments": {"path": "src/broken.py"}},
                {"id": "call_term", "name": "terminal", "arguments": {"command": f"pytest -q # {SECRET_GITHUB}"}},
                {"id": "call_term_env", "name": "terminal", "arguments": {"command": "cat .env"}},
                {"id": "call_coord", "name": "mcp__team__channel_result", "arguments": {"text": "done"}},
            ]
            conn.execute(
                "INSERT INTO messages(session_id, role, content, tool_calls, timestamp) VALUES(?,?,?,?,?)",
                ("hermes-main-1", "assistant", f"Final note {SECRET_GITHUB}", json.dumps(calls_native), now - 60),
            )
            conn.execute(
                "INSERT INTO messages(session_id, role, content, tool_call_id, tool_name, timestamp) VALUES(?,?,?,?,?,?)",
                ("hermes-main-1", "tool", json.dumps({"error": "hunk mismatch", "exit_code": 1}), "call_patch_err", "patch", now - 55),
            )
            conn.execute(
                "INSERT INTO messages(session_id, role, content, tool_call_id, tool_name, timestamp) VALUES(?,?,?,?,?,?)",
                ("hermes-main-1", "tool", json.dumps({"output": f"2 passed; token={SECRET_ANTHROPIC}", "exit_code": 0}), "call_term", "terminal", now - 54),
            )
            conn.execute(
                "INSERT INTO messages(session_id, role, content, tool_call_id, tool_name, timestamp) VALUES(?,?,?,?,?,?)",
                ("hermes-main-1", "tool", json.dumps({"output": f"SHOULD_NOT_SHOW={SECRET_ANTHROPIC}", "exit_code": 0}), "call_term_env", "terminal", now - 53),
            )
            conn.execute(
                "INSERT INTO messages(session_id, role, content, tool_call_id, tool_name, timestamp) VALUES(?,?,?,?,?,?)",
                ("hermes-main-1", "tool", json.dumps({"output": "posted"}), "call_coord", "mcp__team__channel_result", now - 52),
            )

            # Child subagent session (no cwd on row; workspace inferred from single in-scope path)
            conn.execute(
                """INSERT INTO sessions(id, title, source, model, parent_session_id,
                   started_at, last_activity_at, billing_provider, profile_name)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                ("hermes-sub-1", "Subagent check", "subagent", "gpt-4.1-mini", "hermes-main-1", now - 40, now - 5, "openai", profile_label),
            )
            conn.execute(
                "INSERT INTO messages(session_id, role, content, tool_calls, timestamp) VALUES(?,?,?,?,?)",
                (
                    "hermes-sub-1",
                    "assistant",
                    "Subagent delegated check",
                    json.dumps([{"id": "sub_delegate", "name": "delegate_task", "arguments": {"path": str(self.proj / "src/main.py")}}]),
                    now - 30,
                ),
            )

            # Out-of-scope session must NEVER appear
            conn.execute(
                "INSERT INTO sessions(id, title, model, last_activity_at, cwd) VALUES(?,?,?,?,?)",
                ("hermes-private-1", "Private diary chat", "gpt-4.1", now - 2, str(self.outside)),
            )
            conn.execute(
                "INSERT INTO messages(session_id, role, content, tool_calls, timestamp) VALUES(?,?,?,?,?)",
                (
                    "hermes-private-1",
                    "assistant",
                    "My secret taxes",
                    json.dumps([{"id": "priv_read", "name": "read_file", "arguments": {"path": str(self.outside / "diary.txt")}}]),
                    now - 1,
                ),
            )
            # Standalone session without cwd/parent_session_id inferred via tool_path
            conn.execute(
                "INSERT INTO sessions(id, title, source, model, started_at, last_activity_at, profile_name) VALUES(?,?,?,?,?,?,?)",
                ("hermes-toolpath-1", "Inferred by tool path", "cli", "gpt-4.1", now - 35, now - 4, profile_label),
            )
            conn.execute(
                "INSERT INTO messages(session_id, role, content, tool_calls, timestamp) VALUES(?,?,?,?,?)",
                (
                    "hermes-toolpath-1",
                    "assistant",
                    "Read main module",
                    json.dumps([{"id": "tp_read", "name": "read_file", "arguments": {"path": str(self.proj / "src/main.py")}}]),
                    now - 20,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def test_default_profile_and_env_home_capture_and_privacy(self) -> None:
        default_db = self.home / ".hermes" / "state.db"
        coder_db = self.home / ".hermes" / "profiles" / "coder" / "state.db"
        custom_root = self.root / "custom-hermes-home"
        custom_db = custom_root / "state.db"
        self._seed_hermes_db(default_db)
        self._seed_hermes_db(coder_db, profile_label="coder")
        self._seed_hermes_db(custom_db)

        env_clean = {k: v for k, v in os.environ.items() if k != "HERMES_HOME"}
        env_clean.update({"SWARMCONTROL_SHARE_COMMANDS": "1", "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "1"})

        with patch.dict(os.environ, env_clean, clear=True), patch.object(ai, "HOME", self.home):
            snap = ai.collect_activity(self._scope())

        self.assertEqual([s for s in snap["sessions"] if "hermes-private-1" in s["session_id"]], [])
        main_default = next(s for s in snap["sessions"] if s["session_id"] == "hermes:hermes-main-1")
        main_coder = next(s for s in snap["sessions"] if s["session_id"] == "hermes:coder:hermes-main-1")
        sub_default = next(s for s in snap["sessions"] if s["session_id"] == "hermes:hermes-sub-1")
        tp_default = next(s for s in snap["sessions"] if s["session_id"] == "hermes:hermes-toolpath-1")

        self.assertEqual(main_default["harness"], "hermes")
        self.assertEqual(main_default["harness_name"], "Hermes Agent")
        self.assertEqual(main_coder["harness_name"], "Hermes Agent · coder")
        self.assertEqual(main_default["tokens_used"], 500)
        self.assertEqual(main_default["provider"], "openai")
        self.assertEqual(sub_default["parent_session"], "hermes:hermes-main-1")
        self.assertEqual(sub_default["owner_basis"], "parent_session")
        self.assertEqual(sub_default["workspace"], str(self.proj))
        self.assertEqual(tp_default["owner_basis"], "tool_path")
        self.assertEqual(tp_default["workspace"], str(self.proj))

        # Confirmed vs failed edits, .env stripping, redaction
        self.assertIn(str(self.proj / "src/main.py"), main_default["files_edited"])
        self.assertNotIn(str(self.proj / "src/broken.py"), main_default["files_edited"])
        self.assertFalse(any(p.endswith(".env") for p in main_default["files_read"] + main_default["files_edited"]))
        dumped = json.dumps(snap)
        self.assertNotIn(SECRET_ANTHROPIC, dumped)
        self.assertNotIn(SECRET_GITHUB, dumped)
        self.assertNotIn("TopSecret123", dumped)
        self.assertNotIn("Private diary chat", dumped)

        # Every tool step carries valid SOURCE_POSITION src even in map mode
        for st in main_default["steps"]:
            self.assertRegex(st["src"], SOURCE_POSITION)

        # Capture mode preserves command output (redacted) for terminal, suppresses for cat .env
        with patch.dict(os.environ, env_clean, clear=True), patch.object(ai, "HOME", self.home):
            cap = ai.Capture()
            cap_snap = ai.collect_activity(self._scope(), cap)
        cap_main = next(s for s in cap_snap["sessions"] if s["session_id"] == "hermes:hermes-main-1")
        steps_by_tool = cap_main["capture_steps"]
        patch_step = next(s for s in steps_by_tool if s["tool"] == "patch")
        self.assertEqual(patch_step["status"], "error")
        term_steps = [s for s in steps_by_tool if s["tool"] == "terminal"]
        self.assertEqual(term_steps[0]["program"], "pytest")
        self.assertEqual(term_steps[0]["exit_code"], 0)
        self.assertIn("[redacted", term_steps[0]["command_output"])
        self.assertNotIn(SECRET_ANTHROPIC, term_steps[0]["command_output"])
        self.assertNotIn("command_output", term_steps[1])
        self.assertIn("SHOULD_NOT_SHOW", json.dumps(cap_snap)) if False else self.assertNotIn("SHOULD_NOT_SHOW", json.dumps(cap_snap))
        for st in cap_main["capture_steps"]:
            self.assertRegex(st["src"], SOURCE_POSITION)

        # HERMES_HOME override isolation
        env_custom = {**env_clean, "HERMES_HOME": str(custom_root)}
        conn = sqlite3.connect(str(custom_db))
        conn.execute("UPDATE sessions SET title = 'Custom HERMES_HOME session' WHERE id = 'hermes-main-1'")
        conn.execute("DELETE FROM messages WHERE session_id = 'hermes-main-1'")
        conn.commit()
        conn.close()
        with patch.dict(os.environ, env_custom, clear=True), patch.object(ai, "HOME", self.home):
            custom_snap = ai.collect_activity(self._scope())
        custom_main = next(s for s in custom_snap["sessions"] if s["session_id"] == "hermes:hermes-main-1")
        self.assertIn("Custom HERMES_HOME session", custom_main["what_done"])

    def test_hermes_incremental_journal_waits_for_running_tool_and_deduplicates(self) -> None:
        db_path = self.home / ".hermes" / "state.db"
        now = time.time()
        conn = _init_hermes_db(db_path)
        conn.execute(
            "INSERT INTO sessions(id, title, model, started_at, last_activity_at, cwd) VALUES(?,?,?,?,?,?)",
            ("hermes-inc-1", "Incremental", "gpt-4.1", now - 60, now - 10, str(self.proj)),
        )
        conn.execute(
            "INSERT INTO messages(session_id, role, content, tool_calls, timestamp) VALUES(?,?,?,?,?)",
            (
                "hermes-inc-1",
                "assistant",
                "First edit done, second running",
                json.dumps([
                    {"id": "c_done", "name": "write_file", "arguments": {"path": "src/main.py"}},
                    {"id": "c_wait", "name": "patch", "arguments": {"path": "src/broken.py"}},
                ]),
                now - 30,
            ),
        )
        conn.execute(
            "INSERT INTO messages(session_id, role, content, tool_call_id, tool_name, timestamp) VALUES(?,?,?,?,?,?)",
            ("hermes-inc-1", "tool", json.dumps({"output": "ok", "exit_code": 0}), "c_done", "write_file", now - 25),
        )
        conn.commit()
        conn.close()

        jdb_file = self.root / "journal.db"
        Database(str(jdb_file)).close()
        env_clean = {k: v for k, v in os.environ.items() if k != "HERMES_HOME"}

        with sqlite3.connect(str(jdb_file)) as jdb, \
             patch.dict(os.environ, env_clean, clear=True), \
             patch.object(ai, "HOME", self.home):
            # Snapshot shows in-flight tool as running
            snap1 = ai.collect_activity(self._scope())
            s1 = next(s for s in snap1["sessions"] if s["session_id"] == "hermes:hermes-inc-1")
            self.assertEqual([st.get("status") for st in s1["steps"]], ["completed", "running"])

            work_journal.capture_once(jdb, {s1["agent_name"]}, self.proj, now=now, scope=self._scope())
            rows1 = jdb.execute("SELECT id, message, metadata_json FROM events ORDER BY id").fetchall()
            self.assertEqual(len(rows1), 1)
            self.assertIn("main.py", rows1[0][1])

            # Same state rescan inserts nothing
            work_journal.capture_once(jdb, {s1["agent_name"]}, self.proj, now=now + 1, scope=self._scope())
            self.assertEqual(jdb.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)

            # Complete c_wait and append a third terminal command
            conn2 = sqlite3.connect(str(db_path))
            conn2.execute(
                "INSERT INTO messages(session_id, role, content, tool_call_id, tool_name, timestamp) VALUES(?,?,?,?,?,?)",
                ("hermes-inc-1", "tool", json.dumps({"output": "patched", "exit_code": 0}), "c_wait", "patch", now - 15),
            )
            conn2.execute(
                "INSERT INTO messages(session_id, role, content, tool_calls, timestamp) VALUES(?,?,?,?,?)",
                ("hermes-inc-1", "assistant", "Done tests", json.dumps([{"id": "c_run", "name": "terminal", "arguments": {"command": "pytest"}}]), now - 10),
            )
            conn2.execute(
                "INSERT INTO messages(session_id, role, content, tool_call_id, tool_name, timestamp) VALUES(?,?,?,?,?,?)",
                ("hermes-inc-1", "tool", json.dumps({"output": "ok", "exit_code": 0}), "c_run", "terminal", now - 9),
            )
            conn2.commit()
            conn2.close()

            work_journal.capture_once(jdb, {s1["agent_name"]}, self.proj, now=now + 2, scope=self._scope())
            rows2 = jdb.execute("SELECT id, message FROM events ORDER BY id").fetchall()
            self.assertEqual(len(rows2), 3)
            self.assertEqual(len({r[0] for r in rows2}), 3)
