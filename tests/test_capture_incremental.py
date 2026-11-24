"""Step 7 · incremental capture: no action lost to the "last 10 steps" view, bursts, big records, restarts or retries.

Every scenario writes real-format logs for a runtime, appends between scans like a live agent, runs the journal's
incremental scan (`capture_once`) and checks: expected actions == stored actions (losses), no action stored twice
(duplicates), and the per-scan metrics recorded in `capture_metrics`.
"""
import collections
import datetime
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "agent")]
import activity_inspector as ai  # noqa: E402
import activity_shipper  # noqa: E402
import remote_activity  # noqa: E402
from db import Database  # noqa: E402
import work_journal as wj  # noqa: E402

SECRET = "tok_" + "Z" * 24


def stamp(offset: float = 0.0) -> str:
    return datetime.datetime.fromtimestamp(time.time() - 120 + offset, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def append(path: Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        for r in rows:
            f.write((r if isinstance(r, str) else json.dumps(r)) + "\n")


class CaptureHarness(unittest.TestCase):
    """Temp home with agent logs, one shared project folder per runtime, and a journal database."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = Path(self.tmp.name)
        self.home = t / "home"
        self.roots = {n: t / "work" / n for n in ("claude-team", "codex-team", "ag-team", "oc-team")}
        for r in self.roots.values():
            (r / "src").mkdir(parents=True)
        self.outside = t / "private" / "notes"
        self.outside.mkdir(parents=True)
        self.project = t / "work"
        self.agents = set(self.roots)
        self.dbo = Database(t / "journal.db")
        self.addCleanup(self.dbo.close)
        self.conn = sqlite3.connect(self.dbo.db_path)
        self.addCleanup(self.conn.close)
        for p in (patch.object(ai, "HOME", self.home), patch.object(ai, "harnesses", return_value=[])):
            p.start()
            self.addCleanup(p.stop)
        self.scope = ai.Scope(list(self.roots.values()), {}, "host-t")

    def scan(self):
        return wj.capture_once(self.conn, self.agents, self.project, time.time(), None, self.scope)

    def stored(self, agent=None):
        q = "SELECT message, metadata_json FROM events WHERE event_type='observed_step'"
        rows = self.conn.execute(q + (" AND agent_name=?" if agent else ""), (agent,) if agent else ()).fetchall()
        return rows

    # --- runtime writers -------------------------------------------------------------------------
    def claude(self, n, start=0, cwd=None, extra=None, name="c1"):
        f = self.home / f".claude/projects/p/{name}.jsonl"
        root = str(cwd or self.roots["claude-team"])
        if not f.exists():
            append(f, [{"type": "user", "cwd": root, "message": {"role": "user", "content": "start"}}])
        rows = [{"type": "assistant", "cwd": root, "timestamp": stamp(i), "message": {"model": "claude-x", "content": [
            {"type": "tool_use", "name": "Bash", "input": {"command": f"pytest -q --token {SECRET}", "description": f"claude step {i}"}}]}}
            for i in range(start, start + n)]
        append(f, rows + (extra or []))
        return f

    def codex(self, n, start=0):
        rollout = self.home / ".codex/rollout.jsonl"
        root = self.roots["codex-team"]
        append(rollout, [{"timestamp": stamp(i), "payload": {"type": "item_completed", "item": {
            "type": "CommandExecution", "cwd": "file://" + str(root), "command": ["bash", "-lc", f"rg step{i}"],
            "parsed_cmd": [{"type": "unknown", "cmd": f"rg step{i}"}]}}} for i in range(start, start + n)])
        db = self.home / ".codex/state_5.sqlite"
        with sqlite3.connect(db) as c:
            c.execute("CREATE TABLE IF NOT EXISTS threads (id TEXT, cwd TEXT, model TEXT, tokens_used INT, updated_at INT,"
                      " rollout_path TEXT, model_provider TEXT)")
            c.execute("DELETE FROM threads")
            c.execute("INSERT INTO threads VALUES ('t1',?,?,?,?,?,?)", (str(root), "gpt-x", 1, int(time.time()), str(rollout), "openai"))
        return rollout

    def antigravity(self, n, start=0):
        conv = "c0ffee00-0000-4000-8000-0000000000aa"
        root = self.roots["ag-team"]
        t = self.home / ".gemini/antigravity-acp/brain" / conv / ".system_generated/logs/transcript.jsonl"
        append(t, [{"type": "PLANNER_RESPONSE", "content": "working", "created_at": stamp(i), "model": "gemini-x",
                    "tool_calls": [{"name": "run_command", "args": {"CommandLine": json.dumps(f"python3 job{i}.py"),
                                                                     "toolSummary": f"ag step {i}"}}]} for i in range(start, start + n)])
        convdb = self.home / ".gemini/antigravity-acp/conversations" / f"{conv}.db"
        if not convdb.exists():
            convdb.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(convdb) as c:
                c.execute("CREATE TABLE trajectory_metadata_blob (id TEXT, data BLOB)")
                c.execute("INSERT INTO trajectory_metadata_blob VALUES ('main', ?)", (b"\x0a\x10file://" + str(root).encode() + b"\x12:",))
        return t

    def opencode(self, n, start=0, status="completed", seq_base=None):
        db = self.home / ".local/share/opencode/opencode.db"
        db.parent.mkdir(parents=True, exist_ok=True)
        now_ms = int(time.time() * 1000)
        with sqlite3.connect(db) as c:
            c.execute("CREATE TABLE IF NOT EXISTS session_v2(id TEXT PRIMARY KEY, directory TEXT, time_updated INTEGER, model TEXT, title TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS session_message(session_id TEXT, type TEXT, seq INTEGER, time_created INTEGER, data TEXT)")
            c.execute("INSERT INTO session_v2 VALUES ('oc1', ?, ?, 'glm-x', 'Fix') ON CONFLICT(id) DO UPDATE SET time_updated=excluded.time_updated",
                      (str(self.roots["oc-team"]), now_ms + start))
            for i in range(start, start + n):
                part = {"type": "tool", "name": "bash", "state": {"status": status, "input": {"command": f"npm test {i}"}}}
                c.execute("INSERT INTO session_message VALUES ('oc1','assistant',?,?,?)",
                          (seq_base if seq_base is not None else i, now_ms - 60_000 + i, json.dumps({"content": [part]})))


class IncrementalCaptureTests(CaptureHarness):
    def test_script_per_runtime_then_burst_over_20_loses_nothing(self):
        self.claude(3)
        self.codex(3)
        self.antigravity(3)
        self.opencode(3)
        first = self.scan()
        self.assertEqual(first["inserted"], 12, "3 scripted actions per runtime")
        # Burst: 30 actions per runtime appended between two scans (the map would show only the last 10).
        self.claude(30, start=3)
        self.codex(30, start=3)
        self.antigravity(30, start=3)
        self.opencode(30, start=3)
        burst = self.scan()
        self.assertEqual(burst["inserted"], 120, "no loss: 30 per runtime")
        self.assertEqual(self.scan().get("inserted", 0), 0, "a scan with nothing new stores nothing")
        for agent in self.agents:
            self.assertEqual(len(self.stored(agent)), 33, agent)
        rows = self.conn.execute("SELECT agent_name, message, metadata_json, created_at FROM events"
                                 " WHERE event_type='observed_step'").fetchall()
        self.assertEqual(len(rows), 132, "exactly the 132 actions written: none lost, none twice")
        # In the three log-based runtimes every action has its own second, so identical rows would mean a duplicate.
        spaced = [r for r in rows if r[0] != "oc-team"]
        self.assertEqual(len(spaced), len(set(spaced)), "no action stored twice")

    def test_large_records_and_backlog_larger_than_one_read(self):
        big = json.dumps({"type": "user", "message": {"content": [{"type": "tool_result", "content": "A" * 450_000}]}})
        self.claude(2)
        self.scan()
        self.claude(25, start=2, extra=[big] * 3)  # 25 steps followed by 1.3 MB of screenshot-like records
        self.assertEqual(self.scan()["inserted"], 25)
        # A backlog bigger than one read is consumed in order over several scans, never skipped.
        with patch.object(ai, "TAIL_CEILING", 200_000):
            rows = []
            for i in range(40):
                rows.append(big if i % 10 == 0 else None)
            self.claude(40, start=27, extra=[big] * 2)
            total, scans = 0, 0
            capture_ceiling = 200_000
            while scans < 20:
                cap = ai.Capture(wj.load_offsets(self.conn), ceiling=capture_ceiling)
                snap = ai.collect_activity(self.scope, cap)
                got = wj.record(self.conn, snap, self.agents, self.project, time.time(), None, cap, time.perf_counter())
                total += got.get("inserted", 0)
                scans += 1
                if not cap.backlog and got.get("inserted", 0) == 0:
                    break
        self.assertEqual(total, 40, "all 40 recovered across scans")
        self.assertEqual(len(self.stored("claude-team")), 67)

    def test_restart_resumes_from_stored_offsets(self):
        self.claude(5)
        self.scan()
        self.conn.close()
        self.conn = sqlite3.connect(self.dbo.db_path)  # journal process restarted
        self.claude(12, start=5)                         # written while it was down
        self.assertEqual(self.scan()["inserted"], 12)
        self.assertEqual(len(self.stored("claude-team")), 17)

    def test_failed_write_commits_nothing_and_the_retry_stores_once(self):
        self.claude(4)
        self.scan()
        before = self.conn.execute("SELECT offset FROM capture_offsets").fetchall()
        self.claude(15, start=4)
        self.conn.execute("CREATE TABLE fail_flag (x)")
        self.conn.execute("INSERT INTO fail_flag VALUES (1)")
        self.conn.execute("CREATE TRIGGER fail_once BEFORE INSERT ON events WHEN (SELECT COUNT(*) FROM fail_flag) > 0 "
                          "BEGIN SELECT RAISE(ABORT, 'simulated outage'); END")
        self.conn.commit()
        with self.assertRaises(sqlite3.Error):
            self.scan()
        self.assertEqual(self.conn.execute("SELECT offset FROM capture_offsets").fetchall(), before, "offsets did not advance")
        self.assertEqual(len(self.stored("claude-team")), 4)
        self.conn.execute("DELETE FROM fail_flag")
        self.conn.commit()
        self.assertEqual(self.scan()["inserted"], 15)
        self.assertEqual(len(self.stored("claude-team")), 19)

    def test_unfinished_steps_wait_until_they_finish(self):
        self.opencode(1, start=0, status="running", seq_base=0)
        s1 = self.scan()
        self.assertEqual((s1.get("inserted", 0), s1.get("pending", 0)), (0, 1))
        db = self.home / ".local/share/opencode/opencode.db"
        with sqlite3.connect(db) as c:  # the same tool part finishes
            c.execute("UPDATE session_message SET data=replace(data, '\"running\"', '\"completed\"')")
            c.execute("UPDATE session_v2 SET time_updated = time_updated + 5")
        self.assertEqual(self.scan()["inserted"], 1)
        self.assertEqual(len(self.stored("oc-team")), 1)

    def test_rotated_log_is_reported_as_a_gap(self):
        f = self.claude(3)
        self.scan()
        f.write_text("")  # truncated by a rotation
        self.claude(2, start=3)
        result = self.scan()
        self.assertEqual(result.get("gaps"), 1)
        gap = self.conn.execute("SELECT severity, message FROM events WHERE event_type='capture_gap'").fetchone()
        self.assertEqual(gap[0], "WARNING")
        self.assertEqual(len(self.stored("claude-team")), 5)

    def test_upgrade_from_the_sampling_journal_does_not_duplicate(self):
        self.claude(6)
        old_snapshot = ai.collect_activity(self.scope)        # previous journal: map snapshot, content keys
        wj.record(self.conn, old_snapshot, self.agents, self.project, time.time())
        self.assertEqual(len(self.stored("claude-team")), 6)
        first = self.scan()                                    # first incremental scan after the upgrade
        self.assertEqual((first.get("inserted", 0), first.get("duplicates", 0)), (0, 6))
        self.claude(3, start=6)
        self.assertEqual(self.scan()["inserted"], 3)
        self.assertEqual(len(self.stored("claude-team")), 9)

    def test_privacy_is_unchanged(self):
        self.claude(3, cwd=self.outside, name="private-session")    # a session outside the shared folders
        self.claude(3, start=3)
        self.scan()
        blob = json.dumps(self.conn.execute("SELECT message, metadata_json FROM events").fetchall())
        self.assertNotIn(SECRET, blob)
        self.assertNotIn("private", blob)
        self.assertEqual(len(self.stored("claude-team")), 3)

    def test_metrics_record_losses_and_duplicates_per_scan(self):
        self.claude(5)
        self.scan()
        self.claude(22, start=5)
        self.scan()
        self.scan()
        rows = self.conn.execute("SELECT steps_seen, inserted, duplicates, gaps, files_read, bytes_read FROM capture_metrics"
                                 " ORDER BY ts").fetchall()
        self.assertEqual([r[1] for r in rows], [5, 22, 0])
        self.assertTrue(all(r[3] == 0 for r in rows))
        self.assertGreater(rows[1][5], 0)
        self.assertEqual(rows[2][4], 0, "an unchanged log is not re-read")


class AuditFixTests(CaptureHarness):
    """Large records, new logs, sub-agents, session ids and Codex plans: each case in its smallest form, checked against
    the stored journal."""

    def sessions(self):
        return {json.loads(m)["session"] for _, m in self.stored()}

    def test_d1_a_step_record_over_400kB_is_stored(self):
        self.claude(1)
        self.scan()
        f = self.home / ".claude/projects/p/c1.jsonl"
        root = str(self.roots["claude-team"])
        append(f, [{"type": "assistant", "cwd": root, "timestamp": stamp(5), "message": {"model": "claude-x", "content": [
            {"type": "tool_use", "name": "Write", "input": {"file_path": f"{root}/src/big.py", "content": "x = 1\n" * 90_000}}]}}])
        self.claude(2, start=6)
        self.assertGreater(f.stat().st_size, 540_000)
        self.assertEqual(self.scan()["inserted"], 3, "the 540 kB write and the two steps after it")
        self.assertIn("big.py", json.dumps(self.stored("claude-team")))

    def test_d1_a_record_over_the_limit_is_a_visible_gap_and_later_steps_survive(self):
        self.claude(1)
        self.scan()
        with patch.object(ai, "CAPTURE_MAX_RECORD", 100_000):
            self.claude(1, start=1, extra=[json.dumps({"type": "user", "message": {"content": "A" * 150_000}})])
            self.claude(2, start=2)
            result = self.scan()
        self.assertEqual((result["inserted"], result.get("gaps")), (3, 1))
        gap = self.conn.execute("SELECT severity, metadata_json FROM events WHERE event_type='capture_gap'").fetchone()
        self.assertEqual(gap[0], "WARNING")
        self.assertIn("skipped", gap[1])
        self.assertEqual(self.scan().get("inserted", 0), 0, "the skipped record is not retried forever")

    def test_d2_a_new_log_over_640kB_is_read_from_its_first_line(self):
        self.claude(1)
        self.scan()                                     # the journal has run: later logs are new work
        padding = [json.dumps({"type": "user", "message": {"content": "B" * 100_000}})] * 8
        f = self.claude(2, name="c2", extra=padding)    # two steps at the start, then 800 kB of results
        self.claude(1, start=2, name="c2")
        self.assertGreater(f.stat().st_size, 800_000)
        self.assertEqual(self.scan()["inserted"], 3)
        self.assertEqual(len(self.stored("claude-team")), 4)

    def test_d2_a_journal_saved_before_the_baseline_also_reads_new_logs_whole(self):
        self.claude(1)
        self.scan()
        self.conn.execute("DELETE FROM capture_offsets WHERE file_key=?", (ai.BASELINE_KEY,))  # offsets of the previous release
        self.conn.commit()
        padding = [json.dumps({"type": "user", "message": {"content": "B" * 100_000}})] * 8
        self.claude(2, name="c2", extra=padding)
        self.assertEqual(self.scan()["inserted"], 2)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM capture_offsets WHERE file_key=?",
                                           (ai.BASELINE_KEY,)).fetchone()[0], 0, "saved offsets are left as they were")

    def test_d4_claude_sub_agent_actions_are_stored_and_linked(self):
        self.claude(2)
        sub = self.home / ".claude/projects/p/c1/subagents/agent-a1.jsonl"
        root = str(self.roots["claude-team"])
        append(sub, [{"type": "user", "cwd": root, "isSidechain": True, "message": {"role": "user", "content": "check"}}] +
               [{"type": "assistant", "cwd": root, "isSidechain": True, "timestamp": stamp(50 + i), "message": {
                   "model": "claude-x", "content": [{"type": "tool_use", "name": "Bash",
                                                     "input": {"command": f"ls sub{i}", "description": f"sub step {i}"}}]}}
                for i in range(3)])
        self.assertEqual(self.scan()["inserted"], 5, "2 parent steps and 3 sub-agent steps")
        card = next(s for s in ai.collect_activity(self.scope)["sessions"] if s.get("parent_session"))
        self.assertEqual(card["parent_session"], "claude-code:c1")
        self.assertEqual(len(self.sessions()), 2)
        parents = collections.Counter(json.loads(m).get("parent_session") for _, m in self.stored())
        self.assertEqual(parents, {"claude-code:c1": 3, None: 2}, "each sub-agent step names its parent session")

    def test_d5_sessions_sharing_their_first_12_characters_stay_separate(self):
        for name in ("0123456789ab-first", "0123456789ab-second"):
            self.claude(3, name=name)                   # identical steps, same seconds, same folder
        self.assertEqual(self.scan()["inserted"], 6, "neither session is taken for the other's duplicate")
        self.assertEqual(self.sessions(), {"claude-code:0123456789ab-first", "claude-code:0123456789ab-second"})

    def test_d5_rows_stored_with_short_ids_are_not_stored_again(self):
        self.claude(4, name="0123456789ab-long-session")
        old = ai.collect_activity(self.scope)           # what the previous release stored: 12-character ids
        for s in old["sessions"]:
            s["session_id"] = s.pop("legacy_session_id")
        wj.record(self.conn, old, self.agents, self.project, time.time())
        first = self.scan()
        self.assertEqual((first.get("inserted", 0), first.get("duplicates", 0)), (0, 4))
        self.claude(1, start=4, name="0123456789ab-long-session")
        self.assertEqual(self.scan()["inserted"], 1)
        self.assertEqual(len(self.stored("claude-team")), 5)

    def test_d7_codex_plan_updates_are_stored_as_steps(self):
        rollout = self.codex(1)
        append(rollout, [{"timestamp": stamp(30), "type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec",
                          "input": 'tools.update_plan({plan:[{step:"Write tests",status:"completed"},'
                                   '{step:"Ship",status:"in_progress"}]})'}}])
        self.assertEqual(self.scan()["inserted"], 2)
        actions = [json.loads(m)["action"] for _, m in self.stored("codex-team")]
        self.assertIn("plan", actions)


STEP_COLS = "host_id, harness, agent_name, event_type, severity, message, metadata_json, created_at"


def legacy_sample_rows(conn):
    """The rows a legacy journal stored for the same actions: 12-character session ids, no
    `program` (so no " · python3" in the message), and keys in a format no current key reproduces."""
    out = []
    for row in conn.execute(f"SELECT {STEP_COLS} FROM events WHERE event_type='observed_step' ORDER BY id"):
        meta = json.loads(row[6])
        runtime, sid = meta["session"].split(":", 1)
        meta["session"] = f"{runtime}:{sid[:12]}"
        for field in ("program", "command", "task_id"):
            meta.pop(field, None)
        out.append(row[:5] + (row[5].split(" · ")[0], json.dumps(meta, sort_keys=True), row[7]))
    return out


def plant(conn, rows):
    wj.load_offsets(conn)                               # creates the journal tables, as the old journal had them
    for i, row in enumerate(rows):
        conn.execute(f"INSERT INTO events({STEP_COLS}) VALUES (?,?,?,?,?,?,?,?)", row)
        conn.execute("INSERT INTO observed_step_keys(digest, ts) VALUES (?,?)", (f"legacy-format-{i}", row[7]))
    conn.commit()


class LegacyJournalUpgradeTests(CaptureHarness):
    """The first scan after an upgrade preserves actions already stored by a legacy journal,
    on the local journal and on remote ingestion alike, while still storing what that journal missed."""

    def same_second_pair(self):
        """Two real actions of one Antigravity session in the same second (e.g. two commands run back to back)."""
        conv = "c0ffee00-0000-4000-8000-0000000000aa"
        t = self.home / ".gemini/antigravity-acp/brain" / conv / ".system_generated/logs/transcript.jsonl"
        append(t, [{"type": "PLANNER_RESPONSE", "content": "working", "created_at": stamp(40), "model": "gemini-x",
                    "tool_calls": [{"name": "run_command", "args": {"CommandLine": json.dumps(cmd), "toolSummary": cmd}}]}
                   for cmd in ("python3 a.py", "python3 b.py")])

    def old_journal(self, store, keep):
        """Store with the current code into a scratch database, then plant the legacy form of `keep` of them."""
        path = Path(self.tmp.name) / f"scratch-{time.monotonic_ns()}.db"
        Database(path).close()                          # same schema as the journal database
        scratch = sqlite3.connect(path)
        self.addCleanup(scratch.close)
        store(scratch)
        old = legacy_sample_rows(scratch)
        self.assertNotIn(" · ", " ".join(r[5] for r in old))
        return old, [r for i, r in enumerate(old) if i in keep]

    def check_upgrade(self, store, target):
        self.antigravity(4)
        self.same_second_pair()                         # 6 actions; the old journal kept 4 (its 10-step window/sampling)
        old, kept = self.old_journal(store, keep={0, 1, 2, 4})
        self.assertEqual(len(old), 6)
        plant(target, kept)
        store(target)
        rows = target.execute(f"SELECT {STEP_COLS} FROM events WHERE event_type='observed_step'").fetchall()
        self.assertEqual(len(rows), 6, "4 stored before the upgrade + the 2 it missed; none stored twice")
        moments = collections.Counter((r[2], json.loads(r[6])["action"], round(r[7])) for r in rows)
        self.assertEqual(sorted(moments.values()), [1, 1, 1, 1, 2], "only the real same-second pair shares a moment")
        before = len(rows)
        store(target)
        self.assertEqual(len(target.execute("SELECT id FROM events WHERE event_type='observed_step'").fetchall()), before,
                         "a second scan stores nothing")

    def test_local_journal_upgrade_does_not_duplicate_legacy_sample_rows(self):
        def store(conn):
            wj.capture_once(conn, self.agents, self.project, time.time(), None, self.scope)
        self.check_upgrade(store, self.conn)

    def test_remote_ingest_upgrade_does_not_duplicate_legacy_sample_rows(self):
        self.check_upgrade(self.remote_store(use_core=True), self.conn)

    def test_remote_fallback_reader_upgrade_does_not_duplicate_legacy_sample_rows(self):
        with patch.dict("os.environ", {"SWARMCONTROL_ALLOW_FALLBACK": "1"}):
            self.check_upgrade(self.remote_store(use_core=False), self.conn)

    def remote_store(self, use_core):
        def store(conn):
            offsets = getattr(self, "_remote_offsets", {}).get(id(conn), {})
            payload, next_offsets, _ = activity_shipper.collect_incremental_activity(
                raw_roots=[str(self.roots["ag-team"])], host_id="host-r", home_dir=self.home, use_core=use_core,
                offsets=offsets)
            self.assertEqual(payload.get("capture_reader"), "core" if use_core else "fallback")
            path = Path(conn.execute("PRAGMA database_list").fetchone()[2])
            db = Database(path)
            try:
                remote_activity.ingest_remote_activity(db, payload)
            finally:
                db.close()
            self.__dict__.setdefault("_remote_offsets", {})[id(conn)] = next_offsets
        return store

    def test_another_session_at_the_same_moment_is_not_taken_for_a_stored_row(self):
        # Two Antigravity sub-agents of one parent generating images in step: the old journal stored only one.
        self.antigravity(3)
        old, kept = self.old_journal(lambda c: wj.capture_once(c, self.agents, self.project, time.time(), None, self.scope),
                                     keep={0, 1, 2})
        for row in kept:
            meta = json.loads(row[6])
            meta["session"] = "antigravity:83ee39f6-908"   # same agent, action and second, other session
            self.conn.execute(f"INSERT INTO events({STEP_COLS}) VALUES (?,?,?,?,?,?,?,?)", row[:6] + (json.dumps(meta), row[7]))
        self.conn.commit()
        self.assertEqual(self.scan()["inserted"], 3)


if __name__ == "__main__":
    unittest.main()
