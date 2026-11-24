#!/usr/bin/env python3
"""Independent capture-coverage audit.

Writes a KNOWN script of agent actions in each runtime's own log format (shapes copied from real
Codex / Claude Code / OpenCode / Antigravity records), captures it through
  * local:  backend/work_journal.capture_once  (step 7)
  * remote: agent/swarmcontrol_agent.ship_activity_once -> HTTP /api/v1/ingest/activity (step 8),
            with the shared core reader (what a URL install uses) and with the agent's fallback reader,
then compares what was stored with what was written: captured, missing, duplicated, extra,
wrong agent, wrong file, gap events, and privacy leaks.

    python3 tests/product_qa/capture_audit.py            # table + JSON summary on stdout
    python3 tests/product_qa/capture_audit.py --json out.json

Nothing leaves the machine: a temporary HOME, temporary databases and a loopback console.
"""
from __future__ import annotations

import argparse
import collections
import contextlib
import json
import os
import sqlite3
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "agent"), str(Path(__file__).resolve().parent)]

import activity_inspector as ai  # noqa: E402
import work_journal  # noqa: E402
from db import Database  # noqa: E402

SECRET = "sk-live-" + "Q7" * 16
SECRET2 = "ghp_" + "Z9" * 18
RUNTIMES = ("codex", "claude", "opencode", "antigravity")


_TICK = [0]


def id_clock_ms() -> int:
    """Millisecond clock for generated session ids: 70 s apart per writer, so ids only collide when a scenario
    launches sessions at the same instant on purpose (FORCE_SAME_MS)."""
    if FORCE_SAME_MS[0]:
        return FORCE_SAME_MS[0]
    _TICK[0] += 1
    return int(time.time() * 1000) - 3_600_000 + _TICK[0] * 70_000   # > 65 s: OpenCode's id prefix moves


FORCE_SAME_MS = [0]


def iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(ts if ts is not None else time.time()))


# ---------------------------------------------------------------- runtime writers
class Writer:
    """Appends one runtime's records. Every action returns its expected (action, basename, program)."""

    runtime = ""

    def __init__(self, lab: "Lab", cwd: Path, sid: str | None = None, skew: float = 0.0):
        self.lab, self.cwd, self.sid, self.skew = lab, cwd, sid or uuid.uuid4().hex[:12], skew
        self.n = 0
        self.expected: list[tuple[str, str, str]] = []
        self.pending: list[list[bytes]] = []     # records (each a list of lines) not yet written

    def now(self) -> float:
        return time.time() + self.skew - 2

    # action API: queue records; flush() writes them (all, or line by line via trickle())
    def edit(self, rel: str, big: int = 0): raise NotImplementedError
    def read(self, rel: str): raise NotImplementedError
    def run(self, cmd: str, program: str): raise NotImplementedError
    def plan(self): raise NotImplementedError
    def coordinate(self): raise NotImplementedError

    def script(self, prefix: str = "") -> None:
        """The fixed known script: 3 edits, 2 commands, 1 read, 1 plan update, 1 coordination."""
        self.edit(f"src/{prefix}a.py")
        self.edit(f"src/{prefix}b.py")
        self.edit(f"docs/{prefix}c.md")
        self.run("python3 -m unittest discover -s tests", "python3")
        self.run("git status --short", "git")
        self.read("README.md")
        self.plan()
        self.coordinate()

    def lines(self) -> list[bytes]:
        out = [ln for rec in self.pending for ln in rec]
        self.pending = []
        return out

    def flush(self) -> None:
        self.write_lines(self.lines())

    def write_lines(self, lines: list[bytes]) -> None:
        raise NotImplementedError

    def expect(self, action: str, rel: str | None, program: str = "") -> None:
        self.expected.append((action, Path(rel).name if rel else "", program))


class JsonlWriter(Writer):
    path: Path

    def write_lines(self, lines: list[bytes]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("ab") as f:
            for ln in lines:
                f.write(ln)
        self.touch()

    def touch(self) -> None:
        pass

    def rec(self, *objs: dict) -> None:
        self.pending.append([(json.dumps(o, ensure_ascii=False) + "\n").encode() for o in objs])


class CodexWriter(JsonlWriter):
    runtime = "codex"

    def __init__(self, lab, cwd, sid=None, skew=0.0):
        if sid is None:  # Codex thread ids are UUIDv7: 48-bit millisecond timestamp first
            ms, r = id_clock_ms(), uuid.uuid4().hex
            sid = f"{ms:012x}"[:8] + "-" + f"{ms:012x}"[8:] + "-7" + r[:3] + "-" + r[3:7] + "-" + r[7:19]
        super().__init__(lab, cwd, sid, skew)
        self.path = lab.home / f".codex/sessions/2026/11/23/rollout-{self.sid}.jsonl"
        db = lab.home / ".codex/state_5.sqlite"
        db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(db) as c:
            c.execute("CREATE TABLE IF NOT EXISTS threads (id TEXT PRIMARY KEY, cwd TEXT, model TEXT, tokens_used INT, "
                      "updated_at INT, rollout_path TEXT, model_provider TEXT)")
            c.execute("INSERT INTO threads VALUES (?,?,?,?,?,?,?)", (self.sid, str(cwd), "gpt-x", 0, int(time.time()), str(self.path), "openai"))
        self.rec({"timestamp": iso(self.now()), "type": "session_meta", "payload": {"id": self.sid, "cwd": str(cwd)}})

    def touch(self) -> None:
        with sqlite3.connect(self.lab.home / ".codex/state_5.sqlite") as c:
            c.execute("UPDATE threads SET updated_at=? WHERE id=?", (int(time.time()), self.sid))

    def _noise(self):
        return [{"timestamp": iso(self.now()), "type": "event_msg", "payload": {"type": "token_count", "info": {"total": 1}}},
                {"timestamp": iso(self.now()), "type": "response_item", "payload": {"type": "reasoning", "summary": []}}]

    def edit(self, rel, big=0):
        self.n += 1
        target = str(self.cwd / rel)
        diff = "@@ -1 +1 @@\n-old\n+new\n" + ("x" * big)
        self.rec(*self._noise(),
                 {"timestamp": iso(self.now()), "type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec",
                  "call_id": f"c{self.n}", "input": "await tools.apply_patch({patch: '...'})"}},
                 {"timestamp": iso(self.now()), "type": "event_msg", "payload": {"type": "item_completed", "item": {
                     "id": f"fc{self.n}", "type": "FileChange", "status": "completed",
                     "changes": {target: {"type": "update", "unified_diff": diff}}, "stdout": "", "stderr": ""}}})
        self.expect("file_edit", rel)

    def _cmd(self, cmd, parsed):
        self.n += 1
        self.rec(*self._noise(),
                 {"timestamp": iso(self.now()), "type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec",
                  "call_id": f"c{self.n}", "input": "await tools.exec_command({cmd: '...'})"}},
                 {"timestamp": iso(self.now()), "type": "event_msg", "payload": {"type": "item_completed", "item": {
                     "id": f"ce{self.n}", "type": "CommandExecution", "command": ["/bin/bash", "-lc", cmd],
                     "cwd": "file://" + str(self.cwd), "parsed_cmd": parsed, "status": "completed", "exit_code": 0,
                     "aggregated_output": "ok", "source": "agent", "process_id": 1, "duration": 1}}})

    def run(self, cmd, program):
        self._cmd(cmd, [{"type": "unknown", "cmd": cmd}])
        self.expect("shell", None, program)

    def read(self, rel):
        self._cmd(f"cat {rel}", [{"type": "read", "cmd": f"cat {rel}", "name": Path(rel).name, "path": rel}])
        self.expect("file_read", rel)

    def plan(self):
        # Real Codex code mode updates the plan inside `exec`; the journal treats it as map context, not a step.
        self.rec({"timestamp": iso(self.now()), "type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec",
                  "input": 'tools.update_plan({plan:[{step:"Write tests",status:"completed"},{step:"Ship",status:"in_progress"}]})'}})
        self.expect("plan", None)

    def coordinate(self):
        self.n += 1
        self.rec({"timestamp": iso(self.now()), "type": "response_item", "payload": {"type": "function_call", "name": "tool_call",
                  "call_id": f"d{self.n}", "arguments": json.dumps({"name": "openbot.channel_result", "arguments": {"text": "done"}})}},
                 {"timestamp": iso(self.now()), "type": "event_msg", "payload": {"type": "item_completed", "item": {
                     "id": f"dt{self.n}", "type": "DynamicToolCall", "tool": "tool_call", "status": "completed", "success": True,
                     "arguments": {"name": "openbot.channel_result", "arguments": {"text": "done"}}}}})
        self.expect("coordination", None)

    def secret_command(self):
        self._cmd(f'curl -H "Authorization: Bearer {SECRET}" https://example.invalid && export TOKEN={SECRET2}',
                  [{"type": "unknown", "cmd": f'curl -H "Authorization: Bearer {SECRET}" https://example.invalid'}])
        self.expect("shell", None, "curl")


class ClaudeWriter(JsonlWriter):
    runtime = "claude"

    def __init__(self, lab, cwd, sid=None, skew=0.0, subagent_of: "ClaudeWriter | None" = None):
        super().__init__(lab, cwd, sid, skew)
        proj = str(cwd).replace("/", "-")
        if subagent_of is not None:   # Claude Code writes Task sub-agent transcripts below the parent session
            self.path = subagent_of.path.with_suffix("") / "subagents" / f"agent-{self.sid}.jsonl"
        else:
            self.path = lab.home / ".claude/projects" / proj / f"{self.sid}.jsonl"
        self.rec({"type": "user", "cwd": str(cwd), "sessionId": self.sid, "timestamp": iso(self.now()),
                  "message": {"role": "user", "content": "please fix the parser"}})
        self.cur_cwd = cwd

    def _use(self, name, inp):
        self.n += 1
        tid = f"toolu_{self.sid}_{self.n}"
        self.rec({"type": "assistant", "cwd": str(self.cur_cwd), "sessionId": self.sid, "timestamp": iso(self.now()),
                  "message": {"id": f"msg_{self.n}", "model": "claude-x", "role": "assistant",
                              "content": [{"type": "tool_use", "id": tid, "name": name, "input": inp}]}},
                 {"type": "user", "cwd": str(self.cur_cwd), "sessionId": self.sid, "timestamp": iso(self.now()),
                  "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": tid, "content": "ok"}]}})

    def edit(self, rel, big=0):
        if big:
            self._use("Write", {"file_path": str(self.cwd / rel), "content": "y" * big})
        else:
            self._use("Edit", {"file_path": str(self.cwd / rel), "old_string": "a", "new_string": "b"})
        self.expect("file_edit", rel)

    def edit_abs(self, path: Path, label_rel: str):
        self._use("Edit", {"file_path": str(path), "old_string": "a", "new_string": "b"})
        self.expect("file_edit", label_rel)

    def read(self, rel):
        self._use("Read", {"file_path": str(self.cwd / rel)})
        self.expect("file_read", rel)

    def run(self, cmd, program):
        self._use("Bash", {"command": cmd, "description": "Run it"})
        self.expect("shell", None, program)

    def plan(self):
        self._use("TodoWrite", {"todos": [{"content": "Write tests", "status": "completed"}, {"content": "Ship", "status": "in_progress"}]})
        self.expect("plan", None)

    def coordinate(self):
        self._use("mcp__openbot__channel_result", {"text": "done"})
        self.expect("coordination", None)

    def secret_command(self):
        self._use("Bash", {"command": f'curl -H "Authorization: Bearer {SECRET}" https://example.invalid && export TOKEN={SECRET2}'})
        self.expect("shell", None, "curl")


class AntigravityWriter(JsonlWriter):
    runtime = "antigravity"

    def __init__(self, lab, cwd, sid=None, skew=0.0):
        super().__init__(lab, cwd, sid or str(uuid.uuid4()), skew)
        base = lab.home / ".gemini/antigravity-acp"
        self.path = base / "brain" / self.sid / ".system_generated/logs/transcript.jsonl"
        (base / "conversations").mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(base / "conversations" / f"{self.sid}.db") as c:
            c.execute("CREATE TABLE trajectory_metadata_blob (id TEXT, data BLOB)")
            c.execute("INSERT INTO trajectory_metadata_blob VALUES ('main', ?)", (b"\x0a\x10file://" + str(cwd).encode() + b"\x12:",))
        self.rec({"type": "USER_INPUT", "content": "fix the parser", "created_at": iso(self.now())})

    def _call(self, name, args):
        self.rec({"type": "PLANNER_RESPONSE", "content": "Working.", "created_at": iso(self.now()), "model": "gemini-x",
                  "tool_calls": [{"name": name, "args": args}]})

    # Tool names and argument shapes as they appear in real transcripts (string values JSON-quoted).
    def edit(self, rel, big=0):
        q = json.dumps(str(self.cwd / rel))
        if big:
            self._call("write_file", {"Path": q, "Content": json.dumps("z" * big), "Overwrite": "true"})
        else:
            self._call("edit_file", {"Path": q, "Target": '"a"', "Replacement": '"b"'})
        self.expect("file_edit", rel)

    def read(self, rel):
        self._call("read_file", {"Path": json.dumps(str(self.cwd / rel))})
        self.expect("file_read", rel)

    def run(self, cmd, program):
        self._call("run_command", {"CommandLine": json.dumps(cmd), "WaitMsBeforeAsync": "5000", "toolSummary": '"Run it"'})
        self.expect("shell", None, program)

    def plan(self):
        self._call("manage_task", {"Action": '"update"'})
        self.expect("plan", None)

    def coordinate(self):
        self._call("mcp_openbot_tool_call", {"arguments": json.dumps({"arguments": {"text": "done"}, "name": "openbot.channel_result"}),
                                             "toolSummary": '"Post the result"'})
        self.expect("coordination", None)

    def secret_command(self):
        self._call("run_command", {"CommandLine": json.dumps(f'curl -H "Authorization: Bearer {SECRET}" x && export TOKEN={SECRET2}')})
        self.expect("shell", None, "curl")


class OpenCodeWriter(Writer):
    runtime = "opencode"

    def __init__(self, lab, cwd, sid=None, skew=0.0):
        # OpenCode ids: "ses_" + 12 hex of a descending millisecond clock + 14 random chars (real format)
        sid = sid or "ses_%012x%s" % (0xFFFFFFFFFFFF - id_clock_ms(), uuid.uuid4().hex[:14])
        super().__init__(lab, cwd, sid, skew)
        self.db = lab.home / ".local/share/opencode/opencode.db"
        self.db.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db) as c:
            c.execute("CREATE TABLE IF NOT EXISTS session_v2 (id TEXT PRIMARY KEY, project_id TEXT, slug TEXT, directory TEXT, title TEXT, "
                      "version TEXT, model TEXT, time_created INT, time_updated INT, tokens_input INT DEFAULT 0, tokens_output INT DEFAULT 0, "
                      "summary_files INT, summary_additions INT, summary_deletions INT)")
            c.execute("CREATE TABLE IF NOT EXISTS session_message (id TEXT PRIMARY KEY, session_id TEXT, type TEXT, seq INT, "
                      "time_created INT, time_updated INT, data TEXT)")
            ms = int(time.time() * 1000)
            c.execute("INSERT INTO session_v2 (id, project_id, slug, directory, title, version, model, time_created, time_updated) "
                      "VALUES (?,?,?,?,?,?,?,?,?)", (self.sid, "p1", "slug", str(cwd), "Fix parser", "1", '{"providerID":"x","id":"m"}', ms, ms))
        self.seq = 0

    def _tool(self, name, inp, out="ok"):
        self.n += 1
        ms = int(self.now() * 1000)
        part = {"type": "tool", "id": f"call_{self.n}", "name": name, "executed": False,
                "state": {"status": "completed", "input": inp, "content": out, "metadata": {"truncated": False}},
                "time": {"created": ms - 5, "ran": ms - 3, "completed": ms}}
        self.pending.append([json.dumps({"role": "assistant", "content": [part]}).encode()])

    def write_lines(self, lines):
        with sqlite3.connect(self.db) as c:
            for data in lines:
                self.seq += 1
                ms = int(self.now() * 1000)
                c.execute("INSERT INTO session_message VALUES (?,?,?,?,?,?,?)",
                          (f"msg_{self.sid}_{self.seq}", self.sid, "assistant", self.seq, ms, ms, data.decode()))
            c.execute("UPDATE session_v2 SET time_updated=? WHERE id=?", (int(time.time() * 1000) + self.seq, self.sid))

    def edit(self, rel, big=0):
        self._tool("edit", {"filePath": str(self.cwd / rel), "oldString": "a", "newString": "b"}, "x" * big if big else "ok")
        self.expect("file_edit", rel)

    def read(self, rel):
        self._tool("read", {"filePath": str(self.cwd / rel)})
        self.expect("file_read", rel)

    def run(self, cmd, program):
        self._tool("bash", {"command": cmd, "description": "Run it"})
        self.expect("shell", None, program)

    def plan(self):
        self._tool("todowrite", {"todos": [{"content": "Write tests", "status": "completed"}, {"content": "Ship", "status": "in_progress"}]})
        self.expect("plan", None)

    def coordinate(self):
        self._tool("openbot_channel_result", {"text": "done"})
        self.expect("coordination", None)

    def secret_command(self):
        self._tool("bash", {"command": f'curl -H "Authorization: Bearer {SECRET}" x && export TOKEN={SECRET2}'})
        self.expect("shell", None, "curl")


WRITERS = {"codex": CodexWriter, "claude": ClaudeWriter, "opencode": OpenCodeWriter, "antigravity": AntigravityWriter}


# ---------------------------------------------------------------- capture paths
class Lab:
    """A temporary machine: HOME with runtime logs, two shared team folders and one private folder."""

    def __init__(self, base: Path):
        self.base = base
        self.home = base / "home"
        self.teams = base / "teams"
        self.alpha = self.teams / "alpha-repo"
        self.beta = self.teams / "beta-repo"
        self.private = base / "private" / "taxes"
        for d in (self.home, self.alpha / "src", self.alpha / "docs", self.beta / "src", self.beta / "docs", self.private):
            d.mkdir(parents=True, exist_ok=True)
        for d in (self.alpha, self.beta):
            for rel in ("README.md", ".env", "src/app.py"):
                (d / rel).write_text("x\n")
        (self.private / "2025.csv").write_text("income\n")
        self.labels = {str(self.alpha): "agent-alpha", str(self.beta): "agent-beta"}


class LocalPath:
    name = "local"

    def __init__(self, lab: Lab):
        self.lab = lab
        self.dbfile = lab.base / "local.db"
        Database(str(self.dbfile))
        self.db = sqlite3.connect(self.dbfile)
        self.scope = ai.Scope([lab.alpha, lab.beta], lab.labels, "lab-host")

    def scan(self) -> None:
        prev = ai.HOME
        ai.HOME = self.lab.home
        try:
            work_journal.capture_once(self.db, {"agent-alpha", "agent-beta"}, self.lab.teams, time.time(), scope=self.scope)
        finally:
            ai.HOME = prev

    def events(self) -> list[dict]:
        return [dict(zip(("agent", "type", "sev", "msg", "meta"), r)) for r in
                self.db.execute("SELECT agent_name, event_type, severity, message, metadata_json FROM events ORDER BY id")]

    def raw_dump(self) -> str:
        return "\n".join(" ".join(map(str, r)) for t in ("events",) for r in self.db.execute(f"SELECT * FROM {t}"))

    def close(self):
        self.db.close()


class RemotePath:
    def __init__(self, lab: Lab, srv, token: str, use_core: bool, skew_host: str = "lab-remote"):
        import swarmcontrol_agent as sa
        self.sa, self.lab, self.srv, self.token, self.use_core = sa, lab, srv, token, use_core
        self.name = "remote-core" if use_core else "remote-fallback"
        self.state = lab.base / f"agent-state-{self.name}"
        self.state.mkdir(exist_ok=True)
        self.host = skew_host
        self.fail_next = False

    def scan(self) -> None:
        os.environ["SWARMCONTROL_AGENT_LABELS"] = ",".join(f"{k}={v}" for k, v in self.lab.labels.items())
        poster = self.sa.post_json
        if self.fail_next:
            self.fail_next = False

            def poster(url, token, payload, timeout=8):  # noqa: E306
                raise OSError("simulated outage")
        with contextlib.suppress(OSError):
            self.sa.ship_activity_once(self.srv.base_url, self.token, [str(self.lab.alpha), str(self.lab.beta)], self.host,
                                       self.state, home_dir=self.lab.home, poster=poster, use_core=self.use_core)

    def events(self) -> list[dict]:
        with sqlite3.connect(self.srv.db_path) as c:
            rows = c.execute("SELECT agent_name, event_type, severity, message, metadata_json FROM events WHERE host_id=? ORDER BY id",
                             (self.host,)).fetchall()
        return [dict(zip(("agent", "type", "sev", "msg", "meta"), r)) for r in rows]

    def raw_dump(self) -> str:
        with sqlite3.connect(self.srv.db_path) as c:
            return "\n".join(" ".join(map(str, r)) for r in c.execute("SELECT * FROM events WHERE host_id=?", (self.host,)))

    def close(self):
        pass


# ---------------------------------------------------------------- comparison
def compare(writers: list[Writer], events: list[dict], expect_agents: dict[str, str]) -> dict:
    """Match stored steps to the writers' known actions. Sessions are stored as `<runtime>:<first 12 chars of id>`;
    when two writers share that prefix the console cannot tell them apart (counted as merged_sessions) and the
    matcher falls back to the agent label to split them."""
    steps = [e for e in events if e["type"] == "observed_step"]
    gaps = [e for e in events if e["type"] == "capture_gap"]
    merged_writers: set[str] = set()   # writers whose actions were stored under a session id shared with another writer
    by_sid: dict[str, list[dict]] = collections.defaultdict(list)
    unmatched_sessions = []
    res_alt_ids: set[str] = set()
    for e in steps:
        m = json.loads(e["meta"] or "{}")
        sess = str(m.get("session", ""))
        exact = [w for w in writers if sess.split(":", 1)[-1] == w.sid[:96 - len(sess.split(":", 1)[0]) - 1]]
        cands = exact or [w for w in writers if sess.endswith(":" + w.sid[:12]) or w.sid in sess]
        if not exact and len(cands) > 1:   # the stored id cannot tell these sessions apart
            merged_writers.update(w.sid for w in cands)
        if not cands:   # the agent's fallback reader names Codex sessions by the END of the rollout file name
            cands = [w for w in writers if sess.endswith(":" + w.sid[-12:])]
            if cands:
                res_alt_ids.add(cands[0].sid)
        if len(cands) > 1:
            cands = [w for w in cands if expect_agents.get(w.sid) == e["agent"]] or cands[:1]
        if not cands:
            unmatched_sessions.append(sess)
            continue
        w = cands[0]
        by_sid[w.sid].append({"agent": e["agent"], "action": m.get("action"), "files": [Path(f).name for f in m.get("files") or []],
                              "paths": m.get("files") or [], "program": m.get("program") or "", "msg": e["msg"]})
    res = collections.Counter({k: 0 for k in ("expected", "captured", "missing", "duplicates", "extra",
                                               "wrong_agent", "wrong_file_root")})
    detail = []
    for w in writers:
        got = by_sid.get(w.sid, [])
        exp = collections.Counter(w.expected)
        res["expected"] += sum(exp.values())
        pool = list(got)
        for (action, base, program), k in exp.items():
            for _ in range(k):
                hit = next((g for g in pool if g["action"] == action and (not base or base in g["files"]) and
                            (not program or g["program"] == program)), None)
                if hit is None:
                    res["missing"] += 1
                    detail.append(f"{w.runtime}/{w.sid[:12]} missing {action} {base or program}")
                else:
                    pool.remove(hit)
                    res["captured"] += 1
        # A duplicate is a stored copy beyond what was written (repeating the same command on purpose is not one).
        sig = collections.Counter((g["action"], g["files"][0] if g["files"] else "", g["program"]) for g in got)
        wrote = collections.Counter((a, b, pr) for a, b, pr in w.expected)
        res["duplicates"] += sum(max(0, v - max(wrote.get(k, 0), wrote.get((k[0], k[1], ""), 0), wrote.get((k[0], "", k[2]), 0)))
                                 for k, v in sig.items())
        res["extra"] += len(pool)
        for g in pool[:4]:
            detail.append(f"{w.runtime}/{w.sid[:12]} extra {g['action']} {g['files']} {g['msg'][:60]}")
        want = expect_agents.get(w.sid)
        bad = [g for g in got if want and g["agent"] != want]
        res["wrong_agent"] += len(bad)
        others = {"alpha-repo", "beta-repo"} - {Path(w.cwd).name}
        wrong_root = [g for g in got if any(o in p for p in g["paths"] for o in others)]   # a file named under the other team
        res["wrong_file_root"] += len(wrong_root)
        for g in (bad + wrong_root)[:2]:
            detail.append(f"{w.runtime}/{w.sid[:12]} agent={g['agent']} files={g['paths']} expected agent={want} root={root}")
    res["merged_sessions"] = len(merged_writers)   # measured on what was stored, not on the generated ids
    res["other_session_id"] = len(res_alt_ids)
    res["foreign_sessions"] = len(unmatched_sessions)
    res["gap_events"] = len(gaps)
    return {"counts": dict(res), "detail": detail}


def privacy_leaks(dump: str, lab: Lab) -> list[str]:
    needles = {"secret sk-live": SECRET, "secret ghp_": SECRET2, "private folder": "taxes", "private file": "2025.csv",
               ".env file": ".env", "command argument": "example.invalid", "home path": str(lab.home)}
    return [k for k, v in needles.items() if v in dump]


# ---------------------------------------------------------------- scenarios
def sc_script(lab, path, rt):
    w = WRITERS[rt](lab, lab.alpha)
    w.script()
    w.flush()
    path.scan()
    return [w]


def sc_burst(lab, path, rt):
    w = WRITERS[rt](lab, lab.alpha)
    w.script()
    w.flush()
    path.scan()
    for i in range(10):                      # 30 actions appended between two scans
        w.edit(f"src/burst{i}.py")
        w.run(f"python3 -m pytest -k t{i}", "python3")
        w.read(f"docs/n{i}.md")
    w.flush()
    path.scan()
    return [w]


def sc_trickle(lab, path, rt):
    """A slow writer: one record line at a time, one scan after every line (worst case for split records)."""
    w = WRITERS[rt](lab, lab.alpha)
    w.script()
    for ln in w.lines():
        w.write_lines([ln])
        path.scan()
    path.scan()
    return [w]


def sc_rescan(lab, path, rt):
    w = WRITERS[rt](lab, lab.alpha)
    w.script()
    w.flush()
    for _ in range(4):
        path.scan()
    return [w]


def sc_big(lab, path, rt):
    w = WRITERS[rt](lab, lab.alpha)
    w.script()
    w.edit("src/huge.py", big=200_000 if rt == "opencode" else 450_000)   # OpenCode limit is per message (196 608 B)
    w.flush()
    path.scan()
    return [w]


def sc_first_sight(lab, path, rt):
    """The journal is already running; a NEW session then writes > 640 kB (screenshot-sized records) before the next scan."""
    old = WRITERS[rt](lab, lab.beta)
    old.run("ls", "ls")
    old.flush()
    path.scan()
    w = WRITERS[rt](lab, lab.alpha)
    w.edit("src/early1.py")
    w.run("python3 early.py", "python3")
    w.read("README.md")
    for _ in range(3):                        # ~3 x 300 kB of tool output, as when an agent takes screenshots
        if isinstance(w, JsonlWriter):
            w.pending.append([(json.dumps({"type": "user", "timestamp": iso(), "padding": "P" * 300_000}) + "\n").encode()])
        else:
            w._tool("read", {"filePath": str(w.cwd / "img.png")}, "P" * 150_000)
            w.expect("file_read", "img.png")
    w.edit("src/late1.py")
    w.run("git diff", "git")
    w.flush()
    path.scan()
    return [old, w]


def sc_rotation(lab, path, rt):
    w = WRITERS[rt](lab, lab.alpha)
    if not isinstance(w, JsonlWriter):
        return None
    w.script()
    w.flush()
    path.scan()
    w.path.write_bytes(b"")                  # log truncated / rotated in place
    w.edit("src/after_rotation.py")
    w.run("python3 after.py", "python3")
    w.flush()
    path.scan()
    return [w]


def sc_attribution(lab, path, rt):
    """Two agents launched at the same instant (a swarm start) in two team folders, editing the same relative file."""
    FORCE_SAME_MS[0] = int(time.time() * 1000)
    try:
        a, b = WRITERS[rt](lab, lab.alpha), WRITERS[rt](lab, lab.beta)
    finally:
        FORCE_SAME_MS[0] = 0
    for w in (a, b):
        w.edit("src/app.py")                  # same relative file in both team folders
    a.flush(); b.flush()
    for i in range(4):
        a.run(f"python3 a{i}.py", "python3"); a.flush()
        b.read("README.md"); b.flush()
        path.scan()
    return [a, b]


def sc_privacy(lab, path, rt):
    w = WRITERS[rt](lab, lab.alpha)
    w.script()
    w.secret_command()
    w.read(".env")
    w.expected[-1] = ("file_read", "", "")   # the action may be kept, the sensitive file must not be named
    if rt == "claude":
        w.edit_abs(lab.private / "2025.csv", "2025.csv")
        w.expected[-1] = ("file_edit", "", "")   # a file outside the shared folders must not be named
    priv = WRITERS[rt](lab, lab.private)     # a whole session in a folder nobody shared
    priv.script()
    priv.expected.clear()
    w.flush(); priv.flush()
    path.scan()
    return [w, priv]


def sc_outage(lab, path, rt):
    if not isinstance(path, RemotePath):
        return None
    w = WRITERS[rt](lab, lab.alpha)
    w.script()
    w.flush()
    path.fail_next = True
    path.scan()                               # console unreachable: queued, offsets not advanced
    for i in range(5):
        w.edit(f"src/during_outage{i}.py")
    w.flush()
    path.scan()
    path.scan()
    return [w]


def sc_skew(lab, path, rt):
    if not isinstance(path, RemotePath):
        return None
    w = WRITERS[rt](lab, lab.alpha, skew=120.0)   # remote machine clock 2 minutes ahead of the console
    w.script()
    w.flush()
    path.scan()
    return [w]


def sc_subagent(lab, path, rt):
    if rt != "claude":
        return None
    parent = ClaudeWriter(lab, lab.alpha)
    parent.run("python3 -m unittest", "python3")
    parent.flush()
    sub = ClaudeWriter(lab, lab.alpha, subagent_of=parent)
    sub.edit("src/by_subagent.py")
    sub.read("README.md")
    sub.run("git status", "git")
    sub.flush()
    path.scan()
    return [parent, sub]


SCENARIOS = {"script": sc_script, "burst30": sc_burst, "trickle": sc_trickle, "rescan": sc_rescan, "big_record": sc_big,
             "new_log_640k": sc_first_sight, "rotation": sc_rotation, "two_agents": sc_attribution, "privacy": sc_privacy,
             "outage": sc_outage, "clock_skew": sc_skew, "subagent": sc_subagent}


def run_all(paths=("local", "remote-core", "remote-fallback"), runtimes=RUNTIMES, scenarios=None) -> list[dict]:
    from test_acceptance_blackbox import HttpClient, SpawnedConsole
    results = []
    with tempfile.TemporaryDirectory(prefix="capture-audit-") as tmp:
        srv = SpawnedConsole(Path(tmp) / "console")
        try:
            admin = HttpClient(srv.base_url)
            st, _, _ = admin.json("POST", "/api/v1/auth/login", {"username": "bootstrap_admin", "password": "BootstrapPass!2026#QA"})
            assert st == 200
            n = 0
            for name, fn in SCENARIOS.items():
                if scenarios and name not in scenarios:
                    continue
                for rt in runtimes:
                    for pname in paths:
                        n += 1
                        lab = Lab(Path(tmp) / f"lab{n}")
                        if pname == "local":
                            path = LocalPath(lab)
                        else:
                            host = f"lab-remote-{n}"
                            st, _, tok = admin.json("POST", "/api/v1/tokens", {"name": host, "scope": "ingest"})
                            assert st == 201, tok
                            path = RemotePath(lab, srv, tok["token"], use_core=(pname == "remote-core"), skew_host=host)
                        try:
                            writers = fn(lab, path, rt)
                            if writers is None:
                                continue
                            agents = {w.sid: lab.labels.get(str(w.cwd), "") for w in writers}
                            cmp = compare(writers, path.events(), {k: v for k, v in agents.items() if v})
                            cmp["leaks"] = privacy_leaks(path.raw_dump(), lab)
                            if name == "privacy":
                                cmp["counts"]["private_session_events"] = sum(
                                    1 for e in path.events() if writers[1].sid in (e["meta"] or ""))
                            results.append({"scenario": name, "runtime": rt, "path": pname, **cmp})
                        except Exception as exc:  # report, do not hide
                            results.append({"scenario": name, "runtime": rt, "path": pname, "error": f"{type(exc).__name__}: {exc}"[:300]})
                        finally:
                            path.close()
        finally:
            srv.stop()
    return results


def table(results: list[dict]) -> str:
    cols = ("expected", "captured", "missing", "duplicates", "extra", "wrong_agent", "wrong_file_root", "merged_sessions", "gap_events")
    out = [f"{'scenario':13} {'runtime':11} {'path':15} " + " ".join(f"{c[:8]:>8}" for c in cols) + "  leaks/notes"]
    for r in results:
        if "error" in r:
            out.append(f"{r['scenario']:13} {r['runtime']:11} {r['path']:15} ERROR {r['error']}")
            continue
        c = r["counts"]
        extra = ",".join(r["leaks"])
        if "private_session_events" in c:
            extra += f" private_events={c['private_session_events']}"
        out.append(f"{r['scenario']:13} {r['runtime']:11} {r['path']:15} " + " ".join(f"{c.get(k, 0):>8}" for k in cols) + "  " + extra)
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    ap.add_argument("--scenario", action="append")
    ap.add_argument("--runtime", action="append")
    ap.add_argument("--path", action="append")
    a = ap.parse_args()
    res = run_all(tuple(a.path or ("local", "remote-core", "remote-fallback")), tuple(a.runtime or RUNTIMES), a.scenario)
    print(table(res))
    if a.json:
        Path(a.json).write_text(json.dumps(res, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
