"""Portable Activity map: generic folders, opt-in scope, identity, evidence, multi-host aggregation.

Uses two project folders outside any host application (project-alpha, equipo-demo) under a temp dir.
"""
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "agent"), str(ROOT / "backend")]
import activity_inspector as ai  # noqa: E402
from db import Database  # noqa: E402
import remote_activity  # noqa: E402
from validation import sanitize_heartbeat  # noqa: E402

KEY = "sk-ant-" + "A" * 30
TEAM_TRACES = re.compile(r"agent-[0-9a-f]{8}-[0-9a-f]{4}|/srv/example-private|fixture-team|OpenBot", re.I)


def jsonl(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


class Fixture:
    """A home folder with sessions from four harnesses in two generic projects plus one private folder."""

    def __init__(self, tmp: Path):
        self.home = tmp / "home"
        self.alpha = tmp / "clients" / "project-alpha"
        self.demo = tmp / "work" / "equipo-demo"
        self.private = tmp / "personal" / "taxes"
        for folder in (self.alpha / "src", self.demo / "docs", self.private):
            folder.mkdir(parents=True)
        (self.alpha / "src/app.py").write_text("print(1)")
        (self.alpha / "brand-tokens.css").write_text(":root{}")
        (self.alpha / ".env").write_text("X=1")
        (self.demo / "docs/plan.md").write_text("# plan")
        (self.private / "2025.csv").write_text("secret income")

    def scope(self, *roots, labels=None, host="host-a"):
        return ai.Scope(list(roots) or [self.alpha, self.demo], labels or {}, host)

    def claude(self, cwd, name="s1"):
        jsonl(self.home / f".claude/projects/{name}/{name}.jsonl", [
            {"type": "user", "cwd": str(cwd), "message": {"role": "user", "content": "private request"}},
            {"type": "assistant", "cwd": str(cwd), "timestamp": "2026-11-23T10:00:00Z", "message": {"model": "claude-x", "content": [
                {"type": "tool_use", "name": "TodoWrite", "input": {"todos": [
                    {"content": "Build parser", "status": "completed"}, {"content": "Test it", "status": "in_progress"}]}},
                {"type": "tool_use", "name": "Edit", "input": {"file_path": str(self.alpha / "src/app.py")}},
                {"type": "tool_use", "name": "Read", "input": {"file_path": str(self.alpha / ".env")}},
                {"type": "tool_use", "name": "Read", "input": {"file_path": str(self.private / "2025.csv")}},
                {"type": "tool_use", "name": "Bash", "input": {"command": "cat x", "description": "Run the unit tests"}},
                {"type": "tool_use", "name": "mcp__chat__channel_result", "input": {"text": f"Done, key {KEY} and password=hunter22"}}]}},
        ])

    def codex(self, cwd):
        rollout = self.home / ".codex/r.jsonl"
        change = {str(cwd / "docs/plan.md"): {"type": "update", "unified_diff": "private diff"}}
        jsonl(rollout, [
            {"timestamp": "2026-11-23T10:01:00Z", "payload": {"type": "custom_tool_call", "name": "exec",
             "input": 'tools.update_plan({plan:[{step:"Draft plan",status:"completed"},{step:"Review",status:"pending"}]})'}},
            {"timestamp": "2026-11-23T10:01:02Z", "payload": {"type": "item_completed", "item": {"id": "c1", "type": "FileChange",
             "status": "completed", "changes": change}}},
            {"timestamp": "2026-11-23T10:01:03Z", "payload": {"type": "item_completed", "item": {"type": "AgentMessage",
             "content": [{"text": "Updated the plan document."}]}}},
        ])
        db = self.home / ".codex/state_5.sqlite"
        with sqlite3.connect(db) as c:
            c.execute("CREATE TABLE threads (id TEXT, cwd TEXT, model TEXT, tokens_used INT, updated_at INT, rollout_path TEXT, model_provider TEXT)")
            c.execute("INSERT INTO threads VALUES (?,?,?,?,?,?,?)", ("t1", str(cwd), "gpt-x", 42, int(time.time()), str(rollout), "openai"))
            c.execute("INSERT INTO threads VALUES (?,?,?,?,?,?,?)", ("t2", str(self.private), "gpt-x", 1, int(time.time()), str(rollout), "openai"))

    def antigravity(self, workspace, mention):
        conv = "c0ffee00-0000-4000-8000-000000000001"
        brain = self.home / ".gemini/antigravity-acp/brain" / conv
        jsonl(brain / ".system_generated/logs/transcript.jsonl", [
            {"type": "GENERIC", "content": f"ls {mention}"},
            {"type": "PLANNER_RESPONSE", "content": "Plan:\n- [x] Inspect\n- [ ] Report", "created_at": "2026-11-23T10:02:00Z",
             "model": "gemini-x", "tool_calls": [{"name": "write_file", "args": {"Path": '"' + str(workspace / "docs/plan.md") + '"',
                                                                                  "toolSummary": "Write the plan"}}]},
        ])
        convs = self.home / ".gemini/antigravity-acp/conversations"
        convs.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(convs / f"{conv}.db") as c:
            c.execute("CREATE TABLE trajectory_metadata_blob (id TEXT, data BLOB)")
            c.execute("INSERT INTO trajectory_metadata_blob VALUES ('main', ?)", (b"\x0a\x10file://" + str(workspace).encode() + b"\x12:",))


class PortableScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fx = Fixture(Path(self.tmp.name))
        for p in (patch.object(ai, "HOME", self.fx.home), patch.object(ai, "harnesses", return_value=[])):
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)

    def snap(self, scope=None):
        return ai.collect_activity(scope or self.fx.scope())

    def test_no_folders_means_nothing_is_read(self):
        self.fx.claude(self.fx.alpha)
        d = ai.collect_activity(ai.Scope([], {}, "host-a"))
        self.assertFalse(d["activity_enabled"])
        self.assertEqual((d["sessions"], d["workspaces"]), ([], []))

    def test_identity_comes_from_generic_folders_and_labels(self):
        self.fx.claude(self.fx.alpha)
        self.fx.codex(self.fx.demo)
        d = self.snap(self.fx.scope(labels={"equipo-demo": "Demo team"}))
        names = {s["agent_name"] for s in d["sessions"]}
        self.assertEqual(names, {"project-alpha", "Demo team"})
        self.assertEqual({w["label"] for w in d["workspaces"]}, {"project-alpha", "Demo team"})
        self.assertIsNone(TEAM_TRACES.search(json.dumps(d)), "no team id, host-app path or product folder leaks")

    def test_session_outside_shared_folders_is_skipped(self):
        self.fx.codex(self.fx.demo)
        d = self.snap()
        self.assertEqual(len(d["sessions"]), 1, "the thread in the private folder is not read")
        self.assertNotIn("taxes", json.dumps(d))

    def test_confirmed_edit_in_generic_folder_is_kept(self):
        """Regression: a completed Codex edit outside the team project used to lose its file."""
        self.fx.codex(self.fx.demo)
        s, = self.snap()["sessions"]
        target = str(self.fx.demo / "docs/plan.md")
        self.assertEqual(s["files_edited"], [target])
        step = next(st for st in s["steps"] if st["category"] == "file_edit")
        self.assertEqual((step["files"], step["file_basis"]), ([target], "confirmed"))
        self.assertEqual(s["latest_work"]["label"], step["label"])
        self.assertEqual((s["provider"], s["provider_basis"]), ("openai", "recorded"))
        self.assertEqual(s["plan"][0], {"status": "completed", "text": "Draft plan"})
        self.assertNotIn("private diff", json.dumps(s))

    def test_claude_plan_steps_files_and_privacy(self):
        self.fx.claude(self.fx.alpha)
        s, = self.snap()["sessions"]
        self.assertEqual([p["status"] for p in s["plan"]], ["completed", "in_progress"])
        self.assertEqual(s["files_edited"], [str(self.fx.alpha / "src/app.py")])
        self.assertEqual(s["files_read"], [], ".env is a credential; the other read is outside the folders")
        self.assertIn("Run the unit tests", [st["label"] for st in s["steps"]])
        self.assertIn("Post the result to the channel", [st["label"] for st in s["steps"]], "any MCP namespace")
        self.assertEqual((s["provider"], s["provider_basis"]), ("anthropic", "model"))
        blob = json.dumps(s)
        self.assertIn("Read a protected file", [st["label"] for st in s["steps"]])
        self.assertIn("Read a file outside the shared folders", [st["label"] for st in s["steps"]])
        for secret in (KEY, "hunter22", "cat x", "private request", "taxes", "2025.csv", ".env"):
            self.assertNotIn(secret, blob)

    def test_antigravity_owner_from_metadata_not_transcript_text(self):
        self.fx.antigravity(self.fx.demo, mention=self.fx.alpha)
        s, = self.snap()["sessions"]
        self.assertEqual((s["agent_name"], s["owner_basis"]), ("equipo-demo", "conversation metadata"))
        self.assertEqual(s["files_edited"], [str(self.fx.demo / "docs/plan.md")])
        self.assertEqual(s["steps"][0]["label"], "Write the plan")
        self.assertEqual(s["what_done"], "Plan: Inspect Report", "checklist markers are not shown as text")

    def test_longest_root_wins_and_duplicate_names_stay_distinct(self):
        inner = self.fx.alpha / "src"
        other = Path(self.tmp.name) / "elsewhere" / "src"
        other.mkdir(parents=True)
        sc = ai.Scope([self.fx.alpha, inner, other], {}, "h")
        a_id, _, ws = sc.identity(inner / "app.py")
        b_id, _, _ = sc.identity(other)
        self.assertEqual(ws, str(inner))
        self.assertNotEqual(a_id, b_id)
        self.assertTrue(re.fullmatch(r"src-[0-9a-f]{6}", a_id))

    def test_workspaces_hide_credentials_keep_design_tokens(self):
        ws = {w["label"]: w for w in self.snap()["workspaces"]}["project-alpha"]
        names = [f["rel_path"] for f in ws["recent_files"]]
        self.assertIn("brand-tokens.css", names)
        self.assertNotIn(".env", names)

    def test_console_machine_and_remote_observers_share_the_map(self):
        """A first remote observer must not hide the console machine's own agents (the map looked empty in production
        once a Windows observer connected). A remote observer with the same host ID wins for that host."""
        self.fx.claude(self.fx.alpha)
        local = self.snap(self.fx.scope(self.fx.alpha, host="console-box"))
        (self.fx.home / ".claude").rename(self.fx.home / ".claude-a")
        self.fx.codex(self.fx.demo)
        remote = self.snap(self.fx.scope(self.fx.demo, host="win-box"))
        tenant = Database(Path(self.tmp.name) / "tenant-merge.sqlite3")
        remote_activity.ingest_remote_activity(tenant, remote)
        d = remote_activity.build_tenant_activity_map(tenant, local_snapshot=local)
        self.assertEqual({h["host_id"] for h in d["hosts"]}, {"console-box", "win-box"})
        self.assertEqual({(s["host_id"], s["agent_name"]) for s in d["sessions"]},
                         {("console-box", "project-alpha"), ("win-box", "equipo-demo")})
        self.assertEqual(d["summary"]["sessions"], 2)
        self.assertEqual(next(h for h in d["hosts"] if h["host_id"] == "console-box")["capture_reader"], "console")
        # Same host ID reported by a remote observer: the observer's snapshot is used, not a duplicate.
        local_same = {**local, "hosts": [{**local["hosts"][0], "host_id": "win-box"}]}
        d2 = remote_activity.build_tenant_activity_map(tenant, local_snapshot=local_same)
        self.assertEqual([h["host_id"] for h in d2["hosts"]], ["win-box"])
        # No remote observers: unchanged behaviour (the local snapshot is the map).
        empty = Database(Path(self.tmp.name) / "tenant-empty.sqlite3")
        self.assertIs(remote_activity.build_tenant_activity_map(empty, local_fallback=local, local_snapshot=local), local)

    def test_snapshot_is_accepted_by_remote_ingestion_for_two_hosts(self):
        """Two machines, two generic folders, one organization map; nothing from the server's own disk."""
        self.fx.claude(self.fx.alpha)
        host_a = self.snap(self.fx.scope(self.fx.alpha, host="laptop-a"))
        (self.fx.home / ".claude").rename(self.fx.home / ".claude-a")
        self.fx.codex(self.fx.demo)
        host_b = self.snap(self.fx.scope(self.fx.demo, host="build-b"))
        tenant = Database(Path(self.tmp.name) / "tenant.sqlite3")
        for snap in (host_a, host_b):
            remote_activity.ingest_remote_activity(tenant, snap)
        d = remote_activity.build_tenant_activity_map(tenant)
        self.assertEqual({h["host_id"] for h in d["hosts"]}, {"laptop-a", "build-b"})
        self.assertEqual({(s["host_id"], s["agent_name"]) for s in d["sessions"]},
                         {("laptop-a", "project-alpha"), ("build-b", "equipo-demo")})
        b = next(s for s in d["sessions"] if s["host_id"] == "build-b")
        self.assertEqual(b["files_edited"], [str(self.fx.demo / "docs/plan.md")])
        self.assertIn("latest_work", b)
        self.assertIsNone(TEAM_TRACES.search(json.dumps(d)))
        other_org = Database(Path(self.tmp.name) / "other.sqlite3")
        self.assertEqual(remote_activity.build_tenant_activity_map(other_org)["sessions"], [], "other organization sees nothing")


class AdapterTests(unittest.TestCase):
    def test_core_has_no_host_app_or_team_coupling(self):
        for name in ("activity_inspector.py", "work_board.py", "validation.py"):
            src = (ROOT / "backend" / name).read_text()
            self.assertIsNone(re.search(r"agent-[0-9a-f]{8}-|/srv/example-private|fixture-team|fixture-agent-builder|fixture-agent-reviewer|collector-maintainer", src), name)
        self.assertIsNone(re.search(r"/srv/example-private|fixture-team|agent-[0-9a-f]{8}-", (ROOT / "frontend/activity.js").read_text()))

    def test_openbot_adapter_is_optional_and_reads_names_from_its_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            aid = "agent-00000000-0000-4000-8000-000000000001"
            (t / "OB/Agents" / aid).mkdir(parents=True)
            (t / "OB/Shared/team").mkdir(parents=True)
            (t / "cfg").mkdir()
            with sqlite3.connect(t / "cfg/openbot.db") as c:
                c.execute("CREATE TABLE projection_agents (agent_id TEXT, agent_json TEXT)")
                c.execute("INSERT INTO projection_agents VALUES (?,?)", (aid, json.dumps({"id": aid, "name": "Reviewer"})))
            env = {"SWARMCONTROL_ACTIVITY_ADAPTERS": "openbot", "SWARMCONTROL_OPENBOT_ROOT": str(t / "OB"),
                   "SWARMCONTROL_OPENBOT_CONFIG": str(t / "cfg"), "SWARMCONTROL_ACTIVITY_ROOTS": ""}
            with patch.dict("os.environ", env):
                sc = ai.load_scope()
            self.assertEqual(sc.identity(t / "OB/Agents" / aid / "x")[1], "Reviewer")
            self.assertEqual(sc.identity(t / "OB/Shared/team")[1], "team")
            with patch.dict("os.environ", {"SWARMCONTROL_ACTIVITY_ADAPTERS": "missing_adapter", "SWARMCONTROL_ACTIVITY_ROOTS": ""}):
                self.assertFalse(ai.load_scope().enabled, "an unknown adapter is ignored, not fatal")


class GenericWorkspaceLabelTests(unittest.TestCase):
    def test_heartbeat_accepts_generic_relative_labels_only(self):
        for sample, expected in [("equipo-demo", "equipo-demo"), ("clients/project-alpha", "clients/project-alpha"),
                                 ("/home/x", None), ("../up", None), ("a/b/c/d/e", None), ("bad name", None)]:
            got = sanitize_heartbeat({"host_id": "h", "processes": [{"workspace": sample}]})["processes"][0].get("workspace")
            self.assertEqual(got, expected, sample)


class CommandVisibilityTests(unittest.TestCase):
    """Which command ran: program always; full command only with SWARMCONTROL_SHARE_COMMANDS=1, redacted."""

    def test_program_is_found_through_wrappers_and_shell_syntax(self):
        cases = {"cd /x && python3 -m unittest": "python3", '/bin/bash -lc "rg -n foo src"': "rg",
                 "sudo -n systemctl restart a": "systemctl", "timeout 60 npm test": "npm", "cd /x\nrg foo": "rg",
                 "set -e\npython3 a.py": "python3", "if [ -f x ]; then cat x; fi": "cat",
                 "for f in *; do wc -l $f; done": "wc", "TOKEN=abc curl https://e": "curl", "ls | head": "ls"}
        for cmd, program in cases.items():
            self.assertEqual(ai.command_info(cmd).get("program"), program, cmd)

    def test_arguments_stay_hidden_unless_the_operator_opts_in(self):
        with patch.dict("os.environ", {"SWARMCONTROL_SHARE_COMMANDS": ""}):
            self.assertEqual(ai.command_info("curl -u admin:s3cretpass https://x"), {"program": "curl"})

    def test_opt_in_preview_never_shows_secrets(self):
        with patch.dict("os.environ", {"SWARMCONTROL_SHARE_COMMANDS": "1"}):
            cases = ["curl -u admin:s3cretpass https://x", "mysql -p hunter2 db", "gh api --token ghx123 /repos",
                     'curl -H "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123" https://e',
                     "cat /var/lib/x/.config/secret.json --password=hunter2222", "export API_KEY=abcdef123456 && node app.js",
                     "cp .env /tmp/x", "echo " + KEY]
            for cmd in cases:
                shown = ai.command_info(cmd)["command"]
                for secret in ("s3cretpass", "hunter2", "ghx123", "abcdefghijklmnopqrstuvwxyz123", "hunter2222",
                               "abcdef123456", KEY, "secret.json", ".env", "/var/lib/x"):
                    self.assertNotIn(secret, shown, cmd)
            self.assertEqual(ai.command_info("python3 -m unittest discover -s tests")["command"],
                             "python3 -m unittest discover -s tests")
            self.assertLessEqual(len(ai.command_info("echo " + "a " * 200)["command"]), 160)


class OwnerAndCommandRecordTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fx = Fixture(Path(self.tmp.name))
        for p in (patch.object(ai, "HOME", self.fx.home), patch.object(ai, "harnesses", return_value=[])):
            p.start()
            self.addCleanup(p.stop)

    def test_claude_owner_is_the_launch_folder_even_after_cd(self):
        """Regression: an agent that cd'ed into a shared project was attributed to that project, not to itself."""
        jsonl(self.fx.home / ".claude/projects/p/s9.jsonl", [
            {"type": "user", "cwd": str(self.fx.demo), "message": {"role": "user", "content": "x"}},
            {"type": "assistant", "cwd": str(self.fx.alpha), "timestamp": "2026-11-23T10:00:00Z", "message": {"model": "claude-x",
             "content": [{"type": "tool_use", "name": "Bash", "input": {"command": "cd src && pytest -q"}}]}}])
        s, = ai.collect_activity(self.fx.scope())["sessions"]
        self.assertEqual(s["agent_name"], "equipo-demo")
        self.assertEqual(s["current_folder"], str(self.fx.alpha))
        self.assertEqual((s["steps"][0]["program"], s["steps"][0]["label"]), ("pytest", "Run tests"))

    def test_opencode_shell_step_reports_program_not_arguments(self):
        db = self.fx.home / ".local/share/opencode/opencode.db"
        db.parent.mkdir(parents=True)
        with sqlite3.connect(db) as c:
            c.execute("CREATE TABLE session_v2(id TEXT, directory TEXT, time_updated INTEGER, model TEXT, title TEXT)")
            c.execute("INSERT INTO session_v2 VALUES('s1', ?, ?, 'glm-x', 'Fix')", (str(self.fx.alpha), int(time.time() * 1000)))
            c.execute("CREATE TABLE session_message(session_id TEXT, type TEXT, seq INTEGER, time_created INTEGER, data TEXT)")
            part = {"type": "tool", "name": "bash", "state": {"status": "completed", "input": {"command": "npm test -- --token=zz9"}}}
            c.execute("INSERT INTO session_message VALUES('s1','assistant',1,?,?)", (int(time.time() * 1000), json.dumps({"content": [part]})))
        with patch.dict("os.environ", {"SWARMCONTROL_SHARE_COMMANDS": ""}):
            s, = ai.collect_activity(self.fx.scope())["sessions"]
        self.assertEqual(s["steps"][0]["program"], "npm")
        self.assertNotIn("zz9", json.dumps(s))


class LargeLogAndPolishTests(unittest.TestCase):
    def test_recent_steps_survive_huge_records_at_the_end_of_a_log(self):
        """Regression: screenshots (multi-MB lines) at the end of a session hid every recent step."""
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "s.jsonl"
            small = [json.dumps({"n": i}) for i in range(60)]
            huge = json.dumps({"image": "A" * 300_000})
            log.write_text("\n".join(small + [huge] * 6) + "\n")
            lines = ai._tail_lines(log)
            self.assertGreaterEqual(len(lines), 40)
            self.assertIn('{"n": 59}', lines)

    def test_wrapped_tool_calls_are_named_by_the_inner_action(self):
        self.assertEqual(ai._step("openbot_browser.screenshot", "")["label"], "Take a screenshot")
        self.assertEqual(ai._step("openbot.channel_result", "")["label"], "Post the result to the channel")

    def test_map_ui_contract(self):
        js = (ROOT / "frontend/activity.js").read_text()
        css = (ROOT / "frontend/activity-product.css").read_text()
        for needle in ('data-view="${v}"', "function timeline(", 'data-role="search"', "prefers-reduced-motion", "ap-burst",
                       "state.print", "aria-selected"):
            self.assertIn(needle, js + css, needle)
        self.assertIsNone(re.search(r"\son[a-z]+=", js), "no inline event handlers (CSP)")
        self.assertIn("@media (prefers-reduced-motion: reduce)", css)


if __name__ == "__main__":
    unittest.main()
