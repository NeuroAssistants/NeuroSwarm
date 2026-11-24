"""Line survival: which lines an agent's edit added are still in the code, from explicit Git evidence only.

Real Git repositories and real Claude Code session logs (synthetic content). Each case is a timeline of edits and
commits with fixed timestamps, read by the journal (local) and by the remote observer (HTTP), then checked through the
same detail the Activity map opens:
  * attributed: the session's own `git commit` output names the commit; later commits change and delete some lines
  * concurrent edit: two sessions edit one file and one commit contains both -> refused (other_session)
  * insufficient evidence: no commit by the session; an earlier commit to the file after the edit
  * privacy: no file contents, no paths outside shared folders, no protected files, no path from the request
  * isolation: another organization, a changed organization, an ingest-only token
"""
from __future__ import annotations

import datetime
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "agent"), str(Path(__file__).resolve().parent)]
import activity_inspector as ai  # noqa: E402
import activity_shipper  # noqa: E402
import line_survival  # noqa: E402
import work_journal as wj  # noqa: E402
from db import Database  # noqa: E402
from test_security import ServerHarness  # noqa: E402

SECRET_LINE = "LINE_CONTENT_MUST_NOT_LEAVE_7f3a"
BASE = time.time() - 900


def iso(t: float) -> str:
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def git(repo: Path, *args: str, at: float | None = None) -> str:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(repo), "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_AUTHOR_NAME": "dev", "GIT_AUTHOR_EMAIL": "dev@example.invalid",
           "GIT_COMMITTER_NAME": "dev", "GIT_COMMITTER_EMAIL": "dev@example.invalid"}
    if at is not None:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = f"@{int(at)} +0000"
    return subprocess.run(["git", "-C", str(repo), *args], env=env, capture_output=True, text=True, check=True).stdout


class Lab:
    """A shared folder that is a Git repository, and Claude Code sessions that edit and commit inside it."""

    def __init__(self, tmp: Path):
        self.home = tmp / "home"
        self.repo = tmp / "work" / "shop"
        self.repo.mkdir(parents=True)
        git(self.repo, "init", "-q", "-b", "main")
        self.write("app.py", ["base 1", "base 2"])
        self.write("shared.py", ["base"])
        self.write("late.py", ["base"])
        self.write(".env", ["TOKEN=x"])
        self.commit(BASE, "initial")
        self.n = 0

    def write(self, name: str, lines: list[str], append: bool = False) -> None:
        p = self.repo / name
        old = p.read_text().splitlines() if append and p.exists() else []
        p.write_text("\n".join(old + lines) + "\n")

    def commit(self, at: float, msg: str) -> None:
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", msg, at=at)

    def log(self, session: str, rows: list[dict]) -> None:
        f = self.home / ".claude/projects/shop" / f"{session}.jsonl"
        f.parent.mkdir(parents=True, exist_ok=True)
        first = not f.exists()
        with f.open("a") as out:
            if first:
                out.write(json.dumps({"type": "user", "cwd": str(self.repo), "message": {"role": "user", "content": "go"}}) + "\n")
            for r in rows:
                out.write(json.dumps(r) + "\n")

    def tool(self, session: str, at: float, name: str, inp: dict, result: str) -> None:
        self.n += 1
        tid = f"t{self.n}"
        self.log(session, [
            {"type": "assistant", "cwd": str(self.repo), "timestamp": iso(at), "message": {"model": "claude-x", "content": [
                {"type": "tool_use", "id": tid, "name": name, "input": inp}]}},
            {"type": "user", "cwd": str(self.repo), "timestamp": iso(at + 0.5), "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": tid, "content": result}]}}])

    def edit(self, session: str, at: float, name: str, lines: list[str]) -> None:
        self.write(name, lines, append=True)
        self.tool(session, at, "Edit", {"file_path": str(self.repo / name), "old_string": "x", "new_string": "y"}, "ok")

    def agent_commit(self, session: str, at: float, msg: str, *files: str) -> str:
        """The session runs `git commit`; its tool result is git's own output ("[main abc1234] msg")."""
        git(self.repo, "add", *files)
        out = git(self.repo, "commit", "-m", msg, at=at)
        self.tool(session, at, "Bash", {"command": f"git add {' '.join(files)} && git commit -m '{msg}'",
                                        "description": "Commit"}, out)
        return out.split("]")[0].split()[-1]

    def script(self) -> dict[str, str]:
        """The timeline every test reads. Returns the commit IDs printed by sessions."""
        ids = {}
        # A: three lines in app.py, committed by A; a later human commit changes one and deletes another.
        self.edit("sess-a", BASE + 10, "app.py", ["a one", "a two", f"a three {SECRET_LINE}"])
        ids["a"] = self.agent_commit("sess-a", BASE + 20, "A adds three lines", "app.py")
        p = self.repo / "app.py"
        lines = p.read_text().splitlines()
        kept = ["a ONE changed" if x == "a one" else x for x in lines if x != "a two"]
        p.write_text("\n".join(["# header 1", "# header 2"] + kept) + "\n")   # numbers below shift by 2
        git(self.repo, "commit", "-qam", "human edits A's lines", at=BASE + 30)
        # B and C edit shared.py concurrently; B commits both changes, C never commits.
        self.edit("sess-b", BASE + 40, "shared.py", ["b line"])
        self.edit("sess-c", BASE + 45, "shared.py", ["c line"])
        ids["b"] = self.agent_commit("sess-b", BASE + 50, "B commits shared.py", "shared.py")
        # D edits late.py, a human commits it first, then D edits again and commits.
        self.edit("sess-d", BASE + 60, "late.py", ["d first"])
        git(self.repo, "commit", "-qam", "human commits late.py", at=BASE + 65)
        self.edit("sess-d", BASE + 70, "late.py", ["d second 1", "d second 2"])
        ids["d"] = self.agent_commit("sess-d", BASE + 75, "D commits late.py", "late.py")
        # E commits a protected file: it is never measured or keyed.
        self.edit("sess-e", BASE + 80, ".env", ["TOKEN=y"])
        ids["e"] = self.agent_commit("sess-e", BASE + 85, "E touches env", ".env")
        return ids


def line_of(repo: Path, name: str, text: str) -> int:
    """Independent check: the 1-based line number of `text` in the file at HEAD, read with plain Git (not blame)."""
    lines = git(repo, "show", f"HEAD:{name}").splitlines()
    hits = [i + 1 for i, line in enumerate(lines) if text in line]
    assert len(hits) == 1, (name, text, hits)
    return hits[0]


ITEM_KEYS = {"sha", "path", "added", "surviving", "exists", "commit_time", "prev_time", "head", "measured_at",
             "repo_path", "ranges", "ranges_truncated", "too_large"}


def edits(conn, session):
    return [(r[0], json.loads(r[1])) for r in conn.execute(
        "SELECT id, metadata_json FROM events WHERE event_type='observed_step' "
        "AND json_extract(metadata_json,'$.session')=? AND json_extract(metadata_json,'$.action')='file_edit' ORDER BY created_at",
        (f"claude-code:{session}",)).fetchall()]


class LocalJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.lab = Lab(Path(self.tmp.name))
        self.ids = self.lab.script()
        self.dbo = Database(Path(self.tmp.name) / "j.db")
        self.addCleanup(self.dbo.close)
        self.conn = sqlite3.connect(self.dbo.db_path)
        self.addCleanup(self.conn.close)
        for p in (patch.object(ai, "HOME", self.lab.home), patch.object(ai, "harnesses", return_value=[]),
                  patch.dict(os.environ, {"SWARMCONTROL_SHARE_LINE_SURVIVAL": "1"})):
            p.start()
            self.addCleanup(p.stop)
        ai._SURVIVAL_LAST.clear()
        self.scope = ai.Scope([self.lab.repo], {}, "host-ls")
        self.result = wj.capture_once(self.conn, {"shop"}, self.lab.repo, time.time(), None, self.scope)

    def detail(self, session, index=0):
        event_id = edits(self.conn, session)[index][0]
        return line_survival.detail(self.dbo, 1, event_id)

    def test_session_commit_attributes_its_lines_and_counts_changed_and_deleted_ones(self):
        d = self.detail("sess-a")
        f, = d["files"]
        self.assertEqual((f["file"], f["status"]), ("app.py", "attributed"))
        self.assertEqual((f["added"], f["surviving"], f["changed_or_removed"]), (3, 1, 2), "one kept, one changed, one deleted")
        self.assertTrue(self.ids["a"].startswith(f["commit"][:7]))
        self.assertTrue(f["file_exists"])
        self.assertGreater(self.result.get("line_survival", 0), 0)

    def test_concurrent_edit_in_one_commit_is_refused_and_the_other_session_has_no_commit(self):
        self.assertEqual(self.detail("sess-b")["files"][0]["status"], "other_session")
        self.assertEqual(self.detail("sess-c")["files"][0]["status"], "no_commit")

    def test_an_earlier_commit_after_the_edit_is_insufficient_evidence(self):
        self.assertEqual(self.detail("sess-d", 0)["files"][0]["status"], "earlier_commit")
        second = self.detail("sess-d", 1)["files"][0]
        self.assertEqual((second["status"], second["added"], second["surviving"]), ("attributed", 2, 2))

    def test_protected_files_and_non_edit_events_get_no_lines(self):
        (_, meta), = edits(self.conn, "sess-e")
        self.assertEqual((meta["files"], meta.get("line_keys")), ([], None), "an edit of .env names no file")
        self.assertEqual(self.detail("sess-e")["files"], [])
        rows = self.conn.execute("SELECT path FROM line_survival").fetchall()
        self.assertTrue(rows and all(".env" not in r[0] for r in rows))
        cmd_id = self.conn.execute("SELECT id FROM events WHERE json_extract(metadata_json,'$.git_commit') IS NOT NULL").fetchone()[0]
        self.assertFalse(line_survival.detail(self.dbo, 1, cmd_id)["applies"])
        self.assertIsNone(line_survival.detail(self.dbo, 1, 999_999))

    def test_no_file_content_and_no_absolute_path_is_stored(self):
        dump = json.dumps([list(r) for t in ("events", "line_survival")
                           for r in self.conn.execute(f"SELECT * FROM {t}").fetchall()])
        self.assertNotIn(SECRET_LINE, dump)
        self.assertNotIn(str(self.lab.repo), dump)

    def test_sharing_off_sends_nothing_and_says_so(self):
        with patch.dict(os.environ, {"SWARMCONTROL_SHARE_LINE_SURVIVAL": "0"}):
            ai._SURVIVAL_LAST.clear()
            snap = ai.collect_activity(self.scope, ai.Capture({}))
        self.assertNotIn("line_survival", snap)
        self.assertFalse(any("git_commit" in st for s in snap["sessions"] for st in s.get("capture_steps") or []))
        self.conn.execute("DELETE FROM line_survival")
        self.conn.commit()
        self.assertEqual(self.detail("sess-a")["files"][0]["status"], "not_shared")


    def measure_again(self):
        ai._SURVIVAL_LAST.clear()
        wj.capture_once(self.conn, {"shop"}, self.lab.repo, time.time(), None, self.scope)

    def test_which_lines_remain_are_named_by_their_number_at_the_measured_revision(self):
        f = self.detail("sess-a")["files"][0]
        n = line_of(self.lab.repo, "app.py", SECRET_LINE)
        self.assertEqual(n, 6, "two lines inserted above moved it from 5 to 6")
        self.assertEqual((f["ranges"], f["ranges_truncated"], f["repo_path"]), ([[n, n]], False, "app.py"))
        self.assertEqual(f["head_commit"], git(self.lab.repo, "rev-parse", "HEAD").strip())
        blame = git(self.lab.repo, "blame", "-M", "-l", "-L", f"{n},{n}", f["head_commit"], "--", "app.py")
        self.assertTrue(blame.startswith(git(self.lab.repo, "rev-parse", self.ids["a"]).strip()),
                        "the shown command confirms the line comes from the session's commit")
        d2 = self.detail("sess-d", 1)["files"][0]
        first = line_of(self.lab.repo, "late.py", "d second 1")
        self.assertEqual(d2["ranges"], [[first, first + 1]])

    def test_a_later_edit_shifts_the_numbers_and_a_changed_line_leaves_the_list(self):
        p = self.lab.repo / "late.py"
        lines = p.read_text().splitlines()
        p.write_text("\n".join(["# a", "# b", "# c"] + ["d second 1 CHANGED" if x == "d second 1" else x for x in lines]) + "\n")
        git(self.lab.repo, "commit", "-qam", "human inserts three lines and changes one of D's", at=BASE + 100)
        self.measure_again()
        f = self.detail("sess-d", 1)["files"][0]
        n = line_of(self.lab.repo, "late.py", "d second 2")
        self.assertEqual((f["added"], f["surviving"], f["changed_or_removed"]), (2, 1, 1))
        self.assertEqual(f["ranges"], [[n, n]], "only the unchanged line, at its new number")
        self.assertEqual(f["head_commit"], git(self.lab.repo, "rev-parse", "HEAD").strip(), "measured at the new revision")

    def test_a_deleted_file_names_no_line(self):
        git(self.lab.repo, "rm", "-q", "late.py")
        git(self.lab.repo, "commit", "-qm", "remove late.py", at=BASE + 110)
        self.measure_again()
        f = self.detail("sess-d", 1)["files"][0]
        self.assertEqual((f["surviving"], f["file_exists"], f["ranges"]), (0, False, None))

    def test_files_over_the_size_limit_are_reported_not_guessed(self):
        with patch.object(ai, "SURVIVAL_MAX_BYTES", 10):
            self.measure_again()
        f = self.detail("sess-a")["files"][0]
        self.assertEqual(f["status"], "too_large")
        self.assertNotIn("ranges", f)
        self.assertNotIn("surviving", f)

    def test_measurements_from_an_older_observer_keep_their_counts_without_line_numbers(self):
        row = self.conn.execute("SELECT * FROM line_survival WHERE path='shop/app.py' AND sha LIKE ?",
                                (self.ids["a"] + "%",)).fetchone()
        cols = [c[1] for c in self.conn.execute("PRAGMA table_info(line_survival)")]
        old = dict(zip(cols, row))
        item = {"sha": old["sha"], "head": old["head"], "path": str(self.lab.repo / "app.py"), "added": old["added"],
                "surviving": old["surviving"], "exists": True, "commit_time": old["commit_time"],
                "prev_time": old["prev_time"], "measured_at": time.time()}          # the first version's payload
        with self.dbo.transaction() as conn:
            line_survival.store(conn, "host-ls", [item], time.time(),
                                lambda p: next(iter(line_survival.canonical_keys([p], project=self.lab.repo)), None))
        f = self.detail("sess-a")["files"][0]
        self.assertEqual((f["status"], f["surviving"], f["ranges"]), ("attributed", 1, None))

    def test_inconsistent_line_numbers_are_dropped_rather_than_shown(self):
        ok = line_survival.clean_ranges
        self.assertEqual(ok([[6, 6]], 1, False), [[6, 6]])
        self.assertIsNone(ok([[6, 7]], 1, False), "two lines for one surviving line")
        self.assertIsNone(ok([[7, 7], [6, 6]], 2, False), "out of order")
        self.assertIsNone(ok([[0, 1]], 2, False), "line 0")
        self.assertIsNone(ok([[1, "2"]], 2, False), "not a number")
        self.assertEqual(ok([[1, 2]], 5, True), [[1, 2]], "a truncated list may cover fewer lines")
        self.assertIsNone(line_survival.clean_repo_path("../etc/passwd", "shop/passwd"))
        self.assertIsNone(line_survival.clean_repo_path("/abs/app.py", "shop/app.py"))
        self.assertIsNone(line_survival.clean_repo_path("other.py", "shop/app.py"), "must be the same file")
        self.assertEqual(line_survival.clean_repo_path("sub/app.py", "shop/app.py"), "sub/app.py")


class CollectorTests(unittest.TestCase):
    def test_only_a_successful_git_commit_output_is_evidence(self):
        out = "[main 1a2b3c4] Fix totals\n 1 file changed, 2 insertions(+)\n"
        self.assertEqual(ai.recorded_commit("git commit -m 'x'", out, 0), "1a2b3c4")
        self.assertEqual(ai.recorded_commit(["bash", "-lc", "git add . && git commit -am x"], out, None), "1a2b3c4")
        self.assertIsNone(ai.recorded_commit("git commit -m x", out, 1), "failed command")
        self.assertIsNone(ai.recorded_commit("git log -1", out, 0), "not a commit command")
        self.assertIsNone(ai.recorded_commit("echo '[main 1a2b3c4] x'", out, 0), "text alone is not evidence")
        self.assertIsNone(ai.recorded_commit("git commit -m x", "nothing to commit, working tree clean", 0))
        self.assertIsNone(ai.recorded_commit("git commit", "[main 1a2b3c4] a\n[main 9f8e7d6] b\n", 0), "two IDs: ambiguous")

    def test_measurement_stays_inside_the_shared_folder_and_never_runs_repository_programs(self):
        with tempfile.TemporaryDirectory() as t:
            repo = Path(t) / "mono"
            (repo / "shared").mkdir(parents=True)
            git(repo, "init", "-q", "-b", "main")
            (repo / "shared" / "in.py").write_text("x\n")
            (repo / "outside.py").write_text("y\n")
            git(repo, "add", "-A")
            git(repo, "commit", "-qm", "both", at=time.time() - 60)
            marker = Path(t) / "fsmonitor-ran"
            git(repo, "config", "core.fsmonitor", f"touch {marker}")   # a repository setting that would run a program
            with patch.dict(os.environ, {"SWARMCONTROL_SHARE_LINE_SURVIVAL": "1"}):
                ai._SURVIVAL_LAST.clear()
                scope = ai.Scope([repo / "shared"], {}, "h")
                ai._CURRENT = scope
                try:
                    items = ai.measure_line_survival(scope, force=True)
                finally:
                    ai._CURRENT = None
            self.assertEqual([Path(i["path"]).name for i in items], ["in.py"])
            self.assertTrue(set(items[0]) <= ITEM_KEYS, "numbers and identifiers only")
            self.assertEqual((items[0]["repo_path"], items[0]["ranges"]), ("shared/in.py", [[1, 1]]))
            self.assertFalse(marker.exists(), "repository settings did not run a program")


class RemoteAndAccessTests(ServerHarness):
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.lab = Lab(Path(self.tmp.name))
        self.lab.script()
        self.login()
        self.ingest = self.bearer(self.token("obs"))
        with patch.object(ai, "HOME", self.lab.home), patch.object(ai, "harnesses", return_value=[]), \
                patch.dict(os.environ, {"SWARMCONTROL_SHARE_LINE_SURVIVAL": "1"}):
            ai._SURVIVAL_LAST.clear()
            payload, _, _ = activity_shipper.collect_incremental_activity(
                raw_roots=[str(self.lab.repo)], host_id="remote-box", home_dir=self.lab.home, use_core=True)
        self.payload = payload
        status, body, _ = self.req("POST", "/api/v1/ingest/activity", payload, headers=self.ingest, cookie=False)
        self.assertIn(status, (200, 201), body)
        with self.ctx.db.transaction(write=False) as conn:
            self.ids = {s: edits(conn, s) for s in ("sess-a", "sess-b", "sess-d")}

    def test_remote_observer_gives_the_same_answer_and_sends_counts_only(self):
        self.assertNotIn(SECRET_LINE, json.dumps(self.payload))
        items = self.payload["line_survival"]
        self.assertTrue(items and all(set(i) <= ITEM_KEYS for i in items))
        status, d, _ = self.req("GET", f"/api/v1/events/{self.ids['sess-a'][0][0]}/line-survival")
        self.assertEqual(status, 200, d)
        f, = d["files"]
        self.assertEqual((f["status"], f["added"], f["surviving"], f["changed_or_removed"]), ("attributed", 3, 1, 2))
        self.assertEqual(f["ranges"], [[line_of(self.lab.repo, "app.py", SECRET_LINE)] * 2], "same lines as the local journal")
        self.assertEqual(f["ranges"], [[6, 6]])
        self.assertEqual(self.req("GET", f"/api/v1/events/{self.ids['sess-b'][0][0]}/line-survival")[1]["files"][0]["status"],
                         "other_session")
        self.assertNotIn(str(self.lab.repo), json.dumps(d))

    def test_access_is_scoped_to_the_organization_and_takes_no_path(self):
        url = f"/api/v1/events/{self.ids['sess-a'][0][0]}/line-survival"
        self.assertEqual(self.req("GET", url + "?path=/etc/passwd")[1]["files"][0]["file"], "app.py", "no path parameter")
        self.assertEqual(self.req("GET", url + "?organization_id=999")[0], 409)
        self.assertEqual(self.req("GET", url, headers=self.ingest, cookie=False)[0], 401)
        _, read, _ = self.req("POST", "/api/v1/tokens", {"name": "reader", "scope": "read"})
        self.assertEqual(self.req("GET", url, headers=self.bearer(read), cookie=False)[0], 200)
        self.assertEqual(self.req("GET", url, cookie=False)[0], 401)
        status, _, hdr = self.req("POST", "/api/v1/auth/register", {"organization": "Other team", "username": "other-user",
                                                                     "password": "Another-Strong-Pass-2026!"}, cookie=False)
        self.assertEqual(status, 201)
        self.cookie = hdr["set-cookie"].split(";")[0]
        self.assertEqual(self.req("GET", url)[0], 404)
        self.assertEqual(self.req("GET", "/api/v1/events/1/line-survival/../../../etc/passwd")[0], 404)


if __name__ == "__main__":
    unittest.main()
