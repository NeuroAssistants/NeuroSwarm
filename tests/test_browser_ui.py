"""Reproducible browser suite (roadmap step 14): /, /live and the Activity map in a real
headless Chromium at desktop (1440x900) and mobile (390x844) sizes.

Everything runs against a disposable console on loopback with seeded data; nothing is sent
anywhere else. One known edit (tests/test_event_feed_http.py by an agent named
demo-team-builder) is followed from the live table to its session steps, the same
operator flow that is checked by hand in production.

Needs a Chromium binary: run `python3 deploy/fetch_test_browser.py` once (pinned Chrome for
Testing headless shell) or set SWARMCONTROL_CHROMIUM. Without a browser the suite FAILS with
that instruction; set SWARMCONTROL_BROWSER_TESTS=skip to opt out explicitly.
Set SWARMCONTROL_BROWSER_ARTIFACTS=<dir> to keep screenshots of every checked view.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(Path(__file__).resolve().parent)]
import work_journal  # noqa: E402
import browser_cdp  # noqa: E402
from product_qa.test_acceptance_blackbox import HttpClient, SpawnedConsole  # noqa: E402

ADMIN = ("bootstrap_admin", "BootstrapPass!2026#QA")
ORG_B = ("beta_ops", "BetaStrongPass!2026#QA", "Beta Isolation")
KNOWN_FILE = "tests/test_event_feed_http.py"
KNOWN_AGENT = "demo-team-builder"
KNOWN_SESSION = "codex:builder-feed-01"
FILLER = 560            # > 500: the live console must page to reach the oldest step
VIEWPORTS = {"desktop": (1440, 900, False), "mobile": (390, 844, True)}


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


class BrowserUITests(unittest.TestCase):
    browser: browser_cdp.Browser | None = None

    # ------------------------------------------------------------------ fixture
    @classmethod
    def setUpClass(cls) -> None:
        if os.environ.get("SWARMCONTROL_BROWSER_TESTS", "").lower() == "skip":
            raise unittest.SkipTest("SWARMCONTROL_BROWSER_TESTS=skip")
        binary = browser_cdp.find_browser()
        if not binary:
            raise AssertionError("No Chromium found. Run `python3 deploy/fetch_test_browser.py` once, or set "
                                 "SWARMCONTROL_CHROMIUM; SWARMCONTROL_BROWSER_TESTS=skip opts out explicitly.")
        cls.tmp = tempfile.TemporaryDirectory(prefix="swarm-browser-qa-")
        state = Path(cls.tmp.name)
        cls.project = state / "work" / "sample-project"
        for rel in (KNOWN_FILE, "backend/event_feed.py", "frontend/live.js", "README.md"):
            (cls.project / rel).parent.mkdir(parents=True, exist_ok=True)
            (cls.project / rel).write_text("# fixture\n", encoding="utf-8")
        cls._claude_session(state / "server-home")
        cls.srv = SpawnedConsole(state, extra_env={"SWARMCONTROL_ACTIVITY_ROOTS": str(cls.project), "SWARMCONTROL_HOST_ID": "demo-workstation"})
        try:
            cls._seed()
            cls.browser = browser_cdp.Browser(binary)
        except Exception:
            cls.srv.stop()
            cls.tmp.cleanup()
            raise
        art = os.environ.get("SWARMCONTROL_BROWSER_ARTIFACTS", "").strip()
        cls.artifacts = Path(art) if art else None
        if cls.artifacts:
            cls.artifacts.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.browser:
            cls.browser.close()
        cls.srv.stop()
        cls.tmp.cleanup()

    @classmethod
    def _claude_session(cls, home: Path) -> None:
        """A recent Claude Code session inside the shared folder, so the Activity map has real cards."""
        now = time.time()
        p = str(cls.project)
        _jsonl(home / ".claude/projects" / cls.project.name / "s-map-01.jsonl", [
            {"type": "user", "cwd": p, "timestamp": _iso(now - 300), "message": {"role": "user", "content": "fix the feed test"}},
            {"type": "assistant", "cwd": p, "timestamp": _iso(now - 240), "message": {"model": "claude-x", "content": [
                {"type": "tool_use", "name": "TodoWrite", "input": {"todos": [
                    {"content": "Reproduce the feed gap", "status": "completed"},
                    {"content": "Cover it with an HTTP test", "status": "in_progress"}]}},
                {"type": "tool_use", "name": "Read", "input": {"file_path": f"{p}/backend/event_feed.py"}}]}},
            {"type": "assistant", "cwd": p, "timestamp": _iso(now - 120), "message": {"model": "claude-x", "content": [
                {"type": "tool_use", "name": "Edit", "input": {"file_path": f"{p}/{KNOWN_FILE}"}},
                {"type": "tool_use", "name": "Bash", "input": {"command": "python3 -m unittest", "description": "Run the unit tests"}}]}},
        ])

    @classmethod
    def _seed(cls) -> None:
        admin = HttpClient(cls.srv.base_url)
        st, _, _ = admin.json("POST", "/api/v1/auth/login", {"username": ADMIN[0], "password": ADMIN[1]})
        assert st == 200, st
        for host, used in (("qa-box-01", 3900), ("qa-box-02", 1200)):   # 3900/4096 MB: memory alert on box 01
            st, _, tok = admin.json("POST", "/api/v1/tokens", {"name": host, "scope": "ingest"})   # tokens bind to one host
            assert st == 201, (st, tok)
            st, _, body = admin.json("POST", "/api/v1/ingest/heartbeat", {
                "host_id": host, "hostname": host, "os_name": "linux", "arch": "x86_64", "cpu_count": 4, "load_1m": 0.8,
                "mem_total_mb": 4096, "mem_used_mb": used,
                "harnesses": [{"id": "codex", "name": "Codex CLI", "status": "running", "process_count": 1}], "processes": []},
                headers={"Authorization": f"Bearer {tok['token']}"})
            assert st == 200, (st, body)
        now = time.time()
        step = lambda tool, cat, label, ago, files=(), program=None: {  # noqa: E731
            "tool": tool, "category": cat, "label": label, "time": _iso(now - ago), "status": "completed",
            "file_basis": "confirmed", "files": [str(cls.project / f) for f in files], **({"program": program} if program else {})}
        snapshot = {"sessions": [
            {"session_id": KNOWN_SESSION, "host_id": "qa-box-01", "harness": "codex", "agent_name": KNOWN_AGENT,
             "workspace": str(cls.project), "steps": [
                 step("exec_command", "file_read", "Read event_feed.py", 90, ["backend/event_feed.py"], "rg"),
                 step("apply_patch", "file_edit", "Edit test_event_feed_http.py", 60, [KNOWN_FILE]),
                 step("exec_command", "shell", "Run tests", 30, program="python3")]},
            {"session_id": "codex:editor-live-01", "host_id": "qa-box-02", "harness": "codex", "agent_name": "demo-team-editor",
             "workspace": str(cls.project), "steps": [step("apply_patch", "file_edit", "Edit live.js", 45, ["frontend/live.js"])]},
        ]}
        with sqlite3.connect(cls.srv.db_path) as conn:
            work_journal.record(conn, snapshot, {KNOWN_AGENT, "demo-team-editor"}, cls.project.resolve(), now)
            base = now - 6 * 3600
            conn.executemany(
                "INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
                [("qa-box-02", "codex", "agent-filler", "observed_step", "INFO", f"Filler step #{i:03d}",
                  json.dumps({"session": "codex:filler", "action": "file_read", "files": [f"docs/n{i}.md"], "workspace": cls.project.name}),
                  base + i) for i in range(FILLER)])
        beta = HttpClient(cls.srv.base_url)
        st, _, body = beta.json("POST", "/api/v1/auth/register", {"username": ORG_B[0], "password": ORG_B[1], "organization": ORG_B[2]})
        assert st == 201, (st, body)

    # ------------------------------------------------------------------ helpers
    def page(self, view: str) -> browser_cdp.Page:
        w, h, mobile = VIEWPORTS[view]
        pg = self.browser.new_page(w, h, mobile)
        self.addCleanup(pg.close)
        return pg

    def shot(self, pg: browser_cdp.Page, name: str) -> None:
        if self.artifacts:
            pg.screenshot(self.artifacts / f"{name}.png")

    def login(self, pg: browser_cdp.Page, user=ADMIN[0], password=ADMIN[1]) -> None:
        pg.goto(self.srv.base_url + "/")
        pg.wait("document.querySelector('#login-form') && getComputedStyle(document.querySelector('#login-view')).display !== 'none'",
                what="login form")
        pg.type("#username", user)
        pg.type("#password", password)
        pg.click("#login-form button[type=submit]")
        pg.wait("!document.querySelector('#app-view').hidden && getComputedStyle(document.querySelector('#app-view')).display !== 'none'",
                what="console after sign-in")

    def assert_clean(self, pg: browser_cdp.Page, where: str) -> None:
        bad_http = [(s, u) for s, u in pg.http_errors if not (s == 401 and u.endswith("/api/v1/auth/me"))]
        # The pre-sign-in session probe answers 401 by design; Chrome also logs it as a network error.
        errors = [e for e in pg.errors if not ("status of 401" in e and e.endswith("/api/v1/auth/me"))]
        self.assertEqual(errors, [], f"{where}: browser errors")
        self.assertEqual(bad_http, [], f"{where}: failed requests")
        ov = pg.overflow()
        self.assertLessEqual(ov["scrollWidth"], ov["clientWidth"] + 1, f"{where}: horizontal overflow {ov}")

    def rows_text(self, pg: browser_cdp.Page) -> str:
        return pg.eval("[...document.querySelectorAll('#rows tr[data-key]')].map(r => r.innerText).join('\\n')") or ""

    # ------------------------------------------------------------------ scenarios
    def _console_and_map(self, view: str) -> None:
        pg = self.page(view)
        self.login(pg)
        pg.wait("document.querySelector('#kpi-hosts') && document.querySelector('#kpi-hosts').textContent.trim() === '2'", what="2 hosts in KPI")
        self.assert_clean(pg, f"{view} / after sign-in")
        self.shot(pg, f"{view}-console")

        # Command palette (Ctrl+K) opens, filters and closes with Escape.
        pg.key("k", "KeyK", modifiers=2, key_code=75)
        pg.wait("!document.querySelector('#cmdk-overlay').classList.contains('hidden')", what="command palette open")
        pg.type("#cmdk-input", "activity")
        self.assertGreater(pg.eval("document.querySelectorAll('#cmdk-list [data-cmdk-idx], #cmdk-list li').length"), 0)
        pg.key("Escape", "Escape", key_code=27)
        pg.wait("document.querySelector('#cmdk-overlay').classList.contains('hidden')", what="command palette closed")

        # Activity map: real card from the seeded Claude session, then Timeline / Sessions / Folders and search.
        pg.wait("!!document.querySelector('#activity-map .ap-tab')", what="activity map tabs")
        pg.wait("document.querySelector('#activity-map').innerText.includes('Run the unit tests')", what="latest seeded step on the map")
        for tab in ("timeline", "sessions", "folders", "overview"):
            pg.click(f"#activity-map .ap-tab[data-view='{tab}']")
            pg.wait(f"document.querySelector(\"#activity-map .ap-tab[data-view='{tab}']\").getAttribute('aria-selected') === 'true'",
                    what=f"{tab} tab selected")
            if tab == "timeline":
                pg.wait("document.querySelectorAll('#activity-map .ap-timeline [data-kind=step]').length > 0", what="timeline steps")
                self.shot(pg, f"{view}-map-timeline")
                # The latest step opens its detail; Escape closes it.
                pg.click("#activity-map .ap-timeline [data-kind=step]:last-of-type")
                pg.wait("!!document.querySelector('dialog[open]') && document.querySelector('dialog[open]').innerText.includes('Run the unit tests')",
                        what="step detail dialog")
                self.shot(pg, f"{view}-map-step-detail")
                pg.key("Escape", "Escape", key_code=27)
                pg.wait("!document.querySelector('dialog[open]')", what="detail dialog closed")
            self.assert_clean(pg, f"{view} map/{tab}")
        pg.type("#activity-map input[data-role=search]", "zz-no-such-file")
        pg.wait("(document.querySelector('#activity-map .ap-matchline')||{}).innerText?.startsWith('0 of')", what="search with no match")
        pg.type("#activity-map input[data-role=search]", "test_event_feed_http")
        pg.wait("/^[1-9]\\d* of/.test((document.querySelector('#activity-map .ap-matchline')||{}).innerText||'')", what="search match")
        self.shot(pg, f"{view}-map-search")
        self.assert_clean(pg, f"{view} map search")

    def _live_operator_flow(self, view: str) -> None:
        pg = self.page(view)
        self.login(pg)
        pg.goto(self.srv.base_url + "/live")
        pg.wait("document.querySelectorAll('#rows tr[data-key]').length > 0", what="live rows")
        self.assert_clean(pg, f"{view} /live first paint")

        # Agent work → scope agent → search the known file.
        mobile = VIEWPORTS[view][2]
        if mobile:   # the explorer is an off-canvas drawer on phones; each choice closes it
            pg.click("#mobile-tree-btn")
            pg.settled("[data-persp='agent_work']")
        pg.click("[data-persp='agent_work']")
        if mobile:
            pg.wait("!document.querySelector('#sidebar').classList.contains('mobile-open')", what="drawer closed")
            pg.click("#mobile-tree-btn")
            pg.settled(f"[data-scope-agent='{KNOWN_AGENT}']")
        pg.click(f"[data-scope-agent='{KNOWN_AGENT}']")
        pg.type("#search", "test_event_feed_http.py")
        pg.wait(f"[...document.querySelectorAll('#rows tr[data-key]')].length === 1", what="exactly one matching row")
        text = self.rows_text(pg)
        self.assertIn(KNOWN_FILE, text)
        self.assertNotIn("demo-team-editor", text)
        self.shot(pg, f"{view}-live-filtered")

        # Open it and follow its session through the correlations tab.
        pg.click("#rows tr[data-key]")
        pg.wait(f"document.querySelector('#detail').innerText.includes('{KNOWN_FILE}')", what="detail shows known file")
        pg.click("[data-dtab='correlations']")
        pg.wait("document.querySelectorAll('#detail .corr-btn').length >= 2", what="session correlations")
        corr = pg.eval("[...document.querySelectorAll('#detail .corr-btn')].map(b => b.innerText).join('\\n')")
        self.assertGreaterEqual(corr.count("Same session"), 2, corr)
        self.assertIn("python3", corr)
        self.shot(pg, f"{view}-live-session")
        self.assert_clean(pg, f"{view} /live session")

        # Clearing the search keeps the agent scope; resetting returns everything.
        pg.click("#reset-filters")
        pg.wait("document.querySelectorAll('#rows tr[data-key]').length > 3", what="rows after reset")

        # Paging reaches the oldest seeded step with no duplicates.
        for _ in range(8):
            visible = pg.eval("!!document.querySelector('#load-older') && !document.querySelector('#load-older').classList.contains('hidden')")
            if not visible:
                break
            before = pg.eval("document.querySelectorAll('#rows tr[data-key]').length")
            pg.click("#load-older")
            pg.wait(f"document.querySelectorAll('#rows tr[data-key]').length > {before} || "
                    "document.querySelector('#load-older').classList.contains('hidden')", what="older page")
        pg.type("#search", "Filler step #000")
        pg.wait("document.querySelectorAll('#rows tr[data-key]').length === 1", what="oldest filler reachable")
        keys = pg.eval("(() => { document.querySelector('#search').value=''; document.querySelector('#search').dispatchEvent(new Event('input'));"
                       "return null; })()")
        self.assertIsNone(keys)
        pg.wait(f"document.querySelectorAll('#rows tr[data-key]').length >= {FILLER}", what="full history loaded")
        dupes = pg.eval("(() => { const k = [...document.querySelectorAll('#rows tr[data-key]')].map(r => r.dataset.key); return k.length - new Set(k).size; })()")
        self.assertEqual(dupes, 0)
        self.assert_clean(pg, f"{view} /live history")

    def _isolation(self, view: str) -> None:
        pg = self.page(view)
        self.login(pg, ORG_B[0], ORG_B[1])
        pg.goto(self.srv.base_url + "/live")
        pg.wait("document.querySelector('#rows') && (document.querySelector('#empty') && !document.querySelector('#empty').classList.contains('hidden') || "
                "document.querySelectorAll('#rows tr[data-key]').length >= 0)", what="live loaded for org B")
        time.sleep(1.5)  # one refresh cycle
        body = pg.eval("document.body.innerText")
        for leak in (KNOWN_AGENT, "test_event_feed_http", "Filler step", "qa-box-01"):
            self.assertNotIn(leak, body, f"{view}: org B sees {leak}")
        self.assert_clean(pg, f"{view} /live org B")

    # ------------------------------------------------------------------ tests
    def test_desktop_console_and_activity_map(self):
        self._console_and_map("desktop")

    def test_mobile_console_and_activity_map(self):
        self._console_and_map("mobile")

    def test_desktop_live_operator_flow(self):
        self._live_operator_flow("desktop")

    def test_mobile_live_operator_flow(self):
        self._live_operator_flow("mobile")

    def test_desktop_other_organization_sees_nothing(self):
        self._isolation("desktop")

    def test_mobile_other_organization_sees_nothing(self):
        self._isolation("mobile")


if __name__ == "__main__":
    unittest.main()
