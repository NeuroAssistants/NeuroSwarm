"""Hosts: what each observer may share, as it last reported it (issue #11).

Two real observers (`swarmcontrol_agent.py --once`) with different settings report to a spawned console; an older
observer sends a heartbeat without the report. The hosts API and the Hosts section in Chromium must show each host's
own settings with the report time, Unknown for the older one, and no absolute path from either machine.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "agent"), str(Path(__file__).resolve().parent)]
import capture_settings  # noqa: E402
import work_journal as wj  # noqa: E402
from product_qa.test_acceptance_blackbox import HttpClient, SpawnedConsole  # noqa: E402

ADMIN = ("bootstrap_admin", "BootstrapPass!2026#QA")
SWITCHES = ("activity", "commands", "command_output", "file_previews", "line_survival")


class CaptureSettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="ns-capture-settings-")
        t = Path(cls.tmp.name)
        cls.t = t
        cls.srv = SpawnedConsole(t / "console")
        cls.admin = HttpClient(cls.srv.base_url)
        assert cls.admin.json("POST", "/api/v1/auth/login", {"username": ADMIN[0], "password": ADMIN[1]})[0] == 200
        cls.tokens = {}
        for name in ("full-box", "quiet-box", "old-box", "junk-box"):
            st, _, tok = cls.admin.json("POST", "/api/v1/tokens", {"name": name, "scope": "ingest"})
            assert st == 201, tok
            cls.tokens[name] = tok["token"]
        cls.private = {}
        for host, flags in (("full-box", ["--share-commands", "--share-command-output", "--share-file-previews"]), ("quiet-box", [])):
            home = t / host / "home"
            folders = [home / "private-client-alpha" / "repo-one", home / "private-client-alpha" / "repo-two"] if host == "full-box" \
                else [home / "private-client-beta" / "only-repo"]
            for f in folders:
                f.mkdir(parents=True)
            cls.private[host] = [str(f) for f in folders]
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(home), "SWARMCONTROL_TOKEN": cls.tokens[host]}
            run = subprocess.run([sys.executable, str(ROOT / "agent" / "swarmcontrol_agent.py"), "--server", cls.srv.base_url,
                                  "--host-id", host, "--activity-roots", os.pathsep.join(cls.private[host]),
                                  "--state-dir", str(t / host / "state"), "--once", *flags],
                                 env=env, capture_output=True, text=True, timeout=60)
            assert run.returncode == 0, run.stdout + run.stderr
        # An observer from before this report: a heartbeat without capture_settings.
        old = {"host_id": "old-box", "hostname": "old-box", "os_name": "linux", "arch": "x86_64", "agent_version": "0.2.0",
               "harnesses": [], "processes": []}
        st, _, body = cls.admin.json("POST", "/api/v1/ingest/heartbeat", old, headers={"Authorization": f"Bearer {cls.tokens['old-box']}"})
        assert st == 200, body

    @classmethod
    def tearDownClass(cls):
        cls.srv.stop()
        cls.tmp.cleanup()

    def hosts(self):
        st, _, body = self.admin.json("GET", "/api/v1/hosts")
        self.assertEqual(st, 200, body)
        return {h["host_id"]: h for h in body["hosts"]}

    def test_each_observer_shows_its_own_settings_and_an_old_one_is_unknown(self):
        hosts = self.hosts()
        full, = hosts["full-box"]["capture_settings"]
        quiet, = hosts["quiet-box"]["capture_settings"]
        self.assertEqual(full["source"], "observer")
        self.assertEqual(full["settings"], {"activity": True, "shared_folders": 2, "commands": True, "command_output": True,
                                            "file_previews": True, "line_survival": False})
        self.assertEqual(quiet["settings"], {"activity": True, "shared_folders": 1, "commands": False, "command_output": False,
                                             "file_previews": False, "line_survival": False})
        self.assertLess(abs(full["reported_at"] - time.time()), 120)
        self.assertEqual(hosts["old-box"]["capture_settings"], [], "no report: the console shows Unknown")
        blob = json.dumps(hosts)
        for paths in self.private.values():
            for path in paths:
                self.assertNotIn(path, blob)
        self.assertNotIn("private-client", blob)

    def test_a_report_keeps_only_known_switches(self):
        junk = {"host_id": "junk-box", "hostname": "junk-box", "os_name": "linux", "arch": "x86_64", "agent_version": "9",
                "harnesses": [], "processes": [],
                "capture_settings": {"commands": "yes", "command_output": True, "roots": ["/home/u/secret"], "shared_folders": -3}}
        st, _, _ = self.admin.json("POST", "/api/v1/ingest/heartbeat", junk, headers={"Authorization": f"Bearer {self.tokens['junk-box']}"})
        self.assertEqual(st, 200)
        report, = self.hosts()["junk-box"]["capture_settings"]
        self.assertEqual(report["settings"], {"command_output": True})
        self.assertNotIn("/home/u/secret", json.dumps(self.hosts()))
        self.assertIsNone(capture_settings.clean({"commands": 1}))

    def test_hosts_section_in_chromium(self):
        if os.environ.get("SWARMCONTROL_BROWSER_TESTS", "").lower() == "skip":
            self.skipTest("SWARMCONTROL_BROWSER_TESTS=skip")
        import browser_cdp
        binary = browser_cdp.find_browser()
        self.assertTrue(binary, "No Chromium found; see tests/BROWSER-TESTS.md")
        browser = browser_cdp.Browser(binary)
        self.addCleanup(browser.close)
        for view, (w, h, mobile) in {"desktop": (1440, 900, False), "mobile": (390, 844, True)}.items():
            with self.subTest(view=view):
                pg = browser.new_page(w, h, mobile)
                self.addCleanup(pg.close)
                pg.goto(self.srv.base_url + "/")
                pg.wait("document.querySelector('#login-form') && getComputedStyle(document.querySelector('#login-view')).display !== 'none'")
                pg.type("#username", ADMIN[0])
                pg.type("#password", ADMIN[1])
                pg.click("#login-form button[type=submit]")
                pg.wait("document.querySelectorAll('#hosts-list .capture-settings').length >= 4", what="capture settings")
                got = pg.eval("""(() => Object.fromEntries([...document.querySelectorAll('#hosts-list .host-card')].map(card => {
                    const head = card.querySelector('.card-head').textContent;
                    const name = (head.match(/\((full-box|quiet-box|old-box|junk-box)\)/) || head.match(/(full-box|quiet-box|old-box|junk-box)/) || [])[1];
                    const src = card.querySelector('[data-capture-source=observer]');
                    return [name, {when: src.querySelector('.capture-source-head .muted').textContent,
                      switches: Object.fromEntries([...src.querySelectorAll('[data-capture]')].map(li => [li.dataset.capture, li.querySelector('strong').textContent])),
                      note: !!src.querySelector('p')}]; })))()""")
                self.assertEqual(got["full-box"]["switches"], {"activity": "On", "commands": "On", "command_output": "On",
                                                              "file_previews": "On", "line_survival": "Off"})
                self.assertIn("2 shared folders", got["full-box"]["when"])
                self.assertIn("reported", got["full-box"]["when"])
                self.assertEqual(got["quiet-box"]["switches"]["command_output"], "Off")
                self.assertIn("1 shared folder", got["quiet-box"]["when"])
                self.assertEqual(set(got["old-box"]["switches"].values()) - {"Unknown", "On"}, set())
                text = pg.eval("document.body.innerText")
                self.assertNotIn("private-client", text)
                self.assertEqual(pg.overflow()["offenders"], [])
                art = os.environ.get("SWARMCONTROL_BROWSER_ARTIFACTS", "").strip()
                if art:
                    Path(art).mkdir(parents=True, exist_ok=True)
                    import base64
                    box = pg.eval("""(() => { const el = document.querySelector('#hosts-list');
                      for (let d = el.closest('details'); d; d = d.parentElement.closest('details')) d.open = true;
                      const r = el.getBoundingClientRect(); return [r.x + scrollX, r.y + scrollY, r.width, Math.min(r.height, 1400)]; })()""")
                    data = pg.send("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True,
                                                              "clip": {"x": box[0], "y": box[1], "width": box[2], "height": box[3], "scale": 1}})["data"]
                    (Path(art) / f"{view}-capture-settings.png").write_bytes(base64.b64decode(data))


class JournalReportTests(unittest.TestCase):
    def test_local_journal_reports_its_switches_for_its_host(self):
        import activity_inspector as ai
        from unittest.mock import patch
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        t = Path(tmp.name)
        project = t / "work" / "team"
        project.mkdir(parents=True)
        (t / "work" / "other").mkdir()
        conn = sqlite3.connect(t / "j.db")
        self.addCleanup(conn.close)
        from db import Database
        Database(t / "j.db").close()
        with patch.object(ai, "HOME", t / "home"), patch.object(ai, "harnesses", return_value=[]), \
                patch.dict(os.environ, {"SWARMCONTROL_SHARE_COMMANDS": "1", "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "0"}):
            wj.capture_once(conn, {"team"}, project, time.time(), ai.Scope([t / "work" / "other"]), ai.Scope([project], {}, "box-j"))
        row = conn.execute("SELECT host_id, source, settings_json FROM capture_settings").fetchone()
        self.assertEqual(row[:2], ("box-j", "journal"))
        settings = json.loads(row[2])
        self.assertEqual((settings["commands"], settings["command_output"], settings["shared_folders"]), (True, False, 2))
        self.assertNotIn(str(t), row[2])


if __name__ == "__main__":
    unittest.main()
