"""Independent black-box acceptance QA for the upgraded Live Operations Console.

Covers:
1. Work journal (`work_journal.py`) recording file edits, reads, shell commands,
   deduplication, and strict redaction/filtering of secrets & out-of-project paths.
2. Incremental real-time cursor feed (`GET /api/v1/event-feed`) delivering bursts
   > 500 records without drops, delivering alert ACK updates on the same key,
   accurate status-bar counts, read-token support, RBAC, and invalid cursor rejection.
3. Keyset-paginated history (`GET /api/v1/live-records?before=...`) reaching older
   events beyond the initial 500 window, plus session correlation filtering
   (`?session=&host=&agent=&runtime=`).
4. Strict two-organization tenant isolation across `/api/v1/event-feed` and
   `/api/v1/live-records` even with identical host_id and session_id.
5. `/live`, `/live.js`, `/live.css` delivery, content-hash versioning, and strict CSP.
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
import work_journal  # noqa: E402

try:
    from .test_acceptance_blackbox import HttpClient, SpawnedConsole
except ImportError:
    from test_acceptance_blackbox import HttpClient, SpawnedConsole


class LiveConsoleAcceptanceTests(unittest.TestCase):
    """Independent black-box acceptance tests for the Live Event Console."""

    def _spawn(self, extra_env: dict[str, str] | None = None) -> tuple[SpawnedConsole, Path]:
        tmp = tempfile.TemporaryDirectory(prefix="swarm-live-qa-")
        self.addCleanup(tmp.cleanup)
        state_dir = Path(tmp.name)
        srv = SpawnedConsole(state_dir, extra_env=extra_env)
        self.addCleanup(srv.stop)
        return srv, state_dir

    def test_01_work_journal_records_edits_reads_commands_dedups_and_redacts_secrets(self):
        srv, state_dir = self._spawn()
        project = state_dir / "demo-project"
        outside = state_dir / "outside-private"
        (project / "frontend").mkdir(parents=True)
        (project / "backend").mkdir(parents=True)
        outside.mkdir(parents=True)
        edit_file = project / "frontend" / "live.js"
        read_file = project / "backend" / "event_feed.py"
        env_file = project / ".env"
        secret_file = project / "secrets.json"
        out_file = outside / "payroll.csv"
        for f in (edit_file, read_file, env_file, secret_file, out_file):
            f.write_text("sample\n", encoding="utf-8")

        now = time.time()
        iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now - 5))
        snapshot = {
            "sessions": [
                {
                    "session_id": "codex:sess-qa-01",
                    "host_id": "qa-box-01",
                    "harness": "codex",
                    "agent_name": "qa-worker-alpha",
                    "workspace": str(project),
                    "steps": [
                        {
                            "tool": "edit_file",
                            "category": "file_edit",
                            "label": "Edit live.js",
                            "time": iso,
                            "status": "completed",
                            "file_basis": "confirmed",
                            "files": [str(edit_file), str(env_file), str(secret_file), str(out_file)],
                        },
                        {
                            "tool": "read_file",
                            "category": "file_read",
                            "label": "Read event_feed.py",
                            "time": iso,
                            "status": "completed",
                            "file_basis": "confirmed",
                            "files": [str(read_file)],
                        },
                        {
                            "tool": "exec_command",
                            "category": "shell",
                            "label": "Run tests",
                            "program": "python3",
                            "time": iso,
                            "status": "completed",
                            "files": [],
                        },
                        {
                            "tool": "update_plan",
                            "category": "plan",
                            "label": "Update the plan",
                            "time": iso,
                            "status": "completed",
                            "files": [],
                        },
                    ],
                },
                {
                    "session_id": "codex:sess-unselected",
                    "host_id": "qa-box-01",
                    "harness": "codex",
                    "agent_name": "unselected-agent",
                    "workspace": str(project),
                    "steps": [
                        {
                            "tool": "edit_file",
                            "category": "file_edit",
                            "label": "Edit live.js",
                            "time": iso,
                            "files": [str(edit_file)],
                        }
                    ],
                },
            ]
        }

        # Run record() twice to confirm deduplication via observed_step_keys
        with sqlite3.connect(srv.db_path) as conn:
            work_journal.record(conn, snapshot, {"qa-worker-alpha"}, project.resolve(), now)
            work_journal.record(conn, snapshot, {"qa-worker-alpha"}, project.resolve(), now + 1)

        admin = HttpClient(srv.base_url)
        st, _, _ = admin.json("POST", "/api/v1/auth/login", {"username": "bootstrap_admin", "password": "BootstrapPass!2026#QA"})
        self.assertEqual(st, 200)

        st, _, live = admin.json("GET", "/api/v1/live-records")
        self.assertEqual(st, 200)
        obs = [r for r in live["records"] if r["source"] == "observed_step"]
        self.assertEqual(len(obs), 4, f"Expected exactly 4 deduplicated steps, got {len(obs)}: {obs}")

        blob = json.dumps(live, ensure_ascii=False)
        self.assertIn("File edit · frontend/live.js", blob)
        self.assertIn("File read · backend/event_feed.py", blob)
        self.assertIn("Run tests · python3", blob)
        self.assertIn("Plan update", blob)
        self.assertNotIn("unselected-agent", blob)
        for forbidden in (".env", "secrets.json", "payroll.csv", "outside-private"):
            self.assertNotIn(forbidden, blob, f"Sensitive or out-of-scope file leaked: {forbidden}")

        # Verify session correlation filter returns the 4 steps with structured work details
        qs = urllib.parse.urlencode(
            {"session": "codex:sess-qa-01", "host": "qa-box-01", "agent": "qa-worker-alpha", "runtime": "codex"}
        )
        st, _, corr = admin.json("GET", f"/api/v1/live-records?{qs}")
        self.assertEqual(st, 200)
        self.assertEqual(len(corr["records"]), 4)
        edit_row = next(r for r in corr["records"] if r.get("work", {}).get("action") == "file_edit")
        self.assertEqual(edit_row["work"]["files"], ["frontend/live.js"])
        self.assertEqual(edit_row["work"]["workspace"], "demo-project")
        self.assertEqual(edit_row["work"]["basis"], "confirmed")

        # Invalid session filter missing required field must return 400
        st_bad, _, _ = admin.json("GET", "/api/v1/live-records?session=codex:sess-qa-01")
        self.assertEqual(st_bad, 400)

    def test_02_event_feed_burst_620_records_ack_update_history_and_rbac(self):
        srv, _ = self._spawn()
        anon = HttpClient(srv.base_url)
        admin = HttpClient(srv.base_url)
        viewer = HttpClient(srv.base_url)

        # Anonymous denied on both routes
        for p in ("/api/v1/event-feed", "/api/v1/live-records"):
            st, _, _ = anon.request("GET", p)
            self.assertEqual(st, 401, f"Anonymous {p} must return 401")

        st, _, _ = admin.json("POST", "/api/v1/auth/login", {"username": "bootstrap_admin", "password": "BootstrapPass!2026#QA"})
        self.assertEqual(st, 200)
        st, _, tok_ing = admin.json("POST", "/api/v1/tokens", {"name": "burst-box", "scope": "ingest"})
        self.assertEqual(st, 201)
        st, _, tok_ro = admin.json("POST", "/api/v1/tokens", {"name": "wallboard-ro", "scope": "read"})
        self.assertEqual(st, 201)

        # Trigger 1 runaway CPU alert via real heartbeat
        st, _, _ = anon.json(
            "POST",
            "/api/v1/ingest/heartbeat",
            {
                "host_id": "burst-box-01",
                "hostname": "burst-box-01",
                "os_name": "linux",
                "arch": "x86_64",
                "cpu_count": 4,
                "load_1m": 1.2,
                "mem_total_mb": 4096,
                "mem_used_mb": 1024,
                "harnesses": [{"id": "codex", "name": "Codex CLI", "status": "running", "process_count": 1}],
                "processes": [
                    {"pid": 4321, "user": "dev", "comm": "codex", "cpu_pct": 95.5, "rss_mb": 210.0, "uptime_sec": 120, "harness": "Codex CLI"}
                ],
            },
            headers={"Authorization": f"Bearer {tok_ing['token']}"},
        )
        self.assertEqual(st, 200)

        # Seed 620 events directly in Org 1 DB (> 500 default feed page and > 250 history page)
        base_ts = time.time() - 700
        with sqlite3.connect(srv.db_path) as conn:
            conn.executemany(
                "INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
                [
                    (
                        "burst-box-01",
                        "codex",
                        "agent-burst",
                        "observed_step",
                        "INFO",
                        f"Burst step #{i}",
                        json.dumps({"session": "s-burst", "action": "file_edit", "files": [f"src/f{i}.py"], "workspace": "app"}),
                        base_ts + i * 0.5,
                    )
                    for i in range(620)
                ],
            )

        # 1) Walk incremental /api/v1/event-feed from start (first page + cursor tail)
        st, _, first_page = admin.json("GET", "/api/v1/event-feed?limit=500")
        self.assertEqual(st, 200)
        self.assertTrue(first_page["reset"])
        self.assertEqual(first_page["counts"]["alerts"]["OPEN"], 1)
        self.assertGreaterEqual(first_page["counts"]["events_24h_by_severity"]["INFO"], 620)
        cursor = first_page["cursor"]
        alert_rec = next(r for r in first_page["records"] if r["kind"] == "alert")
        alert_id = alert_rec["id"]

        # Append 260 MORE events after cursor (testing multi-page burst delivery via cursor + more=True)
        after_ts = time.time() + 1
        with sqlite3.connect(srv.db_path) as conn:
            conn.executemany(
                "INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
                [
                    (
                        "burst-box-01",
                        "codex",
                        "agent-burst",
                        "observed_step",
                        "WARNING",
                        f"Live burst #{j}",
                        json.dumps({"session": "s-live", "action": "shell", "program": "pytest"}),
                        after_ts + j * 0.01,
                    )
                    for j in range(260)
                ],
            )

        delivered_keys = []
        pages = 0
        while True:
            st, _, chunk = admin.json("GET", f"/api/v1/event-feed?cursor={urllib.parse.quote(cursor)}&limit=100")
            self.assertEqual(st, 200, chunk)
            self.assertFalse(chunk["reset"])
            delivered_keys.extend(r["key"] for r in chunk["records"] if r["kind"] == "event")
            cursor = chunk["cursor"]
            pages += 1
            if not chunk["more"]:
                break
            self.assertLess(pages, 10, "Feed pagination loop did not converge")

        self.assertEqual(len(delivered_keys), 260, "All 260 post-cursor burst events must be delivered")
        self.assertEqual(len(set(delivered_keys)), 260, "Burst delivery must not duplicate event keys")

        # 2) Acknowledge alert -> arrives as update on the SAME alert key with acked_by
        st, _, _ = admin.json("POST", f"/api/v1/alerts/{alert_id}/ack", {})
        self.assertEqual(st, 200)
        st, _, ack_delta = admin.json("GET", f"/api/v1/event-feed?cursor={urllib.parse.quote(cursor)}")
        self.assertEqual(st, 200)
        updated_alerts = [r for r in ack_delta["records"] if r["key"] == f"alert:{alert_id}"]
        self.assertEqual(len(updated_alerts), 1, "Acked alert must arrive on same key")
        self.assertEqual(updated_alerts[0]["state"], "ACKED")
        self.assertEqual(updated_alerts[0]["acked_by"], "bootstrap_admin")
        self.assertEqual(ack_delta["counts"]["alerts"]["ACKED"], 1)
        self.assertEqual(ack_delta["counts"]["alerts"]["OPEN"], 0)

        # 3) Walk keyset history /api/v1/live-records?before=... all the way back to Burst step #0
        seen_hist = set()
        hist_messages = set()
        next_cur = None
        hist_pages = 0
        while True:
            url = "/api/v1/live-records" + (f"?before={urllib.parse.quote(next_cur)}" if next_cur else "")
            st, _, hpage = admin.json("GET", url)
            self.assertEqual(st, 200, hpage)
            for r in hpage["records"]:
                k = (r["kind"], r["id"])
                self.assertNotIn(k, seen_hist, f"Duplicate record across history pages: {k}")
                seen_hist.add(k)
                hist_messages.add(r["message"])
            next_cur = hpage.get("next")
            hist_pages += 1
            if not next_cur:
                break
            self.assertLess(hist_pages, 10)
        self.assertIn("Burst step #0", hist_messages, "History pagination must reach records older than initial 500")
        self.assertGreaterEqual(len(seen_hist), 881)

        # 4) Invalid cursors rejected with 400
        for bad_url in ("/api/v1/event-feed?cursor=tampered", "/api/v1/event-feed?limit=99999", "/api/v1/live-records?before=bad"):
            st_b, _, _ = admin.json("GET", bad_url)
            self.assertEqual(st_b, 400, f"Expected 400 for {bad_url}, got {st_b}")

        # 5) Read token works on BOTH /api/v1/event-feed and /api/v1/live-records
        for ro_path in ("/api/v1/event-feed?limit=10", "/api/v1/live-records"):
            st_ro, _, _ = anon.json("GET", ro_path, headers={"Authorization": f"Bearer {tok_ro['token']}"})
            self.assertEqual(st_ro, 200, f"Read token must be allowed on {ro_path}")

        # 6) Viewer role can read live console routes but gets 403 on alert ack
        st, _, inv = admin.json("POST", "/api/v1/invitations", {"username": "live_viewer", "role": "viewer"})
        self.assertEqual(st, 201)
        st, _, _ = viewer.json(
            "POST",
            "/api/v1/auth/accept-invitation",
            {"token": inv["token"], "username": "live_viewer", "password": "LiveViewerPass!2026"},
        )
        self.assertEqual(st, 200)
        st, _, _ = viewer.json("GET", "/api/v1/event-feed?limit=10")
        self.assertEqual(st, 200)
        st, _, _ = viewer.json("GET", "/api/v1/live-records")
        self.assertEqual(st, 200)
        st, _, _ = viewer.json("POST", f"/api/v1/alerts/{alert_id}/ack", {})
        self.assertEqual(st, 403)

    def test_03_two_org_isolation_on_event_feed_history_and_session_correlation(self):
        srv, _ = self._spawn()
        org1 = HttpClient(srv.base_url)
        org2 = HttpClient(srv.base_url)
        anon = HttpClient(srv.base_url)

        st, _, _ = org1.json("POST", "/api/v1/auth/login", {"username": "bootstrap_admin", "password": "BootstrapPass!2026#QA"})
        self.assertEqual(st, 200)
        st, _, _ = org2.json(
            "POST",
            "/api/v1/auth/register",
            {"username": "org2_ops", "password": "Org2StrongPass!2026", "organization": "Beta Isolation"},
        )
        self.assertEqual(st, 201)

        st, _, t1 = org1.json("POST", "/api/v1/tokens", {"name": "shared-box-1"})
        self.assertEqual(st, 201)
        st, _, t2 = org2.json("POST", "/api/v1/tokens", {"name": "shared-box-2"})
        self.assertEqual(st, 201)

        # Ingest events with the EXACT SAME host_id & session into Org 1 and Org 2
        for tok, msg in ((t1["token"], "ORG1_ONLY_EVENT_MARKER"), (t2["token"], "ORG2_ONLY_EVENT_MARKER")):
            st, _, _ = anon.json(
                "POST",
                "/api/v1/ingest/event",
                {
                    "host_id": "same-host-99",
                    "harness": "codex",
                    "agent_name": "same-agent",
                    "event_type": "observed_step",
                    "severity": "WARNING",
                    "message": msg,
                    "metadata": {"session": "shared-sess-1", "action": "file_edit", "files": ["app.py"]},
                },
                headers={"Authorization": f"Bearer {tok}"},
            )
            self.assertEqual(st, 200)

        for path in (
            "/api/v1/event-feed",
            "/api/v1/live-records",
            "/api/v1/live-records?session=shared-sess-1&host=same-host-99&agent=same-agent&runtime=codex",
        ):
            st1, _, d1 = org1.json("GET", path)
            st2, _, d2 = org2.json("GET", path)
            self.assertEqual(st1, 200)
            self.assertEqual(st2, 200)
            b1, b2 = json.dumps(d1), json.dumps(d2)
            self.assertIn("ORG1_ONLY_EVENT_MARKER", b1)
            self.assertNotIn("ORG2_ONLY_EVENT_MARKER", b1, f"Org 1 leaked Org 2 on {path}")
            self.assertIn("ORG2_ONLY_EVENT_MARKER", b2)
            self.assertNotIn("ORG1_ONLY_EVENT_MARKER", b2, f"Org 2 leaked Org 1 on {path}")

    def test_04_live_console_assets_csp_and_no_inline_scripts(self):
        srv, _ = self._spawn()
        c = HttpClient(srv.base_url)

        st_h, hdrs_h, body_h = c.request("HEAD", "/live")
        self.assertEqual(st_h, 200)
        self.assertEqual(body_h, b"")
        self.assertIn("script-src 'self'", hdrs_h.get("content-security-policy", ""))
        self.assertIn(
            "no-store",
            hdrs_h.get("cache-control", ""),
            "BLOCKER: /live serves Cache-Control: no-cache without content-hashed live.js/live.css (Cloudflare CDN will serve stale JS/CSS for up to 4h)",
        )

        st, _, raw = c.request("GET", "/live")
        self.assertEqual(st, 200)
        html = raw.decode("utf-8")
        # No inline script bodies or inline event handlers
        self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)[^>]*>")
        self.assertNotRegex(html, r"\son[a-z]+\s*=", "Inline event handler violates strict CSP")
        for asset in ("live.css", "live.js"):
            m = re.search(rf"/{re.escape(asset)}\?v=([0-9a-f]{{12}})", html)
            self.assertIsNotNone(m, f"Expected content-hashed /{asset}?v=<hash> in live.html")
            st_a, _, raw_a = c.request("GET", m.group(0))
            self.assertEqual(st_a, 200, f"{m.group(0)} returned {st_a}")
            self.assertGreater(len(raw_a), 500)


if __name__ == "__main__":
    unittest.main()
