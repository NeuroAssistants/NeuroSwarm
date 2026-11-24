"""Independent HTTP and console checks against the ephemeral ServerHarness fixture.

Run: python3 -m unittest discover -s tests -p test_console_blackbox.py -v
The DOM case needs Node.js and jsdom 26. To install only this test dependency,
use npm install --prefix /tmp/swarm-qa-js --ignore-scripts --no-save jsdom@26.1.0
and set NODE_PATH=/tmp/swarm-qa-js/node_modules for the test run.
"""

import hashlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

if __package__:
    from .test_security import ServerHarness
else:
    from test_security import ServerHarness


# Run the served UI in a DOM implementation. Replay only responses read from the
# test server. jsdom does not fetch resources or execute scripts from page markup.
RENDER_CONSOLE = """
const {JSDOM} = require('jsdom');
const fs = require('node:fs');

async function render() {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  const dom = new JSDOM(input.html, {url: input.origin, runScripts: 'outside-only'});
  const {window} = dom;
  try {
    const hasEntry = Array.from(window.document.scripts).some(script => {
      const url = new URL(script.src, input.origin);
      return url.origin === input.origin && url.pathname === '/app.js';
    });
    if (!hasEntry) {
      throw new Error('Console entry script is missing');
    }
    window.fetch = async path => {
      if (path === '/api/v1/activity') return {ok: false, status: 503};
      if (!Object.hasOwn(input.responses, path)) throw new Error('Unexpected API path: ' + path);
      return {ok: true, status: 200, json: async () => input.responses[path]};
    };
    window.eval(input.script);
    window.eval(input.activityScript);
    await new Promise(resolve => setImmediate(resolve));
    const sections = {};
    for (const id of ['hosts-list', 'events-list', 'alerts-list', 'digest-bullets']) {
      sections[id] = window.document.getElementById(id).textContent;
    }
    for (const id of ['work-board', 'activity-map']) {
      for (const selector of ['.report-summary', '.report-steps p']) {
        sections[id + ' ' + selector] = Array.from(
          window.document.querySelectorAll('#' + id + ' ' + selector), node => node.textContent
        );
      }
    }
    return {
      sections,
      appVisible: !window.document.getElementById('app-view').classList.contains('hidden'),
      markerElements: window.document.querySelectorAll('qa-note').length
    };
  } finally {
    window.close();
  }
}
render().then(result => process.stdout.write(JSON.stringify(result)))
  .catch(error => { console.error(error.message); process.exitCode = 1; });
"""


class BlackBoxGLMTests(ServerHarness):
    env_overrides = {"SWARMCONTROL_QUIET": "1"}

    def setUp(self):
        super().setUp()
        self.assertNotEqual(self.port, 8790, "QA requires an ephemeral port")
        self.origin = f"http://127.0.0.1:{self.port}"
        self.assertEqual(self.login(headers={"Origin": self.origin})[0], 200)

    def read(self, path):
        status, body, _ = self.req("GET", path)
        self.assertEqual(status, 200, path)
        return body

    def ingest(self, token, kind, body):
        status, _, _ = self.req(
            "POST", f"/api/v1/ingest/{kind}", body, headers=self.bearer(token), cookie=False
        )
        return status

    def test_operator_and_observer_credentials_have_separate_roles(self):
        observer = self.token("QA observer")
        for path in ("/api/v1/overview", "/api/v1/tokens", "/api/v1/audit/verify", "/api/v1/work-board"):
            for headers in ({}, self.bearer(observer)):
                with self.subTest(path=path, observer=bool(headers)):
                    status, _, response_headers = self.req("GET", path, headers=headers, cookie=False)
                    self.assertEqual(status, 401)
                    self.assertEqual(response_headers["cache-control"], "no-store")
        self.assertEqual(self.req("POST", "/api/v1/ingest/event", {"host_id": "qa-roles"})[0], 401)
        self.assertEqual(self.read("/api/v1/events")["events"], [])

    def test_logging_out_one_operator_session_leaves_another_active(self):
        first = {"Cookie": self.cookie, "Origin": self.origin}
        self.assertEqual(self.login(headers={"Origin": self.origin})[0], 200)
        self.assertEqual(self.req("POST", "/api/v1/auth/logout", {}, headers=first, cookie=False)[0], 200)
        self.assertEqual(self.req("GET", "/api/v1/auth/me", headers=first, cookie=False)[0], 401)
        self.assertTrue(self.read("/api/v1/auth/me")["authenticated"])

    def test_foreign_origin_does_not_revoke_session_or_enrollment(self):
        token = self.token("QA origin")
        other_site = {"Origin": "https://other.invalid"}
        self.assertEqual(self.req("POST", "/api/v1/auth/logout", {}, headers=other_site)[0], 403)
        self.assertTrue(self.read("/api/v1/auth/me")["authenticated"])
        path = f"/api/v1/tokens/{token['id']}"
        self.assertEqual(self.req("DELETE", path, headers=other_site)[0], 403)
        self.assertIsNone(self.read("/api/v1/tokens")["tokens"][0]["revoked_at"])
        self.assertEqual(self.req("DELETE", path, headers={"Origin": self.origin})[0], 200)

    def test_parallel_first_heartbeat_and_event_share_one_enrollment(self):
        token = self.token("QA observer and hook")
        host = "qa-observer"
        with ThreadPoolExecutor(max_workers=2) as pool:
            heartbeat = pool.submit(self.ingest, token, "heartbeat", self.hb(host))
            event = pool.submit(self.ingest, token, "event", {"host_id": host, "message": "hook ready"})
            self.assertEqual(heartbeat.result(), 200)
            self.assertEqual(event.result(), 200)
        overview = self.read("/api/v1/overview")
        self.assertEqual([row["host_id"] for row in overview["hosts"]], [host])
        self.assertEqual([(row["host_id"], row["message"]) for row in overview["events"]], [(host, "hook ready")])
        self.assertEqual([row["bound_host_id"] for row in self.read("/api/v1/tokens")["tokens"]], [host])

    def test_independent_hosts_enroll_concurrently_with_their_own_tokens(self):
        enrollments = [(self.token(host), host) for host in ("qa-east", "qa-west")]
        with ThreadPoolExecutor(max_workers=2) as pool:
            reports = [pool.submit(self.ingest, token, "heartbeat", self.hb(host))
                       for token, host in enrollments]
            self.assertEqual([report.result() for report in reports], [200, 200])
        tokens = self.read("/api/v1/tokens")["tokens"]
        self.assertCountEqual([(r["id"], r["bound_host_id"]) for r in tokens],
                              [(token["id"], host) for token, host in enrollments])
        self.assertCountEqual([r["host_id"] for r in self.read("/api/v1/hosts")["hosts"]],
                              ["qa-east", "qa-west"])

    def test_token_rotation_preserves_history_and_rejects_retired_observer(self):
        old = self.token("before rotation")
        host = "qa-rotation"
        self.assertEqual(self.ingest(old, "heartbeat", self.hb(host)), 200)
        self.assertEqual(self.ingest(old, "event", {"host_id": host, "message": "before"}), 200)
        new = self.token("after rotation")
        self.assertEqual(self.ingest(new, "heartbeat", self.hb(host)), 403)
        self.assertEqual(self.req("DELETE", f"/api/v1/tokens/{old['id']}")[0], 200)
        self.assertEqual(self.ingest(new, "heartbeat", self.hb(host)), 200)
        self.assertEqual(self.ingest(old, "event", {"host_id": host, "message": "retired"}), 401)
        self.assertEqual(self.ingest(new, "event", {"host_id": host, "message": "after"}), 200)
        self.assertCountEqual([e["message"] for e in self.read("/api/v1/events")["events"]], ["before", "after"])
        active = [row for row in self.read("/api/v1/tokens")["tokens"] if row["revoked_at"] is None]
        self.assertEqual([(r["id"], r["bound_host_id"]) for r in active], [(new["id"], host)])

    def test_process_batch_limit_preserves_last_accepted_snapshot(self):
        token = self.token("process limit")
        processes = [{"pid": i, "comm": "worker"} for i in range(1, 201)]
        original = self.hb("qa-processes", hostname="accepted", processes=processes)
        self.assertEqual(self.ingest(token, "heartbeat", original), 200)
        oversized = dict(original, hostname="pending", processes=[*processes, {"pid": 201}])
        self.assertEqual(self.ingest(token, "heartbeat", oversized), 400)
        host, = self.read("/api/v1/hosts")["hosts"]
        self.assertEqual(host["hostname"], "accepted")
        self.assertEqual([p["pid"] for p in host["processes"]], list(range(1, 201)))

    def test_metadata_limit_is_checked_before_enrollment(self):
        token = self.token("metadata limit")
        host = "qa-metadata"
        note = "z" * (8192 - len(json.dumps({"note": ""}).encode("utf-8")))
        self.assertEqual(self.ingest(token, "event", {"host_id": host, "metadata": {"note": note + "z"}}), 400)
        self.assertEqual(self.read("/api/v1/events")["events"], [])
        self.assertIsNone(self.read("/api/v1/tokens")["tokens"][0]["bound_host_id"])
        self.assertEqual(self.ingest(token, "event", {"host_id": host, "metadata": {"note": note}}), 200)
        event, = self.read("/api/v1/events")["events"]
        self.assertEqual(event["metadata"], {"note": note})
        self.assertEqual(self.read("/api/v1/tokens")["tokens"][0]["bound_host_id"], host)

    def test_audit_head_matches_sha256_recomputed_from_public_rows(self):
        before = self.read("/api/v1/audit/verify")
        token = self.token('QA estación & "A"')
        self.assertEqual(self.req("DELETE", f"/api/v1/tokens/{token['id']}")[0], 200)
        after = self.read("/api/v1/audit/verify")
        rows = sorted(self.read("/api/v1/audit")["audit"], key=lambda r: r["id"])
        self.assertTrue(after["ok"])
        self.assertIsNone(after["broken_at"])
        self.assertEqual(after["entries"], before["entries"] + 2)
        self.assertEqual(len(rows), after["entries"])
        self.assertEqual([r["action"] for r in rows[-2:]], ["TOKEN_CREATED", "TOKEN_REVOKED"])
        previous = "GENESIS"
        for row in rows:
            self.assertEqual(row["prev_hash"], previous)
            fields = [previous, row["id"], f"{row['created_at']:.6f}", row["actor"],
                      row["action"], row["target"], row["detail"]]
            material = json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            previous = hashlib.sha256(material).hexdigest()
            self.assertEqual(row["entry_hash"], previous)
        self.assertEqual(after["head"], previous)

    def test_installer_enrolls_from_environment_in_private_directory(self):
        token = self.token("installer QA")
        expected = f"curl -fsSL {self.origin}/install.sh | SWARMCONTROL_TOKEN={token['token']} bash"
        self.assertTrue(token["install_command"] == expected, "Unexpected installation command")
        directory = Path(self.tmp.name) / "QA install"
        # Observe the actual observer invocation without logging argv or its test credential.
        bin_dir = Path(self.tmp.name) / "bin"
        bin_dir.mkdir()
        python_shim = bin_dir / "python3"
        python_shim.write_text(
            '#!/bin/sh\n'
            'for arg do\n'
            '    case "$arg" in *"$SWARMCONTROL_TOKEN"*) echo "Token found in argv" >&2; exit 86;; esac\n'
            'done\n'
            ': > "$0.checked"\n'
            f'exec {shlex.quote(sys.executable)} "$@"\n',
            encoding="utf-8",
        )
        python_shim.chmod(0o700)
        env = {
            "PATH": f"{bin_dir}{os.pathsep}{os.defpath}",
            "SWARMCONTROL_TOKEN": token["token"],
            "SWARMCONTROL_HOST_ID": "qa-installer",
            "SWARMCONTROL_INSTALL_DIR": str(directory),
            "CURL_HOME": self.tmp.name,
            "NO_PROXY": "*",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        run = subprocess.run(["bash", "-s", "--", "--no-service"], input=self.read("/install.sh"),
                             env=env, cwd=self.tmp.name, text=True, capture_output=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr.replace(token["token"], "[redacted]"))
        self.assertFalse(token["token"] in run.stdout + run.stderr, "Installer printed the enrollment token")
        self.assertTrue((bin_dir / "python3.checked").is_file(), "Observer argv was not observed")
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((directory / "agent.env").stat().st_mode), 0o600)
        for asset in ("detector.py", "swarmcontrol_agent.py"):
            self.assertEqual((directory / asset).read_text(), self.read(f"/agent/{asset}"))
        host, = self.read("/api/v1/hosts")["hosts"]
        self.assertEqual(host["host_id"], "qa-installer")
        self.assertEqual(self.read("/api/v1/tokens")["tokens"][0]["bound_host_id"], host["host_id"])

    def test_stored_hostname_process_and_message_render_as_literal_text(self):
        node = shutil.which("node")
        if not node or subprocess.run([node, "-e", "require.resolve('jsdom')"],
                                      capture_output=True, timeout=5).returncode:
            self.skipTest("Install Node.js and jsdom 26 to run the console DOM case")
        token = self.token("UI QA")
        hostname = 'Node <qa-note>Á & "B"</qa-note>'
        command = "Worker <qa-note>O'Brien & C</qa-note>"
        message = 'Batch <qa-note>3 & "4"</qa-note> completed'
        host = "qa-frontend"
        beat = self.hb(host, hostname=hostname, processes=[{"pid": 11, "comm": command, "cpu_pct": 95}])
        self.assertEqual(self.ingest(token, "heartbeat", beat), 200)
        self.assertEqual(self.ingest(token, "event", {"host_id": host, "event_type": "work_done", "message": message}), 200)
        api_paths = ("/api/v1/auth/me", "/api/v1/overview", "/api/v1/tokens", "/api/v1/audit/verify", "/api/v1/work-board")
        page = {"origin": self.origin, "html": self.read("/"), "script": self.read("/app.js"),
                "activityScript": self.read("/activity.js"),
                "responses": {path: self.read(path) for path in api_paths}}
        result = subprocess.run([node, "-e", RENDER_CONSOLE], input=json.dumps(page), text=True,
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        rendered = json.loads(result.stdout)
        self.assertTrue(rendered["appVisible"])
        self.assertEqual(rendered["markerElements"], 0)
        for section, values in (("hosts-list", (hostname, command)), ("events-list", (message,)),
                                ("alerts-list", (hostname, command)), ("digest-bullets", (hostname, command))):
            for value in values:
                with self.subTest(section=section, value=value):
                    self.assertIn(value, rendered["sections"][section])
        for view in ("work-board", "activity-map"):
            for selector in (".report-summary", ".report-steps p"):
                with self.subTest(view=view, selector=selector):
                    self.assertIn(message, rendered["sections"][f"{view} {selector}"])
