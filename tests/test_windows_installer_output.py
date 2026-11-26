"""Black-box checks for the PowerShell installer, served by a disposable console."""
from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlparse

try:
    from .product_qa.test_acceptance_blackbox import _seed_generic_agent_records
    from .test_security import ServerHarness
except ImportError:
    from product_qa.test_acceptance_blackbox import _seed_generic_agent_records
    from test_security import ServerHarness


POWERSHELL = os.environ.get("NEUROSWARM_TEST_POWERSHELL") or shutil.which("powershell.exe") or shutil.which("pwsh")
PIPE_INSTALLER = """
try {
    Invoke-RestMethod "$env:SWARMCONTROL_TEST_URL/install.ps1" | Invoke-Expression
    Write-Host '[QA] Caller continued'
    exit ([int] $LASTEXITCODE)
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    Write-Host '[QA] Caller caught installer failure'
    exit ([int] $LASTEXITCODE)
}
"""


@unittest.skipUnless(POWERSHELL, "PowerShell required for installer tests")
class WindowsInstallerOutputTests(ServerHarness):
    host_id = "windows-installer-qa"

    def run_installer(self, token: str, root: Path | None = None, *, from_file: bool = False, extra_env: dict | None = None):
        temp = Path(self.tmp.name)
        install_dir = temp / "observer install"
        profile = temp / "observer-profile"
        profile.mkdir(exist_ok=True)
        env = {k: v for k, v in os.environ.items() if not k.startswith("SWARMCONTROL_")}
        env.update(
            SWARMCONTROL_TEST_URL=f"http://127.0.0.1:{self.port}",
            SWARMCONTROL_TOKEN=token,
            SWARMCONTROL_HOST_ID=self.host_id,
            SWARMCONTROL_INSTALL_DIR=str(install_dir),
            SWARMCONTROL_STATE_DIR=str(temp / "observer-state"),
            SWARMCONTROL_ACTIVITY_HOME=str(profile),
            SWARMCONTROL_NO_SERVICE="1",
        )
        if root is not None:
            env["SWARMCONTROL_ACTIVITY_ROOTS"] = str(root)
        env.update(extra_env or {})
        args = [POWERSHELL, "-NoProfile", "-NoLogo", "-NonInteractive"]
        if os.name == "nt":
            args += ["-ExecutionPolicy", "Bypass"]
        if from_file:
            status, script, _ = self.req("GET", "/install.ps1", cookie=False)
            self.assertEqual(status, 200)
            path = temp / "downloaded-install.ps1"
            path.write_text(script, encoding="utf-8")
            args += ["-File", str(path)]
        else:
            args += ["-Command", PIPE_INSTALLER]
        run = subprocess.run(args, env=env, capture_output=True, text=True, timeout=45)
        output = run.stdout + run.stderr
        self.assertIn("Windows observer installer", output)
        log = (install_dir / "install.log").read_text(encoding="utf-8-sig")
        if token:
            self.assertNotIn(token, output)
            self.assertNotIn(token, log)
        return run.returncode, output, log

    def assert_test_event(self, output: str):
        receipt = re.search(r"Test event #([0-9]+) recorded\.", output)
        self.assertIsNotNone(receipt, output)
        number = int(receipt.group(1))
        url = re.search(r"http://127\.0\.0\.1:\d+/live\?\S+", output)
        self.assertIsNotNone(url, output)
        link = urlparse(url.group())
        self.assertEqual(parse_qs(link.query), {"host": [self.host_id], "event": [f"event:{number}"]})
        self.assertEqual(self.req("GET", link.path + "?" + link.query)[0], 200)

        status, feed, _ = self.req("GET", "/api/v1/event-feed")
        self.assertEqual(status, 200)
        marker = next(row for row in feed["records"] if row["key"] == f"event:{number}")
        self.assertEqual(marker["host_id"], self.host_id)
        self.assertEqual(marker["source"], "observer_install_check")

        status, _, headers = self.req("POST", "/api/v1/auth/register", {
            "username": "other-org", "organization": "Other organization", "password": secrets.token_urlsafe(24),
        }, cookie=False)
        self.assertEqual(status, 201)
        self.cookie = headers["set-cookie"].split(";")[0]
        status, other_feed, _ = self.req("GET", "/api/v1/event-feed")
        self.assertEqual(status, 200)
        self.assertEqual(other_feed["records"], [])

    def test_irm_shows_health_only_and_link_to_real_event(self):
        self.assertEqual(self.login()[0], 200)
        code, output, log = self.run_installer(self.token()["token"])
        self.assertEqual(code, 0, output)
        self.assertIn("Caller continued", output)
        for message in ("Heartbeat accepted", "Host monitoring only", "Test event #", "background monitoring disabled"):
            self.assertIn(message, output)
            self.assertIn(message, log)
        self.assert_test_event(output)

    def test_irm_distinguishes_rejected_enrollment_and_preserves_caller(self):
        fixture_token = "sc_tok_fixture_" + secrets.token_urlsafe(24)
        code, output, log = self.run_installer(fixture_token)
        self.assertEqual(code, 1, output)
        self.assertIn("Caller caught installer failure", output)
        self.assertIn("Heartbeat rejected (HTTP 401)", log)
        self.assertNotIn("[INSTALLED]", output)
        self.assertNotIn("Test event #", output)

    def test_file_mode_keeps_missing_key_exit_code(self):
        code, output, log = self.run_installer("", from_file=True)
        self.assertEqual(code, 2, output)
        self.assertIn("Missing enrollment token", log)
        self.assertNotIn("[INSTALLED]", output)

    def test_rerun_preserves_the_project_and_rolls_back_a_rejected_key(self):
        self.assertEqual(self.login()[0], 200)
        token = self.token()["token"]
        temp = Path(self.tmp.name)
        project = temp / "team's project"
        project.mkdir()
        config = temp / "observer install" / "agent.env"

        code, output, _ = self.run_installer(token, project)
        self.assertEqual(code, 0, output)
        original = config.read_bytes()

        code, output, _ = self.run_installer(token)
        self.assertEqual(code, 0, output)
        self.assertIn("Watching 1 project folder", output)
        self.assertEqual(config.read_bytes(), original)

        rejected = "sc_tok_fixture_" + secrets.token_urlsafe(24)
        code, output, _ = self.run_installer(rejected)
        self.assertEqual(code, 1, output)
        self.assertIn("Restored previous observer", output)
        self.assertEqual(config.read_bytes(), original)

    def test_irm_sends_real_activity_with_a_configured_project(self):
        self.assertEqual(self.login()[0], 200)
        temp = Path(self.tmp.name)
        project = temp / "sample project"
        _seed_generic_agent_records(
            temp / "observer-profile", project, "src/example.py", "notes.md", temp / "private",
        )
        code, output, log = self.run_installer(self.token()["token"], project)
        self.assertEqual(code, 0, output)
        self.assertRegex(log, r"Watching 1 project folder\(s\); [1-9][0-9]* matching session")
        status, activity, _ = self.req("GET", "/api/v1/activity")
        self.assertEqual(status, 200)
        self.assertTrue(any(s["host_id"] == self.host_id for s in activity["sessions"]))
        self.assert_test_event(output)

    def test_logo_and_openbot_projects_are_suggested_without_sharing_them(self):
        """A machine with OpenBot and no project folder: the logo shows, OpenBot's shared projects are listed with the
        exact command to share one, and nothing is shared until the operator reruns with that folder."""
        self.assertEqual(self.login()[0], 200)
        temp = Path(self.tmp.name)
        profile = temp / "windows-user"
        for name in ("alpha-project", "beta-project", ".hidden"):
            (profile / "OpenBot" / "Shared" / name).mkdir(parents=True)
        code, output, log = self.run_installer(self.token()["token"], extra_env={"USERPROFILE": str(profile), "APPDATA": str(temp / "appdata")})
        self.assertEqual(code, 0, output)
        self.assertIn("N E U R O S W A R M", output)
        self.assertIn("/___________/", output)
        self.assertIn("OpenBot found", output)
        self.assertIn("alpha-project", output)
        self.assertNotIn(".hidden", output)
        suggestion = next(line for line in output.splitlines() if "SWARMCONTROL_ACTIVITY_ROOTS=" in line)
        self.assertIn(str(profile / "OpenBot" / "Shared"), suggestion)
        self.assertIn(f"http://127.0.0.1:{self.port}/install.ps1 | iex", suggestion)
        status, activity, _ = self.req("GET", "/api/v1/activity")
        self.assertEqual(status, 200)
        self.assertFalse(any(s["host_id"] == self.host_id for s in activity.get("sessions", [])), "nothing shared without consent")

    @unittest.skipUnless(os.name == "nt" and os.environ.get("NEUROSWARM_TEST_NATIVE_TASK") == "1",
                         "Requires a disposable Windows runner with Task Scheduler")
    def test_native_scheduled_observer_is_replaced_and_keeps_reporting(self):
        def task(command):
            return subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
                                  check=True, capture_output=True, text=True, timeout=30).stdout.strip()

        name = "SwarmControlAgent"
        self.assertEqual(task(f"if (Get-ScheduledTask -TaskName {name} -ErrorAction SilentlyContinue) {{ 'present' }}"), "")
        self.assertEqual(self.login()[0], 200)
        token = self.token()["token"]
        try:
            for install in ("first", "upgrade"):
                code, output, _ = self.run_installer(token, extra_env={"SWARMCONTROL_NO_SERVICE": "0",
                                                                       "SWARMCONTROL_INTERVAL": "5"})
                self.assertEqual(code, 0, output)
                self.assertIn("running and scheduled at sign-in", output)
                if install == "upgrade":
                    self.assertIn("Restarting the running observer", output)
                self.assertEqual(task(f"(Get-ScheduledTask -TaskName {name}).State.ToString()"), "Running")
                last_seen = self.ctx.db.query_one("SELECT last_seen_at FROM hosts WHERE host_id=?", (self.host_id,))
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    time.sleep(1)
                    row = self.ctx.db.query_one("SELECT last_seen_at FROM hosts WHERE host_id=?", (self.host_id,))
                    if row["last_seen_at"] > last_seen["last_seen_at"]:
                        break
                else:
                    self.fail(f"Background observer did not report after {install}")
        finally:
            task(f"if (Get-ScheduledTask -TaskName {name} -ErrorAction SilentlyContinue) {{ "
                 f"Stop-ScheduledTask -TaskName {name}; Unregister-ScheduledTask -TaskName {name} -Confirm:$false }}")


if __name__ == "__main__":
    unittest.main()
