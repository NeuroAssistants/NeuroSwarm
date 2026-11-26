"""Run the public PowerShell installation command against a temporary real console."""
import os
from pathlib import Path
import shutil
import shlex
import sys
import subprocess
import unittest
from unittest.mock import patch

from test_security import ServerHarness
from validation import ValidationError

POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")


@unittest.skipUnless(POWERSHELL, "PowerShell is required to run the Windows installer")
class PowerShellInstallTests(ServerHarness):
    def run_install(self, token, prelude="", **overrides):
        install_dir = Path(self.tmp.name) / "observer"
        env = {k: v for k, v in os.environ.items() if not k.startswith("SWARMCONTROL_")}
        env.update(SWARMCONTROL_SERVER=f"http://127.0.0.1:{self.port}", SWARMCONTROL_HOST_ID="setup-test",
                   SWARMCONTROL_INSTALL_DIR=str(install_dir), SWARMCONTROL_STATE_DIR=self.tmp.name,
                   SWARMCONTROL_NO_SERVICE="1", SWARMCONTROL_TOKEN=token)
        env.update(overrides)
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command",
             prelude + "\nirm ($env:SWARMCONTROL_SERVER + '/install.ps1') | iex"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
        report = (install_dir / "install.log").read_text(encoding="utf-8-sig")
        if token:
            self.assertFalse(token in result.stdout or token in report, "Token printed during setup")
        self.assertIn("N E U R O S W A R M", result.stdout)
        return result.returncode, report

    def test_pipeline_confirms_exact_live_event(self):
        self.assertEqual(self.login()[0], 200)
        code, report = self.run_install(self.token()["token"])
        self.assertEqual(code, 0, report)
        self.assertIn("Host monitoring only", report)
        self.assertIn("Heartbeat accepted for setup-test", report)
        status, feed, _ = self.req("GET", "/api/v1/event-feed")
        self.assertEqual(status, 200)
        markers = [r for r in feed["records"] if r["source"] == "observer_install_check"]
        self.assertEqual(len(markers), 1)
        marker = markers[0]
        self.assertEqual(marker["host_id"], "setup-test")
        self.assertIn(f'/live?host=setup-test&event=event%3A{marker["id"]}', report)
        self.assertIn("no-service mode", report)

    def test_rejected_key_never_reports_success(self):
        code, report = self.run_install("example-invalid-token")
        self.assertNotEqual(code, 0)
        self.assertIn("HTTP 401", report)
        self.assertNotIn("[INSTALLED]", report)

    def test_missing_key_prints_banner_and_reason(self):
        code, report = self.run_install("")
        self.assertNotEqual(code, 0)
        self.assertIn("[FAILED] Missing enrollment token", report)
        self.assertNotIn("[INSTALLED]", report)

    def test_heartbeat_and_event_failures_are_distinct(self):
        self.assertEqual(self.login()[0], 200)
        with patch.object(self.ctx.guardrails, "evaluate_event", side_effect=ValidationError("Test rejection")):
            code, report = self.run_install(self.token()["token"], SWARMCONTROL_ACTIVITY_ROOTS=self.tmp.name)
        self.assertEqual(code, 0, report)
        self.assertIn("Watching 1 project folder", report)
        self.assertIn("Test event unconfirmed", report)
        self.assertNotIn("[OK] Test event", report)

    def test_retry_keeps_previous_configuration_when_heartbeat_is_rejected(self):
        self.assertEqual(self.login()[0], 200)
        token = self.token()["token"]
        code, report = self.run_install(token, SWARMCONTROL_ACTIVITY_ROOTS=self.tmp.name)
        self.assertEqual(code, 0, report)
        config = Path(self.tmp.name) / "observer" / "agent.env"
        previous = config.read_bytes()
        code, report = self.run_install("example-invalid-token")
        self.assertNotEqual(code, 0)
        self.assertIn("[ROLLBACK]", report)
        self.assertTrue(config.read_bytes() == previous, "Previous agent configuration was lost")

    def test_task_must_report_running_before_success(self):
        self.assertEqual(self.login()[0], 200)
        fake_scheduler = """
function New-ScheduledTaskAction {}
function New-ScheduledTaskTrigger {}
function Register-ScheduledTask {}
function Start-ScheduledTask {}
function Start-Sleep {}
function Get-ScheduledTask { @{ State = 'Ready' } }
"""
        code, report = self.run_install(self.token()["token"], prelude=fake_scheduler,
                                        SWARMCONTROL_NO_SERVICE="0")
        self.assertNotEqual(code, 0)
        self.assertIn("SwarmControlAgent is not running", report)
        self.assertNotIn("[INSTALLED]", report)

    def test_rerun_checks_replacement_instead_of_previous_task_instance(self):
        self.assertEqual(self.login()[0], 200)
        token = self.token()["token"]
        code, report = self.run_install(token)
        self.assertEqual(code, 0, report)
        scheduler = """
$script:ExistingObserver = $true
$script:FreshObserver = $false
function New-ScheduledTaskAction {}
function New-ScheduledTaskTrigger {}
function Register-ScheduledTask {}
function Start-ScheduledTask {
    if (-not $script:ExistingObserver) { $script:FreshObserver = $true }
}
function Stop-ScheduledTask { $script:ExistingObserver = $false }
function Get-ScheduledTask {
    if ($script:ExistingObserver) { return @{ State = 'Running' } }
    if ($script:FreshObserver) { return @{ State = $env:SWARMCONTROL_TEST_FRESH_TASK_STATE } }
    return @{ State = 'Ready' }
}
function Start-Sleep {}
"""
        for state in ("Ready", "Running"):
            with self.subTest(state=state):
                code, report = self.run_install(token, prelude=scheduler, SWARMCONTROL_NO_SERVICE="0",
                                                SWARMCONTROL_TEST_FRESH_TASK_STATE=state)
                last_run = report.rsplit("[START]", 1)[-1]
                self.assertIn("Restarting the running observer", last_run)
                self.assertEqual(code == 0, state == "Running", last_run)
                self.assertEqual("[INSTALLED]" in last_run, state == "Running", last_run)

    @unittest.skipIf(os.name == 'nt', 'Uses a disposable POSIX executable to simulate WinGet')
    def test_prerequisite_install_and_recheck(self):
        self.assertEqual(self.login()[0], 200)
        token = self.token()["token"]
        tools = Path(self.tmp.name) / 'tools'
        tools.mkdir()
        env = dict(PATH=str(tools), LOCALAPPDATA=self.tmp.name)
        code, report = self.run_install(token, **env)
        self.assertNotEqual(code, 0)
        self.assertIn('Install Microsoft App Installer', report)
        winget = tools / 'winget'
        winget.write_text('#!/bin/sh\nexit 19\n')
        winget.chmod(0o700)
        code, report = self.run_install(token, **env)
        self.assertNotEqual(code, 0)
        self.assertIn('WinGet returned 19', report)
        folder = Path(self.tmp.name) / 'Programs/Python/Python313'
        folder.mkdir(parents=True)
        winget.write_text('#!/bin/sh\n' + 'echo "$@" > "$LOCALAPPDATA/args"\n' +
                          '/bin/ln -s ' + shlex.quote(sys.executable) + ' ' + shlex.quote(str(folder / 'python.exe')) + '\n')
        code, report = self.run_install(token, **env)
        self.assertEqual(code, 0, report)
        self.assertIn('Test event #', report)
        self.assertIn('--id Python.Python.3.13 --exact --source winget --scope user',
                      (Path(self.tmp.name) / 'args').read_text())
