"""Two observers share a console while keeping their historical evidence separate."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from threading import Barrier
import time
from unittest.mock import patch

try:
    from .test_capture_incremental import append, stamp
    from .test_security import ServerHarness, ROOT
except ImportError:
    from test_capture_incremental import append, stamp
    from test_security import ServerHarness, ROOT

from swarmcontrol_agent import load_capture_state, load_pending_queue

# Separate processes mirror independent observer installations and isolate the
# capture reader's process-wide home directory.
OBSERVER_SCAN = """
import json
from pathlib import Path
import sys

from swarmcontrol_agent import post_json, ship_activity_once

config = json.load(sys.stdin)

def post(url, token, payload):
    ack = post_json(url, token, payload)
    if config["drop_ack"] and ack.get("steps_persisted") == 1:
        raise ConnectionError("simulated lost acknowledgement after commit")
    return ack

try:
    result = ship_activity_once(
        server=config["server"],
        token=config["token"],
        raw_roots=[config["workspace"]],
        host_id=config["host"],
        state_dir=Path(config["state"]),
        home_dir=Path(config["home"]),
        poster=post,
        use_core=True,
    )
except ConnectionError as exc:
    result = {"error": str(exc)}
print(json.dumps(result))
"""

HISTORY = "/api/v1/live-records"
ACTIVITY = "/api/v1/ingest/activity"


class RemoteObserverIsolationTests(ServerHarness):
    def test_parallel_capture_and_restart_after_lost_ack(self):
        self.assertEqual(self.login()[0], 200)
        hosts = {
            "qa-east": ("cat result.txt", "east original\n"),
            "qa-west": ("head -n 1 result.txt", "west original\n"),
        }
        tokens = {host: self.token(host) for host in hosts}
        for host, token in tokens.items():
            status, _, _ = self.req("POST", "/api/v1/ingest/heartbeat", self.hb(host),
                                    headers=self.bearer(token), cookie=False)
            self.assertEqual(status, 200)

        observed_at = stamp()
        for host, (command, output) in hosts.items():
            root = Path(self.tmp.name) / host
            self.record_command(root, command, output, observed_at)

        both_reports = Barrier(2, timeout=8)
        original_post = self.httpd.RequestHandlerClass.do_POST

        def concurrent_post(handler):
            if handler.path == ACTIVITY:
                both_reports.wait()
            return original_post(handler)

        with patch.object(self.httpd.RequestHandlerClass, "do_POST", concurrent_post):
            with ThreadPoolExecutor(max_workers=2) as pool:
                east = pool.submit(self.scan_observer, "qa-east", tokens["qa-east"], drop_ack=True)
                west = pool.submit(self.scan_observer, "qa-west", tokens["qa-west"])
                self.assertEqual(east.result(), {"error": "simulated lost acknowledgement after commit"})
                self.assertEqual(west.result()["steps_persisted"], 1)

        east_root = Path(self.tmp.name) / "qa-east"
        east_state = east_root / "state"
        self.assertEqual(len(load_pending_queue(east_state)), 1)
        self.assertFalse(load_capture_state(east_state)["offsets"])
        expected = [(host, *execution) for host, execution in hosts.items()]
        original_ids = self.assert_history(expected)

        # A new command sees the changed file, while the queued original still
        # carries the old output. Reconnect with the saved queue and same token.
        self.record_command(east_root, "cat result.txt", "east after reconnect\n", stamp(1))
        retry = self.scan_observer("qa-east", tokens["qa-east"])
        self.assertEqual(retry["chunks_sent"], 2)
        self.assertEqual(retry["steps_persisted"], 1)
        self.assertEqual(load_pending_queue(east_state), [])
        self.assertTrue(load_capture_state(east_state)["offsets"])

        final_ids = self.assert_history([*expected, ("qa-east", "cat result.txt", "east after reconnect\n")])
        for event, event_id in original_ids.items():
            self.assertEqual(final_ids[event], event_id)

    def record_command(self, root, command, output, timestamp):
        workspace = root / "project"
        rollout = root / "home/.codex/rollout.jsonl"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "result.txt").write_text(output, encoding="utf-8")
        run = subprocess.run(["sh", "-c", command], cwd=workspace, check=True,
                             capture_output=True, text=True, timeout=5)
        self.assertEqual(run.stdout, output)
        append(rollout, [{"timestamp": timestamp, "payload": {"type": "item_completed", "item": {
            "type": "CommandExecution", "cwd": str(workspace), "command": ["sh", "-c", command],
            "parsed_cmd": [{"type": "read", "cmd": command, "path": "result.txt", "name": "result.txt"}],
            "aggregated_output": run.stdout, "exit_code": run.returncode,
        }}}])
        with closing(sqlite3.connect(rollout.parent / "state_5.sqlite")) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS threads (
                id TEXT PRIMARY KEY, cwd TEXT, model TEXT, tokens_used INT,
                updated_at INT, rollout_path TEXT, model_provider TEXT)""")
            db.execute("INSERT OR REPLACE INTO threads VALUES ('shared-session', ?, ?, 1, ?, ?, ?)",
                       (str(workspace), "gpt-x", int(time.time()), str(rollout), "openai"))

    def scan_observer(self, host, token, *, drop_ack=False):
        root = Path(self.tmp.name) / host
        config = {
            "host": host, "token": token["token"], "server": f"http://127.0.0.1:{self.port}",
            "home": str(root / "home"), "state": str(root / "state"),
            "workspace": str(root / "project"), "drop_ack": drop_ack,
        }
        run = subprocess.run(
            [sys.executable, "-c", OBSERVER_SCAN], cwd=root, input=json.dumps(config),
            env={**os.environ, "PYTHONPATH": str(ROOT / "agent"), "PYTHONDONTWRITEBYTECODE": "1",
                 "SWARMCONTROL_SHARE_COMMANDS": "1", "SWARMCONTROL_SHARE_COMMAND_OUTPUT": "1",
                 "SWARMCONTROL_SHARE_FILE_PREVIEWS": "0"},
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def assert_history(self, expected):
        status, history, _ = self.req("GET", HISTORY)
        self.assertEqual(status, 200)
        records = [record for record in history["records"] if record["source"] == "observed_step"]
        events = {}
        for record in records:
            event_id = record["id"]
            status, detail, _ = self.req("GET", f"/api/v1/events/{event_id}/evidence")
            self.assertEqual(status, 200)
            self.assertEqual(detail["record"]["host_id"], record["host_id"])
            self.assertEqual(detail["files"], ["result.txt"])
            self.assertEqual(detail["session"], "codex:shared-session")
            self.assertEqual(detail["exit_code"], 0)
            key = (record["host_id"], detail["command_input"], detail["command_output"])
            self.assertNotIn(key, events, "Repeated delivery must keep one historical event per command")
            events[key] = event_id
        self.assertCountEqual(events, expected)
        return events
