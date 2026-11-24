"""Exercise an installed Claude Code binary against a loopback-only scripted model.

Run with python3 tests/run_native_edit_verification.py /path/to/claude.
The model supplies tool requests. Claude itself writes the file, runs unittest,
invokes its hooks and writes the transcript consumed by the production reader.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import threading
import unittest
import uuid

from test_edit_verification import EditVerificationTests, ROOT


class ScriptedMessages(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.path.split("?")[0].endswith("/count_tokens"):
            self.reply({"input_tokens": 12})
            return
        if self.path.split("?")[0] != "/v1/messages":
            self.send_error(404)
            return
        seen = sum(1 for m in request["messages"] if isinstance(m.get("content"), list)
                   for b in m["content"] if b.get("type") == "tool_result")
        steps = self.server.steps
        if seen < len(steps):
            name, values = steps[seen]
            block = {"type": "tool_use", "id": f"toolu_local_{seen}", "name": name, "input": values}
            initial = {**block, "input": {}}
            delta = {"type": "input_json_delta", "partial_json": json.dumps(values)}
            reason = "tool_use"
        else:
            block = {"type": "text", "text": "Finished."}
            initial = {"type": "text", "text": ""}
            delta = {"type": "text_delta", "text": block["text"]}
            reason = "end_turn"
        message = {"id": "msg_" + uuid.uuid4().hex, "type": "message", "role": "assistant",
                   "model": request["model"], "content": [], "stop_reason": None, "stop_sequence": None,
                   "usage": {"input_tokens": 12, "output_tokens": 1}}
        if not request.get("stream"):
            self.reply({**message, "content": [block], "stop_reason": reason})
            return
        events = [("message_start", {"message": message}),
                  ("content_block_start", {"index": 0, "content_block": initial}),
                  ("content_block_delta", {"index": 0, "delta": delta}),
                  ("content_block_stop", {"index": 0}),
                  ("message_delta", {"delta": {"stop_reason": reason, "stop_sequence": None},
                                     "usage": {"output_tokens": 1}}),
                  ("message_stop", {})]
        chunks = [f"event: {kind}\ndata: {json.dumps({'type': kind, **data})}\n\n" for kind, data in events]
        self.reply("".join(chunks).encode(), "text/event-stream")

    def reply(self, value, mime="application/json"):
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class NativeAcceptance(EditVerificationTests):
    def run_session(self, model, actor, run_test, value=2):
        sid = str(uuid.uuid4())
        model.steps = [("Read", {"file_path": str(self.file)}),
                       ("Write", {"file_path": str(self.file), "content": f"value = {value}\n"})]
        if run_test:
            model.steps.append(("Bash", {"command": self.command, "description": "Run the widget test"}))
        self.home.mkdir(exist_ok=True)
        local = f"http://127.0.0.1:{model.server_port}"
        env = {k: v for k, v in self.env.items() if k in
               {"SWARMCONTROL_TOKEN", "SWARMCONTROL_SERVER", "SWARMCONTROL_HOST_ID", "SWARMCONTROL_TASK_ID",
                "SWARMCONTROL_VERIFICATION_STATE", "SWARMCONTROL_ACTIVITY_ROOTS"}}
        env.update(PATH=os.environ["PATH"], HOME=str(self.home), CLAUDE_CONFIG_DIR=str(self.home / ".claude"),
                   LANG="C.UTF-8", SWARMCONTROL_AGENT_NAME=actor, PYTHONDONTWRITEBYTECODE="1",
                   ANTHROPIC_BASE_URL=local, ANTHROPIC_API_KEY="local-fixture", SWARMCONTROL_ENV_FILE="",
                   CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1", DISABLE_NON_ESSENTIAL_MODEL_CALLS="1",
                   HTTP_PROXY="http://127.0.0.1:1", HTTPS_PROXY="http://127.0.0.1:1", NO_PROXY="127.0.0.1,localhost")
        settings = subprocess.check_output([sys.executable, str(ROOT / "integrations/verification_hook.py"),
                                            "--print-settings"], text=True)
        result = subprocess.run([CLAUDE, "-p", "Run the local acceptance scenario.", "--session-id", sid,
                                 "--model", "sonnet", "--settings", settings, "--tools", "Read,Write,Bash",
                                 "--permission-mode", "acceptEdits", "--allowedTools", "Read", "Write",
                                 "Bash(python3 -m unittest -v test_widget)", "--max-turns", "6"],
                                cwd=self.repo, env=env, capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(self.file.read_text(), f"value = {value}\n")
        return "claude-code:" + sid

    def test_real_runtime(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), ScriptedMessages) as model:
            threading.Thread(target=model.serve_forever, daemon=True).start()
            try:
                untested = self.run_session(model, "builder-b", False)
                self.file.write_text("value = 1\n")
                tested = self.run_session(model, "builder-a", True)
            finally:
                model.shutdown()
        self.collect(local=True)
        edits = {r["work"]["session"]: r for r in self.events() if r["work"]["action"] == "file_edit"}
        self.assertEqual(set(edits), {tested, untested})
        self.assertEqual(self.detail(edits[untested])["verification"]["status"], "not_recorded")
        result, = self.detail(edits[tested])["verification"]["tests"]
        self.assertEqual(result["result"], "passed")
        evidence = self.req("GET", f"/api/v1/events/{result['event_id']}/evidence")[1]
        self.assertEqual(evidence["session"], tested)
        self.assertEqual(evidence["command_input"], self.command)
        self.assertIn("Ran 1 test", evidence["command_output"])
        self.assertIn("OK", evidence["command_output"])

    def test_native_failed_result(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), ScriptedMessages) as model:
            threading.Thread(target=model.serve_forever, daemon=True).start()
            try:
                self.run_session(model, "builder", True, value=3)
            finally:
                model.shutdown()
        self.collect()
        edit, = [r for r in self.events() if r["work"]["action"] == "file_edit"]
        test, = self.detail(edit)["verification"]["tests"]
        self.assertEqual(test["result"], "failed")
        ev = self.req("GET", f"/api/v1/events/{test['event_id']}/evidence")[1]
        self.assertIn("AssertionError", ev["command_output"])


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python3 tests/run_native_edit_verification.py /path/to/claude")
    CLAUDE = str(Path(sys.argv[1]).resolve(strict=True))
    suite = unittest.TestSuite([NativeAcceptance("test_real_runtime"), NativeAcceptance("test_native_failed_result")])
    sys.exit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
