"""Regression tests for actionable warnings while a swarm is making progress."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from db import Database
from guardrails import GuardrailEngine


class AlertEvidenceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "signals.db")
        self.addCleanup(db.close)
        self.engine = GuardrailEngine(db)

    def emit(self, kind, message, *, harness="codex", **metadata):
        _, alerts = self.engine.evaluate_event({
            "host_id": "fixture", "harness": harness, "agent_name": "worker",
            "event_type": kind, "message": message, "metadata": metadata,
        })
        return {a["rule_code"] for a in alerts}

    def test_successful_batch_is_quiet(self):
        for index in range(8):
            self.assertFalse(self.emit("tool_call", "Invoice processed", item=index))

    def test_progress_interrupts_streak(self):
        for _ in range(3):
            self.assertFalse(self.emit("tool_call", "Review next page", progress=False))
        self.assertFalse(self.emit("tool_call", "Review next page", progress=True))
        for _ in range(3):
            self.assertFalse(self.emit("tool_call", "Review next page", progress=False))
        self.assertEqual(self.emit("tool_call", "Review next page", progress=False), {"LOOP_SUSPECTED"})

    def test_scope_and_interrupted_errors(self):
        for _ in range(3):
            self.assertFalse(self.emit("tool_error", "Timeout", harness="claude-code", task_id="a"))
        self.assertFalse(self.emit("tool_error", "Timeout", task_id="a"))
        self.assertFalse(self.emit("tool_error", "Timeout", harness="claude-code", task_id="b"))
        self.assertIn("LOOP_SUSPECTED", self.emit("tool_error", "Timeout", harness="claude-code", task_id="a"))
        self.assertFalse(self.emit("success", "Artifact saved", task_id="a"))
        for _ in range(3):
            self.assertFalse(self.emit("tool_error", "Timeout", task_id="a"))
        self.assertIn("LOOP_SUSPECTED", self.emit("tool_error", "Timeout", task_id="a"))

    def test_batch_numbers_are_not_rate_limits(self):
        for message in ("Batch 42980 completed", "429 rows saved", "HTTP 4299", "Record 429 delivered"):
            self.assertFalse(self.emit("info", message))
        self.assertFalse(self.emit("rate_limit", "Provider refused request"))
        self.assertFalse(self.emit("error", "Received HTTP/2 429"))
        self.assertIn("QUOTA_EXHAUSTION_BURST", self.emit("info", "Provider status", http_status=429))

    def test_textual_and_typed_429_signals_mix(self):
        self.assertFalse(self.emit("quota_429", "Upstream busy"))
        self.assertFalse(self.emit("retry", "429 Too Many Requests"))
        self.assertIn("QUOTA_EXHAUSTION_BURST", self.emit("error", "HTTP status 429"))
