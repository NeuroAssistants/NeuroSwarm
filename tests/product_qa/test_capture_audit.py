"""Capture coverage audit as a regression test. Runs tests/product_qa/capture_audit.py once (~7 s)
on the local journal and the remote agent with the shared core reader, for Codex, Claude Code, OpenCode and
Antigravity, and checks the invariants. Defects D1-D7 found by the audit are fixed; each has a test that requires
the correct behaviour (no `expectedFailure` remains).
"""
from __future__ import annotations

import unittest

try:
    from . import capture_audit as ca
except ImportError:  # run from inside tests/product_qa
    import capture_audit as ca

NORMAL = ("script", "burst30", "trickle", "rescan", "rotation", "two_agents", "privacy", "outage")
# Audit D7 fixed: Codex plan updates (tools.update_plan inside `exec`) are journal steps, so nothing is allowed missing.
ALLOWED_MISSING: dict[str, int] = {}


class CaptureAuditTests(unittest.TestCase):
    results: list[dict] = []

    @classmethod
    def setUpClass(cls) -> None:
        cls.results = ca.run_all(paths=("local", "remote-core", "remote-fallback"))

    def rows(self, *scenarios):
        out = [r for r in self.results if r["scenario"] in scenarios]
        self.assertTrue(out, scenarios)
        for r in out:
            self.assertNotIn("error", r, r)
        return out

    def test_no_loss_duplicate_or_misattribution_in_normal_operation(self):
        self.assertIn(("antigravity", "remote-fallback"), {(r["runtime"], r["path"]) for r in self.rows("script")})
        for r in self.rows(*NORMAL):
            c, where = r["counts"], f"{r['scenario']}/{r['runtime']}/{r['path']}"
            with self.subTest(where):
                self.assertLessEqual(c["missing"], ALLOWED_MISSING.get(r["runtime"], 0), r["detail"])
                self.assertEqual(c["duplicates"], 0, r["detail"])
                self.assertEqual(c["extra"], 0, r["detail"])
                self.assertEqual(c["wrong_agent"], 0, r["detail"])
                self.assertEqual(c["wrong_file_root"], 0, r["detail"])

    def test_privacy_nothing_leaves_the_shared_folders(self):
        for r in self.results:
            with self.subTest(f"{r['scenario']}/{r['runtime']}/{r['path']}"):
                self.assertEqual(r.get("leaks"), [], r)
        for r in self.rows("privacy"):
            self.assertEqual(r["counts"]["private_session_events"], 0, r)

    def test_rotation_is_reported_as_a_gap(self):
        for r in self.rows("rotation"):
            self.assertGreaterEqual(r["counts"]["gap_events"], 1, r)

    # ---- audit defects D1-D7, now required behaviour ----
    def test_d1_record_over_400kB_is_captured(self):
        for r in self.rows("big_record"):
            self.assertEqual(r["counts"]["missing"], 0, r["detail"])
            self.assertEqual(r["counts"]["duplicates"], 0, r["detail"])

    def test_d2_new_log_over_640kB_is_read_from_its_first_line(self):
        for r in self.rows("new_log_640k"):
            self.assertEqual(r["counts"]["missing"], 0, r["detail"])

    def test_defect_remote_clock_ahead_drops_everything(self):
        rows = self.rows("clock_skew")
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(r["counts"]["missing"], ALLOWED_MISSING.get(r["runtime"], 0), r["detail"])

    def test_d4_claude_subagent_actions_are_read(self):
        for r in self.rows("subagent"):
            self.assertEqual(r["counts"]["missing"], 0, r["detail"])
            self.assertEqual(r["counts"]["wrong_agent"], 0, r["detail"])

    def test_d5_sessions_launched_together_stay_separate(self):
        for r in self.rows("two_agents"):
            self.assertEqual(r["counts"]["merged_sessions"], 0, r)
            self.assertEqual(r["counts"]["missing"], 0, r["detail"])

    def test_d7_codex_plan_updates_are_steps(self):
        for r in self.rows("script"):
            if r["runtime"] == "codex":
                self.assertEqual(r["counts"]["missing"], 0, r["detail"])


if __name__ == "__main__":
    unittest.main()
