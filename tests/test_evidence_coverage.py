import importlib.util
import sqlite3
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("coverage_report", Path(__file__).resolve().parents[1] / "deploy/evidence_coverage.py")
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


class CoverageTests(unittest.TestCase):
    def test_empty_absent_late_and_outside_window(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.executescript("""
            CREATE TABLE events(id INTEGER PRIMARY KEY, event_type, created_at, metadata_json);
            CREATE TABLE event_texts(event_id);
            CREATE TABLE event_images(event_id);
            INSERT INTO event_texts VALUES (4), (4);
            CREATE TABLE event_execution(event_id INTEGER PRIMARY KEY, command_output);
            INSERT INTO events VALUES
              (1,'observed_step',1,'{"action":"shell","program":"wc"}'),
              (2,'observed_step',2,'{"action":"shell","program":"wc"}'),
              (3,'observed_step',3,'{"action":"shell","program":"wc"}'),
              (4,'observed_step',4,'{"action":"web","tool":"snapshot"}'),
              (5,'heartbeat',5,'{}');
            INSERT INTO event_execution VALUES (2,'');
        """)
        rows = report.coverage(db, 2)
        self.assertEqual([(r["program"], r["events"], r["recorded_empty"], r["without_recorded_output"])
                          for r in rows], [("wc", 2, 1, 1), ("snapshot", 1, 0, 1)])
        self.assertEqual(rows[1]["with_file_preview"], 1)
        db.execute("INSERT INTO event_execution VALUES (3,'done')")
        self.assertEqual(report.coverage(db, 2)[1]["without_recorded_output"], 0)
