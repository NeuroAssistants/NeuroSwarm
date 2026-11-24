"""EVENT-FEED-CONTRACT v1: a console that stays open must never skip a record, even in bursts."""
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from db import Database  # noqa: E402
import event_feed as ef  # noqa: E402


def add_event(db, i, sev="INFO", host="worker-01"):
    return db.execute("INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,metadata_json,created_at) "
                      "VALUES (?,?,?,?,?,?,?,?)", (host, "codex", "agent", "tool_error", sev, f"event {i}", '{"n": %d}' % i,
                                                  time.time()))


def add_alert(db, title, sev="CRITICAL", ts=None, host="worker-01"):
    ts = ts or time.time()
    return db.execute("INSERT INTO alerts(host_id,rule_code,severity,title,summary,evidence_json,status,created_at,updated_at) "
                      "VALUES (?,?,?,?,?,?,?,?,?)", (host, "fixture-rule-" + title, sev, title, "summary", '{"cpu": 97}', "OPEN", ts, ts))


def drain(db, cursor, limit=500, max_calls=50):
    """What the console does: keep reading while `more` is true. Returns (records by key, cursor, calls)."""
    seen, calls = {}, 0
    while True:
        calls += 1
        page = ef.feed(db, cursor, limit)
        for r in page["records"]:
            seen[r["key"]] = r
        cursor = page["cursor"]
        if not page["more"] or calls >= max_calls:
            return seen, cursor, calls


class EventFeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Database(Path(self.tmp.name) / "org1.sqlite3")
        self.addCleanup(self.db.close)

    def test_first_read_is_latest_window_with_cursor_at_end(self):
        for i in range(3):
            add_event(self.db, i)
        add_alert(self.db, "CPU high")
        page = ef.feed(self.db)
        self.assertTrue(page["reset"])
        self.assertEqual(len(page["records"]), 4)
        self.assertEqual(ef.feed(self.db, page["cursor"])["records"][0]["kind"], "alert",
                         "only the alert re-sent inside the grace window; no event repeats")

    def test_burst_larger_than_any_page_is_delivered_completely(self):
        cursor = ef.feed(self.db)["cursor"]
        now = time.time()
        for i in range(1200):
            add_event(self.db, i)
        for i in range(1100):  # all inside the grace window, the case that could loop forever
            add_alert(self.db, f"alert {i}", ts=now + i * 0.0001)
        seen, cursor, calls = drain(self.db, cursor, limit=500)
        self.assertEqual(sum(k.startswith("event:") for k in seen), 1200)
        self.assertEqual(sum(k.startswith("alert:") for k in seen), 1100)
        self.assertLessEqual(calls, 6, "pagination terminates")
        later, _, _ = drain(self.db, cursor)
        self.assertFalse(any(k.startswith("event:") for k in later), "no event is delivered twice once caught up")

    def test_acknowledgement_arrives_as_an_update_of_the_same_key(self):
        aid = add_alert(self.db, "Disk full", ts=time.time() - 60)
        cursor = ef.feed(self.db)["cursor"]
        now = time.time()
        self.db.execute("UPDATE alerts SET status='ACKED',acked_by='ana',acked_at=?,updated_at=? WHERE id=?", (now, now, aid))
        rec = {r["key"]: r for r in ef.feed(self.db, cursor)["records"]}[f"alert:{aid}"]
        self.assertEqual((rec["state"], rec["acked_by"]), ("ACKED", "ana"))

    def test_write_with_the_same_timestamp_as_the_cursor_is_not_lost(self):
        ts = time.time()
        add_alert(self.db, "first", ts=ts)
        cursor = ef.feed(self.db)["cursor"]
        late = add_alert(self.db, "same instant, committed later", ts=ts)
        self.assertIn(f"alert:{late}", {r["key"] for r in ef.feed(self.db, cursor)["records"]})

    def test_counts_for_the_status_bar(self):
        add_alert(self.db, "a", "CRITICAL")
        add_alert(self.db, "b", "WARNING")
        acked = add_alert(self.db, "c", "WARNING")
        self.db.execute("UPDATE alerts SET status='ACKED' WHERE id=?", (acked,))
        add_event(self.db, 1, "ERROR")
        c = ef.feed(self.db)["counts"]
        self.assertEqual(c["alerts"], {"OPEN": 2, "ACKED": 1, "RESOLVED": 0})
        self.assertEqual(c["open_alerts_by_severity"]["CRITICAL"], 1)
        self.assertEqual(c["open_alerts_by_severity"]["WARNING"], 1)
        self.assertEqual(c["events_24h_by_severity"]["ERROR"], 1)

    def test_bad_cursor_and_limit_are_rejected(self):
        for bad in ("x", "1.e1.a1.i1.z", "1.e1;DROP TABLE events.a1.i1.c", "1.e" + "9" * 30 + ".a1.i1.c"):
            with self.assertRaises(ef.FeedError, msg=bad):
                ef.feed(self.db, bad)
        with self.assertRaises(ef.FeedError):
            ef.feed(self.db, None, "many")

    def test_records_carry_what_the_console_shows(self):
        add_alert(self.db, "<script>x</script>")
        rec = ef.feed(self.db)["records"][0]
        for field in ("key", "kind", "severity", "state", "host_id", "source", "title", "summary", "details", "created_at",
                      "updated_at", "acked_by"):
            self.assertIn(field, rec)
        self.assertEqual(rec["title"], "<script>x</script>", "stored as text; the browser must escape it")
        self.assertEqual(rec["details"], {"cpu": 97})

    def test_organizations_are_separate_databases(self):
        other = Database(Path(self.tmp.name) / "org2.sqlite3")
        self.addCleanup(other.close)
        add_alert(self.db, "org1 only")
        self.assertEqual(ef.feed(other)["records"], [])


if __name__ == "__main__":
    unittest.main()
