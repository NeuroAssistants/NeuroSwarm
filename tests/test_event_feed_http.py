"""Integration checks for the cursor consumed by the Live events screen."""
from contextlib import closing
import secrets
import sqlite3
from unittest.mock import patch
from urllib.parse import urlencode

try:
    from .test_security import ServerHarness
except ImportError:
    from test_security import ServerHarness


FEED = "/api/v1/event-feed"
EVENT = """INSERT INTO events(host_id,harness,agent_name,event_type,severity,message,created_at)
           VALUES('build-01','codex','worker','notice','INFO',?,1)"""


class EventFeedHTTPTests(ServerHarness):
    def test_cursor_during_concurrent_journal_insert(self):
        self.assertEqual(self.login()[0], 200)
        read = self.ctx.db.query_all
        inserted = []

        def read_while_journal_runs(sql, params=()):
            rows = read(sql, params)
            if not inserted and "FROM events ORDER BY id DESC" in sql:
                # A separate connection commits between the page and the cursor high-water mark,
                # just as the journal service can. WAL permits this while the page is being read.
                with closing(sqlite3.connect(self.db_path, timeout=1)) as writer, writer:
                    inserted.append(writer.execute(EVENT, ("File read while opening the console",)).lastrowid)
            return rows

        with patch.object(self.ctx.db, "query_all", side_effect=read_while_journal_runs):
            status, first, _ = self.req("GET", FEED)
        self.assertEqual(status, 200)
        self.assertEqual(first["records"], [])
        self.assertTrue(inserted)
        status, next_page, _ = self.req("GET", FEED + "?" + urlencode({"cursor": first["cursor"]}))
        self.assertEqual(status, 200)
        self.assertEqual([row["id"] for row in next_page["records"]], inserted)

    def test_reader_ingest_token_and_burst(self):
        self.assertEqual(self.req("GET", FEED)[0], 401)
        self.assertEqual(self.login()[0], 200)
        status, reader, _ = self.req("POST", "/api/v1/tokens", {"name": "Console", "scope": "read"})
        self.assertEqual(status, 201)
        reader_headers = self.bearer(reader)
        self.assertEqual(self.req("GET", FEED, headers=self.bearer(self.token()), cookie=False)[0], 401)
        status, first, headers = self.req("GET", FEED, headers=reader_headers, cookie=False)
        self.assertEqual(status, 200)
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertEqual(first["organization"], 1)
        cursor = first["cursor"]
        with self.ctx.db.transaction() as conn:
            conn.executemany(EVENT, ((str(i),) for i in range(701)))
        keys = []
        for size in (250, 250, 201, 0):
            url = FEED + "?" + urlencode({"cursor": cursor, "limit": 250})
            status, page, _ = self.req("GET", url, headers=reader_headers, cookie=False)
            self.assertEqual(status, 200)
            self.assertEqual(len(page["records"]), size)
            self.assertEqual(page["more"], size == 250)
            keys.extend(row["key"] for row in page["records"])
            cursor = page["cursor"]
        self.assertEqual(len(set(keys)), 701)
        status, _, headers = self.req("POST", "/api/v1/auth/register", {
            "username": "operator-b", "organization": "Org B", "password": secrets.token_urlsafe(22)
        }, cookie=False)
        self.assertEqual(status, 201)
        self.cookie = headers["set-cookie"].split(";")[0]
        for url in (FEED, FEED + "?" + urlencode({"cursor": cursor, "organization": 1})):
            status, other, _ = self.req("GET", url)
            self.assertEqual(status, 200)
            self.assertNotEqual(other["organization"], 1)
            self.assertEqual(other["records"], [])

    def test_bad_parameters_have_actionable_responses(self):
        self.assertEqual(self.login()[0], 200)
        for query in ({"limit": 0}, {"limit": 1001}, {"limit": "many"}, {"cursor": "not-a-cursor"}):
            status, response, _ = self.req("GET", FEED + "?" + urlencode(query))
            self.assertEqual(status, 400)
            self.assertIn(next(iter(query)), response["error"])
