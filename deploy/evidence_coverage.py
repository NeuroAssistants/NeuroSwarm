"""Rank observed actions by missing recorded output in one organization's database."""
import argparse
import json
from pathlib import Path
import sqlite3
import time
from contextlib import closing


def coverage(conn, since):
    rows = conn.execute("""
        WITH steps AS (
            SELECT e.id,
                   CASE WHEN json_valid(e.metadata_json) THEN e.metadata_json ELSE '{}' END AS meta
            FROM events AS e WHERE e.event_type = 'observed_step' AND e.created_at >= ?
        )
        SELECT coalesce(nullif(json_extract(meta, '$.action'), ''), 'unknown') AS action,
               coalesce(nullif(json_extract(meta, '$.program'), ''),
                        nullif(json_extract(meta, '$.tool'), ''), 'unknown') AS program,
               count(*) AS events,
               count(x.command_output) AS recorded_output,
               sum(CASE WHEN x.command_output = '' THEN 1 ELSE 0 END) AS recorded_empty,
               sum(EXISTS(SELECT 1 FROM event_texts t WHERE t.event_id = steps.id)
                   OR EXISTS(SELECT 1 FROM event_images i WHERE i.event_id = steps.id)) AS with_file_preview,
               count(*) - count(x.command_output) AS without_recorded_output
        FROM steps LEFT JOIN event_execution AS x ON x.event_id = steps.id
        GROUP BY action, program ORDER BY without_recorded_output DESC, action, program
    """, (since,))
    return [dict(zip((col[0] for col in rows.description), row)) for row in rows]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--hours", type=int, default=24)
    args = parser.parse_args()
    if args.hours < 1:
        parser.error("--hours must be positive")
    with closing(sqlite3.connect(args.database.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        print(json.dumps(coverage(db, time.time() - args.hours * 3600), indent=2))
