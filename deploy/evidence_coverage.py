"""Rank observed actions by missing recorded output in one organization's database."""
import argparse
import json
from pathlib import Path
import sqlite3
import sys
import time
from contextlib import closing


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from output_coverage import coverage  # noqa: E402


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--hours", type=int, default=24)
    args = parser.parse_args()
    if args.hours < 1:
        parser.error("--hours must be positive")
    with closing(sqlite3.connect(args.database.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        print(json.dumps(coverage(db, time.time() - args.hours * 3600), indent=2))
