"""Online SQLite copies. Restore only into a new, empty instance directory."""
import argparse
import datetime
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import time


def copy_db(source, destination):
    reader = sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)
    writer = sqlite3.connect(destination)
    try:
        reader.backup(writer)
        if writer.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ValueError(f"Integrity check failed for {source.name}")
    finally:
        writer.close()
        reader.close()


def database_files(source):
    yield from sorted(source.rglob("*.db"))
    yield from sorted(source.glob("swarmcontrol.db.tenants/*.sqlite3"))


def copy_state(source, root):
    for db in database_files(source):
        target = root / db.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        copy_db(db, target)
    key = source / "session.key"
    if key.is_file():
        shutil.copyfile(key, root / key.name)
        (root / key.name).chmod(0o600)


def snapshot(source, destination):
    if not source.is_dir() or not (source / "swarmcontrol.db").is_file():
        raise FileNotFoundError("Instance database not found")
    if destination.resolve().is_relative_to(source.resolve()):
        raise ValueError("Store backups outside the live state directory")
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination, prefix=".pending-") as stage:
        stage = Path(stage)
        copy_state(source, stage)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        stage.rename(destination / stamp)
    return destination / stamp


def restore(source, destination):
    if destination.exists():
        raise FileExistsError("Restore target must be a new directory")
    if not (source / "swarmcontrol.db").is_file():
        raise FileNotFoundError("Snapshot has no instance database")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as stage:
        root = Path(stage)
        copy_state(source, root)
        root.rename(destination)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["snapshot", "restore", "schedule"])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.action == "restore":
        restore(args.source, args.destination)
        return
    while True:
        if args.action == "snapshot" or (args.source / "swarmcontrol.db").is_file():
            print(snapshot(args.source, args.destination), flush=True)
            if args.action == "snapshot":
                break
            # Only expire folders whose names match our timestamp format.
            pattern = "[0-9]" * 8 + "T" + "[0-9]" * 12 + "Z"
            for old in sorted(args.destination.glob(pattern))[:-7]:
                if old.is_dir() and not old.is_symlink():
                    shutil.rmtree(old)
            time.sleep(86400)
        else:
            time.sleep(10)


if __name__ == "__main__":
    main()
