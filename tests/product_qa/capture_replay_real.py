#!/usr/bin/env python3
"""Replay REAL Codex / Claude Code logs through the incremental journal.

Copies the given logs into a temporary HOME (the originals are only read), then:
  raw        tool calls counted independently from the raw records (not with the product's parser)
  one-shot   steps the product parser stores when it reads each whole file at once
  replay     steps stored when the file is re-written in random 1-96 kB chunks with a journal scan after
             every chunk (a live agent writing while the journal polls)
Reports losses and duplicates of `replay` against `one-shot` (incremental-capture defects) and what share
of raw tool calls the parser stores at all (coverage by design). Run on a machine with agent logs:

    python3 tests/product_qa/capture_replay_real.py --codex N --claude N --seed 7
Prints only counts; the temporary copies are deleted.
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import random
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "backend")]
import activity_inspector as ai  # noqa: E402
import work_journal  # noqa: E402
from db import Database  # noqa: E402
from step_journal import ACTIONS  # noqa: E402

REAL = Path(os.path.expanduser("~"))


def ts_of(line: dict) -> float:
    t = line.get("timestamp") or ""
    try:
        return time.mktime(time.strptime(t[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
    except ValueError:
        return 0.0


def raw_codex(path: Path) -> collections.Counter:
    c = collections.Counter()
    for ln in path.open("rb"):
        if len(ln) >= 400_000:
            c["in_lines_over_400kB"] += ln.count(b'"item_completed"')
            continue
        try:
            o = json.loads(ln)
        except ValueError:
            continue
        p = o.get("payload") or {}
        it = p.get("item") if p.get("type") == "item_completed" else None
        if isinstance(it, dict) and it.get("type") in ("CommandExecution", "FileChange", "DynamicToolCall", "Extension"):
            c[it["type"]] += 1
    return c


def raw_claude(path: Path) -> collections.Counter:
    c = collections.Counter()
    for ln in path.open("rb"):
        big = len(ln) >= 400_000
        try:
            o = json.loads(ln)
        except ValueError:
            continue
        msg = o.get("message") if o.get("type") == "assistant" else None
        for b in (msg or {}).get("content") or []:
            if isinstance(b, dict) and b.get("type") == "tool_use":
                c["in_lines_over_400kB" if big else "tool_use"] += 1
    return c


class Home:
    def __init__(self, base: Path, cwd: str):
        self.home = base / "home"
        self.cwd = cwd
        self.dbfile = base / "j.db"
        Database(str(self.dbfile))
        self.db = sqlite3.connect(self.dbfile)
        self.scope = ai.Scope([cwd], {cwd: "agent-under-test"}, "replay-host")

    def scan(self, now: float) -> None:
        prev = ai.HOME
        ai.HOME = self.home
        try:
            work_journal.capture_once(self.db, {"agent-under-test"}, Path(self.cwd), now, scope=self.scope)
        finally:
            ai.HOME = prev

    def stored(self) -> list[tuple[str, str]]:
        return [(json.loads(m).get("action"), msg) for m, msg in
                self.db.execute("SELECT metadata_json, message FROM events WHERE event_type='observed_step'")]


def setup(base: Path, kind: str, src: Path, cwd: str, sid: str) -> tuple[Home, Path]:
    h = Home(base, cwd)
    if kind == "codex":
        dst = h.home / ".codex/sessions" / src.name
        dst.parent.mkdir(parents=True)
        with sqlite3.connect(h.home / ".codex/state_5.sqlite") as c:
            c.execute("CREATE TABLE threads (id TEXT, cwd TEXT, model TEXT, tokens_used INT, updated_at INT, rollout_path TEXT, model_provider TEXT)")
            c.execute("INSERT INTO threads VALUES (?,?,?,?,?,?,?)", (sid, cwd, "gpt", 0, int(time.time()), str(dst), "openai"))
    else:
        dst = h.home / ".claude/projects" / src.parent.name / src.name
        dst.parent.mkdir(parents=True)
    dst.touch()
    return h, dst


def run_one(kind: str, src: Path, cwd: str, sid: str, rng: random.Random) -> dict:
    data = src.read_bytes()
    stamps = [ts_of(json.loads(l)) for l in data.splitlines()[-50:] if l.strip().startswith(b"{")]
    now = max(stamps or [time.time()]) + 30
    raw = raw_codex(src) if kind == "codex" else raw_claude(src)
    out = {"kind": kind, "bytes": len(data), "raw": dict(raw)}
    with tempfile.TemporaryDirectory(prefix="replay-") as t:
        # one-shot: whole file, read in full on first sight
        h, dst = setup(Path(t) / "one", kind, src, cwd, sid)
        dst.write_bytes(data)
        saved = ai.Capture.lines.__defaults__
        ai.Capture.lines.__defaults__ = (10**12,)
        try:
            cap = ai.Capture({}, ceiling=10**12)
            prev = ai.HOME
            ai.HOME = h.home
            snap = ai.collect_activity(h.scope, cap)
            ai.HOME = prev
            parsed = collections.Counter(s["category"] for sess in snap["sessions"] for s in sess.get("capture_steps", []))
            h.scan(now)
        finally:
            ai.Capture.lines.__defaults__ = saved
        one = collections.Counter(h.stored())
        out["parsed_by_category"] = dict(parsed)
        out["one_shot_stored"] = sum(one.values())
        # replay: random chunks, scan after each
        h2, dst2 = setup(Path(t) / "rep", kind, src, cwd, sid)
        pos, scans = 0, 0
        with dst2.open("ab") as f:
            while pos < len(data):
                n = rng.randint(1_000, 96_000)
                f.write(data[pos:pos + n]); f.flush()
                pos += n
                h2.scan(now)
                scans += 1
        h2.scan(now)
        rep = collections.Counter(h2.stored())
        out["replay_scans"] = scans
        out["replay_stored"] = sum(rep.values())
        out["replay_missing_vs_one_shot"] = sum((one - rep).values())
        out["replay_extra_vs_one_shot"] = sum((rep - one).values())
        out["replay_extra_examples"] = [m for m, _ in list((rep - one).items())[:3]]
        out["replay_missing_examples"] = [m for m, _ in list((one - rep).items())[:3]]
        h.db.close(); h2.db.close()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--codex", type=int, default=2)
    ap.add_argument("--claude", type=int, default=2)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--max-bytes", type=int, default=30_000_000)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    results = []
    con = sqlite3.connect(f"file:{REAL / '.codex/state_5.sqlite'}?mode=ro", uri=True)
    rows = con.execute("SELECT id, cwd, rollout_path FROM threads ORDER BY updated_at DESC").fetchall()
    picked = [(i, c, Path(r)) for i, c, r in rows if r and Path(r).is_file() and Path(r).stat().st_size <= a.max_bytes and c][:a.codex]
    for sid, cwd, rp in picked:
        results.append(run_one("codex", rp, cwd.removeprefix("file://"), sid, rng))
    claude = sorted(glob.glob(str(REAL / ".claude/projects/*/*.jsonl")), key=os.path.getmtime, reverse=True)[:a.claude]
    for p in claude:
        p = Path(p)
        cwd = ai._claude_launch_cwd(p) or "/"
        results.append(run_one("claude", p, cwd, p.stem, rng))
    print(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
