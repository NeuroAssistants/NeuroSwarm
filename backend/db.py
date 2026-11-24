"""SQLite persistence layer for NeuroSwarm backend."""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
import json
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

import incidents
import event_evidence


SCHEMA_SQL = """

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_used_at REAL,
    revoked_at REAL
);

CREATE TABLE IF NOT EXISTS hosts (
    host_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    os_name TEXT NOT NULL,
    arch TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    ip_hint TEXT,
    cpu_count INTEGER NOT NULL DEFAULT 1,
    load_1m REAL NOT NULL DEFAULT 0.0,
    mem_total_mb REAL NOT NULL DEFAULT 0.0,
    mem_used_mb REAL NOT NULL DEFAULT 0.0,
    agent_rss_mb REAL NOT NULL DEFAULT 0.0,
    scan_duration_ms REAL NOT NULL DEFAULT 0.0,
    harnesses_json TEXT NOT NULL DEFAULT '[]',
    processes_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'HEALTHY',
    first_seen_at REAL NOT NULL,
    last_seen_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id TEXT NOT NULL,
    harness TEXT NOT NULL,
    agent_name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id TEXT NOT NULL,
    rule_code TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'OPEN',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    acked_by TEXT,
    acked_at REAL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at REAL NOT NULL,
    prev_hash TEXT,
    entry_hash TEXT
);

CREATE TABLE IF NOT EXISTS revoked_sessions (
    sig TEXT PRIMARY KEY,
    expires_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_host_time ON events(host_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status_time ON alerts(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(created_at);
CREATE INDEX IF NOT EXISTS idx_work_reports_time ON events(created_at DESC, id DESC)
    WHERE event_type IN ('plan', 'task_plan', 'work_started', 'work_done');
"""

AUDIT_GENESIS = "GENESIS"


def audit_entry_hash(prev_hash: str, row_id: int, created_at: float, actor: str, action: str, target: str, detail: str) -> str:
    """Hash of one audit entry chained to its predecessor (tamper-evident log)."""
    material = json.dumps(
        [prev_hash, int(row_id), f"{float(created_at):.6f}", actor, action, target, detail],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class Database:
    """Thread-safe SQLite wrapper using a single lock and WAL mode."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if str(self.db_path) != ":memory:" and not self.db_path.exists():
            fd = os.open(self.db_path, os.O_WRONLY | os.O_CREAT, 0o600)
            os.close(fd)
        self._lock = threading.RLock()
        self._depth = 0
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.create_function("regexp", 2, lambda pattern, text: bool(re.search(pattern, text)), deterministic=True)
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            with self.transaction() as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS resource_migrations(version INTEGER PRIMARY KEY, applied_at REAL NOT NULL)")
                version = conn.execute("SELECT COALESCE(MAX(version),0) FROM resource_migrations").fetchone()[0]
                if version > 2:
                    raise RuntimeError("Resource database schema is newer than this server")
                if version == 0:
                    self._migrate_pre_schema()
                    # This static schema contains only table and index definitions.
                    for statement in SCHEMA_SQL.split(";"):
                        if statement.strip():
                            conn.execute(statement)
                    self._migrate_post_schema()
                    conn.execute("INSERT INTO resource_migrations VALUES(1,?)", (time.time(),))
                if version < 2:
                    incidents.migrate(conn)
                    conn.execute("INSERT INTO resource_migrations VALUES(2,?)", (time.time(),))
                event_evidence.ensure_tables(conn)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_time_severity ON events(created_at,severity)")
        except BaseException:
            self._conn.close()
            raise

    @contextmanager
    def transaction(self, *, write: bool = True):
        """Use a stable snapshot for reads and reserve the writer for mutations."""
        with self._lock:
            depth = self._depth
            mark = f"nested_{depth}"
            begin = "BEGIN IMMEDIATE" if write else "BEGIN"
            self._conn.execute(f"SAVEPOINT {mark}" if depth else begin)
            self._depth += 1
            try:
                yield self._conn
                self._conn.execute(f"RELEASE {mark}" if depth else "COMMIT")
            except BaseException:
                if depth:
                    self._conn.execute(f"ROLLBACK TO {mark}")
                    self._conn.execute(f"RELEASE {mark}")
                else:
                    self._conn.rollback()
                raise
            finally:
                self._depth -= 1

    def _columns(self, table: str) -> set[str]:
        return {r[1] for r in self._conn.execute(f"PRAGMA table_info({table})").fetchall()}

    def _migrate_pre_schema(self) -> None:
        """Add columns introduced after v0.1 to existing databases (idempotent)."""
        tables = {r[0] for r in self._conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "audit_log" in tables:
            cols = self._columns("audit_log")
            for col in ("prev_hash", "entry_hash"):
                if col not in cols:
                    self._conn.execute(f"ALTER TABLE audit_log ADD COLUMN {col} TEXT")
        if "agent_tokens" in tables and "bound_host_id" not in self._columns("agent_tokens"):
            self._conn.execute("ALTER TABLE agent_tokens ADD COLUMN bound_host_id TEXT")

    def _migrate_post_schema(self) -> None:
        if "bound_host_id" not in self._columns("agent_tokens"):
            self._conn.execute("ALTER TABLE agent_tokens ADD COLUMN bound_host_id TEXT")
        if "scope" not in self._columns("agent_tokens"):
            self._conn.execute("ALTER TABLE agent_tokens ADD COLUMN scope TEXT NOT NULL DEFAULT 'ingest'")
        # Chain legacy audit rows written before the hash chain existed, in id order.
        legacy = self._conn.execute("SELECT COUNT(*) FROM audit_log WHERE entry_hash IS NULL").fetchone()[0]
        if legacy:
            prev = AUDIT_GENESIS
            for r in self._conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall():
                if r["entry_hash"] is None:
                    h = audit_entry_hash(prev, r["id"], r["created_at"], r["actor"], r["action"], r["target"], r["detail"])
                    self._conn.execute(
                        "UPDATE audit_log SET prev_hash = ?, entry_hash = ? WHERE id = ?", (prev, h, r["id"])
                    )
                    prev = h
                else:
                    prev = r["entry_hash"]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.lastrowid or 0

    def query_one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
            return dict(row) if row is not None else None

    def query_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]

    def recent_work_reports(self) -> list[dict[str, Any]]:
        """Get explicit task reports independently of the high-volume event stream."""
        rows = self.query_all(
            """SELECT id, host_id, harness, agent_name, event_type, message, created_at, metadata_json
               FROM events WHERE event_type IN ('plan', 'task_plan', 'work_started', 'work_done')
               ORDER BY created_at DESC, id DESC LIMIT 60"""
        )
        for row in rows:
            try:
                meta = json.loads(row.pop("metadata_json") or "{}")
            except (TypeError, ValueError):
                meta = {}
            if not isinstance(meta, dict):
                meta = {}
            fields = {key: meta[key][:512] for key in ("task_id", "workspace", "method")
                      if isinstance(meta.get(key), str)}
            if isinstance(meta.get("files"), list):
                fields["files"] = [p[:256] for p in meta["files"][:12] if isinstance(p, str)]
            row["metadata"] = fields
        return rows

    @staticmethod
    def append_audit(conn, actor: str, action: str, target: str, detail: str) -> None:
        """Append an audit entry to the SHA-256 hash chain (atomic under the DB lock)."""
        actor, action, target, detail = str(actor)[:128], str(action)[:64], str(target)[:256], str(detail)[:1000]
        now = time.time()
        last = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["entry_hash"] if last and last["entry_hash"] else AUDIT_GENESIS
        cur = conn.execute(
            "INSERT INTO audit_log(actor, action, target, detail, created_at, prev_hash) VALUES (?, ?, ?, ?, ?, ?)",
            (actor, action, target, detail, now, prev),
        )
        row_id = cur.lastrowid
        conn.execute(
            "UPDATE audit_log SET entry_hash = ? WHERE id = ?",
            (audit_entry_hash(prev, row_id, now, actor, action, target, detail), row_id),
        )

    def log_audit(self, actor: str, action: str, target: str, detail: str) -> None:
        with self.transaction() as conn:
            self.append_audit(conn, actor, action, target, detail)

    def verify_audit_chain(self) -> dict[str, Any]:
        """Recompute every hash. Detects edited, reordered or deleted-in-the-middle entries."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
        prev = AUDIT_GENESIS
        for r in rows:
            expected = audit_entry_hash(prev, r["id"], r["created_at"], r["actor"], r["action"], r["target"], r["detail"])
            if r["prev_hash"] != prev or r["entry_hash"] != expected:
                return {"ok": False, "entries": len(rows), "broken_at": r["id"], "head": None}
            prev = r["entry_hash"]
        return {"ok": True, "entries": len(rows), "broken_at": None, "head": prev}

    def bind_token_host(self, token_id: int, host_id: str) -> tuple[bool, str]:
        """Bind an enrollment token to the first host_id it reports; reject any other host afterwards.

        Returns (allowed, reason). A host_id already bound to another *active* token is refused,
        so one leaked token cannot impersonate or overwrite other enrolled machines.
        """
        with self.transaction():
            row = self._conn.execute(
                "SELECT bound_host_id FROM agent_tokens WHERE id = ? AND scope = 'ingest' AND revoked_at IS NULL", (token_id,)
            ).fetchone()
            if row is None:
                return False, "Token revoked"
            bound = row["bound_host_id"]
            if bound is not None:
                return (True, "") if bound == host_id else (False, "Token is bound to another host_id")
            owner = self._conn.execute(
                "SELECT id FROM agent_tokens WHERE bound_host_id = ? AND revoked_at IS NULL AND id != ?",
                (host_id, token_id),
            ).fetchone()
            if owner is not None:
                return False, "host_id is owned by another active enrollment token; revoke it first"
            self._conn.execute(
                "UPDATE agent_tokens SET bound_host_id = ? WHERE id = ? AND bound_host_id IS NULL",
                (host_id, token_id),
            )
            return True, ""

    def prune_events(self, older_than: float) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM events WHERE created_at < ?", (older_than,))
            return cur.rowcount or 0

    def upsert_host_heartbeat(self, payload: dict[str, Any], status: str) -> None:
        now = time.time()
        existing = self.query_one("SELECT first_seen_at FROM hosts WHERE host_id = ?", (payload["host_id"],))
        first_seen = existing["first_seen_at"] if existing else now
        self.execute(
            """
            INSERT INTO hosts (
                host_id, hostname, os_name, arch, agent_version, ip_hint,
                cpu_count, load_1m, mem_total_mb, mem_used_mb, agent_rss_mb,
                scan_duration_ms, harnesses_json, processes_json, status,
                first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(host_id) DO UPDATE SET
                hostname=excluded.hostname,
                os_name=excluded.os_name,
                arch=excluded.arch,
                agent_version=excluded.agent_version,
                ip_hint=excluded.ip_hint,
                cpu_count=excluded.cpu_count,
                load_1m=excluded.load_1m,
                mem_total_mb=excluded.mem_total_mb,
                mem_used_mb=excluded.mem_used_mb,
                agent_rss_mb=excluded.agent_rss_mb,
                scan_duration_ms=excluded.scan_duration_ms,
                harnesses_json=excluded.harnesses_json,
                processes_json=excluded.processes_json,
                status=excluded.status,
                last_seen_at=excluded.last_seen_at
            """,
            (
                payload["host_id"],
                payload.get("hostname", "unknown"),
                payload.get("os_name", "linux"),
                payload.get("arch", "x86_64"),
                payload.get("agent_version", "0.1.0"),
                payload.get("ip_hint", ""),
                int(payload.get("cpu_count", 1)),
                float(payload.get("load_1m", 0.0)),
                float(payload.get("mem_total_mb", 0.0)),
                float(payload.get("mem_used_mb", 0.0)),
                float(payload.get("agent_rss_mb", 0.0)),
                float(payload.get("scan_duration_ms", 0.0)),
                json.dumps(payload.get("harnesses", [])),
                json.dumps(payload.get("processes", [])),
                status,
                first_seen,
                now,
            ),
        )

    def upsert_open_alert(
        self,
        host_id: str,
        rule_code: str,
        severity: str,
        title: str,
        summary: str,
        evidence: dict[str, Any],
    ) -> int:
        return incidents.observe(self, host_id, rule_code, severity, title, summary, evidence)
