"""Authentication, password hashing, session cookies, and agent token helpers."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
from typing import Any

from db import Database


PBKDF2_ITERATIONS = 600_000
SESSION_TTL_SECONDS = 12 * 3600



class LoginRateLimiter:
    """In-memory sliding-window limiter for failed logins.

    Two buckets: per (client IP, username) and per client IP. Exceeding either returns a
    retry-after delay. Successful logins clear the (IP, username) bucket. Process-local by
    design (single-node MVP); state resets on restart.
    """

    def __init__(self, window_sec: int = 900, max_per_user_ip: int = 5, max_per_ip: int = 20) -> None:
        self.window_sec = window_sec
        self.max_per_user_ip = max_per_user_ip
        self.max_per_ip = max_per_ip
        self._failures: dict[str, list[float]] = {}
        self._pending: dict[str, int] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> list[float]:
        stamps = [t for t in self._failures.get(key, []) if t > now - self.window_sec]
        if stamps:
            self._failures[key] = stamps
        else:
            self._failures.pop(key, None)
        return stamps

    def begin(self, ip: str, username: str) -> int:
        """Reserve an attempt before hashing a password, even for concurrent requests."""
        keys = (f"u:{ip}|{username.lower()}", f"ip:{ip}")
        now = time.time()
        with self._lock:
            waits = []
            for key, limit in zip(keys, (self.max_per_user_ip, self.max_per_ip)):
                failures = self._recent(key, now)
                pending = self._pending.get(key, 0)
                if len(failures) + pending >= limit:
                    waits.append(max(1, int(failures[0] + self.window_sec - now) + 1) if failures else 1)
            if waits:
                return max(waits)
            for key in keys:
                self._pending[key] = self._pending.get(key, 0) + 1
            return 0

    def finish(self, ip: str, username: str, success: bool) -> None:
        user_key = f"u:{ip}|{username.lower()}"
        with self._lock:
            for key in (user_key, f"ip:{ip}"):
                self._pending[key] -= 1
                if self._pending[key] == 0:
                    del self._pending[key]
                if not success:
                    self._failures.setdefault(key, []).append(time.time())
            if success:
                self._failures.pop(user_key, None)
            if len(self._failures) > 10_000:
                # Drop stale buckets first. Bound process-local storage for this single-node server.
                for key in list(self._failures)[:5_000]:
                    self._recent(key, time.time())
                while len(self._failures) > 10_000:
                    self._failures.pop(next(iter(self._failures)))


def hash_password(password: str, salt: bytes | None = None) -> str:
    raw_salt = salt if salt is not None else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), raw_salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${raw_salt.hex()}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, iters_str, salt_hex, dk_hex = stored_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iters = int(iters_str)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(dk_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def token_organization(raw: str) -> int | None:
    """The routing hint selects the database. The full hash and scope authenticate the caller."""
    if re.fullmatch(r"sc_tok_[A-Za-z0-9_-]{32}", raw):
        return 1  # Legacy host token.
    match = re.fullmatch(r"sc_(?:tok|ro)_t([1-9][0-9]{0,18})_[A-Za-z0-9_-]{32}", raw)
    if match and int(match[1]) < 2**63:
        return int(match[1])
    return None


class AuthManager:
    """Machine credentials for exactly one organization."""

    def __init__(self, db: Database, organization_id: int):
        self.db = db
        self.organization_id = organization_id

    def create_agent_token(self, name: str, actor: str, scope: str = "ingest") -> dict[str, Any]:
        kind = {"ingest": "tok", "read": "ro"}[scope]
        raw = f"sc_{kind}_t{self.organization_id}_{secrets.token_urlsafe(24)}"
        prefix = raw[:14]
        now = time.time()
        with self.db.transaction() as conn:
            token_id = conn.execute(
                """INSERT INTO agent_tokens(name,token_prefix,token_hash,created_by,created_at,scope)
                   VALUES(?,?,?,?,?,?)""", (name, prefix, hash_token(raw), actor, now, scope),
            ).lastrowid
            self.db.append_audit(conn, actor, "TOKEN_CREATED", f"token:{token_id}", f"Issued {scope} token '{name}'")
        return {"id": token_id, "name": name, "token_prefix": prefix, "token": raw, "scope": scope, "created_at": now}

    def verify_agent_token(self, raw_token: str) -> dict[str, Any] | None:
        row = self.db.query_one(
            """SELECT id,name,token_prefix,bound_host_id,scope FROM agent_tokens
               WHERE token_hash=? AND revoked_at IS NULL""", (hash_token(raw_token),),
        )
        if not row:
            return None
        with self.db.transaction() as conn:
            updated = conn.execute("UPDATE agent_tokens SET last_used_at=? WHERE id=? AND revoked_at IS NULL",
                                   (time.time(), row["id"])).rowcount
        return row if updated else None

    def revoke_agent_token(self, token_id: int, actor: str) -> bool:
        with self.db.transaction() as conn:
            updated = conn.execute(
                "UPDATE agent_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (time.time(), token_id)
            ).rowcount
            if updated:
                self.db.append_audit(conn, actor, "TOKEN_REVOKED", f"token:{token_id}", "Credential revoked")
            return bool(updated)
