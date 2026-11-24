"""Local account directory. Tenant data stores are selected only after credential verification."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import struct
import time
from typing import Mapping
from urllib.parse import quote, urlencode

from auth import hash_password, hash_token, SESSION_TTL_SECONDS
from identity_providers import CredentialProvider, LocalProvider, FederationProvider, VerifiedSubject
from db import Database, audit_entry_hash, AUDIT_GENESIS

ROLES = {"admin", "operator", "viewer"}


class IdentityError(Exception):
    def __init__(self, status: int, message: str, code: str = ""):
        super().__init__(message)
        self.status, self.code = status, code


def totp(secret, counter):
    digest = hmac.new(base64.b32decode(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def check_otp(secret, otp, previous=-1):
    if not isinstance(otp, str) or not re.fullmatch("[0-9]{6}", otp):
        raise IdentityError(401, "Authenticator code required", "mfa_required")
    now = int(time.time()) // 30
    for counter in (now, now - 1, now + 1):
        if counter > previous and hmac.compare_digest(totp(secret, counter), otp):
            return counter
    raise IdentityError(401, "Invalid or previously used authenticator code", "invalid_otp")


def name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._@+-]{3,128}", value):
        raise IdentityError(400, "Username must be 3–128 valid characters")
    return value


def password_hash(value):
    if not isinstance(value, str) or not 12 <= len(value) <= 128:
        raise IdentityError(400, "Use a password of 12–128 characters")
    return hash_password(value)


def role(value):
    if not isinstance(value, str) or value not in ROLES:
        raise IdentityError(400, "Unknown role")
    return value


def org_name(value):
    if not isinstance(value, str) or not 1 <= len(value.strip()) <= 80 or not value.isprintable():
        raise IdentityError(400, "Provide an organization name of up to 80 characters")
    return value.strip()


SCHEMA = (
    "CREATE TABLE IF NOT EXISTS identity_migrations(version INTEGER PRIMARY KEY, applied_at REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS organizations(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL)",
    """CREATE TABLE IF NOT EXISTS memberships(org_id INTEGER REFERENCES organizations(id),user_id INTEGER REFERENCES users(id),
        role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')), PRIMARY KEY(org_id,user_id))""",
    """CREATE TABLE IF NOT EXISTS identity_sessions(digest TEXT PRIMARY KEY,user_id INTEGER REFERENCES users(id),
        org_id INTEGER REFERENCES organizations(id),expires REAL NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS invitations(id INTEGER PRIMARY KEY,org_id INTEGER REFERENCES organizations(id),
        username TEXT NOT NULL,role TEXT NOT NULL,digest TEXT NOT NULL UNIQUE,expires_at REAL NOT NULL,
        accepted_at REAL,revoked_at REAL)""",
    """CREATE TABLE IF NOT EXISTS factors(user_id INTEGER PRIMARY KEY REFERENCES users(id), secret TEXT,
        last_counter INTEGER NOT NULL DEFAULT -1,pending TEXT,pending_session TEXT,pending_until REAL)""",
    """CREATE TABLE IF NOT EXISTS identity_audit(org_id INTEGER NOT NULL REFERENCES organizations(id),
        id INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,detail TEXT NOT NULL,
        created_at REAL NOT NULL,prev_hash TEXT NOT NULL,entry_hash TEXT NOT NULL, PRIMARY KEY(org_id,id))""",
    "CREATE INDEX IF NOT EXISTS sessions_expiry ON identity_sessions(expires)",
    "CREATE INDEX IF NOT EXISTS memberships_user ON memberships(user_id)",
)


class Directory:
    def __init__(
        self,
        db,
        provider: CredentialProvider | None = None,
        bootstrap=None,
        session_secret=None,
        federation: Mapping[str, FederationProvider] | None = None,
    ):
        self.db = db
        self.bootstrap_created = False
        self.federation = dict(federation or {})
        self.session_key = session_secret.encode() if session_secret else None
        with db.transaction() as c:
            for sql in SCHEMA:
                c.execute(sql)
            latest = c.execute("SELECT COALESCE(MAX(version),0) FROM identity_migrations").fetchone()[0]
            if latest > 2:
                raise RuntimeError("Database identity schema is newer than this server")
            if latest < 1:
                if not c.execute("SELECT 1 FROM users LIMIT 1").fetchone() and bootstrap:
                    self.bootstrap_created = True
                    username, password = bootstrap
                    c.execute(
                        "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,'admin',?)",
                        (username, hash_password(password), time.time()),
                    )
                    db.append_audit(
                        c, "system", "USER_BOOTSTRAP", username, "Initialized organization administrator"
                    )
                c.execute("INSERT INTO organizations(id,name) VALUES(1,'Default workspace')")
                c.execute("""INSERT INTO memberships SELECT 1,id,
                    CASE WHEN role IN ('admin','operator','viewer') THEN role ELSE 'viewer' END FROM users""")
                c.execute("INSERT INTO identity_migrations VALUES(1,?)", (time.time(),))
            if latest < 2:
                c.execute("""CREATE TABLE federated_subjects(
                    issuer TEXT NOT NULL, subject TEXT NOT NULL, user_id INTEGER NOT NULL REFERENCES users(id),
                    PRIMARY KEY(issuer, subject), UNIQUE(issuer, user_id))""")
                c.execute("INSERT INTO identity_migrations VALUES(2,?)", (time.time(),))
        self.provider = provider or LocalProvider(db)

    @staticmethod
    def audit(c, org, actor, action, target, detail=""):
        if org == 1:
            Database.append_audit(c, actor, action, str(target), detail)
            return
        last = c.execute(
            "SELECT id,entry_hash FROM identity_audit WHERE org_id=? ORDER BY id DESC LIMIT 1", (org,)
        ).fetchone()
        seq, prev = (last[0] + 1, last[1]) if last else (1, AUDIT_GENESIS)
        now = time.time()
        target = str(target)
        digest = audit_entry_hash(prev, seq, now, actor, action, target, detail)
        c.execute(
            "INSERT INTO identity_audit VALUES(?,?,?,?,?,?,?,?,?)",
            (org, seq, actor, action, target, detail, now, prev, digest),
        )

    def audit_rows(self, org, limit):
        return self.db.query_all(
            "SELECT id,actor,action,target,detail,created_at,prev_hash,entry_hash FROM identity_audit WHERE org_id=? ORDER BY id DESC LIMIT ?",
            (org, limit),
        )

    def audit_chain(self, org):
        rows = self.db.query_all("SELECT * FROM identity_audit WHERE org_id=? ORDER BY id", (org,))
        prev = AUDIT_GENESIS
        for r in rows:
            predicted = audit_entry_hash(
                prev, r["id"], r["created_at"], r["actor"], r["action"], r["target"], r["detail"]
            )
            if r["prev_hash"] != prev or r["entry_hash"] != predicted:
                return dict(ok=False, entries=len(rows), broken_at=r["id"], head=None)
            prev = predicted
        return dict(ok=True, entries=len(rows), broken_at=None, head=prev)

    def session_digest(self, raw):
        if self.session_key:
            return hmac.new(self.session_key, raw.encode(), hashlib.sha256).hexdigest()
        return hash_token(raw)

    def session(self, raw):
        if not raw or len(raw) > 180 or not raw.startswith("s2."):
            return None
        digest = self.session_digest(raw)
        row = self.db.query_one(
            """SELECT u.id,u.username,m.role,m.org_id,o.name AS org_name,
            f.secret IS NOT NULL AS mfa_enabled FROM identity_sessions s JOIN users u ON s.user_id=u.id
            JOIN memberships m ON m.user_id=u.id AND m.org_id=s.org_id JOIN organizations o ON o.id=m.org_id
            LEFT JOIN factors f ON f.user_id=u.id WHERE s.digest=? AND s.expires>?""",
            (digest, time.time()),
        )
        if row:
            row["_session"] = digest
        return row

    def view(self, user):
        memberships = self.db.query_all(
            """SELECT o.id,o.name,m.role FROM memberships m JOIN organizations o
            ON o.id=m.org_id WHERE m.user_id=? ORDER BY o.id""",
            (user["id"],),
        )
        return {
            "authenticated": True,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
                "mfa_enabled": bool(user["mfa_enabled"]),
            },
            "organization": {"id": user["org_id"], "name": user["org_name"]},
            "memberships": memberships,
        }

    def issue(self, c, uid, org):
        raw = "s2." + secrets.token_urlsafe(32)
        c.execute("DELETE FROM identity_sessions WHERE expires<=?", (time.time(),))
        c.execute(
            "INSERT INTO identity_sessions VALUES(?,?,?,?)",
            (self.session_digest(raw), uid, org, time.time() + SESSION_TTL_SECONDS),
        )
        return raw

    def verify(self, username, password):
        uid = self.provider.authenticate(username, password)
        if uid is None:
            raise IdentityError(401, "Invalid username or password")
        return uid

    @staticmethod
    def factor(c, uid, otp):
        row = c.execute("SELECT secret,last_counter FROM factors WHERE user_id=?", (uid,)).fetchone()
        if row and row["secret"]:
            counter = check_otp(row["secret"], otp, row["last_counter"])
            c.execute("UPDATE factors SET last_counter=? WHERE user_id=?", (counter, uid))

    def _session_after_verification(self, user_id: int, otp, action="LOGIN_OK"):
        with self.db.transaction() as conn:
            self.factor(conn, user_id, otp)
            account = conn.execute(
                """SELECT m.org_id,u.username FROM memberships m JOIN users u ON u.id=m.user_id
                   WHERE m.user_id=? ORDER BY m.org_id LIMIT 1""",
                (user_id,),
            ).fetchone()
            if not account:
                raise IdentityError(403, "No active membership")
            self.audit(conn, account["org_id"], account["username"], action, "auth")
            return self.issue(conn, user_id, account["org_id"])

    def login(self, body):
        username = body.get("username")
        if not isinstance(username, str) or len(username) > 128:
            raise IdentityError(401, "Invalid username or password")
        return self._session_after_verification(
            self.verify(username.strip(), body.get("password")), body.get("otp")
        )

    def failed_login(self, username):
        # Unknown usernames are never written into a customer's activity or audit log.
        with self.db.transaction() as conn:
            member = conn.execute(
                """SELECT m.org_id,u.username FROM memberships m JOIN users u ON u.id=m.user_id
                   WHERE u.username=? ORDER BY m.org_id LIMIT 1""",
                (username,),
            ).fetchone()
            if member:
                self.audit(conn, member["org_id"], "anonymous", "LOGIN_FAILED", member["username"])

    def _verified_subject(self, adapter_name, response, transaction):
        adapter = self.federation.get(adapter_name)
        if adapter is None:
            raise IdentityError(403, "Identity provider is not configured")
        account = adapter.verify_callback(response, transaction)
        if (
            not isinstance(account, VerifiedSubject)
            or account.issuer != adapter.issuer
            or not isinstance(account.subject, str)
            or not 1 <= len(account.subject) <= 255
        ):
            raise IdentityError(401, "Identity provider could not verify this account")
        return account

    def link_federated(self, user, adapter_name, response, transaction, password, otp=None):
        """Called from a completed, state-bound account-link flow in a trusted callback handler."""
        uid = self.verify(user["username"], password)
        if uid != user["id"]:
            raise IdentityError(401, "Invalid account credential")
        subject = self._verified_subject(adapter_name, response, transaction)
        with self.db.transaction() as conn:
            self.authorize(conn, user)
            self.factor(conn, uid, otp)
            try:
                conn.execute(
                    "INSERT INTO federated_subjects(issuer,subject,user_id) VALUES(?,?,?)",
                    (subject.issuer, subject.subject, uid),
                )
            except sqlite3.IntegrityError:
                raise IdentityError(409, "Account already linked") from None
            self.audit(conn, user["org_id"], user["username"], "PROVIDER_LINKED", adapter_name)

    def login_federated(self, adapter_name, response, transaction, otp=None):
        """Issue the same opaque tenant session as a password login, after explicit subject mapping."""
        subject = self._verified_subject(adapter_name, response, transaction)
        mapping = self.db.query_one(
            "SELECT user_id FROM federated_subjects WHERE issuer=? AND subject=?",
            (subject.issuer, subject.subject),
        )
        if not mapping:
            raise IdentityError(403, "Provider account is not linked")
        return self._session_after_verification(mapping["user_id"], otp, action="PROVIDER_LOGIN")

    def register(self, b):
        username = name(b.get("username"))
        org = org_name(b.get("organization"))
        hashed = password_hash(b.get("password"))
        with self.db.transaction() as c:
            if c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
                raise IdentityError(409, "Username is unavailable")
            uid = c.execute(
                "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,'viewer',?)",
                (username, hashed, time.time()),
            ).lastrowid
            oid = c.execute("INSERT INTO organizations(name) VALUES(?)", (org,)).lastrowid
            c.execute("INSERT INTO memberships VALUES(?,?,'admin')", (oid, uid))
            self.audit(c, oid, username, "ORGANIZATION_CREATED", org)
            return self.issue(c, uid, oid)

    @staticmethod
    def authorize(c, user, admin=False):
        row = c.execute(
            """SELECT m.role FROM identity_sessions s JOIN memberships m
           ON m.user_id=s.user_id AND m.org_id=s.org_id WHERE s.digest=? AND s.org_id=? AND s.user_id=? AND s.expires>?""",
            (user["_session"], user["org_id"], user["id"], time.time()),
        ).fetchone()
        if not row:
            raise IdentityError(401, "Session expired")
        if admin and row[0] != "admin":
            raise IdentityError(403, "Administrator access required")
        return row[0]

    def switch(self, user, oid):
        if isinstance(oid, str) and re.fullmatch(r"[1-9][0-9]{0,18}", oid):
            oid = int(oid)
        if type(oid) is not int or not 0 < oid < 2**63:
            raise IdentityError(400, "Invalid organization ID")
        with self.db.transaction() as c:
            self.authorize(c, user)
            if not c.execute(
                "SELECT 1 FROM memberships WHERE user_id=? AND org_id=?", (user["id"], oid)
            ).fetchone():
                raise IdentityError(404, "Organization unavailable")
            c.execute("DELETE FROM identity_sessions WHERE digest=?", (user["_session"],))
            self.audit(c, oid, user["username"], "ORGANIZATION_SELECTED", "auth")
            return self.issue(c, user["id"], oid)

    def logout(self, user):
        with self.db.transaction() as c:
            c.execute("DELETE FROM identity_sessions WHERE digest=?", (user["_session"],))
            self.audit(c, user["org_id"], user["username"], "LOGOUT", "auth")

    def members(self, org):
        return self.db.query_all(
            """SELECT u.id,u.username,m.role FROM memberships m JOIN users u ON m.user_id=u.id
            WHERE m.org_id=? ORDER BY u.username""",
            (org,),
        )

    def change_member(self, user, uid, new_role):
        oid = user["org_id"]
        with self.db.transaction() as c:
            self.authorize(c, user, admin=True)
            row = c.execute(
                "SELECT role FROM memberships WHERE org_id=? AND user_id=?", (oid, uid)
            ).fetchone()
            if not row:
                raise IdentityError(404, "Member not found")
            if (
                row[0] == "admin"
                and new_role != "admin"
                and c.execute(
                    "SELECT count(*) FROM memberships WHERE org_id=? AND role='admin'", (oid,)
                ).fetchone()[0]
                == 1
            ):
                raise IdentityError(409, "Keep at least one administrator")
            if new_role is None:
                c.execute("DELETE FROM memberships WHERE org_id=? AND user_id=?", (oid, uid))
                c.execute("DELETE FROM identity_sessions WHERE org_id=? AND user_id=?", (oid, uid))
            else:
                c.execute(
                    "UPDATE memberships SET role=? WHERE org_id=? AND user_id=?", (role(new_role), oid, uid)
                )
            self.audit(c, oid, user["username"], "MEMBER_CHANGED", uid, new_role or "removed")

    def invitations(self, org):
        return self.db.query_all(
            "SELECT id,username,role,expires_at,accepted_at,revoked_at FROM invitations WHERE org_id=? ORDER BY id DESC LIMIT 100",
            (org,),
        )

    def invite(self, user, b):
        oid = user["org_id"]
        username, access = name(b.get("username")), role(b.get("role"))
        raw = secrets.token_urlsafe(32)
        expiry = time.time() + 48 * 3600
        with self.db.transaction() as c:
            self.authorize(c, user, admin=True)
            if c.execute(
                "SELECT 1 FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=? AND u.username=?",
                (oid, username),
            ).fetchone():
                raise IdentityError(409, "Already a member")
            c.execute(
                "UPDATE invitations SET revoked_at=? WHERE org_id=? AND username=? AND accepted_at IS NULL AND revoked_at IS NULL",
                (time.time(), oid, username),
            )
            iid = c.execute(
                "INSERT INTO invitations(org_id,username,role,digest,expires_at) VALUES(?,?,?,?,?)",
                (oid, username, access, hash_token(raw), expiry),
            ).lastrowid
            self.audit(c, oid, user["username"], "INVITATION_CREATED", iid, access)
        return {"id": iid, "token": raw, "expires_at": expiry}

    def revoke_invite(self, user, iid):
        with self.db.transaction() as c:
            self.authorize(c, user, admin=True)
            count = c.execute(
                "UPDATE invitations SET revoked_at=? WHERE org_id=? AND id=? AND accepted_at IS NULL AND revoked_at IS NULL",
                (time.time(), user["org_id"], iid),
            ).rowcount
            if not count:
                raise IdentityError(404, "Active invitation not found")
            self.audit(c, user["org_id"], user["username"], "INVITATION_REVOKED", iid)

    def accept(self, b):
        username = name(b.get("username"))
        token = b.get("token")
        if not isinstance(token, str) or len(token) > 128:
            raise IdentityError(400, "Invalid invitation")
        digest = hash_token(token)

        def active(c):
            invite = c.execute(
                """SELECT * FROM invitations WHERE digest=? AND username=? AND accepted_at IS NULL
                AND revoked_at IS NULL AND expires_at>?""",
                (digest, username, time.time()),
            ).fetchone()
            if not invite:
                raise IdentityError(404, "Active invitation not found")
            return invite

        with self.db.transaction() as c:
            active(c)
        existing = self.db.query_one("SELECT id FROM users WHERE username=?", (username,))
        uid = self.verify(username, b.get("password")) if existing else None
        if existing and uid != existing["id"]:
            raise IdentityError(401, "Invalid account credential")
        hashed = None if existing else password_hash(b.get("password"))
        with self.db.transaction() as c:
            inv = active(c)
            if uid is None:
                if c.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
                    raise IdentityError(409, "Account now exists; retry")
                uid = c.execute(
                    "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,'viewer',?)",
                    (username, hashed, time.time()),
                ).lastrowid
            else:
                self.factor(c, uid, b.get("otp"))
            if c.execute(
                "SELECT 1 FROM memberships WHERE org_id=? AND user_id=?", (inv["org_id"], uid)
            ).fetchone():
                raise IdentityError(409, "Already a member")
            c.execute("INSERT INTO memberships VALUES(?,?,?)", (inv["org_id"], uid, inv["role"]))
            c.execute("UPDATE invitations SET accepted_at=? WHERE id=?", (time.time(), inv["id"]))
            self.audit(c, inv["org_id"], username, "INVITATION_ACCEPTED", inv["id"], inv["role"])
            return self.issue(c, uid, inv["org_id"])

    def mfa(self, user, action, b):
        uid = self.verify(user["username"], b.get("password"))
        if uid != user["id"]:
            raise IdentityError(401, "Invalid account credential")
        with self.db.transaction() as c:
            self.authorize(c, user)
            row = c.execute("SELECT * FROM factors WHERE user_id=?", (uid,)).fetchone()
            if action == "setup":
                if row and row["secret"]:
                    raise IdentityError(409, "Factor already active")
                secret = base64.b32encode(secrets.token_bytes(20)).decode()
                c.execute(
                    """INSERT INTO factors(user_id,pending,pending_session,pending_until) VALUES(?,?,?,?)
                    ON CONFLICT(user_id) DO UPDATE SET pending=excluded.pending,pending_session=excluded.pending_session,
                    pending_until=excluded.pending_until""",
                    (uid, secret, user["_session"], time.time() + 600),
                )
                self.audit(c, user["org_id"], user["username"], "MFA_SETUP", "account")
                label = quote("NeuroSwarm:" + user["username"], safe="")
                return {
                    "secret": secret,
                    "otpauth_uri": "otpauth://totp/"
                    + label
                    + "?"
                    + urlencode({"secret": secret, "issuer": "NeuroSwarm", "digits": 6, "period": 30}),
                }
            if action == "confirm":
                if (
                    not row
                    or not row["pending"]
                    or row["pending_session"] != user["_session"]
                    or row["pending_until"] < time.time()
                ):
                    raise IdentityError(409, "Start setup again")
                n = check_otp(row["pending"], b.get("otp"))
                c.execute(
                    "UPDATE factors SET secret=pending,last_counter=?,pending=NULL,pending_session=NULL,pending_until=NULL WHERE user_id=?",
                    (n, uid),
                )
            elif action == "disable":
                if not row or not row["secret"]:
                    raise IdentityError(409, "Factor not active")
                self.factor(c, uid, b.get("otp"))
                c.execute("DELETE FROM factors WHERE user_id=?", (uid,))
            else:
                raise IdentityError(404, "Not found")
            c.execute("DELETE FROM identity_sessions WHERE user_id=?", (uid,))
            self.audit(c, user["org_id"], user["username"], "MFA_" + action.upper(), "account")
            return self.issue(c, uid, user["org_id"])
