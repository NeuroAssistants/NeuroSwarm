"""Trusted credential adapters. Organization membership and authorization live in Directory."""

from __future__ import annotations

from dataclasses import dataclass
import secrets
from typing import Protocol

from auth import PBKDF2_ITERATIONS, hash_password, verify_password
from db import Database


class CredentialProvider(Protocol):
    """Verify a local credential and return its immutable user ID, or None."""

    def authenticate(self, username: str, password: str) -> int | None: ...


class LocalProvider:
    def __init__(self, db: Database):
        self.db = db
        self.dummy_hash = hash_password(secrets.token_urlsafe(24))

    def authenticate(self, username: str, password: str) -> int | None:
        if not isinstance(password, str) or len(password) > 1024:
            return None
        user = self.db.query_one("SELECT id,password_hash FROM users WHERE username=?", (username,))
        valid = verify_password(password, user["password_hash"] if user else self.dummy_hash)
        if not valid or user is None:
            return None
        stored = user["password_hash"]
        if int(stored.split("$", 2)[1]) < PBKDF2_ITERATIONS:
            # Another concurrent login may have upgraded this exact hash already.
            self.db.execute(
                "UPDATE users SET password_hash=? WHERE id=? AND password_hash=?",
                (hash_password(password), user["id"], stored),
            )
        return user["id"]


@dataclass(frozen=True)
class VerifiedSubject:
    issuer: str
    subject: str


class FederationProvider(Protocol):
    """Bridge for a trusted WorkOS/OIDC callback handler, never supplied by an HTTP client.

    The adapter validates the server-side browser transaction, state, issuer, audience,
    signature, lifetime and nonce as appropriate, and consumes the authorization code.
    It returns only the immutable issuer and subject of the verified account. It must
    return None or raise on failure. Directory never imports organization, email or role
    claims from the identity provider.
    """

    issuer: str

    def verify_callback(self, response: object, transaction: object) -> VerifiedSubject | None: ...
