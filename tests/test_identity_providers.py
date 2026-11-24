"""Offline checks for the identity provider boundary and local HTTPS transport."""

import base64
import http.client
import json
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from auth import LoginRateLimiter
from db import Database
from identity import Directory, IdentityError, totp
from identity_providers import VerifiedSubject
from server import create_server


class TestBroker:
    """Simulates an already-verified, state-bound authorization-code exchange without a network."""

    issuer = "https://broker.example.test"

    def __init__(self):
        self.grants = {}

    def grant(self, subject, issuer=None):
        code, state = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        self.grants[code] = (state, VerifiedSubject(issuer or self.issuer, subject))
        return code, state

    def verify_callback(self, response, transaction):
        grant = self.grants.get(response)
        if not grant or grant[0] != transaction:
            return None
        return self.grants.pop(response)[1]


class IdentityAdapterTests(unittest.TestCase):
    def test_subject_linking_is_explicit_issuer_bound_and_shares_local_authorization(self):
        db = Database(":memory:")
        self.addCleanup(db.close)
        broker = TestBroker()
        directory = Directory(db, federation={"test-broker": broker})
        password = secrets.token_urlsafe(20)
        owner = directory.session(
            directory.register({"username": "owner", "password": password, "organization": "tenant-A"})
        )
        stranger = directory.session(
            directory.register({"username": "stranger", "password": password, "organization": "tenant-B"})
        )

        # A provider returning the local username as its subject cannot auto-link by email/name.
        with self.assertRaises(IdentityError) as unmapped:
            directory.login_federated("test-broker", *broker.grant("owner"))
        self.assertEqual(unmapped.exception.status, 403)
        code, state = broker.grant("provider-213")
        with self.assertRaises(IdentityError):
            directory.link_federated(owner, "test-broker", code, "different state", password)
        directory.link_federated(owner, "test-broker", code, state, password)
        with self.assertRaises(IdentityError):
            directory.login_federated("test-broker", code, state)  # consumed callback
        with self.assertRaises(IdentityError):
            directory.login_federated(
                "test-broker", *broker.grant("provider-213", "https://foreign.example.test")
            )
        with self.assertRaises(IdentityError):
            directory.link_federated(stranger, "test-broker", *broker.grant("provider-213"), password)
        session = directory.session(directory.login_federated("test-broker", *broker.grant("provider-213")))
        self.assertEqual(session["org_id"], owner["org_id"])
        self.assertEqual([m["name"] for m in directory.view(session)["memberships"]], ["tenant-A"])
        with self.assertRaises(IdentityError):
            directory.switch(session, stranger["org_id"])
        # Local TOTP policy also applies after a broker callback.
        import time

        setup = directory.mfa(owner, "setup", {"password": password})
        directory.mfa(
            owner, "confirm", {"password": password, "otp": totp(setup["secret"], int(time.time()) // 30)}
        )
        with self.assertRaises(IdentityError) as no_factor:
            directory.login_federated("test-broker", *broker.grant("provider-213"))
        self.assertEqual(no_factor.exception.code, "mfa_required")

    def test_totp_vector_and_concurrent_rate_reservations(self):
        seed = base64.b32encode(b"12345678901234567890")
        self.assertEqual(totp(seed, 1), "287082")
        limiter = LoginRateLimiter(max_per_user_ip=2, max_per_ip=3)
        self.assertEqual(limiter.begin("test", "user"), 0)
        self.assertEqual(limiter.begin("test", "user"), 0)
        self.assertGreater(limiter.begin("test", "user"), 0)
        limiter.finish("test", "user", False)
        self.assertGreater(limiter.begin("test", "user"), 0)
        limiter.finish("test", "user", True)
        self.assertEqual(limiter.begin("test", "user"), 0)
        limiter.finish("test", "user", True)


class LocalTLSTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"), "openssl required to create a temporary test certificate")
    def test_native_https_head_and_secure_cookie(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = root / "cert.pem", root / "key.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=IP:127.0.0.1",
                    "-days",
                    "1",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(cert, key)
            password = secrets.token_urlsafe(18)
            httpd, _ = create_server(
                port=0, db_path=str(root / "state.db"), admin_pass=password, tls_context=context
            )
            t = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.01})
            t.start()
            client = http.client.HTTPSConnection(
                "127.0.0.1", httpd.server_port, timeout=5, context=ssl.create_default_context(cafile=cert)
            )
            try:
                client.request("HEAD", "/install.ps1")
                response = client.getresponse()
                self.assertEqual((response.status, response.version, response.read()), (200, 11, b""))
                self.assertGreater(int(response.getheader("Content-Length")), 0)
                client.request(
                    "POST",
                    "/api/v1/auth/login",
                    json.dumps({"username": "admin", "password": password}),
                    {"Content-Type": "application/json"},
                )
                response = client.getresponse()
                self.assertEqual(response.status, 200)
                for flag in ("; Secure", "; HttpOnly", "SameSite=Lax"):
                    self.assertIn(flag, response.getheader("Set-Cookie"))
                self.assertTrue(response.getheader("Strict-Transport-Security"))
                response.read()
            finally:
                client.close()
                httpd.shutdown()
                t.join(2)
                httpd.server_close()
