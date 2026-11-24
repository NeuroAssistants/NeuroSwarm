"""Run with python3 -m unittest discover -s tests -p test_multitenant_identity.py."""

import hashlib
import http.client
import json
import os
import secrets
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from auth import hash_token
from identity import totp
from server import create_server


class TenantHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = patch.dict(
            os.environ,
            {"SWARMCONTROL_PUBLIC_URL": "", "SWARMCONTROL_QUIET": "1", "SWARMCONTROL_REGISTRATION": "open"},
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.path = str(Path(self.tmp.name) / "test.sqlite3")
        self.password = secrets.token_urlsafe(18)
        self.start()
        self.addCleanup(self.stop)

    def start(self):
        self.server, _ = create_server(port=0, db_path=self.path, admin_pass=self.password)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01})
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.thread.join(2)
        self.server.server_close()

    def request(self, method, path, data=None, cookie="", token="", more=None):
        headers = {}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if cookie:
            headers["Cookie"] = cookie
        if token:
            headers["Authorization"] = "Bearer " + token
        headers.update(more or {})
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            conn.request(method, path, json.dumps(data) if data is not None else None, headers)
            resp = conn.getresponse()
            raw = resp.read()
            body = (
                json.loads(raw) if raw and "application/json" in resp.getheader("Content-Type", "") else raw
            )
            return resp.status, body, resp.getheader("Set-Cookie", "").split(";")[0]
        finally:
            conn.close()

    def api(self, status, method, path, data=None, **kw):
        received, body, cookie = self.request(method, "/api/v1/" + path, data, **kw)
        self.assertEqual(
            received, status, (method, path, body.get("error") if isinstance(body, dict) else "")
        )
        return body, cookie

    def register(self, label):
        return self.api(
            201,
            "POST",
            "auth/register",
            {"username": label, "password": self.password, "organization": label + " team"},
        )

    def machine(self, cookie, name, scope="ingest"):
        body, _ = self.api(201, "POST", "tokens", {"name": name, "scope": scope}, cookie=cookie)
        self.assertEqual("install_command" in body, scope == "ingest")
        return body

    def invite(self, who, username, role="viewer"):
        return self.api(201, "POST", "invitations", {"username": username, "role": role}, cookie=who)[0]

    def accept(self, status, token, name, pwd=None, **extra):
        return self.api(
            status,
            "POST",
            "auth/accept-invitation",
            {"token": token, "username": name, "password": self.password if pwd is None else pwd, **extra},
        )

    def test_two_independent_organizations_all_resource_routes(self):
        alpha, ca = self.register("alpha-admin")
        beta, cb = self.register("bravo-admin")
        member_cookies = (ca, cb)
        machine_tokens = []
        for team, ck in zip(("violet-Q", "cobalt-Q"), member_cookies):
            ingest = self.machine(ck, team)["token"]
            reader = self.machine(ck, team + "-reader", "read")["token"]
            machine_tokens.append((ingest, reader))
            hb = {
                "host_id": "same-host",
                "hostname": team,
                "harnesses": [{"id": "cli", "name": team}],
                "processes": [{"pid": 1, "comm": team, "cpu_pct": 99}],
            }
            self.api(200, "POST", "ingest/heartbeat", hb, token=ingest)
            self.api(
                200,
                "POST",
                "ingest/event",
                {
                    "host_id": "same-host",
                    "event_type": "work_done",
                    "message": team,
                    "metadata": {"workspace": "client-root", "files": [team + ".py"]},
                },
                token=ingest,
            )
            activity = {
                "host_id": "same-host",
                "hostname": team,
                "schema_version": "1.0",
                "sessions": [{"session_id": "s", "agent_name": team, "files_edited": [team + ".py"]}],
                "workspaces": [{"id": "project", "label": team, "path": "/client/" + team}],
            }
            self.api(200, "POST", "ingest/activity", activity, token=ingest)
            self.api(403, "POST", "ingest/activity", {**activity, "host_id": "different"}, token=ingest)
            self.api(403, "POST", "ingest/event", {"host_id": "same-host"}, token=reader)
            self.api(401, "GET", "activity", token=ingest)
            self.api(403, "GET", "tokens", token=reader)
            self.api(403, "POST", "tokens", {}, token=reader)
            self.api(403, "GET", "members", cookie=ck, token=reader)
            self.api(403, "POST", "auth/logout", {}, cookie=ck, token=reader)
            self.api(200, "GET", "auth/me", cookie=ck)
            self.api(401, "GET", "activity", cookie=ck, token="invalid")
        for index, (team, foreign) in enumerate((("violet-Q", "cobalt-Q"), ("cobalt-Q", "violet-Q"))):
            cookie = member_cookies[index]
            for path in (
                "hosts",
                "events",
                "work-board?include=activity",
                "activity",
                "alerts",
                "digest",
                "overview",
            ):
                for auth in ({"cookie": cookie}, {"token": machine_tokens[index][1]}):
                    obj, _ = self.api(
                        200, "GET", path, more={"X-Organization-ID": str(beta["organization"]["id"])}, **auth
                    )
                    self.assertNotIn(foreign, json.dumps(obj), path)
                    self.assertIn(team, json.dumps(obj), path)
            for path in ("members", "tokens", "audit", "invitations", "audit/verify"):
                obj, _ = self.api(200, "GET", path, cookie=cookie)
                self.assertNotIn(foreign, json.dumps(obj), path)
            self.assertTrue(self.api(200, "GET", "audit/verify", cookie=cookie)[0]["ok"])
        self.api(404, "POST", "auth/switch", {"organization_id": beta["organization"]["id"]}, cookie=ca)
        self.api(404, "POST", f"members/{beta['user']['id']}/role", {"role": "admin"}, cookie=ca)
        self.api(404, "DELETE", f"members/{alpha['user']['id']}", cookie=cb)
        # A revoked colliding numeric ID remains active in the other tenant.
        tokens, _ = self.api(200, "GET", "tokens", cookie=ca)
        first_read = next(r["id"] for r in tokens["tokens"] if r["scope"] == "read")
        self.api(200, "DELETE", f"tokens/{first_read}", cookie=ca)
        self.api(401, "GET", "overview", token=machine_tokens[0][1])
        self.api(200, "GET", "overview", token=machine_tokens[1][1])
        self.assertEqual(len(list(Path(self.path + ".tenants").glob("*.sqlite3"))), 2)

    def test_membership_roles_invites_switch_and_revocation(self):
        alpha, ca = self.register("owner-A")
        beta, cb = self.register("owner-B")
        invite = self.invite(ca, "owner-B", "operator")
        self.api(404, "DELETE", f"invitations/{invite['id']}", cookie=cb)
        self.accept(404, invite["token"], "wrong-name")
        self.accept(401, invite["token"], "owner-B", pwd="wrong")
        membership, op = self.accept(200, invite["token"], "owner-B")
        self.assertEqual(membership["user"]["role"], "operator")
        self.assertEqual(len(membership["memberships"]), 2)
        self.accept(404, invite["token"], "owner-B")
        self.api(403, "GET", "audit", cookie=op)
        self.assertEqual(self.api(200, "GET", "overview", cookie=op)[0]["audit"], [])
        self.api(403, "POST", "tokens", {}, cookie=op)
        self.api(403, "POST", "invitations", {"username": "added", "role": "admin"}, cookie=op)
        ingest = self.machine(ca, "agent")["token"]
        self.api(
            200,
            "POST",
            "ingest/heartbeat",
            {"host_id": "test", "processes": [{"pid": 1, "cpu_pct": 99}]},
            token=ingest,
        )
        alerts = self.api(200, "GET", "alerts", cookie=ca)[0]["alerts"]
        self.api(200, "POST", f"alerts/{alerts[0]['id']}/ack", {}, cookie=op)
        rid = membership["user"]["id"]
        self.api(200, "POST", f"members/{rid}/role", {"role": "viewer"}, cookie=ca)
        self.api(403, "POST", f"alerts/{alerts[0]['id']}/ack", {}, cookie=op)
        self.assertEqual(self.api(200, "GET", "auth/me", cookie=op)[0]["user"]["role"], "viewer")
        br, rotated = self.api(
            200, "POST", "auth/switch", {"organization_id": str(beta["organization"]["id"])}, cookie=op
        )
        self.assertEqual(br["user"]["role"], "admin")
        self.api(401, "GET", "auth/me", cookie=op)
        _, again = self.api(
            200, "POST", "auth/switch", {"organization_id": alpha["organization"]["id"]}, cookie=rotated
        )
        self.api(200, "DELETE", f"members/{rid}", cookie=ca)
        self.api(401, "GET", "auth/me", cookie=again)
        self.api(200, "GET", "auth/me", cookie=cb)
        final = alpha["user"]["id"]
        self.api(409, "DELETE", f"members/{final}", cookie=ca)
        self.api(409, "POST", f"members/{final}/role", {"role": "viewer"}, cookie=ca)
        invited = self.invite(ca, "fresh-user")
        self.api(200, "DELETE", f"invitations/{invited['id']}", cookie=ca)
        self.accept(404, invited["token"], "fresh-user")
        fresh = self.invite(ca, "fresh-user")
        results = []
        with ThreadPoolExecutor(2) as pool:
            for response in pool.map(
                lambda _: self.request(
                    "POST",
                    "/api/v1/auth/accept-invitation",
                    {"username": "fresh-user", "token": fresh["token"], "password": self.password},
                ),
                range(2),
            ):
                results.append(response[0])
        self.assertEqual(sorted(results), [200, 404])
        self.assertNotIn(fresh["token"], json.dumps(self.api(200, "GET", "invitations", cookie=ca)[0]))

    def test_totp_replay_and_cookie_rotation(self):
        test_clock = patch("identity.time", wraps=time)
        clock = test_clock.start()
        self.addCleanup(test_clock.stop)
        clock.time.return_value = (int(time.time()) // 30) * 30 + 5
        org, ck = self.register("factor-owner")
        who = {"username": org["user"]["username"], "password": self.password}
        _, other = self.api(200, "POST", "auth/login", who)
        setup, _ = self.api(200, "POST", "auth/2fa/setup", {"password": self.password}, cookie=ck)
        secret = setup["secret"]
        counter = int(clock.time()) // 30
        old_code = totp(secret, counter - 1)
        self.api(409, "POST", "auth/2fa/confirm", {"password": self.password, "otp": old_code}, cookie=other)
        view, enabled = self.api(
            200, "POST", "auth/2fa/confirm", {"password": self.password, "otp": old_code}, cookie=ck
        )
        self.assertTrue(view["user"]["mfa_enabled"])
        self.api(401, "GET", "auth/me", cookie=ck)
        self.api(401, "GET", "auth/me", cookie=other)
        self.assertEqual(self.api(401, "POST", "auth/login", who)[0]["code"], "mfa_required")
        self.api(401, "POST", "auth/login", {**who, "otp": old_code})
        current = totp(secret, counter)
        _, signed = self.api(200, "POST", "auth/login", {**who, "otp": current})
        self.api(401, "POST", "auth/login", {**who, "otp": current})
        self.api(401, "POST", "auth/2fa/disable", {"password": "incorrect", "otp": current}, cookie=signed)
        view, fresh = self.api(
            200,
            "POST",
            "auth/2fa/disable",
            {"password": self.password, "otp": totp(secret, counter + 1)},
            cookie=signed,
        )
        self.assertFalse(view["user"]["mfa_enabled"])
        self.api(401, "GET", "auth/me", cookie=signed)
        self.api(401, "GET", "auth/me", cookie=enabled)
        self.api(200, "GET", "auth/me", cookie=fresh)
        self.assertNotIn(secret, json.dumps(self.api(200, "GET", "audit", cookie=fresh)[0]))
        self.api(200, "POST", "auth/login", who)

    def test_legacy_migration_restart_cookie_and_original_observer(self):
        # Build a pre-identity database in a fresh temp location with a live host token.
        self.stop()
        self.path = str(Path(self.tmp.name) / "legacy.db")
        raw = "sc_tok_" + secrets.token_urlsafe(24)
        salt = secrets.token_bytes(16)
        old_key = hashlib.pbkdf2_hmac("sha256", self.password.encode(), salt, 150_000)
        old_hash = f"pbkdf2_sha256$150000${salt.hex()}${old_key.hex()}"
        with sqlite3.connect(self.path) as conn:
            conn.executescript("""
                CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password_hash TEXT,
                                   role TEXT,created_at REAL);
                CREATE TABLE agent_tokens(id INTEGER PRIMARY KEY,name TEXT,token_prefix TEXT,token_hash TEXT UNIQUE,
                        created_by TEXT,created_at REAL,last_used_at REAL,revoked_at REAL,bound_host_id TEXT);
            """)
            conn.execute("INSERT INTO users VALUES(7,'legacy',?,'admin',0)", (old_hash,))
            conn.execute(
                "INSERT INTO agent_tokens VALUES(1,'existing',?,?,'legacy',0,NULL,NULL,'same-host')",
                (raw[:14], hash_token(raw)),
            )
        self.start()
        legacy, cookie = self.api(
            200, "POST", "auth/login", {"username": "legacy", "password": self.password}
        )
        self.assertEqual(legacy["organization"]["id"], 1)
        self.assertEqual(legacy["user"]["id"], 7)
        with sqlite3.connect(self.path) as conn:
            upgraded = conn.execute("SELECT password_hash FROM users WHERE id=7").fetchone()[0]
            self.assertTrue(upgraded.startswith("pbkdf2_sha256$600000$"))
        self.api(401, "POST", "auth/login", {"username": "admin", "password": self.password})
        self.api(200, "POST", "ingest/event", {"host_id": "same-host", "message": "legacy-marker"}, token=raw)
        self.api(403, "POST", "ingest/event", {"host_id": "different"}, token=raw)
        _, other = self.register("new-owner")
        self.assertNotIn("legacy-marker", json.dumps(self.api(200, "GET", "overview", cookie=other)[0]))
        self.stop()
        self.start()
        self.assertEqual(self.api(200, "GET", "auth/me", cookie=cookie)[0]["organization"]["id"], 1)
        self.assertIn("legacy-marker", json.dumps(self.api(200, "GET", "events", cookie=cookie)[0]))
        self.api(401, "GET", "auth/me", cookie="sc_session=old.signed.cookie")
        self.api(200, "POST", "auth/logout", {}, cookie=cookie)
        self.api(401, "GET", "auth/me", cookie=cookie)
        self.api(200, "GET", "auth/me", cookie=other)
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM memberships WHERE org_id=1").fetchone()[0], 1)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM identity_migrations WHERE version=1").fetchone()[0], 1
            )

    def test_legacy_fallback_requires_opt_in_and_never_serves_another_organization(self):
        _, legacy = self.api(200, "POST", "auth/login", {"username": "admin", "password": self.password})
        _, customer = self.register("remote-team")
        marker = {"hosts": [{"hostname": "legacy-local-marker"}], "sessions": []}
        with patch("server.ACTIVITY.get", return_value=marker) as local_scan:
            with patch.dict(
                os.environ, {"SWARMCONTROL_ACTIVITY_ROOTS": "", "SWARMCONTROL_ACTIVITY_ADAPTERS": ""}
            ):
                self.assertEqual(self.api(200, "GET", "activity", cookie=legacy)[0]["hosts"], [])
            with patch.dict(os.environ, {"SWARMCONTROL_ACTIVITY_ROOTS": self.tmp.name}):
                self.assertNotIn(
                    "legacy-local-marker",
                    json.dumps(self.api(200, "GET", "work-board?include=activity", cookie=customer)[0]),
                )
                local_scan.assert_not_called()
                self.assertEqual(self.api(200, "GET", "activity", cookie=legacy)[0], marker)
                ingest = self.machine(legacy, "observer")["token"]
                self.api(200, "POST", "ingest/activity", {"host_id": "enrolled-machine"}, token=ingest)
                self.assertNotIn(
                    "legacy-local-marker", json.dumps(self.api(200, "GET", "activity", cookie=legacy)[0])
                )
                local_scan.assert_called_once()

    def test_expired_invite_and_session_and_failed_bind_rollback(self):
        _, cookie = self.register("team-north")
        directory = self.server.app_ctx.db
        inv = self.invite(cookie, "team-new")
        directory.execute("UPDATE invitations SET expires_at=0 WHERE id=?", (inv["id"],))
        self.accept(404, inv["token"], "team-new")
        token = self.machine(cookie, "multi")
        self.api(
            400, "POST", "ingest/activity", {"host_id": "first-host", "sessions": False}, token=token["token"]
        )
        storage = self.api(200, "GET", "tokens", cookie=cookie)[0]["tokens"]
        self.assertIsNone(storage[0]["bound_host_id"])
        self.api(200, "POST", "ingest/activity", {"host_id": "second-host"}, token=token["token"])
        active = directory.query_all("SELECT digest FROM identity_sessions")
        raw = cookie.split("=", 1)[1]
        self.assertTrue(active)
        self.assertNotIn(raw, json.dumps(active))
        self.assertNotIn(inv["token"], json.dumps(directory.query_all("SELECT digest FROM invitations")))
        directory.execute("UPDATE identity_sessions SET expires=0")
        self.api(401, "GET", "overview", cookie=cookie)

    def test_public_downloads_head_and_no_tenant_hints_on_unauthorized(self):
        for path in (
            "/install.sh",
            "/install.ps1",
            "/agent/activity_shipper.py",
            "/agent/activity_core.py",
            "/agent/swarmcontrol_agent.py",
            "/agent/detector.py",
        ):
            self.assertEqual(self.request("GET", path)[0], 200)
            self.assertEqual(self.request("HEAD", path)[:2], (200, b""))
        self.api(401, "GET", "activity", token="sc_ro_t999_" + "q" * 32, more={"X-Organization-ID": "1"})
        self.assertFalse(Path(self.path + ".tenants").exists())
        self.api(
            403,
            "POST",
            "auth/register",
            {"username": "denied", "organization": "org", "password": self.password},
            more={"Origin": "https://another.example"},
        )
        self.assertNotIn("denied", str(self.server.app_ctx.db.query_all("SELECT username FROM users")))
        with patch.dict(os.environ, {"SWARMCONTROL_REGISTRATION": "closed"}):
            self.api(
                403,
                "POST",
                "auth/register",
                {"username": "denied", "organization": "org", "password": self.password},
            )


if __name__ == "__main__":
    unittest.main()
