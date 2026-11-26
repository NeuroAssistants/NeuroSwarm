#!/usr/bin/env python3
"""NeuroSwarm HTTP Server — Backend API, Auth, Guardrails, Installer & Web Console."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import argparse
import gzip
import http.cookies
import ipaddress
import json
import hashlib
import os
import re
import secrets
import ssl
import sys
import tempfile
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"
AGENT_DIR = BASE_DIR / "agent"

sys.path.insert(0, str(BACKEND_DIR))
from auth import LoginRateLimiter, SESSION_TTL_SECONDS, token_organization  # noqa: E402
from db import Database  # noqa: E402
import incidents
import event_evidence
import capture_settings
import mission_activity
import output_coverage
import edit_verification
import needs_attention
import line_survival
import repro_cases
from event_feed import MAX_LIMIT as FEED_MAX_LIMIT, FeedError, feed as event_feed
from identity import Directory, IdentityError, role
from live_history import history
from activity_inspector import ACTIVITY
from adapters.openbot_collaboration import collaboration, task_session_links
from correlation import clean_task_id, resolve_links
from release_manifest import ASSETS, PAGES, VERSION_PATH, build_manifest, render_page, runtime_digest
from remote_activity import build_tenant_activity_map, ingest_remote_activity, inspect_heartbeat_telemetry
from tenant_resources import ResourceStores
from installer import render_install_script, render_powershell_install_script  # noqa: E402
from validation import ValidationError, sanitize_event, sanitize_heartbeat, validate_host_id  # noqa: E402


SESSION_COOKIE = "sc_session"
MAX_BODY_BYTES = 512 * 1024
HOST_HEADER_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}(:\d{1,5})?$|^\[[0-9A-Fa-f:.]+\](:\d{1,5})?$")
EVENT_RETENTION_SEC = float(os.environ.get("SWARMCONTROL_EVENT_RETENTION_DAYS", "30")) * 86400
PRUNE_INTERVAL_SEC = 3600
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
)


def _trusted_proxy_networks() -> list[ipaddress._BaseNetwork]:
    """Peers allowed to set CF-Connecting-IP / X-Forwarded-For (default: loopback only)."""
    raw = os.environ.get("SWARMCONTROL_TRUSTED_PROXIES", "127.0.0.1/32,::1/128")
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                pass
    return nets


MONITORING_ROUTES = {"/api/v1/" + path for path in
                     ("live-records", "event-feed", "output-coverage", "activity", "work-board", "links", "needs-attention",
                      "digest", "hosts", "alerts", "events", "overview", "repro-cases")}
EVENT_DETAIL = re.compile(r"/api/v1/events/([0-9]{1,19})/(?:evidence|images/([a-f0-9]{64}))")
LINE_SURVIVAL = re.compile(r"/api/v1/events/([0-9]{1,19})/line-survival")
ALERT_DETAIL = re.compile(r"/api/v1/alerts/([0-9]{1,19})")
ALERT_ACTION = re.compile(r"/api/v1/alerts/([0-9]{1,19})/(ack|owner|resolve)")
REPRO_CASE_DETAIL = re.compile(r"/api/v1/repro-cases/([0-9]{1,19})")
REPRO_CASE_EXPORT = re.compile(r"/api/v1/repro-cases/([0-9]{1,19})/export")
REPRO_CASE_RUNS = re.compile(r"/api/v1/repro-cases/([0-9]{1,19})/runs")
ADMIN_READS = {"/api/v1/" + path for path in ("members", "invitations", "tokens", "audit", "audit/verify")}


def accepts_gzip(header: str) -> bool:
    for item in header.lower().split(","):
        coding, _, options = item.strip().partition(";")
        if coding.strip() == "gzip":
            if not options:
                return True
            weight = re.fullmatch(r"\s*q\s*=\s*(0(?:\.\d{0,3})?|1(?:\.0{0,3})?)\s*", options)
            return bool(weight and float(weight[1]) > 0)
    return False


class AppContext:
    def __init__(self, db_path: str, admin_user: str, admin_pass: str, provider=None, session_secret=None, federation=None):
        # Python modules are loaded at startup; editing a module on disk does not reload it.
        self.runtime_sha256 = runtime_digest(BASE_DIR)
        self.db = Database(db_path)
        self.directory = Directory(self.db, provider=provider, bootstrap=(admin_user, admin_pass),
                                   session_secret=session_secret, federation=federation)
        self.stores = ResourceStores(self.db)
        self.guardrails = self.stores.primary.guardrails
        self.login_limiter = LoginRateLimiter()
        self.signup_limiter = LoginRateLimiter(window_sec=3600, max_per_user_ip=20, max_per_ip=20)
        self.trusted_proxies = _trusted_proxy_networks()


class ConsoleServer(ThreadingHTTPServer):
    # Wait for in-flight requests to release their tenant connections before closing the stores.
    daemon_threads = False
    allow_reuse_address = True

    tls_context: ssl.SSLContext | None = None

    def get_request(self):
        sock, addr = super().get_request()
        if self.tls_context:
            sock = self.tls_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return sock, addr

    def server_close(self):
        super().server_close()
        if hasattr(self, "app_ctx"):
            self.app_ctx.stores.close()


class SwarmControlHandler(BaseHTTPRequestHandler):
    server_version = "NeuroSwarm"
    protocol_version = "HTTP/1.1"
    timeout = 15
    sys_version = ""

    @property
    def ctx(self) -> AppContext:
        return self.server.app_ctx  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.environ.get("SWARMCONTROL_QUIET") == "1":
            return
        super().log_message(fmt, *args)

    def log_request(self, code="-", size="-"):
        # Invitation links may carry a secret in the query. Never log URL parameters or credentials.
        self.log_message("%s %s %s %s", getattr(self, "command", "-"),
                         getattr(self, "path", "").partition("?")[0], str(code), str(size))

    def _peer_is_trusted_proxy(self) -> bool:
        try:
            peer = ipaddress.ip_address(self.client_address[0])
        except ValueError:
            return False
        return any(peer in net for net in self.ctx.trusted_proxies)

    def _client_ip(self) -> str:
        """Real client IP; forwarded headers are only honoured from trusted proxy peers."""
        if self._peer_is_trusted_proxy():
            fwd = self.headers.get("CF-Connecting-IP") or (self.headers.get("X-Forwarded-For", "").split(",")[0])
            fwd = fwd.strip()
            try:
                return str(ipaddress.ip_address(fwd))
            except ValueError:
                pass
        return self.client_address[0]

    def _is_https(self) -> bool:
        """True when this request reached a trusted TLS-terminating proxy (e.g. cloudflared)."""
        return isinstance(self.connection, ssl.SSLSocket) or (
            self._peer_is_trusted_proxy() and self.headers.get("X-Forwarded-Proto", "").lower() == "https"
        )

    def _cookie_secure(self) -> bool:
        public = os.environ.get("SWARMCONTROL_PUBLIC_URL", "").strip().lower()
        return self._is_https() or public.startswith("https://")

    def _request_host(self) -> str:
        host = (self.headers.get("Host") or "").strip()
        if host and HOST_HEADER_RE.match(host):
            return host
        return f"127.0.0.1:{self.server.server_port}"

    def _public_base_url(self) -> str:
        override = os.environ.get("SWARMCONTROL_PUBLIC_URL", "").strip()
        if override:
            return override.rstrip("/")
        proto = "https" if self._is_https() else "http"
        return f"{proto}://{self._request_host()}"

    def _origin_allowed(self) -> bool:
        """CSRF defence in depth for cookie-authenticated mutations (SameSite=Lax is the first layer)."""
        if self.headers.get("Sec-Fetch-Site", "").lower() in {"cross-site", "same-site"}:
            return False
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        allowed = {self._public_base_url().lower()}
        host = self._request_host().lower()
        scheme = "https" if self._is_https() else "http"
        allowed.add(f"{scheme}://{host}")
        return origin.rstrip("/").lower() in allowed

    def _send_bytes(
        self,
        data: bytes,
        status: int = 200,
        content_type: str = "application/json; charset=utf-8",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if self.path.startswith("/api/"):
            self.send_header("Cache-Control", "no-store")
        if self._is_https():
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        if not self._body_consumed:
            self.close_connection = True
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _send_json(self, obj: Any, status: int = 200, extra_headers: dict[str, str] | None = None) -> None:
        self._send_bytes(json.dumps(obj).encode("utf-8"), status=status, extra_headers=extra_headers)

    def _send_inventory(self, snapshot: dict[str, Any]) -> None:
        data = json.dumps(snapshot, separators=(",", ":")).encode("utf-8")
        headers = {"Vary": "Accept-Encoding"}
        if len(data) > 2048 and accepts_gzip(self.headers.get("Accept-Encoding", "")):
            data = gzip.compress(data, compresslevel=3, mtime=0)
            headers["Content-Encoding"] = "gzip"
        self._send_bytes(data, extra_headers=headers)

    def _read_json(self) -> dict[str, Any] | None:
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            self._send_json({"error": "Chunked bodies are not supported"}, status=411)
            self.close_connection = True
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json({"error": "Invalid Content-Length"}, status=400)
            self.close_connection = True
            return None
        if length < 0 or length > MAX_BODY_BYTES:
            self._send_json({"error": "Payload too large"}, status=413)
            self.close_connection = True
            return None
        raw = self.rfile.read(length) if length > 0 else b"{}"
        self._body_consumed = True
        try:

            def _reject_constant(token: str) -> Any:
                raise ValueError(f"Non-finite number {token} not allowed")

            parsed = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
            # Reject unpaired surrogates and out-of-range floats before text reaches storage.
            json.dumps(parsed, ensure_ascii=False, allow_nan=False).encode("utf-8")
        except Exception:
            self._send_json({"error": "Malformed JSON body"}, status=400)
            return None
        if not isinstance(parsed, dict):
            self._send_json({"error": "JSON object expected"}, status=400)
            return None
        return parsed

    def _get_session_user(self) -> dict[str, Any] | None:
        raw_cookie = self.headers.get("Cookie", "")
        jar = http.cookies.SimpleCookie()
        try:
            jar.load(raw_cookie)
        except Exception:
            return None
        morsel = jar.get(SESSION_COOKIE)
        if not morsel:
            return None
        return self.ctx.directory.session(morsel.value)

    def _bearer(self):
        header = self.headers.get("Authorization", "")
        scheme, _, raw = header.partition(" ")
        oid = token_organization(raw) if scheme.lower() == "bearer" else None
        if oid is not None and self.ctx.db.query_one("SELECT id FROM organizations WHERE id=?", (oid,)):
            resources = self._leases.enter_context(self.ctx.stores.open(oid, existing_only=True))
            if resources:
                credential = resources.auth.verify_agent_token(raw)
                if credential:
                    self.resources = resources
                    return credential
        raise IdentityError(401, "Valid Bearer token required")

    def _require_operator(self, path):
        if "Authorization" in self.headers:
            token = self._bearer()
            if token["scope"] == "ingest":
                raise IdentityError(401, "A reader credential is required")
            if token["scope"] == "read" and self.command in {"GET", "HEAD"} and (
                path in MONITORING_ROUTES or ALERT_DETAIL.fullmatch(path) or EVENT_DETAIL.fullmatch(path)
                or LINE_SURVIVAL.fullmatch(path) or REPRO_CASE_DETAIL.fullmatch(path) or REPRO_CASE_EXPORT.fullmatch(path)
            ):
                return {"org_id": self.resources.org_id, "role": "viewer", "username": "read token"}
            raise IdentityError(403, "Token does not grant access to this route")
        user = self._get_session_user()
        if not user:
            raise IdentityError(401, "Authentication required")
        self.resources = self._leases.enter_context(self.ctx.stores.open(user["org_id"]))
        return user

    def _require_agent_token(self):
        credential = self._bearer()
        if credential["scope"] != "ingest":
            raise IdentityError(403, "Ingest credential required")
        return credential

    @staticmethod
    def _require_role(user, *roles):
        if user["role"] not in roles:
            raise IdentityError(403, "This role does not permit that action")

    def _authorize_host(self, token, host_id):
        allowed, reason = self.resources.db.bind_token_host(token["id"], host_id)
        if not allowed:
            raise IdentityError(403, reason)

    def _cookie(self, raw=""):
        age = SESSION_TTL_SECONDS if raw else 0
        cookie = f"{SESSION_COOKIE}={raw}; Path=/; HttpOnly; SameSite=Lax; Max-Age={age}"
        return cookie + "; Secure" if self._cookie_secure() else cookie

    def _session_response(self, raw, status=200):
        user = self.ctx.directory.session(raw)
        if not user:
            raise IdentityError(401, "Session expired")
        view = self.ctx.directory.view(user)
        view["public_url"] = self._public_base_url()
        self._send_json(view, status, {"Set-Cookie": self._cookie(raw)})

    def _audit_rows(self, limit):
        entries = self.resources.db.query_all("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        identity = self.ctx.directory.audit_rows(self.resources.org_id, limit)
        for entry in entries:
            entry["stream"] = "resource"
        for entry in identity:
            entry["stream"] = "identity"
        return sorted(entries + identity, key=lambda e: e["created_at"], reverse=True)[:limit]

    def _audit_status(self):
        resources = self.resources.db.verify_audit_chain()
        identity = self.ctx.directory.audit_chain(self.resources.org_id)
        streams = {"resource": resources, "identity": identity}
        if not identity["entries"]:
            return {**resources, "streams": streams}
        failed = next((status for status in streams.values() if not status["ok"]), None)
        head = None if failed else hashlib.sha256((resources["head"] + ":" + identity["head"]).encode()).hexdigest()
        return {"ok": failed is None, "entries": resources["entries"] + identity["entries"],
                "head": head, "broken_at": failed["broken_at"] if failed else None, "streams": streams}

    def _activity_view(self):
        snapshot = build_tenant_activity_map(self.resources.db)
        if (self.resources.org_id == 1 and not snapshot.get("hosts") and
                (os.environ.get("SWARMCONTROL_ACTIVITY_ROOTS", "").strip() or
                 os.environ.get("SWARMCONTROL_ACTIVITY_ADAPTERS", "").strip())):
            return event_evidence.link_map_steps(self.resources.db, self.resources.org_id, ACTIVITY.get())
        active_ids = {h["host_id"] for h in snapshot.get("hosts", [])}
        health_only = [
            {**dict(h), "activity_enabled": False, "activity_roots": []}
            for h in self.resources.db.query_all(
                "SELECT host_id, hostname, os_name, arch, last_seen_at AS updated_at FROM hosts ORDER BY last_seen_at DESC"
            ) if h["host_id"] not in active_ids
        ]
        if health_only:
            hosts = snapshot.get("hosts", []) + health_only
            snapshot = {**snapshot, "hosts": hosts, "host": hosts[0]["hostname"] if len(hosts) == 1 else f"{len(hosts)} hosts"}
        return event_evidence.link_map_steps(self.resources.db, self.resources.org_id, snapshot)

    def _resolve_links(self, collab=None, reports=None, *, filter_task_id="", filter_session=""):
        db = self.resources.db
        org_id = self.resources.org_id
        collab_data = collab if collab is not None else collaboration(org_id)
        rep_list = reports if reports is not None else db.recent_work_reports()
        task_ids = [
            t["id"]
            for ch in collab_data.get("changes", [])
            for t in ch.get("tasks", [])
            if isinstance(t, dict) and t.get("id")
        ]
        turn_links = task_session_links(org_id, task_ids) if task_ids else {}
        return resolve_links(
            db,
            org_id,
            collab_data,
            rep_list,
            turn_links,
            filter_task_id=filter_task_id,
            filter_session=filter_session,
        )

    def _read_board(self, user, include_activity):
        db = self.resources.db
        reports = db.recent_work_reports()
        collab = collaboration(self.resources.org_id)
        board = {
            "project": user.get("org_name", ""),
            "reports": reports,
            "runtimes": [],
            "collaboration": collab,
            "links": self._resolve_links(collab, reports),
        }
        for row in db.query_all("SELECT hostname,harnesses_json FROM hosts ORDER BY hostname"):
            for harness in json.loads(row["harnesses_json"]):
                board["runtimes"].append({"name": harness["name"], "source": row["hostname"],
                                          "version": harness.get("version", "")})
        if include_activity:
            try:
                board["activity"] = self._activity_view()
            except Exception as exc:
                print(f"[NeuroSwarm] Remote activity unavailable ({type(exc).__name__})", file=sys.stderr)
        return board

    # Every handler is wrapped so an unexpected error returns JSON 500 instead of dropping the socket.
    def do_GET(self) -> None:
        self._dispatch(self._do_get)

    def do_HEAD(self) -> None:
        self._dispatch(self._do_get)

    def do_POST(self) -> None:
        self._dispatch(self._do_post)

    def do_DELETE(self) -> None:
        self._dispatch(self._do_delete)

    def _dispatch(self, fn: Any) -> None:
        self.resources = None
        self._body_consumed = self.headers.get("Content-Length", "0") == "0"
        try:
            with ExitStack() as self._leases:
                if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) > 1:
                    self.close_connection = True
                    self._send_json({"error": "A single Content-Length is required"}, status=411)
                    return
                fn()
        except IdentityError as exc:
            payload = {"error": str(exc)}
            if exc.code:
                payload["code"] = exc.code
            self._send_json(payload, status=exc.status)
        except ValidationError as exc:
            self._send_json({"error": str(exc)}, status=400)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            traceback.print_exc(file=sys.stderr)
            try:
                self._send_json({"error": "Internal server error"}, status=500)
            except Exception:
                pass

    def _serve_static(self, file_path: Path, content_type: str) -> None:
        if not file_path.is_file():
            self._send_json({"error": "Not found"}, status=404)
            return
        is_page = file_path.parent == FRONTEND_DIR and file_path.name in PAGES.values()
        data = render_page(file_path) if is_page else file_path.read_bytes()
        self._send_bytes(data, content_type=content_type,
                         extra_headers={"Cache-Control": "no-store" if is_page else "no-cache"})

    def _do_get(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/health":
            self._send_json({"status": "ok", "service": "swarmcontrol", "time": time.time(), "version_url": VERSION_PATH})
            return
        if path == VERSION_PATH:
            self._send_json(build_manifest(BASE_DIR, running_runtime=self.ctx.runtime_sha256))
            return

        # Public installer & passive agent files (no credentials embedded)
        if path == "/install.sh":
            script = render_install_script(self._public_base_url())
            self._send_bytes(script.encode("utf-8"), status=200, content_type="text/x-shellscript; charset=utf-8")
            return
        if path == "/install.ps1":
            script = render_powershell_install_script(self._public_base_url())
            self._send_bytes(script.encode(), content_type="text/plain; charset=utf-8")
            return
        if path == "/agent/activity_core.py":
            self._serve_static(BACKEND_DIR / "activity_inspector.py", "text/x-python; charset=utf-8")
            return
        if path in {"/agent/detector.py", "/agent/activity_shipper.py", "/agent/swarmcontrol_agent.py"}:
            self._serve_static(AGENT_DIR / path.split("/")[-1], "text/x-python; charset=utf-8")
            return

        # Frontend static assets
        if path == "/index.html":
            path = "/"
        if path in PAGES:
            self._serve_static(FRONTEND_DIR / PAGES[path], "text/html; charset=utf-8")
            return
        if path in ASSETS:
            self._serve_static(FRONTEND_DIR / path[1:], ASSETS[path] + "; charset=utf-8")
            return

        # Operator session info
        if path == "/api/v1/auth/me":
            user = None if "Authorization" in self.headers else self._get_session_user()
            if not user:
                self._send_json({"authenticated": False}, status=401)
                return
            self._send_json({**self.ctx.directory.view(user), "public_url": self._public_base_url()})
            return

        # Protected operator API endpoints
        if path.startswith("/api/v1/"):
            user = self._require_operator(path)
            if path in ADMIN_READS:
                self._require_role(user, "admin")
            if path == "/api/v1/members":
                self._send_json({"members": self.ctx.directory.members(user["org_id"])})
                return
            if path == "/api/v1/invitations":
                self._send_json({"invitations": self.ctx.directory.invitations(user["org_id"])})
                return
            if path == "/api/v1/activity":
                self._send_inventory(self._activity_view())
                return
            if path == "/api/v1/missions":
                payload = mission_activity.activity(self.resources.db, self.resources.org_id)
                task = (qs.get("task") or [""])[0]
                if task:
                    if not clean_task_id(task):
                        raise ValidationError("Invalid task identifier")
                    changes = []
                    for mission in payload["missions"]:
                        tasks = {e["task_id"]: {"id": e["task_id"]} for e in mission["events"] if e["task_id"]}
                        changes.append({"id": mission["id"], "tasks": list(tasks.values())})
                    if not any(t["id"] == task for c in changes for t in c["tasks"]):
                        self._send_json({"error": "Unknown mission task"}, status=404)
                        return
                    links = self._resolve_links({"changes": changes}, [], filter_task_id=task)
                    self._send_inventory({"organization": payload["organization"], "link": links["by_task"].get(task)})
                    return
                self._send_inventory(payload)
                return
            if path == "/api/v1/work-board":
                board = self._read_board(user, qs.get("include") == ["activity"])
                if qs.get("missions") == ["1"] and "Authorization" not in self.headers:
                    board["missions"] = mission_activity.activity(self.resources.db, self.resources.org_id)["missions"]
                self._send_inventory(board)
                return
            if path == "/api/v1/links":
                raw_tid = (qs.get("task_id") or [""])[0]
                if raw_tid and not clean_task_id(raw_tid):
                    raise ValidationError("Invalid task_id filter")
                raw_sid = (qs.get("session") or [""])[0]
                if len(raw_sid) > 256:
                    raise ValidationError("Invalid session filter")
                self._send_inventory(
                    self._resolve_links(filter_task_id=raw_tid, filter_session=raw_sid)
                )
                return
            if path == "/api/v1/digest":
                self._send_json(self.resources.guardrails.build_executive_digest())
                return
            if path == "/api/v1/needs-attention":
                org = self.resources.org_id
                if "organization_id" in qs and qs["organization_id"] != [str(org)]:
                    raise IdentityError(409, "Active organization changed")
                with self.resources.db.transaction(write=False):
                    payload = needs_attention.build_needs_attention(
                        self.resources.db,
                        org,
                        stale_host_sec=self.resources.guardrails.stale_host_sec,
                    )
                self._send_inventory(payload)
                return

            if path == "/api/v1/hosts":
                self.resources.guardrails.check_stale_hosts()
                rows = self.resources.db.query_all("SELECT * FROM hosts ORDER BY last_seen_at DESC")
                reported = capture_settings.by_host(self.resources.db)
                hosts = []
                for r in rows:
                    hosts.append(
                        {
                            "host_id": r["host_id"],
                            "hostname": r["hostname"],
                            "os_name": r["os_name"],
                            "arch": r["arch"],
                            "agent_version": r["agent_version"],
                            "cpu_count": r["cpu_count"],
                            "load_1m": r["load_1m"],
                            "mem_total_mb": r["mem_total_mb"],
                            "mem_used_mb": r["mem_used_mb"],
                            "agent_rss_mb": r["agent_rss_mb"],
                            "scan_duration_ms": r["scan_duration_ms"],
                            "harnesses": json.loads(r["harnesses_json"] or "[]"),
                            "processes": json.loads(r["processes_json"] or "[]"),
                            "status": r["status"],
                            "first_seen_at": r["first_seen_at"],
                            "last_seen_at": r["last_seen_at"],
                            "capture_settings": reported.get(r["host_id"], []),
                        }
                    )
                self._send_json({"hosts": hosts})
                return

            if path == "/api/v1/live-records":
                self._send_json(history(self.resources.db, self.resources.org_id, qs))
                return
            if path == "/api/v1/output-coverage":
                org = self.resources.org_id
                if "organization_id" in qs and qs["organization_id"] != [str(org)]:
                    raise IdentityError(409, "Active organization changed")
                with self.resources.db.transaction(write=False) as conn:
                    try:
                        result = output_coverage.report(conn, org, qs)
                    except output_coverage.CoverageChanged as exc:
                        raise IdentityError(409, str(exc)) from exc
                self._send_inventory(result)
                return
            if path == "/api/v1/event-feed":
                limit = qs.get("limit", [None])[0]
                if limit is not None and (not re.fullmatch(r"[0-9]{1,4}", limit) or not 1 <= int(limit) <= FEED_MAX_LIMIT):
                    raise ValidationError("invalid limit")
                cursor = qs.get("cursor", [None])[0]
                try:
                    # The journal can append on another connection between the page and cursor queries.
                    with self.resources.db.transaction(write=False):
                        page = event_feed(self.resources.db, cursor, limit)
                except FeedError as exc:
                    raise ValidationError(str(exc)) from exc
                except OverflowError as exc:
                    raise ValidationError("invalid cursor") from exc
                page["organization"] = self.resources.org_id
                self._send_inventory(page)
                return
            survival_route = LINE_SURVIVAL.fullmatch(path)
            if survival_route:
                org = self.resources.org_id
                if "organization_id" in qs and qs["organization_id"] != [str(org)]:
                    raise IdentityError(409, "Active organization changed")
                result = line_survival.detail(self.resources.db, org, self._id(survival_route[1]))
                if result is None:
                    raise IdentityError(404, "Event not found")
                self._send_json(result)
                return
            evidence_route = EVENT_DETAIL.fullmatch(path)
            if evidence_route:
                org = self.resources.org_id
                if "organization_id" in qs and qs["organization_id"] != [str(org)]:
                    raise IdentityError(409, "Active organization changed")
                event_id, digest = self._id(evidence_route[1]), evidence_route[2]
                if digest:
                    image = event_evidence.image(self.resources.db, event_id, digest)
                    if image is None:
                        raise IdentityError(404, "Image not found")
                    self._send_bytes(image["content"], content_type=image["mime_type"],
                                     extra_headers={"Cross-Origin-Resource-Policy": "same-origin"})
                else:
                    detail = event_evidence.detail(self.resources.db, org, event_id)
                    if detail is None:
                        raise IdentityError(404, "Event not found")
                    self._send_json(detail)
                return
            alert_detail = ALERT_DETAIL.fullmatch(path)
            if alert_detail:
                self._get_incident(user, self._id(alert_detail[1]), qs)
                return
            if path == "/api/v1/repro-cases":
                org = self.resources.org_id
                if "organization_id" in qs and qs["organization_id"] != [str(org)]:
                    raise IdentityError(409, "Active organization changed")
                self._send_json(
                    repro_cases.list_overview(
                        self.resources.db,
                        org,
                        can_write=user["role"] in ("operator", "admin"),
                        role=user["role"],
                    )
                )
                return
            repro_export = REPRO_CASE_EXPORT.fullmatch(path)
            if repro_export:
                org = self.resources.org_id
                if "organization_id" in qs and qs["organization_id"] != [str(org)]:
                    raise IdentityError(409, "Active organization changed")
                fmt = (qs.get("format", ["json"])[0] or "json")
                exported = repro_cases.export_case(
                    self.resources.db,
                    org,
                    self._id(repro_export[1]),
                    fmt,
                    can_write=user["role"] in ("operator", "admin"),
                    role=user["role"],
                )
                if exported is None:
                    raise IdentityError(404, "Repro case not found")
                payload, ctype, filename = exported
                self._send_bytes(
                    payload,
                    content_type=ctype,
                    extra_headers={"Content-Disposition": f'attachment; filename="{filename}"'},
                )
                return
            repro_detail = REPRO_CASE_DETAIL.fullmatch(path)
            if repro_detail:
                org = self.resources.org_id
                if "organization_id" in qs and qs["organization_id"] != [str(org)]:
                    raise IdentityError(409, "Active organization changed")
                detail = repro_cases.get_case(
                    self.resources.db,
                    org,
                    self._id(repro_detail[1]),
                    can_write=user["role"] in ("operator", "admin"),
                    role=user["role"],
                )
                if detail is None:
                    raise IdentityError(404, "Repro case not found")
                self._send_json(detail)
                return
            if path == "/api/v1/alerts":
                status_filter = (qs.get("status", ["OPEN"])[0] or "OPEN").upper()
                where = {"ALL": "", "ACTIVE": " WHERE " + incidents.ACTIVE}.get(status_filter, " WHERE status=?")
                params = () if status_filter in ("ALL", "ACTIVE") else (status_filter,)
                rows = self.resources.db.query_all(
                    "SELECT * FROM incident_cases" + where + " ORDER BY updated_at DESC,id DESC LIMIT 100", params)
                self._send_json({"alerts": [incidents.present(r) for r in rows]})
                return

            if path == "/api/v1/events":
                rows = self.resources.db.query_all("SELECT * FROM events ORDER BY created_at DESC LIMIT 50")
                for r in rows:
                    r["metadata"] = json.loads(r.pop("metadata_json") or "{}")
                self._send_json({"events": rows})
                return

            if path == "/api/v1/audit/verify":
                self._send_json(self._audit_status())
                return

            if path == "/api/v1/tokens":
                rows = self.resources.db.query_all(
                    "SELECT id, name, token_prefix, created_by, created_at, last_used_at, revoked_at, bound_host_id, scope "
                    "FROM agent_tokens ORDER BY created_at DESC"
                )
                self._send_json({"tokens": rows, "install_base_url": self._public_base_url()})
                return

            if path == "/api/v1/audit":
                rows = self._audit_rows(80)
                self._send_json({"audit": rows})
                return

            if path == "/api/v1/overview":
                self.resources.maybe_prune(EVENT_RETENTION_SEC, PRUNE_INTERVAL_SEC)
                digest = self.resources.guardrails.build_executive_digest()
                hosts_raw = self.resources.db.query_all("SELECT * FROM hosts ORDER BY last_seen_at DESC")
                reported = capture_settings.by_host(self.resources.db)
                hosts = [
                    {
                        **{k: v for k, v in h.items() if k not in {"harnesses_json", "processes_json"}},
                        "harnesses": json.loads(h["harnesses_json"] or "[]"),
                        "processes": json.loads(h["processes_json"] or "[]"),
                        "capture_settings": reported.get(h["host_id"], []),
                    }
                    for h in hosts_raw
                ]
                alerts = self.resources.db.query_all("SELECT * FROM incident_cases ORDER BY updated_at DESC,id DESC LIMIT 60")
                alerts = [incidents.present(a) for a in alerts]
                events = self.resources.db.query_all("SELECT * FROM events ORDER BY created_at DESC LIMIT 30")
                for e in events:
                    e["metadata"] = json.loads(e.pop("metadata_json") or "{}")
                audit = self._audit_rows(30) if user["role"] == "admin" else []
                self._send_json(
                    {
                        "public_url": self._public_base_url(),
                        "digest": digest,
                        "hosts": hosts,
                        "alerts": alerts,
                        "events": events,
                        "audit": audit,
                    }
                )
                return

        self._send_json({"error": "Not found"}, status=404)

    def _check_origin(self):
        if not self._origin_allowed():
            raise IdentityError(403, "Cross-origin request rejected")

    def _account_request(self, path, body):
        directory = self.ctx.directory
        if path == "/api/v1/auth/logout":
            user = self._get_session_user()
            if user:
                directory.logout(user)
            self._send_json({"authenticated": False}, extra_headers={"Set-Cookie": self._cookie()})
            return

        if path == "/api/v1/auth/switch":
            user = self._require_operator(path)
            self._session_response(directory.switch(user, body.get("organization_id")))
            return

        mfa = re.fullmatch(r"/api/v1/auth/2fa/(setup|confirm|disable)", path)
        signup = path == "/api/v1/auth/register"
        username = body.get("username", "")
        if mfa:
            user = self._require_operator(path)
            username = user["username"]
        elif not signup and path not in {"/api/v1/auth/login", "/api/v1/auth/accept-invitation"}:
            raise IdentityError(404, "Not found")

        if signup and os.environ.get("SWARMCONTROL_REGISTRATION", "open") != "open":
            raise IdentityError(403, "Public registration is closed")
        ip = self._client_ip()
        limiter = self.ctx.signup_limiter if signup else self.ctx.login_limiter
        bucket = "signup" if signup else username[:128] if isinstance(username, str) else ""
        wait = limiter.begin(ip, bucket)
        if wait:
            self._send_json({"error": "Too many attempts. Try again later.", "retry_after": wait},
                            status=429, extra_headers={"Retry-After": str(wait)})
            return
        success = False
        try:
            if mfa:
                result = directory.mfa(user, mfa[1], body)
            elif signup:
                result = directory.register(body)
            elif path == "/api/v1/auth/accept-invitation":
                result = directory.accept(body)
            else:
                result = directory.login(body)
            success = True
        except IdentityError as exc:
            if path == "/api/v1/auth/login" and exc.status == 401 and exc.code != "mfa_required":
                directory.failed_login(bucket)
            raise
        finally:
            # Public registration has an hourly creation limit as well as an attempt limit.
            limiter.finish(ip, bucket, success and not signup)
        if isinstance(result, dict):
            self._send_json(result)
        else:
            self._session_response(result, 201 if signup else 200)

    def _ingest(self, path):
        token = self._require_agent_token()
        body = self._read_json()
        if body is None:
            return
        db = self.resources.db
        rules = self.resources.guardrails
        with db.transaction() as conn:
            host = validate_host_id(body.get("host_id"))
            self._authorize_host(token, host)
            if path == "/api/v1/ingest/heartbeat":
                clean = sanitize_heartbeat(body)
                clean["ip_hint"] = self._client_ip()
                rules.resolve_stale(clean["host_id"])
                status, alerts = rules.evaluate_heartbeat(clean, measured=body)
                db.upsert_host_heartbeat(clean, status)
                capture_settings.store(conn, clean["host_id"], "observer", body.get("capture_settings"))
                telemetry = inspect_heartbeat_telemetry(conn, clean["host_id"], body, time.time())
                result = {"ok": True, "host_id": clean["host_id"], "status": status, "alerts_triggered": alerts, **telemetry}
            elif path == "/api/v1/ingest/event":
                event, alerts = rules.evaluate_event(sanitize_event(body))
                result = {"ok": True, **event, "alerts_triggered": alerts}
            elif path == "/api/v1/ingest/verification":
                result = edit_verification.receive(conn, host, body)
            else:
                result = ingest_remote_activity(db, body)
        http_status = 422 if path == "/api/v1/ingest/activity" and result.get("commit_offsets") is False else 200
        self._send_json(result, status=http_status)

    @contextmanager
    def _resource_mutation(self, user, *allowed_roles):
        # Keep membership changes serialized with privileged resource writes.
        with self.ctx.db.transaction() as conn:
            current_role = self.ctx.directory.authorize(conn, user)
            if current_role not in allowed_roles:
                raise IdentityError(403, "This role does not permit that action")
            with self.resources.db.transaction():
                yield self.resources.db

    @staticmethod
    def _id(text):
        value = int(text)
        if not 0 < value < 2**63:
            raise IdentityError(400, "Invalid resource ID")
        return value

    def _do_post(self) -> None:
        path = urlparse(self.path).path
        if path in {"/api/v1/ingest/heartbeat", "/api/v1/ingest/event", "/api/v1/ingest/activity", "/api/v1/ingest/verification"}:
            self._ingest(path)
            return
        self._check_origin()
        if path.startswith("/api/v1/auth/"):
            if "Authorization" in self.headers:
                raise IdentityError(403, "Machine credentials cannot manage user sessions")
            body = self._read_json()
            if body is not None:
                self._account_request(path, body)
            return
        user = self._require_operator(path)
        body = self._read_json()
        if body is None:
            return
        if path == "/api/v1/invitations":
            self._require_role(user, "admin")
            self._send_json(self.ctx.directory.invite(user, body), 201)
            return
        member = re.fullmatch(r"/api/v1/members/([0-9]{1,19})/role", path)
        if member:
            self._require_role(user, "admin")
            self.ctx.directory.change_member(user, self._id(member[1]), role(body.get("role")))
            self._send_json({"ok": True})
            return
        if path == "/api/v1/tokens":
            scope = body.get("scope", "ingest")
            name = body.get("name", "remote-host")
            with self._resource_mutation(user, "admin"):
                if scope not in ("read", "ingest"):
                    raise IdentityError(400, "Unknown token scope")
                if not isinstance(name, str) or not name.strip() or not name.isprintable() or len(name) > 64:
                    raise IdentityError(400, "Provide a token name of 1–64 characters")
                created = self.resources.auth.create_agent_token(name.strip(), user["username"], scope)
            if scope == "ingest":
                base_url = self._public_base_url()
                created["install_command"] = f"curl -fsSL {base_url}/install.sh | SWARMCONTROL_TOKEN={created['token']} bash"
            self._send_json(created, 201)
            return
        match = ALERT_ACTION.fullmatch(path)
        if match:
            self._update_incident(user, self._id(match[1]), match[2], body)
            return
        if path == "/api/v1/repro-cases":
            with self._resource_mutation(user, "admin", "operator") as db:
                if "organization_id" in body and body["organization_id"] is not None:
                    raw_oid = body["organization_id"]
                    if isinstance(raw_oid, (bool, dict, list)):
                        raise ValidationError("Invalid organization_id")
                    if str(raw_oid) != str(user["org_id"]):
                        raise IdentityError(409, "Active organization changed")
                created = repro_cases.create_case(db, self.resources.org_id, user["username"], body, role=user["role"])
            self._send_json(created, 201)
            return
        repro_run = REPRO_CASE_RUNS.fullmatch(path)
        if repro_run:
            case_id = self._id(repro_run[1])
            with self._resource_mutation(user, "admin", "operator") as db:
                if "organization_id" in body and body["organization_id"] is not None:
                    raw_oid = body["organization_id"]
                    if isinstance(raw_oid, (bool, dict, list)):
                        raise ValidationError("Invalid organization_id")
                    if str(raw_oid) != str(user["org_id"]):
                        raise IdentityError(409, "Active organization changed")
                recorded = repro_cases.record_run(db, self.resources.org_id, case_id, user["username"], body, role=user["role"])
                if recorded is None:
                    raise IdentityError(404, "Repro case not found")
            self._send_json(recorded, 201)
            return
        raise IdentityError(404, "Not found")

    def _get_incident(self, user, ident, qs):
        if "organization_id" in qs and qs["organization_id"] != [str(user["org_id"])]:
            raise IdentityError(409, "Active organization changed")
        cursor = qs.get("before")
        if cursor is not None and (len(cursor) != 1 or not re.fullmatch(r"[0-9]{1,19}", cursor[0])):
            raise ValidationError("Invalid incident history cursor")
        detail = incidents.detail(self.resources.db, ident, self._id(cursor[0]) if cursor else None)
        if detail is None:
            raise IdentityError(404, "Alert not found")
        detail["organization"] = user["org_id"]
        if user["role"] in ("operator", "admin") and detail["alert"]["status"] != "RESOLVED":
            detail["assignees"] = self.ctx.db.query_all(
                """SELECT u.id,u.username FROM memberships m JOIN users u ON u.id=m.user_id
                   WHERE m.org_id=? AND m.role IN ('operator','admin') ORDER BY u.username""", (user["org_id"],))
        self._send_json(detail)

    def _update_incident(self, user, ident, action, body):
        actor = user["username"]
        with self._resource_mutation(user, "admin", "operator") as db:
            if "organization_id" in body and str(body["organization_id"]) != str(user["org_id"]):
                raise IdentityError(409, "Active organization changed")
            row = incidents.find_case(db, ident)
            if row is None:
                raise IdentityError(404, "Alert not found")
            if row["status"] == "RESOLVED" and action != "resolve":
                raise IdentityError(409, "Incident already resolved")
            if action == "ack":
                incidents.acknowledge(db, row, actor)
            elif action == "resolve":
                if body.get("reason") != "operator_verified":
                    raise ValidationError("Confirm recovery with reason operator_verified")
                incidents.resolve(db, row, actor, "operator_verified", {})
            else:
                owner = None
                if "owner_id" not in body:
                    raise ValidationError("Provide owner_id or null to unassign")
                uid = body["owner_id"]
                if uid is not None:
                    if type(uid) is not int or not 0 < uid < 2**63:
                        raise ValidationError("Invalid owner ID")
                    member = self.ctx.db.query_one(
                        """SELECT u.username FROM users u JOIN memberships m ON m.user_id=u.id
                           WHERE u.id=? AND m.org_id=? AND m.role IN ('operator','admin')""", (uid, user["org_id"]))
                    if not member:
                        raise IdentityError(404, "Eligible owner not found in this organization")
                    owner = member["username"]
                incidents.assign(db, row, actor, owner)
            status = self.resources.guardrails._compute_host_status(row["host_id"])
            db.execute("UPDATE hosts SET status=? WHERE host_id=?", (status, row["host_id"]))
            result = incidents.present(incidents.find_case(db, row["id"]))
        self._send_json({"ok": True, "alert_id": row["id"], "host_status": status,
                         "organization": user["org_id"], "alert": result})

    def _do_delete(self) -> None:
        path = urlparse(self.path).path
        self._check_origin()
        user = self._require_operator(path)
        self._require_role(user, "admin")
        match = re.fullmatch(r"/api/v1/(members|invitations|tokens)/([0-9]{1,19})", path)
        if not match:
            raise IdentityError(404, "Not found")
        resource_id = self._id(match[2])
        result = {"ok": True}
        if match[1] == "members":
            self.ctx.directory.change_member(user, resource_id, None)
        elif match[1] == "invitations":
            self.ctx.directory.revoke_invite(user, resource_id)
        else:
            with self._resource_mutation(user, "admin"):
                if not self.resources.auth.revoke_agent_token(resource_id, user["username"]):
                    raise IdentityError(404, "Token not found or already revoked")
            result["revoked_id"] = resource_id
        self._send_json(result)


def create_server(
    host: str = "127.0.0.1",
    port: int = 8790,
    db_path: str = "swarmcontrol.db",
    admin_user: str = "admin",
    admin_pass: str | None = None,
    session_secret: str | None = None,
    identity_provider=None,
    federation=None,
    tls_context: ssl.SSLContext | None = None,
) -> tuple[ThreadingHTTPServer, str]:
    resolved_pass = admin_pass or os.environ.get("SWARMCONTROL_ADMIN_PASS") or secrets.token_urlsafe(12)
    httpd = ConsoleServer((host, port), SwarmControlHandler)
    httpd.tls_context = tls_context
    try:
        httpd.app_ctx = AppContext(db_path, admin_user, resolved_pass, provider=identity_provider,
                                   session_secret=session_secret or os.environ.get("SWARMCONTROL_SESSION_SECRET"),
                                   federation=federation)
    except BaseException:
        httpd.server_close()
        raise
    return httpd, resolved_pass


def main() -> int:
    parser = argparse.ArgumentParser(description="NeuroSwarm Monitoring Console Server")
    parser.add_argument("--host", default=os.environ.get("SWARMCONTROL_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("SWARMCONTROL_PORT", "8790")))
    parser.add_argument("--db", default=os.environ.get("SWARMCONTROL_DB", str(BASE_DIR / "data" / "swarmcontrol.db")))
    parser.add_argument("--admin-user", default=os.environ.get("SWARMCONTROL_ADMIN_USER", "admin"))
    parser.add_argument("--admin-pass", default=os.environ.get("SWARMCONTROL_ADMIN_PASS", ""))
    parser.add_argument("--tls-cert", default=os.environ.get("SWARMCONTROL_TLS_CERT"))
    parser.add_argument("--tls-key", default=os.environ.get("SWARMCONTROL_TLS_KEY"))
    args = parser.parse_args()
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("Provide both --tls-cert and --tls-key")
    tls = None
    if args.tls_cert:
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(args.tls_cert, args.tls_key)

    httpd, actual_pass = create_server(
        host=args.host,
        port=args.port,
        db_path=args.db,
        admin_user=args.admin_user,
        admin_pass=args.admin_pass or None,
        tls_context=tls,
    )
    scheme = "https" if tls else "http"
    print(f"[NeuroSwarm] Listening on {scheme}://{args.host}:{args.port} (db={args.db})", flush=True)
    if not args.admin_pass and httpd.app_ctx.directory.bootstrap_created:
        with tempfile.NamedTemporaryFile(mode="w", dir=Path(args.db).resolve().parent,
                prefix="swarmcontrol-initial-password-", delete=False) as credential:
            credential.write(actual_pass + "\n")
        print(f"[NeuroSwarm] Initial administrator password saved in private file {credential.name}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
