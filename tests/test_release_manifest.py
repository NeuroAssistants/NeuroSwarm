"""Exercise the release command against the real HTTPS server and a locally trusted certificate."""
from contextlib import ExitStack
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
import server
from release_manifest import VERSION_PATH, build_manifest


@unittest.skipUnless(shutil.which("openssl"), "openssl is needed for the temporary TLS certificate")
class ReleaseManifestHTTPS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stack = ExitStack()
        cls.addClassCleanup(stack.close)
        tmp = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        cls.candidate = tmp / "candidate"
        for folder in ("agent", "backend", "frontend"):
            shutil.copytree(ROOT / folder, cls.candidate / folder,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        # Always exercise a difference beyond the old 64 KiB smoke-check read, even if JS is minified.
        with (cls.candidate / "frontend/live.js").open("ab") as out:
            out.write(b"\n" + b" " * 65536)
        cert, key = tmp / "local.pem", tmp / "local.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-days", "1", "-keyout", str(key), "-out", str(cert)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.cert = cert
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        stack.enter_context(patch.multiple(server, BASE_DIR=cls.candidate, FRONTEND_DIR=cls.candidate / "frontend"))
        stack.enter_context(patch.dict(os.environ, {"SWARMCONTROL_QUIET": "1", "SWARMCONTROL_PUBLIC_URL": ""}))
        httpd, _ = server.create_server(port=0, tls_context=tls, db_path=str(tmp / "state.db"),
                                        admin_pass=secrets.token_urlsafe(24))
        cls.port = httpd.server_port
        thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        stack.callback(httpd.server_close)
        stack.callback(thread.join)
        stack.callback(httpd.shutdown)

    def request(self, method, path):
        conn = http.client.HTTPSConnection("127.0.0.1", self.port, timeout=5,
                                           context=ssl.create_default_context(cafile=self.cert))
        try:
            conn.request(method, path)
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            return response.headers, response.read()
        finally:
            conn.close()

    def verify(self, candidate=None):
        return subprocess.run(
            [sys.executable, str(ROOT / "deploy/check_release.py"), f"https://127.0.0.1:{self.port}",
             "--candidate", str(candidate or self.candidate)], text=True, capture_output=True, timeout=15,
            env={**os.environ, "SSL_CERT_FILE": str(self.cert), "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def test_public_contract_and_browser_urls(self):
        headers, raw = self.request("GET", VERSION_PATH)
        self.assertEqual(headers["Cache-Control"], "no-store")
        manifest = json.loads(raw)
        self.assertEqual(manifest["schema_version"], 1)
        self.assertRegex(manifest["version"], r"^sha256:[a-f0-9]{64}$")
        self.assertEqual(manifest, build_manifest(self.candidate))
        head, body = self.request("HEAD", VERSION_PATH)
        self.assertEqual(body, b"")
        self.assertEqual(int(head["Content-Length"]), len(raw))
        self.assertEqual(json.loads(self.request("GET", "/health")[1])["version_url"], VERSION_PATH)

        expected_paths = {"/": {"/instrument-serif.ttf", "/identity.css", "/swarm-fold.webp", "/toon-workshop.webp", "/app.js", "/activity.js", "/activity-product.css", "/needs-attention.js", "/needs-attention.css", "/repro-cases.js", "/repro-cases.css", "/styles.css"},
                          "/live": {"/identity.css", "/live.js", "/live.css"}}
        self.assertEqual(set(manifest["pages"]), set(expected_paths))
        self.assertEqual(set(manifest["assets"]), expected_paths["/"] | expected_paths["/live"])
        for page, paths in expected_paths.items():
            _, html = self.request("GET", page)
            self.assertEqual(manifest["pages"][page], {"bytes": len(html), "sha256": hashlib.sha256(html).hexdigest()})
            for path in paths:
                asset = (self.candidate / "frontend" / path[1:]).read_bytes()
                digest = hashlib.sha256(asset).hexdigest()
                self.assertEqual(manifest["assets"][path], {"bytes": len(asset), "sha256": digest})
                self.assertIn(f'"{path}?v={digest[:12]}"'.encode(), html)

    def test_matching_checkout_passes(self):
        cmd = self.verify()
        self.assertEqual(cmd.returncode, 0, cmd.stderr + cmd.stdout)
        self.assertIn("PASS Published manifest", cmd.stdout)
        self.assertEqual(cmd.stdout.count("PASS Published bytes "), 16)
        self.assertIn("PASS Anonymous monitoring API denied", cmd.stdout)

    def test_matching_manifest_and_stale_cached_asset_fails(self):
        send = server.SwarmControlHandler._send_bytes

        def stale_asset(handler, data, *args, **kwargs):
            if handler.path.startswith("/live.js?v="):
                data = data[:-1] + b"\n"
            return send(handler, data, *args, **kwargs)

        with patch.object(server.SwarmControlHandler, "_send_bytes", stale_asset):
            cmd = self.verify()
        self.assertEqual(cmd.returncode, 1, cmd.stderr + cmd.stdout)
        self.assertIn("PASS Published manifest", cmd.stdout)
        self.assertIn("FAIL Published bytes /live.js?v=", cmd.stdout)
        self.assertEqual(cmd.stdout.count("FAIL "), 1)

    def test_stale_html_fails_even_if_assets_match(self):
        send = server.SwarmControlHandler._send_bytes

        def stale_html(handler, data, *args, **kwargs):
            if handler.path == "/live":
                data = re.sub(rb'\?v=[a-f0-9]{12}', b"", data)
            return send(handler, data, *args, **kwargs)

        with patch.object(server.SwarmControlHandler, "_send_bytes", stale_html):
            cmd = self.verify()
        self.assertEqual(cmd.returncode, 1, cmd.stderr + cmd.stdout)
        self.assertIn("FAIL Published bytes /live ", cmd.stdout)
        self.assertIn("PASS Published bytes /live.js?v=", cmd.stdout)

    def test_candidate_in_different_directory_and_backend_only_difference(self):
        with tempfile.TemporaryDirectory() as tmp:
            other = Path(tmp) / "other"
            shutil.copytree(self.candidate, other, copy_function=shutil.copyfile)
            (other / "example-private.env").write_text("IGNORED=example")
            self.assertEqual(self.verify(other).returncode, 0)
            with (other / "backend/server.py").open("ab") as out:
                out.write(b"\n# Different candidate\n")
            cmd = self.verify(other)
        self.assertEqual(cmd.returncode, 1, cmd.stderr + cmd.stdout)
        self.assertIn("FAIL Published manifest", cmd.stdout)
        self.assertEqual(cmd.stdout.count("PASS Published bytes "), 16)


if __name__ == "__main__":
    unittest.main()
