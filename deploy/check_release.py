"""Check the published console against a local candidate with anonymous GET requests."""
import argparse
import gzip
import http.client
import json
import re
import ssl
import sys
import zlib
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from release_manifest import VERSION_PATH, asset_url, build_manifest, sha256


def check_manifest(get, candidate):
    expected = build_manifest(Path(candidate))
    print("Candidate version:", expected["version"])
    status, _, body = get(VERSION_PATH)
    try:
        published = json.loads(body) if status == 200 and len(body) <= 65536 else None
    except ValueError:
        published = None
    version = published.get("version") if isinstance(published, dict) else None
    if isinstance(version, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", version):
        print("Published version:", version)
    # JSON distinguishes booleans and numbers even though e.g. True == 1 in Python.
    matches = json.dumps(published, sort_keys=True) == json.dumps(expected, sort_keys=True)
    checks = {f"Published manifest matches the candidate (HTTP {status})": matches}

    # Request the browser's URLs from the local manifest, even if the server reports
    # a matching version. A cache or a rolling deployment can still serve stale bytes.
    urls = dict(expected["pages"])
    for path, resource in expected["assets"].items():
        urls[asset_url(path, resource["sha256"])] = resource
    for url, resource in urls.items():
        size = resource["bytes"]
        status, _, body = get(url, size)
        label = f"Published bytes {url}"
        if status != 200:
            checks[f"{label} (HTTP {status})"] = False
        elif len(body) != size:
            relation = "more than" if len(body) > size else "fewer than"
            checks[f"{label} ({relation} {size} bytes)"] = False
        else:
            actual = sha256(body)
            checks[f"{label} (sha256 {actual})"] = actual == resource["sha256"]
    return checks


def check(origin, private_path, candidate=ROOT):
    url = urlsplit(origin)
    if (not url.hostname or url.username is not None or url.password is not None
            or url.path not in ("", "/") or url.query or url.fragment):
        raise ValueError("Supply an origin without credentials, path, query or fragment")
    if url.scheme == "https":
        connection = http.client.HTTPSConnection(url.hostname, url.port, timeout=10,
                                                 context=ssl.create_default_context())
    elif url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"}:
        connection = http.client.HTTPConnection(url.hostname, url.port, timeout=10)
    else:
        raise ValueError("Remote checks require HTTPS")

    def get(path, limit=65536):
        try:
            connection.request("GET", path, headers={"Accept-Encoding": "identity"})
            response = connection.getresponse()
            encoding = response.getheader("Content-Encoding", "identity").strip().lower()
            if encoding == "gzip":
                with gzip.GzipFile(fileobj=response) as decoded:
                    body = decoded.read(limit + 1)
            elif encoding in ("", "identity"):
                body = response.read(limit + 1)
            else:
                raise ValueError(f"Unsupported response encoding on {path}")
            return response.status, response.headers, body
        finally:
            connection.close()

    status, headers, body = get("/")
    location = headers.get("Location", "")
    login = (status == 200 and b"<html" in body.lower()) or (
        status in (302, 303, 307) and location.startswith("/") and not location.startswith("//"))
    private_status, _, _ = get(private_path)
    audit_status, _, _ = get("/api/v1/audit/verify")
    directives = {item.strip() for item in headers.get("Content-Security-Policy", "").split(";")}
    script_status, _, script = get("/install.sh")
    checks = {"Web entry": login, "Anonymous monitoring API denied": private_status in (401, 403),
              "Shell installer served": (script_status == 200
                  and script.startswith(b"#!/usr/bin/env bash\n")
                  and b"SWARMCONTROL_TOKEN" in script)}
    checks.update({
        "Anonymous audit verification returns 401": audit_status == 401,
        "Frame embedding denied": headers.get("X-Frame-Options", "").upper() == "DENY",
        "MIME sniffing disabled": headers.get("X-Content-Type-Options") == "nosniff",
        "Content security policy": {"default-src 'self'", "script-src 'self'", "frame-ancestors 'none'"} <= directives,
    })
    checks.update(check_manifest(get, candidate))
    for label, passed in checks.items():
        print(("PASS" if passed else "FAIL"), label)
    return all(checks.values())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin")
    parser.add_argument("private_path", nargs="?", default="/api/v1/overview", help="Real authenticated fleet API path")
    parser.add_argument("--candidate", type=Path, default=ROOT, metavar="DIR",
                        help="Extracted candidate root (defaults to the checkout containing this script)")
    args = parser.parse_args()
    try:
        success = check(args.origin, args.private_path, args.candidate)
    except (OSError, EOFError, ValueError, zlib.error, http.client.HTTPException) as exc:
        sys.exit(f"Unavailable: {exc}")
    sys.exit(0 if success else 1)
