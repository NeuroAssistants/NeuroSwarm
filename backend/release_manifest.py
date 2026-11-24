"""Content identity for the running console and its public browser resources."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


VERSION_PATH = "/api/v1/version"
PAGES = {"/": "index.html", "/live": "live.html"}
# This is also the server's allowlist of public scripts and styles.
ASSETS = {
    "/identity.css": "text/css",
    "/swarm-fold.webp": "image/webp",
    "/app.js": "application/javascript",
    "/activity.js": "application/javascript",
    "/needs-attention.js": "application/javascript",
    "/repro-cases.js": "application/javascript",
    "/live.js": "application/javascript",
    "/styles.css": "text/css",
    "/activity-product.css": "text/css",
    "/needs-attention.css": "text/css",
    "/repro-cases.css": "text/css",
    "/live.css": "text/css",
}
ASSET_REF = re.compile(
    rb"""(?P<quote>["'])(?P<path>""" + b"|".join(re.escape(p.encode("ascii")) for p in ASSETS)
    + rb""")(?:\?v=[^"'\s<>]*)?(?P=quote)"""
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_digest(value: dict) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii"))


def runtime_digest(root: Path) -> str:
    """One aggregate over shipped Python sources, independent of the install directory."""
    source_hashes = {}
    for relative_dir in ("backend", "backend/adapters", "agent"):
        for source in (root / relative_dir).glob("*.py"):
            source_hashes[source.relative_to(root).as_posix()] = sha256(source.read_bytes())
    if "backend/server.py" not in source_hashes:
        raise ValueError("Candidate must contain backend/server.py")
    return _json_digest(source_hashes)


def asset_url(path: str, digest: str) -> str:
    return f"{path}?v={digest[:12]}"


def render_page(template: Path, assets: dict | None = None) -> bytes:
    """Render the exact public HTML, keeping its existing versioned-URL contract."""
    def replace(match: re.Match[bytes]) -> bytes:
        path = match["path"].decode("ascii")
        if assets is None:
            asset = template.parent / path[1:]
            digest = sha256(asset.read_bytes()) if asset.is_file() else "missing"
        else:
            digest = assets[path]["sha256"]
        quote = match["quote"]
        return quote + asset_url(path, digest).encode("ascii") + quote

    return ASSET_REF.sub(replace, template.read_bytes())


def _resource(data: bytes) -> dict:
    return {"sha256": sha256(data), "bytes": len(data)}


def build_manifest(root: Path, *, running_runtime: str | None = None) -> dict:
    frontend = root / "frontend"
    assets = {path: _resource((frontend / path[1:]).read_bytes()) for path in ASSETS}
    pages = {path: _resource(render_page(frontend / template, assets)) for path, template in PAGES.items()}
    description = {
        "schema_version": 1,
        "runtime_sha256": running_runtime if running_runtime is not None else runtime_digest(root),
        "assets": assets,
        "pages": pages,
    }
    return {"version": "sha256:" + _json_digest(description), **description}
