#!/usr/bin/env python3
"""Download the pinned headless Chromium used by tests/test_browser_ui.py (development only).

Fetches Google's "Chrome for Testing" chrome-headless-shell build for this platform into
~/.cache/swarmcontrol/chrome-headless-shell/<version>/ (override with SWARMCONTROL_BROWSER_CACHE).
Nothing is installed system-wide and the console itself never needs a browser.

    python3 deploy/fetch_test_browser.py          # download if missing, print the binary path
    python3 deploy/fetch_test_browser.py --check  # only report whether it is present

The linux64 archive is checked against the SHA-256 recorded when the suite was set up
(Chrome for Testing does not publish checksums); other platforms print the hash they got.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
import browser_cdp  # noqa: E402

VERSION = browser_cdp.PINNED_VERSION
URL = "https://storage.googleapis.com/chrome-for-testing-public/{v}/{p}/chrome-headless-shell-{p}.zip"
RECORDED_SHA256 = {  # observed 2026-11-23 on the first download of this version
    "linux64": "63401333cc587645bfaeea7f0c90958b327d249251e23954a47f30112ca23d5b",
}


def platform_key() -> str:
    system, machine = platform.system(), platform.machine().lower()
    if system == "Linux" and machine in ("x86_64", "amd64"):
        return "linux64"
    if system == "Darwin":
        return "mac-arm64" if machine == "arm64" else "mac-x64"
    if system == "Windows":
        return "win64"
    raise SystemExit(f"No Chrome for Testing build for {system}/{machine}; set SWARMCONTROL_CHROMIUM to a local Chromium instead.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="only report whether a browser is available")
    ap.add_argument("--pinned", action="store_true", help="use the pinned download even if another browser is installed")
    args = ap.parse_args()
    found = browser_cdp.find_browser(pinned_only=args.pinned)
    if found or args.check:
        print(found or "missing: run python3 deploy/fetch_test_browser.py")
        return 0 if found else 1
    key = platform_key()
    dest = browser_cdp.CACHE_ROOT / VERSION
    dest.mkdir(parents=True, exist_ok=True)
    url = URL.format(v=VERSION, p=key)
    print(f"Downloading {url}", file=sys.stderr)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "chs.zip"
        with urllib.request.urlopen(url, timeout=120) as resp, archive.open("wb") as out:
            while chunk := resp.read(1 << 20):
                out.write(chunk)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        expected = RECORDED_SHA256.get(key)
        if expected and digest != expected:
            raise SystemExit(f"SHA-256 mismatch for {key}: got {digest}, expected {expected}")
        print(f"sha256 {digest}" + (" (matches recorded)" if expected else " (no recorded hash for this platform)"), file=sys.stderr)
        with zipfile.ZipFile(archive) as zf:
            for member in zf.infolist():
                target = (dest / member.filename).resolve()
                if dest.resolve() not in target.parents and target != dest.resolve():
                    raise SystemExit(f"unsafe path in archive: {member.filename}")
                zf.extract(member, dest)
                mode = member.external_attr >> 16
                if mode:
                    os.chmod(target, mode)
    found = browser_cdp.find_browser(pinned_only=args.pinned)
    if not found:
        raise SystemExit("Download finished but no executable was found; set SWARMCONTROL_CHROMIUM.")
    print(found)
    return 0


if __name__ == "__main__":
    sys.exit(main())
