"""Minimal headless-Chromium driver over the DevTools pipe (standard library only).

Used by tests/test_browser_ui.py. No Playwright, Selenium, Node or websocket package:
Chrome is started with --remote-debugging-pipe and speaks JSON messages terminated by
NUL on file descriptors 3 (commands in) and 4 (responses/events out).

Binary resolution order:
  1. SWARMCONTROL_CHROMIUM (path to chrome, chromium or chrome-headless-shell)
  2. the pinned download from deploy/fetch_test_browser.py (~/.cache/swarmcontrol/...)
  3. chrome-headless-shell, chromium, chromium-browser, google-chrome on PATH
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path

PINNED_VERSION = "158.0.8127.88"
CACHE_ROOT = Path(os.environ.get("SWARMCONTROL_BROWSER_CACHE", Path.home() / ".cache" / "swarmcontrol" / "chrome-headless-shell"))


def find_browser() -> str | None:
    env = os.environ.get("SWARMCONTROL_CHROMIUM", "").strip()
    if env:
        return env if os.access(env, os.X_OK) else None
    for sub in ("chrome-headless-shell-linux64/chrome-headless-shell",
                "chrome-headless-shell-mac-arm64/chrome-headless-shell",
                "chrome-headless-shell-mac-x64/chrome-headless-shell",
                "chrome-headless-shell-win64/chrome-headless-shell.exe"):
        p = CACHE_ROOT / PINNED_VERSION / sub
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    for name in ("chrome-headless-shell", "chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        found = shutil.which(name)
        if found:
            return found
    return None


class CDPError(RuntimeError):
    pass


class Browser:
    """One Chrome process; each Page gets its own isolated browser context (cookies, storage)."""

    def __init__(self, binary: str, timeout: float = 20.0) -> None:
        self.timeout = timeout
        self.profile = tempfile.TemporaryDirectory(prefix="swarm-browser-")
        cmd_r, cmd_w = os.pipe()   # we write, chrome reads on fd 3
        out_r, out_w = os.pipe()   # chrome writes on fd 4, we read

        def child_fds() -> None:
            # Move both ends above 4 first so dup2 cannot clobber one with the other.
            a, b = os.dup(cmd_r), os.dup(out_w)
            a2, b2 = os.dup2(a, 100), os.dup2(b, 101)
            os.dup2(a2, 3)
            os.dup2(b2, 4)
            os.set_inheritable(3, True)
            os.set_inheritable(4, True)

        args = [binary, "--headless", "--remote-debugging-pipe", "--no-first-run", "--no-default-browser-check",
                "--disable-gpu", "--disable-extensions", "--disable-background-networking", "--disable-sync",
                "--disable-dev-shm-usage", "--hide-scrollbars", "--mute-audio", "--force-color-profile=srgb",
                f"--user-data-dir={self.profile.name}", "about:blank"]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            args.insert(1, "--no-sandbox")
        self.proc = subprocess.Popen(args, preexec_fn=child_fds, pass_fds=(3, 4),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(cmd_r)
        os.close(out_w)
        self._w = os.fdopen(cmd_w, "wb", buffering=0)
        self._r = os.fdopen(out_r, "rb", buffering=0)
        self._id = 0
        self._lock = threading.Lock()
        self._cond = threading.Condition()
        self._results: dict[int, dict] = {}
        self._listeners: dict[str, list] = {}
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        self.version = self.send("Browser.getVersion")["product"]

    # -- transport -------------------------------------------------------
    def _read_loop(self) -> None:
        buf = b""
        while True:
            try:
                chunk = self._r.read(65536)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while b"\0" in buf:
                raw, buf = buf.split(b"\0", 1)
                msg = json.loads(raw)
                if "id" in msg:
                    with self._cond:
                        self._results[msg["id"]] = msg
                        self._cond.notify_all()
                else:
                    for fn in list(self._listeners.get(msg.get("sessionId", ""), [])):
                        fn(msg)
        with self._cond:
            self._cond.notify_all()

    def send(self, method: str, params: dict | None = None, session: str | None = None, timeout: float | None = None) -> dict:
        with self._lock:
            self._id += 1
            mid = self._id
            msg = {"id": mid, "method": method, "params": params or {}}
            if session:
                msg["sessionId"] = session
            self._w.write(json.dumps(msg).encode() + b"\0")
        deadline = time.monotonic() + (timeout or self.timeout)
        with self._cond:
            while mid not in self._results:
                left = deadline - time.monotonic()
                if left <= 0 or self.proc.poll() is not None:
                    raise CDPError(f"{method}: no reply (browser alive={self.proc.poll() is None})")
                self._cond.wait(min(left, 0.5))
            res = self._results.pop(mid)
        if "error" in res:
            raise CDPError(f"{method}: {res['error'].get('message')} {res['error'].get('data', '')}")
        return res.get("result", {})

    def new_page(self, width: int = 1440, height: int = 900, mobile: bool = False) -> "Page":
        ctx = self.send("Target.createBrowserContext", {"disposeOnDetach": True})["browserContextId"]
        target = self.send("Target.createTarget", {"url": "about:blank", "browserContextId": ctx})["targetId"]
        session = self.send("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
        page = Page(self, session, target, ctx)
        self._listeners[session] = [page._on_event]
        page.setup(width, height, mobile)
        return page

    def close(self) -> None:
        try:
            self.send("Browser.close", timeout=5)
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        for f in (self._w, self._r):
            try:
                f.close()
            except OSError:
                pass
        self.profile.cleanup()


class Page:
    def __init__(self, browser: Browser, session: str, target: str, ctx: str) -> None:
        self.b = browser
        self.session = session
        self.target = target
        self.ctx = ctx
        self.errors: list[str] = []       # uncaught exceptions, console.error, CSP / load errors
        self.http_errors: list[tuple[int, str]] = []
        self._loaded = threading.Event()

    def send(self, method: str, params: dict | None = None, timeout: float | None = None) -> dict:
        return self.b.send(method, params, session=self.session, timeout=timeout)

    def _on_event(self, msg: dict) -> None:
        m, p = msg.get("method"), msg.get("params", {})
        if m == "Page.loadEventFired":
            self._loaded.set()
        elif m == "Runtime.exceptionThrown":
            d = p.get("exceptionDetails", {})
            self.errors.append("exception: " + (d.get("exception", {}).get("description") or d.get("text", "")).split("\n")[0])
        elif m == "Runtime.consoleAPICalled" and p.get("type") in ("error", "assert"):
            self.errors.append("console.error: " + " ".join(str(a.get("value", a.get("description", ""))) for a in p.get("args", [])))
        elif m == "Log.entryAdded" and p.get("entry", {}).get("level") == "error":
            e = p["entry"]
            self.errors.append(f"log[{e.get('source')}]: {e.get('text', '')} {e.get('url', '')}".strip())
        elif m == "Network.responseReceived":
            r = p.get("response", {})
            if r.get("status", 0) >= 400:
                self.http_errors.append((r["status"], r.get("url", "")))

    def setup(self, width: int, height: int, mobile: bool) -> None:
        for dom in ("Page", "Runtime", "Log", "Network"):
            self.send(f"{dom}.enable")
        self.viewport(width, height, mobile)

    def viewport(self, width: int, height: int, mobile: bool = False) -> None:
        self.send("Emulation.setDeviceMetricsOverride", {"width": width, "height": height, "deviceScaleFactor": 2 if mobile else 1,
                                                          "mobile": mobile, "screenWidth": width, "screenHeight": height})
        self.send("Emulation.setTouchEmulationEnabled", {"enabled": mobile, "maxTouchPoints": 5 if mobile else 1})

    def reduced_motion(self, on: bool = True) -> None:
        self.send("Emulation.setEmulatedMedia", {"features": [{"name": "prefers-reduced-motion", "value": "reduce" if on else ""}]})

    def goto(self, url: str, timeout: float = 20.0) -> None:
        self._loaded.clear()
        res = self.send("Page.navigate", {"url": url})
        if res.get("errorText"):
            raise CDPError(f"navigate {url}: {res['errorText']}")
        if not self._loaded.wait(timeout):
            raise CDPError(f"navigate {url}: load event not fired in {timeout}s")

    def eval(self, expr: str, timeout: float | None = None):
        res = self.send("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": True, "userGesture": True}, timeout=timeout)
        if res.get("exceptionDetails"):
            d = res["exceptionDetails"]
            raise CDPError("eval failed: " + (d.get("exception", {}).get("description") or d.get("text", "")) + f"\n  in: {expr[:200]}")
        return res.get("result", {}).get("value")

    def wait(self, expr: str, timeout: float = 15.0, what: str = "") -> object:
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            try:
                last = self.eval(expr)
            except CDPError:
                last = None
            if last:
                return last
            time.sleep(0.1)
        raise AssertionError(f"timed out after {timeout}s waiting for {what or expr}")

    def settled(self, selector: str, timeout: float = 5.0) -> None:
        """Wait until the element is inside the viewport and has stopped moving (CSS transitions)."""
        probe = f"""(() => {{ const e = document.querySelector({json.dumps(selector)}); if (!e) return null;
            const r = e.getBoundingClientRect(); return [Math.round(r.left), Math.round(r.top), r.width > 0 && r.left >= 0 && r.right <= innerWidth + 1]; }})()"""
        deadline, last = time.monotonic() + timeout, None
        while time.monotonic() < deadline:
            cur = self.eval(probe)
            if cur and cur[2] and cur == last:
                return
            last = cur
            time.sleep(0.12)
        raise AssertionError(f"{selector} did not settle inside the viewport within {timeout}s (last {last})")

    def click(self, selector: str) -> None:
        """Trusted mouse click at the element's centre (after scrolling it into view)."""
        box = self.eval(f"""(() => {{ const e = document.querySelector({json.dumps(selector)}); if (!e) return null;
            e.scrollIntoView({{block: 'center', inline: 'center', behavior: 'instant'}}); const r = e.getBoundingClientRect();
            return r.width && r.height ? [r.left + r.width / 2, r.top + r.height / 2] : null; }})()""")
        if not box:
            raise AssertionError(f"click: {selector} not found or not visible")
        x, y = box
        deadline = time.monotonic() + 3.0   # an overlay or drawer may still be animating away
        while True:
            hit = self.eval(f"""(() => {{ const t = document.elementFromPoint({x}, {y}); const e = document.querySelector({json.dumps(selector)});
                return !!t && (t === e || e.contains(t)); }})()""")
            if hit:
                break
            if time.monotonic() > deadline:
                raise AssertionError(f"click: {selector} is covered by another element at ({x:.0f},{y:.0f})")
            time.sleep(0.1)
        for kind in ("mousePressed", "mouseReleased"):
            self.send("Input.dispatchMouseEvent", {"type": kind, "x": x, "y": y, "button": "left", "clickCount": 1})

    def type(self, selector: str, text: str) -> None:
        self.eval(f"(() => {{ const e = document.querySelector({json.dumps(selector)}); e.focus(); e.select && e.select(); }})()")
        self.send("Input.insertText", {"text": text})

    def key(self, key: str, code: str = "", modifiers: int = 0, key_code: int = 0) -> None:
        """modifiers bitmask: Alt=1, Ctrl=2, Meta=4, Shift=8."""
        base = {"key": key, "code": code or key, "modifiers": modifiers, "windowsVirtualKeyCode": key_code, "nativeVirtualKeyCode": key_code}
        self.send("Input.dispatchKeyEvent", {"type": "rawKeyDown", **base})
        if len(key) == 1 and not modifiers & 6:
            self.send("Input.dispatchKeyEvent", {"type": "char", "text": key, **base})
        self.send("Input.dispatchKeyEvent", {"type": "keyUp", **base})

    def overflow(self) -> dict:
        """Horizontal overflow of the page and the widest offending visible elements."""
        return self.eval("""(() => { const vw = document.documentElement.clientWidth;
            const over = [...document.querySelectorAll('body *')].filter(e => { const r = e.getBoundingClientRect();
              const s = getComputedStyle(e); if (!r.width || s.visibility === 'hidden' || s.position === 'fixed') return false;
              let p = e.parentElement; while (p && p !== document.body) { const o = getComputedStyle(p).overflowX;
                if (o === 'auto' || o === 'scroll' || o === 'hidden' || o === 'clip') return false; p = p.parentElement; }
              return r.right > vw + 1; })
              .slice(0, 5).map(e => (e.id ? '#' + e.id : e.tagName.toLowerCase() + '.' + [...e.classList].join('.')) + ' right=' + Math.round(e.getBoundingClientRect().right));
            return {scrollWidth: document.documentElement.scrollWidth, clientWidth: vw, offenders: over}; })()""")

    def screenshot(self, path: str | Path) -> None:
        import base64
        data = self.send("Page.captureScreenshot", {"format": "png"}, timeout=30)["data"]
        Path(path).write_bytes(base64.b64decode(data))

    def close(self) -> None:
        try:
            self.b.send("Target.closeTarget", {"targetId": self.target})
            self.b.send("Target.disposeBrowserContext", {"browserContextId": self.ctx})
        except Exception:
            pass
        self.b._listeners.pop(self.session, None)
