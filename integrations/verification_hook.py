"""Optional Claude Code hook: attest a real edit and a later foreground test.

The observer still owns the event, command and output. This hook sends only ids,
digests and the result. Nothing received from the console is ever executed.
"""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import stat
import subprocess
import sys
import time
from urllib.request import Request, urlopen
from urllib.error import URLError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))
from activity_inspector import Scope, _split_roots, is_sensitive_path, native_call_ref, redact
from correlation import clean_task_id
from integrations.client import load_config

MAX_FILES = 2048
MAX_FILE = 4 * 1024 * 1024
MAX_TREE = 32 * 1024 * 1024
WEEK = 7 * 86400


def digest(data):
    return hashlib.sha256(data).hexdigest()


def ident(value):
    return isinstance(value, str) and value and clean_task_id(value) == redact(value, 96) == value


def git(root, *args):
    return subprocess.run(["git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(root), *args],
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3).stdout


def file_state(path):
    if is_sensitive_path(str(path)) or path.resolve() != path or ".git" in path.parts:
        raise ValueError("Unshareable file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE:
            raise ValueError("Unsupported file")
        raw = f.read(MAX_FILE + 1)
        after = os.fstat(f.fileno())
        if (len(raw) != st.st_size or st.st_ctime_ns != after.st_ctime_ns or path.resolve() != path
                or not os.path.samestat(st, path.lstat())):
            raise ValueError("File changed during capture")
        return raw, (st.st_dev, st.st_ino, st.st_mode, st.st_ctime_ns, st.st_mtime_ns)


def revision(root, edit_path=None, expected=None):
    """Snapshot materialized Git inputs, including staged, dirty and unignored new files."""
    head = git(root, "rev-parse", "--verify", "HEAD").strip()
    def paths():
        return sorted(set(git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")) - {b""})
    names = paths()
    if len(names) > MAX_FILES:
        raise ValueError("Project exceeds capture limit")
    tree, changes = hashlib.sha256(head), hashlib.sha256()
    states = {}
    matched, total = edit_path is None, 0
    for name in names:
        p = root / os.fsdecode(name)
        if not p.is_relative_to(root) or ".." in p.parts or is_sensitive_path(str(p)) or p.resolve() != p:
            raise ValueError("Unshareable Git path")
        try:
            raw, guard = file_state(p)
        except FileNotFoundError:
            tree.update(name + b"\0deleted\0")
            states[p] = None
            continue
        states[p] = guard
        total += len(raw)
        if total > MAX_TREE:
            raise ValueError("Project exceeds capture limit")
        sha = digest(raw)
        tree.update(name + b"\0" + str(guard[2] & 0o111).encode() + b":" + sha.encode() + b"\0")
        changes.update(repr(guard).encode())
        if p == edit_path and sha == expected:
            matched = True
    if not matched or paths() != names or git(root, "rev-parse", "--verify", "HEAD").strip() != head:
        raise ValueError("Edit or Git revision changed")
    for path, guard in states.items():
        try:
            st = path.lstat()
        except FileNotFoundError:
            if guard is None:
                continue
            raise ValueError("File disappeared during capture")
        if guard != (st.st_dev, st.st_ino, st.st_mode, st.st_ctime_ns, st.st_mtime_ns):
            raise ValueError("File changed during capture")
    return tree.hexdigest(), changes.hexdigest()


def expected_edit(path, tool, args):
    try:
        old, _ = file_state(path)
    except FileNotFoundError:
        old = None
    if tool == "Write" and isinstance(args.get("content"), str):
        new = args["content"].encode()
    elif tool == "Edit" and old is not None and all(isinstance(args.get(k), str) for k in ("old_string", "new_string")):
        before, after = args["old_string"].encode(), args["new_string"].encode()
        if not before or before not in old or (old.count(before) != 1 and args.get("replace_all") is not True):
            return None
        new = old.replace(before, after, -1 if args.get("replace_all") is True else 1)
    else:
        return None
    return digest(new) if new != old and len(new) <= MAX_FILE else None


def foreground_test(args, cwd, root):
    cmd = args.get("command")
    if not isinstance(cmd, str) or len(cmd) > 4096 or args.get("run_in_background") or re.search(r"[;&|<>()$`\\\r\n#]", cmd):
        return False
    argv = shlex.split(cmd)
    if not argv or any(a.split("=", 1)[0] in ("-h", "-V", "--help", "--version", "--collect-only", "--co",
            "--listTests", "--no-run", "--fixtures", "--fixtures-per-test", "--list", "-list", "-c",
            "--watch", "--watchAll", "--dry-run") for a in argv):
        return False
    for raw in argv[1:]:
        target = raw.split("=", 1)[-1].split("::", 1)[0]
        if target.startswith("~"):
            return False
        if ("/" in target or target == "..") and not (Path(cwd) / target).resolve().is_relative_to(root):
            return False
    name = argv[0]
    return (name in ("pytest", "py.test") or
            (re.fullmatch(r"python(?:3(?:\.\d+)?)?", name) and argv[1:3] in (["-m", "pytest"], ["-m", "unittest"])) or
            (name in ("go", "cargo", "npm", "pnpm", "yarn") and argv[1:2] == ["test"]))


def observe(conn, payload, cfg, task, actor, roots):
    phase, tool = payload.get("hook_event_name"), payload.get("tool_name")
    sid = payload.get("session_id")
    if (phase not in ("PreToolUse", "PostToolUse", "PostToolUseFailure") or tool not in ("Write", "Edit", "Bash")
            or not ident(sid) or not ident(task) or not ident(actor) or payload.get("agent_id")):
        return
    session = "claude-code:" + sid
    ref = native_call_ref(session, payload.get("tool_use_id"))
    args = payload.get("tool_input")
    cwd = payload.get("cwd")
    if len(session) > 96 or not ref or not isinstance(args, dict) or not isinstance(cwd, str) or not roots.contains(cwd):
        return
    root = Path(os.fsdecode(git(cwd, "rev-parse", "--show-toplevel").rstrip(b"\n"))).resolve()
    if not roots.contains(root):
        return
    key = (session, ref)
    role = "test" if tool == "Bash" else "edit"
    if phase == "PreToolUse":
        if role == "edit":
            if not isinstance(args.get("file_path"), str):
                return
            path = Path(cwd) / args["file_path"]
            if not path.is_relative_to(root) or path.resolve() != path or is_sensitive_path(str(path)):
                return
            expected = expected_edit(path, tool, args)
            if not expected:
                return
            state = {"file": str(path), "expected": expected}
        else:
            if not foreground_test(args, cwd, root):
                return
            rev, guard = revision(root)
            matches = conn.execute("""SELECT ref FROM receipts WHERE session=? AND task=? AND actor=? AND
                root=? AND revision=? AND role='edit' ORDER BY rowid DESC LIMIT 32""",
                                   (session, task, actor, str(root), rev)).fetchall()
            if not matches:
                return
            state = {"revision": rev, "guard": guard, "edits": [r[0] for r in matches]}
        conn.execute("INSERT OR IGNORE INTO pending VALUES(?,?,?,?,?,?,?,?)",
                     (*key, task, actor, str(root), role, json.dumps(state), time.time()))
        return
    row = conn.execute("""SELECT state FROM pending WHERE session=? AND ref=? AND task=? AND actor=? AND root=? AND role=?""",
                       (*key, task, actor, str(root), role)).fetchone()
    if not row:
        return
    conn.execute("DELETE FROM pending WHERE session=? AND ref=?", key)
    state, response = json.loads(row[0]), payload.get("tool_response")
    response = response if isinstance(response, dict) else {}
    if payload.get("is_interrupt") or any(response.get(k) for k in (
            "interrupted", "backgroundTaskId", "background_task_id", "backgrounded")):
        return
    receipt = {"host_id": cfg.host_id, "session_id": session, "call_ref": ref,
               "task_id": task, "actor": actor, "role": role}
    if role == "edit":
        if phase != "PostToolUse" or response.get("is_error"):
            return
        rev, _ = revision(root, Path(state["file"]), state["expected"])
    else:
        rev, guard = revision(root)
        if (rev, guard) != (state["revision"], state["guard"]):
            return
        code = response.get("exit_code", response.get("exitCode"))
        if phase == "PostToolUseFailure" or response.get("is_error"):
            # Failures before executing the shell (e.g. permission denied) are not test runs.
            error = payload.get("error")
            reported_exit = isinstance(error, str) and re.match(r"^(?:Error: )?Exit code [1-9]\d*(?:\s|$)", error)
            if not (type(code) is int and code != 0 or reported_exit):
                return
            failed = True
        elif type(code) is int or isinstance(response.get("stdout"), str) or isinstance(response.get("stderr"), str):
            failed = type(code) is int and code != 0
        else:
            return
        receipt.update(result="failed" if failed else "passed", edits=state["edits"])
    receipt["revision"] = rev
    conn.execute("INSERT OR IGNORE INTO receipts VALUES(?,?,?,?,?,?,?,?,0,?)",
                 (*key, task, actor, str(root), rev, role, json.dumps(receipt), time.time()))


def flush(conn, cfg):
    deadline = time.monotonic() + 3
    for session, ref, payload in conn.execute("SELECT session,ref,payload FROM receipts WHERE sent=0 ORDER BY rowid LIMIT 32").fetchall():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        request = Request(cfg.server + "/api/v1/ingest/verification", data=payload.encode(),
                          headers={"Content-Type": "application/json"})
        request.add_unredirected_header("Authorization", "Bearer " + cfg.token)
        with urlopen(request, timeout=min(cfg.timeout, remaining)) as response:
            if json.load(response).get("ok") is not True:
                return
        with conn:
            conn.execute("UPDATE receipts SET sent=1 WHERE session=? AND ref=?", (session, ref))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-settings", action="store_true", help="Print hooks to merge into Claude Code settings")
    parser.add_argument("--flush", action="store_true", help="Retry queued receipts without running a tool")
    options = parser.parse_args(argv)
    if options.print_settings:
        command = shlex.join([sys.executable, str(Path(__file__).resolve())])
        hook = [{"matcher": "^(Write|Edit|Bash)$", "hooks": [{"type": "command", "command": command}]}]
        print(json.dumps({"hooks": dict.fromkeys(("PreToolUse", "PostToolUse", "PostToolUseFailure"), hook)}, indent=2))
        return 0
    cfg = load_config()
    roots = Scope(_split_roots(os.environ.get("SWARMCONTROL_ACTIVITY_ROOTS", "")))
    if not cfg.token or not roots.enabled:
        return 1 if options.flush else 0
    folder = Path(os.getenv("SWARMCONTROL_VERIFICATION_STATE") or Path.home() / ".local/state/neuroswarm/verification")
    # A different enrollment must never drain a previous tenant's queue.
    namespace = digest(json.dumps([cfg.server, cfg.host_id, cfg.token]).encode())
    private = folder / namespace
    try:
        private.mkdir(parents=True, exist_ok=True, mode=0o700)
        with closing(sqlite3.connect(private / "receipts.sqlite3", timeout=2)) as conn:
            with conn:
                conn.execute("""CREATE TABLE IF NOT EXISTS pending(session,ref,task,actor,root,role,state,ts,
                                PRIMARY KEY(session,ref))""")
                conn.execute("""CREATE TABLE IF NOT EXISTS receipts(session,ref,task,actor,root,revision,role,payload,sent,ts,
                                PRIMARY KEY(session,ref))""")
                conn.execute("DELETE FROM pending WHERE ts<?", (time.time()-WEEK,))
                conn.execute("DELETE FROM receipts WHERE ts<?", (time.time()-WEEK,))
                if not options.flush:
                    raw = sys.stdin.buffer.read(2 * MAX_FILE + 1)
                    if len(raw) <= 2 * MAX_FILE:
                        payload = json.loads(raw)
                        if isinstance(payload, dict):
                            observe(conn, payload, cfg, os.getenv("SWARMCONTROL_TASK_ID"),
                                    os.getenv("SWARMCONTROL_AGENT_NAME"), roots)
            flush(conn, cfg)
    except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.SubprocessError, URLError):
        if options.flush:
            print("Could not deliver queued verification receipts.", file=sys.stderr)
            return 1
        # Missing evidence is safe. A collector outage must not change the tool's behavior.
    return 0


if __name__ == "__main__":
    sys.exit(main())
