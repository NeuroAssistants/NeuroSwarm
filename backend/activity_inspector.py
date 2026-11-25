"""Passive, read-only view of what local agent harnesses did inside the folders an operator chose.

Answers four questions per agent session, from the harness's own local records:
  what it did (latest summary), what it plans (checklist), how it worked (readable
  steps and a tool mix), and where (workspace, files edited, files read).

Sources: Codex (state DB + rollout JSONL, incl. code-mode `exec`), Claude Code
(project JSONL + task files), Gemini/Antigravity (brain transcripts + conversation
metadata), OpenCode (`session_v2`, read-only SQLite) and Pi Coding Agent (v3 session JSONL).

Privacy model (opt-in): nothing is read unless the operator lists folders in
SWARMCONTROL_ACTIVITY_ROOTS. Sessions whose working folder is outside those roots are
skipped, and file paths outside them are dropped. Identity comes from the folder (or
SWARMCONTROL_AGENT_LABELS); the core knows no team, product or path. Optional adapters
(e.g. `adapters/openbot.py`, enabled with SWARMCONTROL_ACTIVITY_ADAPTERS=openbot) may add
roots and labels from a host application without the core depending on it.

Output follows REMOTE-CONTRACT v1 (`POST /api/v1/ingest/activity`), so a local scan and a
remote agent produce the same snapshot. Never writes, signals or blocks anything.
"""
from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
import re
import shlex
import shutil
import socket
import sqlite3
import stat
import subprocess
import threading
import time
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from urllib.request import url2pathname

SCHEMA_VERSION = "1.0"
HOME = Path(os.environ.get("SWARMCONTROL_ACTIVITY_HOME") or Path.home())
ACTIVE_WINDOW_SEC = 900
LABEL_RE = re.compile(r"[^\w .@+-]+", re.UNICODE)


# --- scope: which folders may be read, and how they are named ---------------------
def _split_roots(raw: str) -> list[str]:
    # Same syntax as the remote agent: os.pathsep (":" Unix, ";" Windows) or commas.
    return [p.strip() for p in re.split(r"[,%s]" % re.escape(os.pathsep), raw or "") if p.strip()]


def parse_labels(raw: str) -> dict[str, str]:
    """`key=Name,key2=Name` where key is a folder name or absolute folder path."""
    labels: dict[str, str] = {}
    for pair in (raw or "").split(","):
        key, sep, value = pair.partition("=")
        if sep and key.strip() and value.strip():
            labels[key.strip().rstrip("/")] = LABEL_RE.sub("", value.strip())[:64] or key.strip()
    return labels


class Scope:
    """Allowed roots plus display labels. Longest matching root owns a path."""

    def __init__(self, roots: list[str | Path] | None = None, labels: dict[str, str] | None = None,
                 host_id: str | None = None, adapters: list[Any] | None = None):
        clean = []
        for r in roots or []:
            try:
                p = Path(r).expanduser().resolve()
            except (OSError, RuntimeError):
                continue
            if p.is_dir() and not is_sensitive_path(str(p)) and p not in clean:
                clean.append(p)
        self.roots = sorted(clean, key=lambda p: len(p.parts), reverse=True)
        self.labels = dict(labels or {})
        self.host_id = (host_id or socket.gethostname())[:128]
        self.adapters = list(adapters or [])
        names = Counter(p.name for p in self.roots)
        self._ids = {p: (p.name if names[p.name] == 1 else
                         f"{p.name}-{hashlib.sha256(str(p).encode()).hexdigest()[:6]}") for p in self.roots}

    @property
    def enabled(self) -> bool:
        return bool(self.roots)

    def root_of(self, path: Any) -> Path | None:
        s = str(path or "")
        if s.startswith("file://"):
            s = s[7:]
        if not Path(s).is_absolute():
            return None
        try:
            p = Path(s).resolve()
        except (OSError, RuntimeError):
            return None
        if is_sensitive_path(str(p)):
            return None
        return next((r for r in self.roots if p == r or p.is_relative_to(r)), None)

    def contains(self, path: Any) -> bool:
        return self.root_of(path) is not None

    def identity(self, path: Any) -> tuple[str, str, str]:
        """(agent_id, agent_name, workspace) for a path inside a root, else ("", "", "")."""
        root = self.root_of(path)
        if root is None:
            return "", "", ""
        name = self.labels.get(str(root)) or self.labels.get(root.name) or root.name
        return self._ids[root], name, str(root)


def load_scope() -> Scope:
    roots = _split_roots(os.environ.get("SWARMCONTROL_ACTIVITY_ROOTS", ""))
    labels: dict[str, str] = {}
    adapters = []
    for name in _split_roots(os.environ.get("SWARMCONTROL_ACTIVITY_ADAPTERS", "")):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name):
            continue
        try:
            adapter = importlib.import_module(f"adapters.{name}")
        except ImportError:
            continue  # an optional integration must never break the core scan
        adapters.append(adapter)
        for pre in getattr(adapter, "TOOL_PREFIXES", []):
            if pre not in TOOL_PREFIXES:
                TOOL_PREFIXES.append(pre)
        try:
            roots += [str(r) for r in adapter.roots()]
            labels.update(adapter.labels())
        except Exception:
            continue
    labels.update(parse_labels(os.environ.get("SWARMCONTROL_AGENT_LABELS", "")))  # operator wins
    return Scope(roots, labels, os.environ.get("SWARMCONTROL_HOST_ID"), adapters)


_CURRENT: Scope | None = None


def _scope() -> Scope:
    return _CURRENT if _CURRENT is not None else load_scope()

# --- redaction & sensitive paths -------------------------------------------------
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("swarmcontrol_token", re.compile(r"\bsc_(?:live|tok)_[A-Za-z0-9_-]{8,}")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{25,}")),
    ("xai_key", re.compile(r"\bxai-[A-Za-z0-9_-]{20,}")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{20,}")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{20,}")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("url_credentials", re.compile(r"(?<=://)[^/\s:@]+:[^/\s@]+(?=@)")),
]
INLINE_SECRET = re.compile(
    r"(?i)\b(password|passwd|pass|secret|api[_-]?key|token|admin[_-]?pass|session[_-]?secret)"
    r"(\s*[:=]\s*)(['\"]?)([^\s'\",;]{6,})")
NOISE_TAGS = re.compile(r"</?(?:USER_REQUEST|SYSTEM_MESSAGE|system-reminder|[a-z]+-[a-z_-]+-instructions|agent_[a-z_-]+)>", re.I)

SENSITIVE_DIRS = {".vault", "vault", "agent-api-keys", ".farm-connector", ".beszel-access", ".ssh", ".gnupg"}
SENSITIVE_FILE = re.compile(
    r"(?i)(?:^\.env(?:\.|$)|auth\.json$|credentials?\.json$|operator-password$|server-password$|\.pw$|"
    r"admin_credentials|id_rsa|id_ed25519|ssh_ed25519|\.(?:pem|key|p12|pfx|kdbx)$|^cookies(?:\.|$)|"
    r"(?:^|[._-])(?:secret|secrets|passwd|password|credential|credentials|api[_-]?key)(?:$|[._-])|"
    r"(?:^|[._-])token\.(?:txt|json|env|key|secret)$|oauth-token$)")
SKIP_WALK_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".cache", "Cache", "Code Cache",
                  "GPUCache", "Crashpad", "dist", "build"} | SENSITIVE_DIRS


def is_sensitive_path(path: str) -> bool:
    p = Path(str(path).replace("\\", "/"))
    if any(part.lower() in SENSITIVE_DIRS for part in p.parts):
        return True
    return bool(SENSITIVE_FILE.search(p.name))


def redact(text: Any, max_len: int = 240) -> str:
    if not text:
        return ""
    clean = NOISE_TAGS.sub(" ", str(text))
    clean = re.sub(r"\s+", " ", clean).strip()
    for name, pat in SECRET_PATTERNS:
        clean = pat.sub(f"[redacted:{name}]", clean)
    clean = INLINE_SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", clean)
    if len(clean) > max_len:
        clean = clean[: max_len - 1].rstrip() + "…"
    return clean


def clean_path(raw: Any) -> str:
    s = str(raw or "").strip()
    for _ in range(3):
        s = s.strip().strip('"').strip("'").rstrip("\\")
    if s.startswith("file://"):
        s = s[7:]
    if not Path(s).is_absolute() or "\n" in s or len(s) > 400:
        return ""
    if ".system_generated/" in s or is_sensitive_path(s):
        return ""
    return s


# --- tool classification -----------------------------------------------------------
CATEGORY_LABEL = {
    "file_edit": "Edit files", "file_read": "Read files", "shell": "Run commands",
    "web": "Web & browser", "coordination": "Coordinate", "plan": "Plan", "think": "Reason", "visual": "Images",
    "other": "Other",
}


def categorize_tool(name: str) -> str:
    low = (name or "").lower()
    if any(k in low for k in ("todo", "update_plan", "task_create", "taskcreate", "taskupdate", "manage_task", "plan")):
        return "plan"
    if any(k in low for k in ("write", "edit", "patch", "notebook", "replace")):
        return "file_edit"
    if any(k in low for k in ("read", "view", "glob", "grep", "list_dir", "find_by")):
        return "file_read"
    if any(k in low for k in ("command", "bash", "exec", "shell", "terminal")):
        return "shell"
    if any(k in low for k in ("image", "screenshot")):
        return "visual"
    if any(k in low for k in ("web", "browser", "fetch", "url", "search")):
        return "web"
    if any(k in low for k in ("message", "channel", "subagent", "agent", "mcp", "tool_call", "attach")):
        return "coordination"
    return "other"


FRIENDLY = {
    "channel_result": "Post the result to the channel", "channel_reply": "Reply in the channel",
    "send_message": "Message a teammate", "attach_files_to_response": "Attach files to the answer",
    "run_script": "Drive the browser", "open": "Open a web page", "browser_open": "Open a web page",
    "tool_call": "Call an OpenBot tool", "list_agents": "Check available teammates",
    "tool_describe": "Look up a tool", "tool_search": "Look up a tool", "toolsearch": "Look up a tool",
    "search_memories": "Search saved memory", "screenshot": "Take a screenshot", "imagegen": "Generate an image",
    "generate_image": "Generate an image", "web_search": "Search the web", "search_web": "Search the web",
    "web__run": "Search the web", "run_command": "Run a command", "bash": "Run a command",
    "exec_command": "Run a command", "todowrite": "Update the plan", "update_plan": "Update the plan",
    "taskcreate": "Add a task to the plan", "taskupdate": "Update a task in the plan", "manage_task": "Update a task",
    "agent": "Delegate to a helper", "invoke_subagent": "Delegate to a helper", "ask_user": "Ask the user",
    "askuserquestion": "Ask the user", "close_tab": "Close a browser tab", "set_environment": "Change browser size",
    "remember": "Save a memory", "react_to_user_message": "React to a message", "routine_no_update": "Finish routine",
}
FILE_VERB = {"file_edit": "Edit", "file_read": "Read"}


TOOL_PREFIXES: list[str] = []  # adapters may add single-underscore MCP prefixes (e.g. "mcp_<server>_")


def _tool_key(tool: str) -> str:
    """Strip any MCP server namespace: mcp__<server>__name, <server>.name, plus adapter prefixes."""
    t = str(tool or "").lower()
    t = re.sub(r"^mcp__.+?__", "", t)
    for pre in TOOL_PREFIXES:
        if t.startswith(pre):
            t = t[len(pre):]
            break
    return re.sub(r"^[a-z0-9_-]+\.", "", t)


def readable(text: Any, max_len: int = 220) -> str:
    """Plain, short sentence(s): no markdown, links, absolute paths or status prefixes."""
    t = str(text or "")
    t = re.sub(r"\[([^\]]{1,200})\]\((?:file://|https?://)[^)]*\)", r"\1", t)
    t = re.sub(r"file://(/[^\s)`'\"]+)", lambda m: Path(m.group(1)).name, t)
    t = re.sub(r"(?<![\w.])/(?:var|home|opt|tmp|etc|usr)/[^\s)`'\",;]+", lambda m: Path(m.group(0).rstrip("/.")).name or m.group(0), t)
    t = re.sub(r"```.*?```", " ", t, flags=re.S)
    t = re.sub(r"(\*\*|__|`|^#+\s*|^\s*[-*•]\s+|^\s*\d+\.\s+)", "", t, flags=re.M)
    t = re.sub(r"(?<!\w)\*(?!\s)([^*]{1,80})\*", r"\1", t)
    t = re.sub(r"(?:(?<=\s)|^)[-*]?\s*\[[ xX/]\]\s+", "", t, flags=re.M)  # checklist markers, inline or per line
    t = re.sub(r"^\s*(?:status:\s*\w+\s*)?(?:result:\s*)", "", t, flags=re.I)
    t = redact(t, 4000)
    if len(t) > max_len:
        cut = t[:max_len]
        end = max(cut.rfind(". "), cut.rfind("; "), cut.rfind(": "))
        t = (cut[: end + 1] if end > max_len * 0.45 else cut.rsplit(" ", 1)[0] + "…").strip()
    return t


def _step(tool: str, label: Any, ts: Any = None) -> dict[str, Any]:
    cat = categorize_tool(tool)
    key = _tool_key(tool)
    text = str(label or "").strip()
    first = text.split(" ", 1)
    flat = text.replace(" ", "_").lower()
    if not text or _tool_key(first[0]) == key or _tool_key(flat) == key or (len(key) > 4 and flat.endswith("_" + key)):
        rest = first[1] if len(first) > 1 and _tool_key(first[0]) == key else ""
        if rest and cat in FILE_VERB:
            text = f"{FILE_VERB[cat]} {rest}"
        else:
            text = FRIENDLY.get(key) or key.replace("__", " ").replace("_", " ").strip().capitalize() or "Use a tool"
    step = {"tool": redact(key, 48), "category": cat, "label": readable(text, 110), "time": str(ts or "")[:19]}
    if _CAPTURE is not None and os.environ.get("SWARMCONTROL_SHARE_FILE_PREVIEWS") == "1" and isinstance(ts, str):
        step["_evidence_time"] = ts
    global _POS_N
    if _POS is not None:  # exact origin: <log key>:<byte offset of the record>:<n-th step from that record>
        step["src"] = f"{_POS[0]}:{_POS[1]}:{_POS_N}"
        _POS_N += 1
    return step


_PYTHON_EXE = r"(?:\S*[/\\])?python(?:\d+(?:\.\d+)?)?(?:\.exe)?"
_PYTHON_FLAGS = rf"^{_PYTHON_EXE}\s+(?:-[bBdEiIOPqRsSuvx]+\s+)*"
CMD_KIND = [
    (re.compile(r"^(?:\S*[/\\])?(?:unittest|pytest|py\.test|npm (?:run )?test|go test|cargo test)(?=\s|$)"
                rf"|{_PYTHON_FLAGS}-m\s*(?:unittest|pytest)(?=\s|$)"), "Run tests"),
    (re.compile(r"^(?:sudo\s+(?:-n\s+)?)?systemctl\b"), "Manage a service"),
    (re.compile(_PYTHON_FLAGS + r"-c"), "Run inline Python"),
    (re.compile(_PYTHON_FLAGS + r"-m"), "Run a Python module"),
    (re.compile(_PYTHON_FLAGS + r"-(?=\s|$)"), "Run Python from standard input"),
    (re.compile(rf"^{_PYTHON_EXE}(?=\s|$)"), "Run a Python script"),
    (re.compile(r"^(?:node|npx|npm)\b"), "Run a Node.js script"),
    (re.compile(r"^curl\b|^wget\b"), "Call a web address"),
    (re.compile(r"^git\b"), "Use Git"),
    (re.compile(r"^sqlite3\b"), "Query a database"),
    (re.compile(r"^(?:grep|rg|find)\b"), "Search files"),
    (re.compile(r"^(?:ls|tree|du|stat)\b"), "List files"),
    (re.compile(r"^(?:cat|head|tail|sed -n|less|wc)\b"), "Read a file"),
    (re.compile(r"^(?:cp|mv|mkdir|rm|tee|install|chmod)\b"), "Change files"),
    (re.compile(r"^(?:pdftoppm|convert|magick|weasyprint|rsvg-convert|ffmpeg)\b"), "Render or convert media"),
]


def command_kind(cmd: Any) -> str:
    """Describe a shell command by its kind only; never return its arguments."""
    c = str(cmd or "").strip()
    c = re.sub(r"^(?:cd\s+\S+\s*(?:&&|;)\s*)+", "", c)
    c = re.sub(r"^(?:[A-Z_][A-Z0-9_]*=\S*\s+)+", "", c)
    for pat, label in CMD_KIND:
        if pat.search(c):
            return label
    return "Run a shell command"


PROGRAM_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,39}")
WRAPPERS = {"sudo", "env", "nohup", "time", "timeout", "nice", "exec", "xargs", "stdbuf"}
KEYWORD_PREFIX = {"then", "do", "else", "if", "while", "until", "!", "{"}
SHELL_BUILTINS = {"cd", "set", "export", "source", ".", "if", "then", "else", "elif", "fi", "for", "do", "done", "while",
                  "until", "case", "esac", "function", "local", "trap", "true", "false", ":", "[", "[[", "test", "{", "}",
                  "unset", "shopt", "alias", "eval", "builtin", "umask", "pushd", "popd", "wait", "read"}


def command_info(cmd: Any) -> dict[str, str]:
    """{'program': <name>} for any shell command, plus 'command' (redacted, ≤160 chars) when the operator
    opted in with SWARMCONTROL_SHARE_COMMANDS=1. Never returns arguments otherwise."""
    c = str(cmd or "").strip()
    unwrapped = re.match(r"""^(?:/\S*/)?(?:ba|z)?sh\s+-l?c\s+(['"])(.*)\1\s*$""", c, re.S)
    if unwrapped:
        c = unwrapped.group(2).strip()
    program = ""
    # First real program across segments (newlines, ;, &&, ||, |); shell builtins and keywords are skipped.
    for segment in re.split(r"\n|;|&&|\|\||\|", c):
        for tok in re.findall(r"[^\s()]+", segment):
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S*", tok) or tok.startswith("-"):
                continue
            name = tok.rsplit("/", 1)[-1]
            if name in WRAPPERS or name in KEYWORD_PREFIX or re.fullmatch(r"\d+[smh]?", name):
                continue  # `then cat x`, `do wc -l`, `if grep -q`: the command follows the keyword
            if name not in SHELL_BUILTINS and PROGRAM_RE.fullmatch(name) and not is_sensitive_path(name):
                program = name
            break
        if program:
            break
    out = {"program": program} if program else {}
    if os.environ.get("SWARMCONTROL_SHARE_COMMANDS") == "1" and c:
        shown = re.sub(r"(?i)((?:^|\s)(?:-u|-p|--user|--password|--passwd|--pass|--token|--secret|--api[-_]?key|--auth|"
                       r"--header|-H)\s+)(?:\"[^\"]*\"|'[^']*'|\S+)", r"\1[redacted]", c)
        shown = redact(shown, 4000)  # secrets first, so masking can never hide the keyword that triggers redaction
        shown = mask_evidence_paths(shown)
        out["command"] = shown if len(shown) <= 160 else shown[:159].rstrip() + "…"
    return out


FILE_OPERAND_PROGRAMS = {
    "cat", "head", "tail", "less", "more", "nl", "wc", "sed", "awk", "grep", "egrep", "rg", "diff", "cmp", "sort", "uniq",
    "cut", "jq", "yq", "python", "python3", "node", "deno", "bun", "bash", "sh", "zsh", "ruby", "perl", "php", "pytest",
    "black", "ruff", "mypy", "eslint", "tsc", "shellcheck", "cp", "mv", "tee", "touch", "rm", "chmod", "stat", "file",
    "xxd", "hexdump", "md5sum", "sha256sum", "sqlite3", "pdftotext", "pdftoppm", "identify", "convert", "magick",
}


def command_files(command: Any, cwd: Any, limit: int = 6) -> list[str]:
    """Existing files a shell command names as operands (`tail -n 20 app.log`, `python3 tools/run.py`, `cd x && cat y`).

    Only programs that take files are considered, only arguments that resolve to an existing regular file count, and
    the caller keeps only paths inside the shared folders. Nothing is read; the file is only checked to exist."""
    c = str(command or "").strip()
    unwrapped = re.match(r"""^(?:/\S*/)?(?:ba|z)?sh\s+-l?c\s+(['"])(.*)\1\s*$""", c, re.S)
    if unwrapped:
        c = unwrapped.group(2).strip()
    here = clean_path(cwd) if cwd else ""
    found: list[str] = []
    for segment in re.split(r"\n|;|&&|\|\||\|", c)[:24]:
        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            tokens = segment.split()
        while tokens and (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S*", tokens[0]) or tokens[0].rsplit("/", 1)[-1] in WRAPPERS
                          or tokens[0] in KEYWORD_PREFIX):
            tokens = tokens[1:]
        if not tokens:
            continue
        program = tokens[0].rsplit("/", 1)[-1]
        if program == "cd":
            target = tokens[1] if len(tokens) > 1 else ""
            if target and not target.startswith(("~", "$", "-")):
                base = Path(target) if Path(target).is_absolute() else (Path(here) / target if here else None)
                here = clean_path(base) if base is not None else ""
            continue
        if re.fullmatch(r"python3?(?:\.\d+)?", program):
            program = "python3"
        if program not in FILE_OPERAND_PROGRAMS:
            continue
        for tok in tokens[1:]:
            tok = tok.lstrip("<")
            if (not tok or tok.startswith("-") or len(tok) > 400 or any(ch in tok for ch in "*?$`>{}")
                    or re.match(r"^(?:[A-Za-z][\w+.-]*:|~)", tok)):
                continue
            candidate = Path(tok) if Path(tok).is_absolute() else (Path(here) / tok if here else None)
            if candidate is None or ".." in candidate.parts:
                continue
            try:
                if candidate.is_symlink() or not candidate.is_file():
                    continue
            except OSError:
                continue
            path = clean_path(candidate)
            if path and path not in found and redact(path, 401) == path:
                found.append(path)
                if len(found) >= limit:
                    return found
    return found


_SECRET_ARGS = re.compile(r"""(?ix)(?<![\w.-])(-[upH]|--(?:password|passwd|pass|secret|token|user|api[-_]?key|header|auth))(?:=|\s+)(?:"[^"]*"|'[^']*'|[^\s]+)""")
_SECRET_VALUE = re.compile(r"""(?ix)(\b(?:authorization|cookie|set-cookie|password|passwd|secret|access[_-]?token|api[_-]?key|token)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\r\n,;]+)""")
_CONTROL_SEQ = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")


_PATH_FIELDS = re.compile(r"""[^\s"'=<>()|;&\[\]{}]+""")


def _mask_evidence_path(match):
    token = match.group()
    path = token.rstrip(".,:").replace("\\", "/")
    # Preserve assignment labels such as api_key=[redacted], while hiding a file named api_key.
    if "/" not in path and "." not in path:
        suffix = match.string[match.end():match.end() + 12].lstrip(" \t'\"")
        if token.endswith(":") or suffix.startswith(("=", ":")):
            return token
    looks_like_path = any(mark in path for mark in ("/", ".", "_", "-"))
    if looks_like_path and not token.startswith("-") and is_sensitive_path(path):
        return "[protected file]"
    if (path.startswith("/") and path.count("/") >= 2) or re.match(r"^[a-zA-Z]:/", path):
        return ".../" + path.rsplit("/", 1)[-1]
    return token


def mask_evidence_paths(text):
    return _PATH_FIELDS.sub(_mask_evidence_path, text)


def protected_command(command):
    """Suppress output when a command explicitly requests private files or environment values."""
    if not isinstance(command, str):
        return False
    if "[protected file]" in command or re.search(r"(?i)(?:^|[;&|\s])(?:env|set|printenv|export)(?:$|[;&|\s])", command):
        return True
    for field in _PATH_FIELDS.finditer(command):
        token = field.group().rstrip(".,:")
        if token and not token.startswith("-") and is_sensitive_path(token):
            return True
    return False


def evidence_text(value, limit):
    """Bound an explicitly shared text excerpt and preserve line breaks after redaction."""
    if not isinstance(value, str):
        return None, False
    if "PRIVATE KEY-----" in value or "\x00" in value:
        return "[protected content]", False
    scan_limit = limit * 2 + 1024
    capped = len(value) > scan_limit
    value = _CONTROL_SEQ.sub("", value[:scan_limit])
    value = re.sub(r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+",
                   r"\1: [redacted]", value)
    value = _SECRET_ARGS.sub(r"\1 [redacted]", value)
    value = _SECRET_VALUE.sub(r"\1[redacted]", value)
    for name, pattern in SECRET_PATTERNS:
        value = pattern.sub(f"[redacted:{name}]", value)
    value = INLINE_SECRET.sub(lambda m: f"{m[1]}{m[2]}[redacted]", value)
    value = mask_evidence_paths(value)
    excerpt = "".join(c for c in value if c in "\n\t" or c.isprintable())
    return excerpt[:limit], capped or len(excerpt) > limit


def execution_detail(command, output, code):
    info = command_info(command)
    if isinstance(command, str) and command.strip():
        info["_shell"] = command[:4000]  # private: read for file operands in _finish, then removed
    if _CAPTURE is None:
        return info
    if type(code) is int:
        info["exit_code"] = code
    if line_survival_enabled():
        sha = recorded_commit(command, output, code)
        if sha:
            info["git_commit"] = sha
    if os.environ.get("SWARMCONTROL_SHARE_COMMANDS") == "1":
        text, _ = evidence_text(command, 1024)
        if text is not None:
            info["command_input"] = text
    if os.environ.get("SWARMCONTROL_SHARE_COMMAND_OUTPUT") == "1":
        # A command that asks for credential files or the environment has no shareable output.
        if protected_command(command):
            return info
        text, cut = evidence_text(output, 4096)
        if text is not None:
            info.update(command_output=text, output_truncated=cut)
    return info



def _workspace_image(path, when, scope):
    """Capture a small, unchanged raster at collection time. Never dereference a link."""
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd or not isinstance(when, str):
        return None
    try:
        stamp = datetime.fromisoformat(when.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return None
        root = scope.root_of(path)
        if root is None:
            return None
        parts = Path(path).relative_to(root).parts
        if not parts or any(p.startswith(".") for p in parts):
            return None
        mime = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
                ".webp": "image/webp", ".gif": "image/gif"}.get(Path(path).suffix.lower())
        if not mime:
            return None
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        with ExitStack() as stack:
            directory = os.open(root, directory_flags)
            stack.callback(os.close, directory)
            for part in parts[:-1]:
                directory = os.open(part, directory_flags, dir_fd=directory)
                stack.callback(os.close, directory)
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            with os.fdopen(os.open(parts[-1], flags, dir_fd=directory), "rb") as handle:
                before = os.fstat(handle.fileno())
                if (not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 160*1024
                        or max(before.st_mtime, before.st_ctime) > stamp.timestamp()):
                    return None
                data = handle.read(160*1024+1)
                after = os.fstat(handle.fileno())
                if (len(data), after.st_mtime_ns, after.st_ctime_ns) != (before.st_size, before.st_mtime_ns, before.st_ctime_ns):
                    return None
        signatures = {"image/png": (b"\x89PNG\r\n\x1a\n",), "image/jpeg": (b"\xff\xd8\xff",),
                      "image/gif": (b"GIF87a", b"GIF89a"), "image/webp": (b"RIFF",)}
        if not data.startswith(signatures[mime]) or (mime == "image/webp" and data[8:12] != b"WEBP"):
            return None
        return {"path": path, "source": "workspace_snapshot", "mime_type": mime,
                "data_base64": base64.b64encode(data).decode("ascii"), "captured_at": time.time()}
    except (OSError, ValueError, OverflowError):
        return None



def _tool_result_text(result, path):
    """Keep text only when the runtime returned it for one explicit source file."""
    if (_CAPTURE is None or os.environ.get("SWARMCONTROL_SHARE_FILE_PREVIEWS") != "1" or not path
            or Path(path).suffix.lower() not in {".md", ".txt", ".py", ".js", ".ts", ".jsx", ".tsx", ".css",
                                                 ".html", ".json", ".toml", ".yaml", ".yml", ".go", ".rs",
                                                 ".c", ".h", ".cpp", ".sh", ".sql", ".java", ".rb"}):
        return []
    if isinstance(result, dict):
        result = result.get("content")
    if isinstance(result, list):
        lines = [b["text"] for b in result if isinstance(b, dict) and b.get("type") in ("text", "input_text")
                 and isinstance(b.get("text"), str)]
        result = "\n".join(lines) if lines else None
    text, cut = evidence_text(result, 4096)
    if text is None:
        return []
    return [{"path": path, "source": "tool_result", "text": text, "truncated": cut}]


def _tool_result_image(item, path):
    """Retain only an explicit image result for this recorded image read."""
    if _CAPTURE is None or os.environ.get("SWARMCONTROL_SHARE_FILE_PREVIEWS") != "1" or not path:
        return []
    result = item.get("result", item.get("content_items", item.get("output")))
    if isinstance(result, dict):
        result = result.get("content", [result])
    if not isinstance(result, list):
        return []
    for block in result:
        if not isinstance(block, dict):
            continue
        src = block.get("source") if isinstance(block.get("source"), dict) else {}
        data = src.get("data", block.get("data"))
        mime = src.get("media_type") or block.get("mimeType", block.get("mime_type"))
        if block.get("type") in ("image_url", "input_image", "Image"):
            url = block.get("image_url", block.get("url"))
            if isinstance(url, dict):
                url = url.get("url")
            if isinstance(url, str) and url.startswith(("data:image/png;base64,", "data:image/jpeg;base64,", "data:image/gif;base64,", "data:image/webp;base64,")):
                header, data = url.split(",", 1)
                mime = header[5:].split(";")[0]
        elif block.get("type") != "image":
            continue
        if mime in ("image/png", "image/jpeg", "image/gif", "image/webp") and isinstance(data, str) and 0 < len(data) <= 218456:
            return [{"path": path, "source": "tool_result", "mime_type": mime, "data_base64": data}]
    return []


def _model(raw: Any) -> str:
    m = str(raw or "")
    if m.startswith("{"):
        try:
            m = str(json.loads(m).get("id") or "")
        except (ValueError, AttributeError):
            hit = re.search(r'"id"\s*:\s*"([^"]+)"', m)
            m = hit.group(1) if hit else ""
    return redact(m, 40)


TAIL_CEILING = 4_000_000  # bytes; logs with huge records (e.g. screenshots) need a wider window to show recent steps
MIN_USEFUL_LINES = 40


def _tail_lines(path: Path, max_bytes: int = 160_000, max_lines: int = 400, *, positions=False):
    """Read the recent tail, widening the window when large records hide the last steps.
    With positions, each line carries the same byte offset used by incremental capture.
    """
    try:
        size = path.stat().st_size
        window = max_bytes
        while True:
            with path.open("rb") as f:
                if size > window:
                    f.seek(size - window)
                    f.readline()
                data = f.read(window)
                end = f.tell()
            # Split the bytes before decoding. Character offsets (e.g. for UTF-8 and CRLF)
            # are not byte offsets and would select a different record in the journal.
            tail = data.splitlines(keepends=True)[-max_lines:]
            pos = end - sum(map(len, tail))
            lines = []
            for raw in tail:
                line = raw.decode("utf-8", errors="ignore").rstrip("\r\n")
                if len(line) < 400_000:
                    lines.append((pos, line) if positions else line)
                pos += len(raw)
            if len(lines) >= MIN_USEFUL_LINES or window >= size or window >= TAIL_CEILING:
                return lines
            window = min(window * 4, TAIL_CEILING)
    except OSError:
        return []


# --- incremental capture for the work journal ---------------------------------------------
# The map needs a recent view; the journal needs *every* action. In capture mode each log is read from the byte
# offset where the previous scan stopped (minus a small overlap for parser context), steps carry their exact
# source position, and nothing is truncated to "the last 10". The caller (work_journal) persists offsets in the
# same transaction as the events, so a crash or a failed write simply re-reads the same bytes next time.
CAPTURE_OVERLAP = 262_144        # bytes re-read before the saved offset so multi-line records keep their context
CAPTURE_FIRST_SIGHT = 640_000    # bytes read the first time a log is seen (older history predates the journal)
CAPTURE_SESSION_LIMIT = 200      # sessions per runtime considered in one scan (the map keeps its own small limits)
CAPTURE_OPENCODE_PARTS = 2000
CAPTURE_MAX_RECORD = 32 * 1024 * 1024  # bytes; one log record (e.g. a large file write) is read whole up to this size
BASELINE_KEY = "__baseline__"         # stored with the offsets: when the journal first ran
NONTERMINAL = {"running", "pending", "in_progress"}
_CAPTURE: "Capture | None" = None
_POS: tuple[str, int] | None = None
_POS_N = 0


def _file_key(path: Any) -> str:
    return hashlib.sha256(str(path).encode()).hexdigest()[:20]


def native_call_ref(session, call_id):
    """Opaque correlation with the source hook for the same native tool call."""
    if not isinstance(call_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", call_id):
        return None
    return hashlib.sha256(json.dumps([session, call_id]).encode()).hexdigest()


class Capture:
    """Per-scan read state. `offsets` comes from storage; `read` holds the new positions to persist on success."""

    def __init__(self, offsets: dict[str, dict[str, int]] | None = None, ceiling: int = TAIL_CEILING):
        self.offsets = dict(offsets or {})
        self.ceiling = ceiling
        self.read: dict[str, dict[str, int]] = {}
        self.reader = ""
        self._by_reader: dict[str, set[str]] = {}
        self.gaps: list[dict[str, Any]] = []
        self.backlog: list[str] = []
        self.bytes_read = 0
        self.files_read = 0
        self.oversize = 0
        # The first scan ever (no stored offsets) marks a baseline; logs found after it are read from the start.
        # Saved offsets without a baseline (journals before baselines existed) also prove an earlier scan, so they are not a first run.
        self.first_run = not self.offsets
        if self.first_run:
            self.read[BASELINE_KEY] = {"inode": 0, "offset": int(time.time()), "legacy_until": 0}

    def legacy_until(self, key: str) -> int:
        state = self.read.get(key) or self.offsets.get(key) or {}
        return int(state.get("legacy_until", 0))

    def unchanged(self, path: Path) -> bool:
        try:
            st = path.stat()
        except OSError:
            return True
        prev = self.offsets.get(_file_key(path))
        return bool(prev) and prev.get("inode") == st.st_ino and prev.get("offset") == st.st_size

    def note(self, key: str, state: dict[str, int]) -> None:
        self.read[key] = state
        self._by_reader.setdefault(self.reader, set()).add(key)

    def fail_reader(self, name: str) -> None:
        """A parser crashed: do not advance its offsets, so the next scan re-reads those bytes."""
        for key in self._by_reader.pop(name, set()):
            self.read.pop(key, None)

    def lines(self, path: Path, first_sight: int = CAPTURE_FIRST_SIGHT):
        """Yield complete lines appended since the last scan; set the source position used by `_step`.

        - A log seen for the first time on the journal's very first scan is read from its last `first_sight` bytes
          (its older history predates the journal). Any log that appears later is read from its first line.
        - Records of any size up to CAPTURE_MAX_RECORD are read whole, even past the per-scan budget.
          Larger records are skipped and reported as a `capture_gap`, never silently.
        """
        global _POS, _POS_N
        try:
            st = path.stat()
        except OSError:
            return
        key = _file_key(path)
        prev = self.offsets.get(key)
        size = st.st_size
        if prev and prev.get("inode") == st.st_ino and size >= prev.get("offset", 0):
            saved = int(prev["offset"])
            start = max(0, saved - CAPTURE_OVERLAP)
            legacy = int(prev.get("legacy_until", 0))
        else:
            if prev:  # rotated or truncated: what was between the old offset and the rewrite cannot be recovered
                self.gaps.append({"file": key, "reason": "log rotated or truncated", "path": path.name})
            start = max(0, size - first_sight) if self.first_run else 0
            # Only bytes that existed before the first scan can have been stored by an older journal (exact or
            # same-moment keys). A rotated log or one created later holds only new actions.
            saved, legacy = start, (size if self.first_run else 0)
        budget_end = saved + self.ceiling                   # a large backlog is read in order over several scans
        try:
            f = path.open("rb")
        except OSError:
            return
        with f:
            f.seek(start)
            pos = start
            if start > 0:                                  # drop the partial first line, in bounded chunks
                while True:
                    chunk = f.readline(1 << 20)
                    if not chunk:
                        return                             # no complete line yet; same offsets next scan
                    pos += len(chunk)
                    if chunk.endswith(b"\n"):
                        break
            first = pos
            while pos < size:
                if pos >= budget_end:
                    self.backlog.append(key)
                    break
                raw = f.readline(CAPTURE_MAX_RECORD + 1)
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    if len(raw) <= CAPTURE_MAX_RECORD:
                        break                              # the writer is mid-record: read it next scan
                    skipped = len(raw)                     # oversize: skip to the end of the record, visibly
                    while True:
                        chunk = f.readline(1 << 20)
                        skipped += len(chunk)
                        if not chunk or chunk.endswith(b"\n"):
                            break
                    if not chunk:
                        break                              # the oversize record is still being written
                    self.gaps.append({"file": key, "reason": f"record over {CAPTURE_MAX_RECORD // (1 << 20)} MB skipped",
                                      "path": path.name, "bytes": skipped})
                    self.oversize += 1
                    pos += skipped
                    continue
                line_pos = pos
                pos += len(raw)
                _POS, _POS_N = (key, line_pos), 0
                yield raw[:-1].decode("utf-8", errors="ignore")
            _POS = None
        self.bytes_read += pos - first
        self.files_read += 1
        self.note(key, {"inode": st.st_ino, "offset": pos, "legacy_until": legacy})


def _lines(path: Path, max_bytes: int = 160_000, max_lines: int = 400):
    """Both the map and journal identify a step by its original log record and ordinal."""
    global _POS, _POS_N
    if _CAPTURE is not None:
        yield from _CAPTURE.lines(path)
        return
    key = _file_key(path)
    try:
        for offset, line in _tail_lines(path, max_bytes, max_lines, positions=True):
            _POS, _POS_N = (key, offset), 0
            yield line
    finally:
        _POS = None


def _checklist(text: str) -> list[dict[str, Any]]:
    items = []
    for line in str(text).splitlines():
        m = re.match(r"^\s*[-*]\s*\[([ xX/])\]\s+(.+)$", line)
        if m:
            mark = m.group(1).lower()
            items.append({"status": "completed" if mark == "x" else "in_progress" if mark == "/" else "pending",
                          "text": redact(m.group(2), 140)})
    return items[:12]


def _plan_item(status: Any, text: Any) -> dict[str, Any]:
    s = str(status or "pending").lower()
    s = "completed" if s in {"completed", "done", "complete"} else "in_progress" if "progress" in s else "pending"
    return {"status": s, "text": redact(text, 140)}


PROVIDERS = {"openai": "OpenAI", "azure": "Azure OpenAI", "anthropic": "Anthropic", "google": "Google",
             "zai": "Z.ai", "zai-coding-plan": "Z.ai", "deepseek": "DeepSeek", "openrouter": "OpenRouter",
             "ollama": "Ollama", "opencode": "OpenCode", "xai": "xAI", "mistral": "Mistral"}
MODEL_FAMILIES = [(re.compile(r"^(?:gpt|o[1345])(?:[-.]|$)", re.I), "openai"), (re.compile(r"^claude", re.I), "anthropic"),
                  (re.compile(r"^gemini", re.I), "google"), (re.compile(r"^glm", re.I), "zai"),
                  (re.compile(r"^deepseek", re.I), "deepseek"), (re.compile(r"^grok", re.I), "xai"),
                  (re.compile(r"^(?:mistral|codestral)", re.I), "mistral")]


def _provider(card: dict[str, Any], recorded: Any = None) -> None:
    """Recorded provider when the harness stored one; otherwise a labelled guess from the model name."""
    rec = str(recorded or "").lower()
    if rec in PROVIDERS:
        pid, basis = ("zai" if rec == "zai-coding-plan" else rec), "recorded"
    else:
        pid = next((p for rx, p in MODEL_FAMILIES if rx.search(card.get("model") or "")), "")
        basis = "model" if pid else "unknown"
    card["provider"], card["provider_label"], card["provider_basis"] = pid, PROVIDERS.get(pid, "Unreported"), basis
    card["provider_id"] = pid  # compatibility with the first map client


def _session(harness: str, harness_name: str, sid: str, cwd: str, updated: float, model: str = "",
             tokens: int = 0, owner_basis: str = "workspace") -> dict[str, Any] | None:
    """A session card, or None when its working folder is outside the operator's roots."""
    scope = _scope()
    agent_id, agent_name, workspace = scope.identity(cwd)
    if not agent_id:
        return None
    # Full id: sessions launched in the same millisecond share their first 12 characters. The short form
    # is kept as `legacy_session_id` so keys stored before this change still match.
    card = {"session_id": f"{harness}:{sid}"[:96], "legacy_session_id": f"{harness}:{sid[:12]}",
            "host_id": scope.host_id, "harness": harness,
            "harness_name": harness_name, "agent_id": agent_id, "agent_name": agent_name, "owner_basis": owner_basis,
            "workspace": workspace, "model": _model(model), "tokens_used": int(tokens or 0),
            "updated_at": updated, "status": "active" if time.time() - updated < ACTIVE_WINDOW_SEC else "idle",
            "what_done": "", "plan": [], "how": {}, "steps": [], "files_edited": [], "files_read": [],
            "files_delivered": []}
    current = clean_path(cwd)
    if current and current != workspace:
        card["current_folder"] = current
    _provider(card)
    return card


def _finish(card: dict[str, Any], steps: list[dict[str, Any]], edited: list[str], read: list[str],
            delivered: list[str] | None = None) -> dict[str, Any]:
    card["how"] = dict(Counter(s["category"] for s in steps))
    if _CAPTURE is not None:
        card["capture_steps"] = steps  # every step read in this scan, not only the last ten shown on the map

    scope = _scope()
    base = card.get("current_folder") or card.get("workspace")
    for step in steps:
        raw = step.pop("_shell", None)
        here = step.pop("_cwd", None)
        # Recognize the effective directory only for an unambiguous single read.
        if isinstance(raw, str) and here:
            scoped_read = re.fullmatch(r"cd (/[-./\w]+) && cat ([-./\w]+)", raw.strip())
            if scoped_read and not scoped_read[2].startswith("-") and ".." not in Path(scoped_read[2]).parts:
                here = scoped_read[1]
        if here and _CAPTURE is not None and scope.contains(clean_path(here)):
            step["cwd"] = clean_path(here)  # read by the journal to resolve relative paths and the command's folder
        if raw and not step.get("files") and step.get("category") in ("shell", "file_read", "file_edit"):
            operands = [p for p in command_files(raw, here or base) if scope.contains(p)]
            if operands:
                step["files"] = operands
                step["file_basis"] = "recorded"  # named by the command; the command itself may not have used it
    for step in steps:
        if "files" in step:
            step["files"] = [p for p in step["files"] if scope.contains(p)]
            step.setdefault("file_basis", "confirmed" if step["files"] and step.get("status", "completed") == "completed"
                            and step["category"] in ("file_edit", "file_read") else "recorded")

    if _CAPTURE is not None and os.environ.get("SWARMCONTROL_SHARE_FILE_PREVIEWS") == "1":
        for step in steps:
            recorded_at = step.pop("_evidence_time", None)
            if (step.get("category") == "file_read" and step.get("file_basis") == "confirmed" and step.get("status") == "completed"
                    and not step.get("image_previews") and len(step.get("files", [])) == 1):
                preview = _workspace_image(step["files"][0], recorded_at, scope)
                if preview:
                    step["image_previews"] = [preview]

    def uniq(items: list[str], n: int) -> list[str]:
        out: list[str] = []
        for p in reversed(items):
            p = clean_path(p)
            if p and p not in out and scope.contains(p):
                out.append(p)
        return out[:n]
    card["files_edited"] = uniq(edited, 12)
    card["files_read"] = [p for p in uniq(read, 12) if p not in card["files_edited"]][:8]
    card["files_delivered"] = uniq(delivered or [], 8)
    session_files = set(card["files_edited"] + card["files_read"] + card["files_delivered"])
    for item in card["plan"]:
        # A literal filename in the checklist is a reference, not evidence of an edit.
        names = re.findall(r"`([^`\n]+)`|(?<![\w./-])([\w./-]+\.\w+)(?![\w/-])", item["text"])
        mentioned = []
        for quoted, plain in names:
            token = (quoted or plain).removeprefix("./")
            matches = [p for p in session_files if p == token or (not token.startswith("/") and p.endswith("/" + token))]
            if len(matches) == 1 and matches[0] not in mentioned:
                mentioned.append(matches[0])
        if mentioned:
            item["named_files"] = mentioned
    card["what_done"] = readable(card["what_done"])
    if not card["what_done"]:
        card["what_done"] = "No written summary in the latest part of this session."
    private_fields = {"command_input", "command_output", "exit_code", "output_truncated", "image_previews", "text_previews",
                      "native_call_ref", "git_commit"}
    shown = [{k: v for k, v in s.items() if k not in private_fields} for s in steps[-10:]]
    card["steps"] = shown
    card["latest_action"] = shown[-1] if shown else None
    # The step an operator usually wants: the last real piece of work, not a status message.
    card["latest_work"] = next((s for s in reversed(shown) if s["category"] in
                                ("file_edit", "shell", "file_read", "web", "visual")), card["latest_action"])
    return card


def _file_label(name: str, fp: Any) -> str:
    """'<tool> <file>' only for a file inside the shared folders; otherwise a neutral phrase (no file name)."""
    safe = clean_path(fp)
    if safe and _scope().contains(safe):
        return f"{name} {Path(safe).name}"
    verb = {"file_edit": "Edit", "file_read": "Read"}.get(categorize_tool(name), "Use")
    return f"{verb} a file outside the shared folders" if not is_sensitive_path(str(fp)) else f"{verb} a protected file"


def _recorded_file(raw: Any, card: dict[str, Any]) -> str:
    if not isinstance(raw, str) or not raw:
        return ""
    supplied = raw.strip()
    if len(supplied) > 1 and supplied[0] == supplied[-1] and supplied[0] in ("'", '"'):
        supplied = supplied[1:-1]
    supplied = supplied.removeprefix("file://")
    base = clean_path(card.get("current_folder") or card.get("workspace"))
    if not Path(supplied).is_absolute() and (not base or re.match(r"^(?:[A-Za-z][\w+.-]*:|~|\\\\)", supplied)):
        return ""
    path = Path(base) / supplied
    safe = clean_path(path)
    if not safe or redact(safe, 401) != safe or ".." in path.parts or any(ord(c) < 32 for c in safe):
        return ""
    # Any folder the operator opted in to; never a path outside those roots.
    return safe if _scope().contains(safe) else ""


def _codex_change(changes: Any, status: str, ts: Any, cwd: str) -> dict[str, Any]:
    # Completed FileChange records (and older patch_apply_end events) supply paths
    # and the outcome separately from the patch/diff. A proposed patch is not an edit.
    paths = []
    verbs = set()
    if status == "completed" and isinstance(changes, dict):
        for raw, entry in changes.items():
            if not isinstance(entry, dict):
                continue
            for target in (raw, entry.get("move_path")):
                safe = _codex_target(target, cwd)
                if safe and safe not in paths:
                    paths.append(safe)
                    verbs.add("move" if entry.get("move_path") else str(entry.get("type")).lower())
    verb = "Change"
    if len(verbs) == 1:
        verb = {"add": "Add", "delete": "Delete", "update": "Edit", "move": "Move"}.get(next(iter(verbs)), verb)
    target = "files"
    if len(paths) == 1:
        target = Path(paths[0]).name
    elif paths:
        target = f"{len(paths)} files"
    action = _step("apply_patch", f"{verb} {target}", ts)
    action["status"] = status
    action["files"] = paths[:12]
    if len(paths) > 12:
        action["file_count"] = len(paths)
    return action


# --- where each runtime keeps its records -----------------------------------------------
# The runtime's own environment variable wins (as the runtime itself does), then its documented default. The same
# catalogue feeds the readers and `log_sources()`, which tells an operator what was found and why something was not.
ANTIGRAVITY_DIRS = ("antigravity-acp", "antigravity", "antigravity-ide", "antigravity-cli")
CODEX_COLUMNS = {"id", "cwd", "model", "tokens_used", "updated_at", "rollout_path"}


def _env_dir(name: str) -> Path | None:
    value = os.environ.get(name, "").strip()
    return Path(value).expanduser() if value else None


def codex_home() -> Path:
    return _env_dir("CODEX_HOME") or HOME / ".codex"


def claude_home() -> Path:
    return _env_dir("CLAUDE_CONFIG_DIR") or HOME / ".claude"


def opencode_db() -> Path:
    return (_env_dir("XDG_DATA_HOME") or HOME / ".local/share") / "opencode/opencode.db"


def antigravity_bases() -> list[Path]:
    """Every Antigravity variant that keeps conversations in the known layout (brain/<id>/.system_generated)."""
    return [b for b in (HOME / ".gemini" / name for name in ANTIGRAVITY_DIRS) if (b / "brain").is_dir()]


def codex_state_db() -> tuple[Path | None, str]:
    """The newest `state_N.sqlite` whose `threads` table has the columns the reader uses, and a status word."""
    try:
        found = sorted(((int(m[1]), p) for p in codex_home().glob("state_*.sqlite")
                        if (m := re.fullmatch(r"state_(\d+)\.sqlite", p.name))), reverse=True)
    except OSError:
        return None, "no permission"
    if not found:
        return None, "not found"
    for i, (_, db) in enumerate(found):
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
            try:
                columns = {r[1] for r in conn.execute("PRAGMA table_info(threads)")}
            finally:
                conn.close()
        except sqlite3.Error:
            columns = set()
        if CODEX_COLUMNS <= columns:
            return db, "found" if i == 0 else f"unsupported format ({found[0][1].name}); reading {db.name}"
    return None, f"unsupported format ({found[0][1].name})"


def _shown(path: Path, variable: str | None) -> str:
    """A location an operator can recognise without revealing paths outside their home folder."""
    try:
        return "~/" + path.resolve().relative_to(HOME.resolve()).as_posix()
    except (ValueError, OSError):
        return f"set by {variable}" if variable else "custom location"


def log_sources() -> list[dict[str, str]]:
    """For each runtime: where its records were looked for, and found / not found / unsupported / no permission."""
    out = []

    def add(runtime: str, path: Path, variable: str | None, status: str) -> None:
        out.append({"runtime": runtime, "location": _shown(path, variable if os.environ.get(variable or "") else None),
                    "origin": variable if variable and os.environ.get(variable) else "default", "status": status})

    db, status = codex_state_db()
    add("Codex CLI", codex_home(), "CODEX_HOME", status)
    projects = claude_home() / "projects"
    try:
        status = "found" if projects.is_dir() and any(projects.iterdir()) else "not found"
    except PermissionError:
        status = "no permission"
    except OSError:
        status = "not found"
    add("Claude Code", projects, "CLAUDE_CONFIG_DIR", status)
    db_oc = opencode_db()
    add("OpenCode", db_oc.parent, "XDG_DATA_HOME", "found" if db_oc.is_file() else "not found")
    bases = antigravity_bases()
    for base in bases:
        add("Gemini / Antigravity", base, None, "found")
    if not bases:
        add("Gemini / Antigravity", HOME / ".gemini", None, "not found")
    return out


# --- Codex ---------------------------------------------------------------------------
CODE_TOOL = re.compile(r"tools\.([a-z_]+)\(")
CODE_PLAN_STEP = re.compile(r"step\s*:\s*\"((?:[^\"\\]|\\.){2,200})\"\s*,\s*status\s*:\s*\"([a-z_]+)\"")
_CODEX_EDIT_TOOLS = {"edit", "edit_file", "write", "write_file", "multiedit", "notebookedit"}
_CODEX_READ_TOOLS = {"read", "read_file", "view_image", "read_image"}
_CODEX_FILE_TOOLS = _CODEX_EDIT_TOOLS | _CODEX_READ_TOOLS


def _literal_shell_words(command: str) -> list[str]:
    # Only a simple command. Guessing after cd, expansion, substitution, a pipe,
    # redirection or a shell comment can associate an entirely different file.
    if len(command) > 8192 or re.search(r"""[^\w \t.,/@%+:="'-]""", command):
        return []
    try:
        return shlex.split(command)
    except ValueError:
        return []


def _codex_command_parts(raw, parsed) -> tuple[str, list[str]]:
    """The full recorded input for evidence and literal argv, when available, for file attribution."""
    if isinstance(raw, list) and raw and all(isinstance(arg, str) for arg in raw):
        words = raw
        command = shlex.join(words)
    else:
        command = raw if isinstance(raw, str) else ""
        if not command and len(parsed) == 1 and isinstance(parsed[0].get("cmd"), str):
            command = parsed[0]["cmd"]
        words = _literal_shell_words(command)
    if (len(words) >= 3 and Path(words[0]).name in {"sh", "bash", "dash", "zsh", "ksh"}
            and words[1] in {"-c", "-lc", "-cl"}):
        command = words[2]
        words = _literal_shell_words(command)
    return command, words


def _command_file_operands(words: list[str]) -> list[str]:
    """Filenames explicitly passed to tail or to the Python interpreter, never script arguments."""
    if not words:
        return []
    program = Path(words[0]).name.lower().removesuffix(".exe")
    args = iter(words[1:])
    if re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", program):
        for arg in args:
            if arg in {"-W", "-X", "--check-hash-based-pycs"}:
                next(args, None)
            elif arg == "--" or not arg.startswith("-"):
                script = next(args, "") if arg == "--" else arg
                return [script] if script and script != "-" else []
            elif not re.fullmatch(r"-(?:[bBdEiIOPqRsSuvx]+|[WX].+)", arg):
                return []  # includes stdin, -c, -m, help and version
        return []
    if program != "tail":
        return []

    files = []
    for arg in args:
        if arg == "--":
            files.extend(path for path in args if path and path != "-")
            break
        if arg in {"-n", "-c", "--lines", "--bytes"}:
            if not re.fullmatch(r"[+-]?\d+[a-zA-Z]*", next(args, "")):
                return []
        elif arg.startswith("-") and arg != "-":
            if not (re.fullmatch(r"-(?:[qvfF]+|\d+|[nc][+-]?\d+[a-zA-Z]*)", arg)
                    or re.fullmatch(r"--(?:lines|bytes)=[+-]?\d+[a-zA-Z]*", arg)
                    or arg in {"--quiet", "--silent", "--verbose", "--follow", "--follow=name",
                               "--follow=descriptor", "--retry"}):
                return []
        elif arg and arg != "-":
            files.append(arg)
    return files


def _codex_local_path(raw) -> str:
    if not isinstance(raw, str) or len(raw) > 4096 or any(ord(c) < 32 for c in raw):
        return ""
    if not raw.startswith("file://"):
        return raw
    try:
        uri = urlsplit(raw)
        if uri.netloc not in ("", "localhost") or uri.query or uri.fragment:
            return ""
        path = url2pathname(uri.path)
        return path if Path(path).is_absolute() and not any(ord(c) < 32 for c in path) else ""
    except (ValueError, OSError):
        return ""


def _codex_target(raw, cwd) -> str:
    """Use the call's directory and the same root-relative visibility rule as Files & Workspace."""
    raw = _codex_local_path(raw)
    cwd = _codex_local_path(cwd)
    if not raw or (not Path(raw).is_absolute() and not _scope().contains(cwd)):
        return ""
    target = _recorded_file(raw, {"workspace": cwd})
    if not target:
        return ""
    path = Path(target)
    root = _scope().root_of(path)
    if root is None:
        return ""
    try:
        for spelling in (path, path.resolve()):
            parts = spelling.relative_to(root).parts
            if not parts or any(part.startswith(".") for part in parts):
                return ""
    except (ValueError, RuntimeError, OSError):
        return ""
    return target


def _codex_command_step(item, cwd, stamp, read):
    parsed = [p for p in item.get("parsed_cmd") or [] if isinstance(p, dict)]
    kinds = {p.get("type") for p in parsed}
    command, words = _codex_command_parts(item.get("command"), parsed)
    # Each descriptor may record its own directory. A relative path after a cd
    # in a compound shell command cannot safely use the launcher directory.
    moved = re.search(r"(?:^|[\s(;|&])(?:cd|pushd|popd)(?=\s|$)", command)
    withheld = False
    files = []
    native_operands = set()
    for entry in parsed:
        operand = entry.get("path")
        if entry.get("type") != "read" or not isinstance(operand, str) or not operand:
            continue
        native_operands.add(operand)
        if moved and not entry.get("cwd") and not Path(operand.removeprefix("file://")).is_absolute():
            withheld = True
            continue
        target = _codex_target(operand, entry.get("cwd") or cwd)
        if not target:
            withheld = True
        elif len(files) < 12 and target not in files:
            files.append(target)
    read.extend(files)
    confirmed = len(files)
    operands = _command_file_operands(words)
    if len(operands) > 64:
        withheld = True  # the public file list is bounded; do not ship output from unchecked operands
    for operand in operands[:64]:
        # argv contains native path spellings, not quoted/URI-encoded path metadata.
        if operand in native_operands:
            continue  # the descriptor supplied the directory for this operand
        if operand.startswith("file://") or operand.strip(" \t'\"") != operand:
            withheld = True
            continue
        target = _codex_target(operand, cwd)
        if not target:
            withheld = True
        elif len(files) < 12 and target not in files:
            files.append(target)

    category = "file_read" if kinds and kinds <= {"read", "list_files", "search"} else "shell"
    if kinds == {"read"}:
        label = "Read " + (", ".join(Path(p).name for p in files)[:100] or "files")
    elif category == "file_read":
        label = "List or search files"
    else:
        label = command_kind(command or (parsed[0].get("cmd") if parsed else ""))
    step = _step("exec_command", label, stamp)
    step.update(category=category, files=files)
    if len(files) > confirmed:
        step["file_basis"] = "recorded"  # an argv operand alone does not prove a successful read or edit
    evidence = execution_detail(command, None if withheld else item.get("aggregated_output"), item.get("exit_code"))
    if withheld:
        evidence.pop("command", None)
        evidence.pop("command_input", None)
    if cwd:
        step["_cwd"] = cwd
    if withheld or (words and Path(words[0]).name.lower().startswith(("python", "tail"))):
        evidence.pop("_shell", None)  # explicit operand parser already handled these
    step.update(evidence)
    return step


def codex_sessions(limit: int = 8) -> list[dict[str, Any]]:
    if _CAPTURE is not None:
        limit = CAPTURE_SESSION_LIMIT
    db, _ = codex_state_db()
    if db is None:
        return []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.5)
        try:
            columns = {r[1] for r in conn.execute("PRAGMA table_info(threads)")}
            provider_column = "model_provider" if "model_provider" in columns else "NULL"
            rows = conn.execute(f"SELECT id, cwd, model, tokens_used, updated_at, rollout_path, {provider_column} "
                                "FROM threads ORDER BY updated_at DESC LIMIT ?", (limit * 6,)).fetchall()
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    out = []
    for tid, cwd, model, tokens, updated, rollout, provider in rows:
        if len(out) >= limit:
            break
        ts = float(updated or 0)
        ts = ts / 1000.0 if ts > 1e12 else ts
        card = _session("codex", "Codex CLI", str(tid), str(cwd or ""), ts, model or "codex", tokens)
        if card is None:
            continue  # outside the operator's folders: not read
        _provider(card, provider)
        steps: list[dict[str, Any]] = []
        read: list[str] = []
        delivered: list[str] = []
        legacy: list[dict[str, Any]] = []
        change_slots: dict[str, tuple[int, str]] = {}
        session_cwd = card.get("current_folder") or card["workspace"]
        path = Path(str(rollout or ""))
        if _CAPTURE is not None and (not rollout or _CAPTURE.unchanged(path)):
            continue  # nothing appended since the last scan
        if rollout and path.is_file():
            for ln in _lines(path, max_bytes=640_000, max_lines=1200):
                try:
                    o = json.loads(ln)
                except ValueError:
                    continue
                p = o.get("payload") if isinstance(o, dict) else None
                if not isinstance(p, dict):
                    continue
                kind, stamp = p.get("type"), o.get("timestamp")
                item = p.get("item") if kind == "item_completed" else None
                if kind == "patch_apply_end" or (isinstance(item, dict) and item.get("type") == "FileChange"):
                    if kind == "patch_apply_end":
                        change, status, key = p, "completed" if p.get("success") is True else "error", p.get("call_id")
                    else:
                        change, status, key = item, str(item.get("status") or "unreported"), item.get("id")
                    normalized = {"failed": "error", "declined": "error", "error": "error", "completed": "completed",
                                  "in_progress": "running", "pending": "pending"}.get(status, "unreported")
                    slot = change_slots.get(key) if isinstance(key, str) else None
                    directory = change.get("cwd") or change.get("workdir") or (slot[1] if slot else session_cwd)
                    step = _codex_change(change.get("changes"), normalized, stamp, directory)
                    if slot is None:
                        if isinstance(key, str) and key:
                            change_slots[key] = len(steps), directory
                        steps.append(step)
                    elif kind == "item_completed" and normalized != "unreported":
                        index, _ = slot
                        if steps[index].get("src"):
                            step["src"] = steps[index]["src"]  # same edit, now final: keep its original identity
                        steps[index] = step
                    continue
                if kind == "item_completed" and isinstance(p.get("item"), dict):
                    # Structured items: readable intent, classified commands, tool calls.
                    it = p["item"]
                    t = it.get("type")
                    if t == "Reasoning":
                        heads = [h.strip("* ") for h in it.get("summary_text") or [] if isinstance(h, str)]
                        if heads:
                            steps.append(_step("reasoning", heads[-1], stamp))
                            steps[-1]["category"] = "think"
                    elif t == "CommandExecution":
                        steps.append(_codex_command_step(it, it.get("cwd") or it.get("workdir") or session_cwd, stamp, read))
                    elif t == "DynamicToolCall":
                        tool, args = str(it.get("tool") or "tool"), it.get("arguments") or {}
                        if _tool_key(tool) == "tool_call" and isinstance(args, dict) and args.get("name"):
                            tool, args = str(args["name"]), args.get("arguments") or {}
                        key = _tool_key(tool)
                        if isinstance(args, str) and key in _CODEX_FILE_TOOLS:
                            try:
                                args = json.loads(args)
                            except ValueError:
                                args = {}
                        if tool.endswith("attach_files_to_response") and isinstance(args, dict):
                            delivered += [str(x) for x in args.get("paths") or []]
                        step = _step(tool, tool.replace("_", " "), stamp)
                        steps.append(step)
                        if key not in _CODEX_FILE_TOOLS or not isinstance(args, dict):
                            continue
                        editing = key in _CODEX_EDIT_TOOLS
                        step["category"] = "file_edit" if editing else "file_read"
                        result = it.get("result")
                        if (it.get("success") is False or it.get("status") in ("failed", "error", "declined", "cancelled")
                                or isinstance(result, dict) and result.get("isError") is True):
                            step["status"] = "error"
                        elif it.get("success") is True or it.get("status") == "completed":
                            step["status"] = "completed"
                        if editing and step.get("status") != "completed":
                            continue  # a write request alone is not a modification
                        directory = args.get("workdir") or args.get("cwd") or it.get("cwd") or session_cwd
                        raw = (args.get("file_path") or args.get("path") or args.get("Path") or
                               args.get("target_file") or args.get("notebook_path"))
                        target = _codex_target(raw, directory)
                        if not target:
                            continue
                        if editing and (args.get("dryRun") is True or args.get("dry_run") is True):
                            step.update(category="file_read", files=[target], file_basis="recorded",
                                        label=f"Preview edit to {Path(target).name}")
                            continue
                        verb = "Write" if key in {"write", "write_file"} else "Edit" if editing else "Read"
                        step.update(files=[target], label=f"{verb} {Path(target).name}")
                        if not editing and step.get("status") != "error":
                            read.append(target)
                            previews = _tool_result_image(it, target)
                            if previews:
                                step["image_previews"] = previews
                            elif key in {"read", "read_file"}:
                                snippets = _tool_result_text(it.get("result", it.get("content_items", it.get("output"))), target)
                                if snippets:
                                    step["text_previews"] = snippets
                    elif t == "Extension" and it.get("query"):
                        steps.append(_step("web_search", f"Search: {it['query']}", stamp))
                    elif t == "AgentMessage":
                        text = " ".join(str(b.get("text") or "") for b in it.get("content") or [] if isinstance(b, dict))
                        if text.strip():
                            card["what_done"] = redact(text, 260)
                    continue
                if kind in ("function_call", "custom_tool_call") and str(p.get("name")) == "exec":
                    body = str(p.get("input") or p.get("arguments") or "")
                    plan = CODE_PLAN_STEP.findall(body)
                    if plan:
                        card["plan"] = [_plan_item(st, text.replace('\\"', '"')) for text, st in plan][:12]
                        steps.append(_step("update_plan", "Update the plan", stamp))  # a plan change is an action
                    continue  # its other inner actions arrive as item_completed records
                if kind in ("function_call", "custom_tool_call"):
                    target = legacy
                    name = str(p.get("name") or "tool")
                    body = str(p.get("arguments") or p.get("input") or "")
                    plan = CODE_PLAN_STEP.findall(body)
                    if name == "update_plan" or plan:
                        try:
                            parsed = json.loads(body).get("plan", []) if name == "update_plan" else []
                            plan = plan or [(i.get("step"), i.get("status")) for i in parsed if isinstance(i, dict)]
                        except (ValueError, AttributeError):
                            pass
                        if plan:
                            card["plan"] = [_plan_item(st, text.replace('\\"', '"')) for text, st in plan][:12]
                    inner = [t for t in CODE_TOOL.findall(body) if t != "update_plan"]
                    if name == "exec" and inner:
                        for t in inner[:3]:
                            target.append(_step(t, t.replace("_", " "), stamp))
                    else:
                        try:
                            args = json.loads(body) if body.startswith("{") else {}
                        except ValueError:
                            args = {}
                        label = args.get("name") if isinstance(args, dict) and name == "tool_call" else name
                        target.append(_step(str(label or name), str(label or name).replace("_", " "), stamp))
                elif kind in ("agent_message", "task_complete"):
                    msg = p.get("message") or p.get("last_agent_message")
                    if msg:
                        card["what_done"] = redact(msg, 260)
                        card["plan"] = card["plan"] or _checklist(msg)
                elif kind == "message" and p.get("role") == "assistant":
                    text = " ".join(b.get("text", "") for b in p.get("content") or [] if isinstance(b, dict))
                    if text.strip():
                        card["what_done"] = redact(text, 260)
        edited = [path for step in steps if step["category"] == "file_edit" and step.get("status") == "completed"
                  for path in step.get("files", [])]
        out.append(_finish(card, steps or legacy, edited, read, delivered))
    return out


# --- Claude Code -----------------------------------------------------------------------
CLAUDE_EDIT = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
CLAUDE_READ = {"Read"}


def _claude_launch_cwd(path: Path) -> str:
    """First recorded working folder of a Claude Code session (its owner), from the head of the log."""
    try:
        with path.open("rb") as f:
            for _ in range(200):
                line = f.readline(2_000_000)
                if not line:
                    break
                if b'"cwd"' in line:
                    try:
                        cwd = json.loads(line).get("cwd")
                    except ValueError:
                        continue
                    if isinstance(cwd, str) and cwd:
                        return cwd
    except OSError:
        pass
    return ""


def claude_sessions(limit: int = 6) -> list[dict[str, Any]]:
    if _CAPTURE is not None:
        limit = CAPTURE_SESSION_LIMIT
    root = claude_home() / "projects"
    try:
        found = list(root.glob("*/*.jsonl")) + list(root.glob("*/*/subagents/*.jsonl"))  # Claude Code sub-agents too
        files = sorted(found, key=lambda p: p.stat().st_mtime, reverse=True)[:limit * 6]
    except OSError:
        return []
    out = []
    for jf in files:
        if len(out) >= limit:
            break
        try:
            mtime = jf.stat().st_mtime
        except OSError:
            continue
        cwd, model = "", ""
        recorded_calls = {}
        steps: list[dict[str, Any]] = []
        edited: list[str] = []
        read: list[str] = []
        summary, plan = "", []
        delivered: list[str] = []
        if _CAPTURE is not None and _CAPTURE.unchanged(jf):
            continue
        for ln in _lines(jf):
            try:
                o = json.loads(ln)
            except ValueError:
                continue
            if not isinstance(o, dict):
                continue
            cwd = str(o.get("cwd") or cwd)  # latest working folder in the recent log
            msg = o.get("message")
            if o.get("type") == "user" and isinstance(msg, dict) and _CAPTURE is not None:
                for result in msg.get("content") or []:
                    if not isinstance(result, dict) or result.get("type") != "tool_result":
                        continue
                    pair = recorded_calls.pop(result.get("tool_use_id"), None) if isinstance(result.get("tool_use_id"), str) else None
                    if pair is None:
                        continue
                    step, command = pair
                    step["status"] = "error" if result.get("is_error") else "completed"
                    payload = result.get("content")
                    if command is not None:
                        if isinstance(payload, list):
                            payload = "\n".join(block["text"] for block in payload if isinstance(block, dict)
                                                and block.get("type") == "text" and isinstance(block.get("text"), str))
                        result_meta = o.get("toolUseResult")
                        code = result_meta.get("exitCode", result_meta.get("exit_code")) if isinstance(result_meta, dict) else None
                        step.update(execution_detail(command, payload, code))
                    elif step.get("files") and step["status"] == "completed":
                        previews = _tool_result_image({"result": payload}, step["files"][0])
                        if previews:
                            step["image_previews"] = previews
                        else:
                            snippets = _tool_result_text(payload, step["files"][0])
                            if snippets:
                                step["text_previews"] = snippets
                continue
            if o.get("type") != "assistant" or not isinstance(msg, dict):
                continue
            model = str(msg.get("model") or model)
            for b in msg.get("content") or []:
                if not isinstance(b, dict):
                    continue
                if b.get("type") == "text" and str(b.get("text") or "").strip():
                    summary = str(b["text"])
                elif b.get("type") == "tool_use":
                    name, inp = str(b.get("name") or "tool"), b.get("input") or {}
                    if not isinstance(inp, dict):
                        inp = {}
                    raw_file = inp.get("file_path") or inp.get("notebook_path")
                    fp = _recorded_file(raw_file, {"workspace": cwd})
                    if name in CLAUDE_EDIT and fp:
                        edited.append(fp)
                    elif name in CLAUDE_READ and fp:
                        read.append(fp)
                    if name == "TodoWrite" and isinstance(inp.get("todos"), list):
                        plan = [_plan_item(t.get("status"), t.get("content")) for t in inp["todos"] if isinstance(t, dict)]
                    if name.endswith("attach_files_to_response") and isinstance(inp.get("paths"), list):
                        delivered += [str(x) for x in inp["paths"]]
                    if _tool_key(name) == "channel_result" and inp.get("text"):
                        summary = str(inp["text"])
                    label = (inp.get("description") or inp.get("subject") or
                             (_file_label(name, fp or raw_file) if raw_file else "") or
                             inp.get("query") or inp.get("name") or _tool_key(name))
                    if _tool_key(name) == "tool_call" and isinstance(inp.get("name"), str) and not inp.get("description"):
                        steps.append(_step(inp["name"], "", o.get("timestamp")))  # wrapper call: show the wrapped tool's action
                    else:
                        steps.append(_step(name, label, o.get("timestamp")))
                    if _CAPTURE is not None and (name in CLAUDE_EDIT or name == "Bash"):
                        ref = native_call_ref(f"claude-code:{jf.stem}", b.get("id"))
                        if ref:
                            steps[-1]["native_call_ref"] = ref
                    if name == "Bash" and inp.get("command"):
                        steps[-1].update(execution_detail(inp["command"], None, None))
                        steps[-1]["_cwd"] = cwd
                        if not inp.get("description"):
                            steps[-1]["label"] = command_kind(inp["command"])
                    if (name in CLAUDE_EDIT or name in CLAUDE_READ) and fp:
                        steps[-1]["files"] = [fp]
                    if (_CAPTURE is not None and isinstance(b.get("id"), str) and
                            (name in CLAUDE_READ or name == "Bash") and (any(
                                os.environ.get(key) == "1" for key in ("SWARMCONTROL_SHARE_COMMAND_OUTPUT", "SWARMCONTROL_SHARE_FILE_PREVIEWS")
                            ) or (name == "Bash" and line_survival_enabled()))):  # the commit ID is read from the result
                        recorded_calls[b["id"]] = (steps[-1], inp.get("command") if name == "Bash" else None)
        tasks = claude_home() / "tasks" / jf.stem
        if tasks.is_dir():
            items = []
            for tf in sorted(tasks.glob("*.json"), key=lambda p: (len(p.stem), p.stem))[:15]:
                try:
                    td = json.loads(tf.read_text(encoding="utf-8", errors="ignore")[:20000])
                except (OSError, ValueError):
                    continue
                if isinstance(td, dict) and td.get("status") != "deleted" and (td.get("subject") or td.get("description")):
                    items.append(_plan_item(td.get("status"), td.get("subject") or td.get("description")))
            plan = items or plan
        launch = _claude_launch_cwd(jf) or cwd
        card = _session("claude-code", "Claude Code", jf.stem, launch, mtime, model or "claude")
        if card is not None and cwd and cwd != launch and _scope().contains(cwd):
            card["current_folder"] = cwd  # where it is working now; the owner stays the launch folder
        if card is None:
            continue  # outside the operator's folders
        if jf.parent.name == "subagents":  # a Task sub-agent: owned by its own launch folder, linked to its parent
            card["parent_session"] = f"claude-code:{jf.parent.parent.name}"[:96]
            card["harness_name"] = "Claude Code · sub-agent"
        card["what_done"] = redact(summary, 260)
        card["plan"] = (plan or _checklist(summary))[:12]
        out.append(_finish(card, steps, edited, read, delivered))
    return out


# --- Pi Coding Agent (v3 JSONL) -----------------------------------------------------
def _epoch_ts(raw: Any) -> float | None:
    if raw is None or isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        val = float(raw)
        if not (0 < val < 1e16):
            return None
        return val / 1000.0 if val > 1e12 else val
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return None
        try:
            num = float(s)
            if 0 < num < 1e16:
                return num / 1000.0 if num > 1e12 else num
        except ValueError:
            pass
        try:
            iso = s[:-1] + "+00:00" if s.endswith("Z") else s
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            return None
    return None


def _iso_ts(raw: Any) -> str:
    if isinstance(raw, str):
        s = raw.strip()
        if len(s) >= 19 and s[4:5] == "-" and s[7:8] == "-" and s[10:11] in ("T", " "):
            return s[:19].replace(" ", "T")
    epoch = _epoch_ts(raw)
    if epoch is not None and 0 < epoch < 1e10:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(epoch))
    return ""


# --- Hermes Agent ----------------------------------------------------------------------
HERMES_EDIT = {"write_file", "patch", "edit_file", "apply_patch", "replace_in_file"}
HERMES_READ = {"read_file", "search_files", "list_dir", "grep", "find_files"}
HERMES_SHELL = {"terminal", "execute_code", "bash", "shell", "run_command"}
HERMES_PLAN = {"todo", "todowrite", "update_plan"}


def _hermes_dbs() -> list[tuple[Path, str]]:
    """Return existing (state.db Path, profile_label) pairs for Hermes Agent, read-only."""
    roots: list[Path] = []
    env_home = os.environ.get("HERMES_HOME", "").strip()
    if env_home:
        roots.append(Path(os.path.expanduser(env_home)))
    else:
        roots.append(HOME / ".hermes")
        local_app = os.environ.get("LOCALAPPDATA", "").strip()
        if local_app:
            roots.append(Path(local_app) / "hermes")

    seen: set[str] = set()
    dbs: list[tuple[Path, str]] = []
    for root in roots:
        if is_sensitive_path(str(root)):
            continue
        main_db = root / "state.db"
        if main_db.is_file() and str(main_db) not in seen:
            seen.add(str(main_db))
            dbs.append((main_db, ""))
        prof_dir = root / "profiles"
        if prof_dir.is_dir():
            for p_db in sorted(prof_dir.glob("*/state.db"))[:16]:
                if p_db.is_file() and not is_sensitive_path(str(p_db)) and str(p_db) not in seen:
                    seen.add(str(p_db))
                    dbs.append((p_db, p_db.parent.name))
    return dbs


def _hermes_parse_calls(raw: Any) -> list[tuple[str, str, dict[str, Any]]]:
    """Decode both OpenAI function tool_calls and native Hermes tool_calls JSON."""
    if isinstance(raw, str):
        try:
            items = json.loads(raw)
        except ValueError:
            return []
    elif isinstance(raw, list):
        items = raw
    else:
        return []
    if not isinstance(items, list):
        return []
    out: list[tuple[str, str, dict[str, Any]]] = []
    for tc in items:
        if not isinstance(tc, dict):
            continue
        cid = str(tc.get("id") or "")
        fn = tc.get("function") if isinstance(tc.get("function"), dict) else None
        if fn is not None:
            name = str(fn.get("name") or "")
            raw_args = fn.get("arguments")
        else:
            name = str(tc.get("name") or tc.get("tool") or "")
            raw_args = tc.get("arguments", tc.get("input"))
        if isinstance(raw_args, str):
            try:
                args = json.loads(raw_args) if raw_args.strip().startswith("{") else {}
            except ValueError:
                args = {}
        elif isinstance(raw_args, dict):
            args = raw_args
        else:
            args = {}
        if name:
            out.append((cid, name, args if isinstance(args, dict) else {}))
    return out


def _hermes_tool_result(raw_content: Any) -> tuple[str, int | None, bool]:
    """Extract (output_text, exit_code, is_error) from a Hermes role='tool' message."""
    if raw_content is None:
        return "", None, False
    if isinstance(raw_content, list):
        raw_content = "\n".join(
            str(b.get("text") or "") for b in raw_content if isinstance(b, dict) and isinstance(b.get("text"), str)
        )
    text = str(raw_content)
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            code = parsed.get("exit_code", parsed.get("returncode", parsed.get("exitCode")))
            exit_code = code if type(code) is int and -(2**31) <= code < 2**31 else None
            err_flag = bool(
                parsed.get("error")
                or parsed.get("success") is False
                or str(parsed.get("status") or "").lower() in {"error", "failed"}
                or (exit_code is not None and exit_code != 0)
            )
            out_val = parsed.get("output")
            if isinstance(out_val, str):
                return out_val, exit_code, err_flag
            parts = [str(parsed[k]) for k in ("stdout", "stderr", "error", "message") if isinstance(parsed.get(k), str) and parsed.get(k)]
            return ("\n".join(parts) if parts else text), exit_code, err_flag
    return text, None, False


def _hermes_infer_workspace(sess_row: dict[str, Any], model_cfg: dict[str, Any], msgs: list[sqlite3.Row]) -> tuple[str, str]:
    """Attribute a Hermes session ONLY when explicitly inside an opted-in Scope root."""
    scope = _scope()
    for cand in (
        sess_row.get("cwd"),
        sess_row.get("workspace"),
        sess_row.get("working_dir"),
        model_cfg.get("cwd"),
        model_cfg.get("workspace"),
        model_cfg.get("working_dir"),
    ):
        if isinstance(cand, str) and cand.strip():
            if scope.contains(cand.strip()):
                return clean_path(cand.strip()), "workspace"
            return "", "outside"

    matched_roots: set[Path] = set()
    first_path = ""
    for m in msgs:
        raw_tc = m["tool_calls"] if "tool_calls" in m.keys() else None
        for _, name, args in _hermes_parse_calls(raw_tc):
            if _tool_key(name) not in HERMES_EDIT | HERMES_READ | HERMES_SHELL:
                continue
            for key in ("path", "file_path", "target_file", "file", "directory", "cwd", "workdir"):
                val = args.get(key)
                if not isinstance(val, str) or not val.strip():
                    continue
                cleaned = clean_path(val.strip())
                root = scope.root_of(cleaned) if cleaned else None
                if Path(cleaned).is_absolute() and root is None:
                    return "", "outside"
                if root is not None:
                    matched_roots.add(root)
                    if not first_path:
                        first_path = cleaned
    if len(matched_roots) == 1:
        root = next(iter(matched_roots))
        return (first_path if first_path == str(root) else str(root)), "tool_path"
    return "", "unknown"


def hermes_sessions(limit: int = 6) -> list[dict[str, Any]]:
    if _CAPTURE is not None:
        limit = CAPTURE_SESSION_LIMIT
    dbs = _hermes_dbs()
    if not dbs:
        return []
    out: list[dict[str, Any]] = []
    msg_limit = 400 if _CAPTURE is not None else 80
    for db_path, profile_dir_name in dbs:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=1.5)
            conn.row_factory = sqlite3.Row
        except sqlite3.Error:
            continue
        try:
            sess_cols = {r[1] for r in conn.execute("PRAGMA table_info(sessions)")}
            msg_cols = {r[1] for r in conn.execute("PRAGMA table_info(messages)")}
            if "id" not in sess_cols or not {"id", "session_id", "role"} <= msg_cols:
                continue
            wanted_sess = (
                "id", "title", "source", "model", "model_config", "parent_session_id",
                "started_at", "last_activity_at", "ended_at", "cwd", "workspace", "working_dir",
                "input_tokens", "output_tokens", "billing_provider", "profile_name",
            )
            sess_proj = ", ".join(c for c in wanted_sess if c in sess_cols)
            ts_cols = [c for c in ("last_activity_at", "ended_at", "started_at") if c in sess_cols]
            order_expr = f"COALESCE({', '.join(ts_cols)}) DESC" if len(ts_cols) > 1 else ((ts_cols[0] + " DESC") if ts_cols else "rowid DESC")
            sess_rows = conn.execute(f"SELECT {sess_proj} FROM sessions ORDER BY {order_expr} LIMIT ?", (limit * 6,)).fetchall()

            wanted_msg = ("id", "session_id", "role", "content", "tool_calls", "tool_call_id", "tool_name", "timestamp")
            msg_proj = ", ".join(c for c in wanted_msg if c in msg_cols)

            for srow in sess_rows:
                if len(out) >= limit:
                    break
                sdict = dict(srow)
                sid = str(sdict["id"])
                max_row = conn.execute("SELECT MAX(id) AS max_id FROM messages WHERE session_id = ?", (sid,)).fetchone()
                max_msg_id = int(max_row["max_id"]) if max_row and max_row["max_id"] is not None else 0
                src_key = _file_key(f"hermes:{db_path}:{sid}")
                prev_state = _CAPTURE.offsets.get(src_key) if _CAPTURE is not None else None
                if _CAPTURE is not None and prev_state is not None and int(prev_state.get("offset", -1)) == max_msg_id:
                    continue

                msgs = conn.execute(
                    f"SELECT * FROM (SELECT {msg_proj} FROM messages WHERE session_id = ? ORDER BY id DESC LIMIT ?) sub ORDER BY id ASC",
                    (sid, msg_limit),
                ).fetchall()
                raw_cfg = sdict.get("model_config")
                try:
                    model_cfg = json.loads(raw_cfg) if isinstance(raw_cfg, str) and raw_cfg.strip().startswith("{") else {}
                except ValueError:
                    model_cfg = {}
                if not isinstance(model_cfg, dict):
                    model_cfg = {}

                cwd, basis = _hermes_infer_workspace(sdict, model_cfg, msgs)
                if not cwd and basis == "unknown" and sdict.get("parent_session_id"):
                    prow = conn.execute(f"SELECT {sess_proj} FROM sessions WHERE id = ?", (str(sdict["parent_session_id"]),)).fetchone()
                    if prow is not None:
                        pdict = dict(prow)
                        praw_cfg = pdict.get("model_config")
                        try:
                            pcfg = json.loads(praw_cfg) if isinstance(praw_cfg, str) and praw_cfg.strip().startswith("{") else {}
                        except ValueError:
                            pcfg = {}
                        if not isinstance(pcfg, dict):
                            pcfg = {}
                        pcwd, _ = _hermes_infer_workspace(pdict, pcfg, [])
                        if pcwd:
                            cwd, basis = pcwd, "parent_session"
                updated_at = (
                    _epoch_ts(sdict.get("last_activity_at"))
                    or _epoch_ts(sdict.get("ended_at"))
                    or _epoch_ts(sdict.get("started_at"))
                )
                if updated_at is None:
                    try:
                        updated_at = db_path.stat().st_mtime
                    except OSError:
                        updated_at = time.time()
                tokens = int(sdict.get("input_tokens") or 0) + int(sdict.get("output_tokens") or 0)
                profile_name = str(sdict.get("profile_name") or profile_dir_name or "").strip()
                prof_prefix = f"{profile_name}:" if profile_name and profile_name != "default" else ""
                display_name = f"Hermes Agent · {profile_name}" if prof_prefix else "Hermes Agent"
                card = _session(
                    "hermes",
                    display_name,
                    f"{prof_prefix}{sid}",
                    cwd,
                    updated_at,
                    str(sdict.get("model") or "hermes"),
                    tokens,
                    owner_basis=basis,
                )
                if card is None:
                    continue
                if sdict.get("parent_session_id"):
                    card["parent_session"] = f"hermes:{prof_prefix}{sdict['parent_session_id']}"[:96]
                _provider(card, sdict.get("billing_provider"))
                if sdict.get("title"):
                    card["what_done"] = redact(str(sdict["title"]), 240)

                global _POS, _POS_N
                steps: list[dict[str, Any]] = []
                edited: list[str] = []
                read: list[str] = []
                plan: list[dict[str, Any]] = []
                pending_by_id: dict[str, tuple[dict[str, Any], str, str, str | None]] = {}
                pending_by_name: dict[str, list[tuple[dict[str, Any], str, str, str | None]]] = {}

                try:
                    for m in msgs:
                        mdict = dict(m)
                        mid = int(mdict["id"])
                        role = str(mdict.get("role") or "").lower()
                        stamp = _iso_ts(mdict.get("timestamp"))
                        if role == "assistant":
                            txt = str(mdict.get("content") or "").strip()
                            if txt:
                                card["what_done"] = redact(txt, 260)
                                plan = _checklist(txt) or plan
                            calls = _hermes_parse_calls(mdict.get("tool_calls"))
                            for idx, (cid, name, args) in enumerate(calls):
                                _POS, _POS_N = (src_key, mid * 10_000 + idx), 0
                                tkey = _tool_key(name)
                                raw_file = args.get("path") or args.get("file_path") or args.get("target_file") or args.get("file") or args.get("directory")
                                fp = _recorded_file(raw_file, card) if raw_file else ""
                                label = (
                                    (_file_label(name, fp or raw_file) if raw_file else "")
                                    or args.get("query")
                                    or FRIENDLY.get(tkey)
                                    or tkey.replace("_", " ")
                                )
                                step = _step(name, label, stamp)
                                cmd_val: str | None = None
                                kind = "other"
                                if tkey in HERMES_EDIT:
                                    kind = "edit"
                                    step["category"] = "file_edit"
                                    if fp:
                                        step["files"] = [fp]
                                elif tkey in HERMES_READ:
                                    kind = "read"
                                    step["category"] = "file_read"
                                    if fp:
                                        read.append(fp)
                                        step["files"] = [fp]
                                elif tkey in HERMES_SHELL:
                                    kind = "shell"
                                    step["category"] = "shell"
                                    raw_cmd = args.get("command") or args.get("cmd")
                                    if isinstance(raw_cmd, str) and raw_cmd.strip():
                                        cmd_val = raw_cmd
                                        step["label"] = command_kind(cmd_val)
                                        step.update(execution_detail(cmd_val, None, None))
                                elif tkey in HERMES_PLAN:
                                    items = args.get("todos") if isinstance(args.get("todos"), list) else args.get("plan")
                                    if isinstance(items, list):
                                        plan = [_plan_item(it.get("status"), it.get("content") or it.get("step")) for it in items if isinstance(it, dict)] or plan
                                if cid and tkey not in HERMES_PLAN:
                                    step["status"] = "running"
                                steps.append(step)
                                entry = (step, kind, fp, cmd_val)
                                if cid:
                                    pending_by_id[cid] = entry
                                pending_by_name.setdefault(tkey, []).append(entry)
                        elif role == "tool":
                            t_cid = str(mdict.get("tool_call_id") or "")
                            t_name = _tool_key(str(mdict.get("tool_name") or ""))
                            matched = pending_by_id.pop(t_cid, None) if t_cid else None
                            if not t_cid and t_name and len(pending_by_name.get(t_name, [])) == 1:
                                matched = pending_by_name[t_name].pop(0)
                            if matched is None:
                                continue
                            queue = pending_by_name.get(_tool_key(matched[0]["tool"]), [])
                            if matched in queue:
                                queue.remove(matched)
                            step, kind, fp, cmd_val = matched
                            out_text, exit_code, is_err = _hermes_tool_result(mdict.get("content"))
                            step["status"] = "error" if is_err else "completed"
                            if kind == "shell" and cmd_val:
                                step.update(execution_detail(cmd_val, out_text, exit_code))
                                if _CAPTURE is not None and line_survival_enabled():
                                    commit = recorded_commit(cmd_val, out_text, exit_code)
                                    if commit:
                                        step["git_commit"] = commit
                            elif kind == "edit" and fp and not is_err:
                                edited.append(fp)
                            elif kind == "read" and fp and not is_err:
                                snippets = _tool_result_text(out_text, fp)
                                if snippets:
                                    step["text_previews"] = snippets
                finally:
                    _POS = None

                if _CAPTURE is not None:
                    _CAPTURE.note(
                        src_key,
                        {
                            "inode": 0,
                            "offset": max_msg_id,
                            "legacy_until": 0,
                        },
                    )
                card["plan"] = plan[:12]
                out.append(_finish(card, steps, edited, read))
        except sqlite3.Error:
            continue
        finally:
            conn.close()
    return out


def _pi_result(name, argument, message, timestamp, card):
    failed = message["isError"]
    if name == "bash":
        step = _step(name, command_kind(argument), timestamp)
        output = None
        blocks = message.get("content")
        if os.environ.get("SWARMCONTROL_SHARE_COMMAND_OUTPUT") == "1" and isinstance(blocks, list):
            # Bound the copy before joining. execution_detail redacts and caps the displayed excerpt.
            parts = []
            remaining = 10_300
            for block in blocks:
                if not isinstance(block, dict) or block.get("type") != "text" or not isinstance(block.get("text"), str):
                    continue
                part = block["text"][:remaining]
                parts.append(part)
                remaining -= len(part) + 1
                if remaining <= 0:
                    break
            if parts:
                output = "\n".join(parts)
        details = message.get("details")
        code = details.get("exitCode") if isinstance(details, dict) else None
        step.update(execution_detail(argument, output, code))
    else:
        # Pi expands @file and Unicode spaces before resolving a tool path against its working folder.
        target = re.sub(r"[\u00a0\u2000-\u200a\u202f\u205f\u3000]", " ", argument).removeprefix("@")
        # Only attribute literal paths we can faithfully represent. Never reinterpret user URI/quoting as a file.
        path = ""
        if (target and target == target.strip() and target[0] not in "~\"'" and target[-1] not in "\"'"
                and not re.match(r"^[a-zA-Z]+://", target) and not any(ord(c) < 32 for c in target)):
            path = _recorded_file(target, card)
        step = _step(name, _file_label(name, path) if path else "File path unavailable", timestamp)
        if path:
            step["files"] = [path]
            if name == "read" and not failed:
                image = _tool_result_image({"result": message.get("content")}, path)
                if image:
                    step["image_previews"] = image
                else:
                    excerpts = _tool_result_text(message.get("content"), path)
                    if excerpts:
                        step["text_previews"] = excerpts
    step["status"] = "error" if failed else "completed"
    return step


def _pi_session(path: Path, updated: float) -> dict[str, Any] | None:
    try:
        with path.open("rb") as stream:
            initial = os.fstat(stream.fileno())
            header = json.loads(stream.readline(16_384))
    except (OSError, ValueError, RecursionError):
        return None
    if not isinstance(header, dict) or header.get("type") != "session" or header.get("version") != 3:
        return None
    cwd, sid = header.get("cwd"), header.get("id")
    if (not isinstance(cwd, str) or not Path(cwd).is_absolute() or "\x00" in cwd
            or not isinstance(sid, str) or not sid):
        return None
    # Pi allows arbitrary custom session IDs. Keep standard UUIDs and avoid sending user text.
    if not re.fullmatch(r"[a-fA-F0-9]{8}(?:-[a-fA-F0-9]{4}){3}-[a-fA-F0-9]{12}", sid):
        sid = hashlib.sha256(sid.encode("utf-8", errors="replace")).hexdigest()
    card = _session("pi", "Pi Coding Agent", sid, cwd, updated)
    if card is None:
        return None
    # Each entry inherits unresolved calls from its own parent. A result in one fork never
    # consumes its sibling's calls, even when both forks have the same tool-call id.
    branches = {}
    steps, edited, read = [], [], []
    for line in _lines(path):
        try:
            entry = json.loads(line)
        except (ValueError, RecursionError):
            continue
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            continue
        if entry.get("type") == "session":
            if entry != header:
                return None
            continue
        parent = entry.get("parentId")
        calls = branches.get(parent, {}) if isinstance(parent, str) else {}
        message = entry.get("message") if entry.get("type") == "message" else None
        if isinstance(message, dict):
            role = message.get("role")
            if role == "assistant":
                calls = {}
                if isinstance(message.get("model"), str):
                    card["model"] = _model(message["model"])
                    _provider(card, message.get("provider"))
                blocks = message.get("content")
                for block in blocks if isinstance(blocks, list) else ():
                    if not isinstance(block, dict) or block.get("type") != "toolCall" or block.get("namespace"):
                        continue
                    name, key, args = block.get("name"), block.get("id"), block.get("arguments")
                    if (name not in ("read", "write", "edit", "bash") or not isinstance(key, str)
                            or not key or not isinstance(args, dict)):
                        continue
                    argument = args.get("command" if name == "bash" else "path")
                    if isinstance(argument, str) and 0 < len(argument) <= 8192:
                        calls[key] = None if key in calls else (name, argument)
            elif role == "toolResult":
                key = message.get("toolCallId")
                pair = calls.get(key) if isinstance(key, str) else None
                if pair and pair[0] == message.get("toolName") and isinstance(message.get("isError"), bool):
                    calls = calls.copy()
                    del calls[key]
                    name, argument = pair
                    step = _pi_result(name, argument, message, entry.get("timestamp"), card)
                    steps.append(step)
                    if step["status"] == "completed" and step.get("files"):
                        (read if name == "read" else edited).extend(step["files"])
            else:
                calls = {}
        if calls:
            branches[entry["id"]] = calls
    # Header and tail are separate reads. A replacement log can belong to another project.
    # Drop its cursor along with the snapshot so the next scan checks its own header.
    try:
        current = path.lstat()
        same_log = os.path.samestat(initial, current) and current.st_size >= initial.st_size
        if same_log and initial.st_ctime_ns != current.st_ctime_ns:
            with path.open("rb") as stream:
                same_log = os.path.samestat(initial, os.fstat(stream.fileno())) and json.loads(stream.readline(16_384)) == header
    except (OSError, ValueError, RecursionError):
        same_log = False
    if not same_log:
        if _CAPTURE is not None:
            _CAPTURE.read.pop(_file_key(path), None)
        return None
    if steps:
        card["what_done"] = steps[-1]["label"]
    return _finish(card, steps, edited, read)


def pi_sessions(limit: int = 6) -> list[dict[str, Any]]:
    profile = Path(os.environ.get("PI_CODING_AGENT_DIR") or HOME / ".pi/agent").expanduser()
    directory = Path(os.environ.get("PI_CODING_AGENT_SESSION_DIR") or profile / "sessions").expanduser()
    # Default layout has one directory per project; a custom session directory may be flat.
    files = []
    for pattern in ("*.jsonl", "*/*.jsonl"):
        for path in directory.glob(pattern):
            try:
                meta = path.lstat()
                if stat.S_ISREG(meta.st_mode) and not path.parent.is_symlink():
                    files.append((meta.st_mtime, path))
            except OSError:
                continue
    out = []
    for updated, path in sorted(files, reverse=True):
        if _CAPTURE is not None and _CAPTURE.unchanged(path):
            continue
        session = _pi_session(path, updated)
        if session is not None:
            out.append(session)
            if len(out) >= (CAPTURE_SESSION_LIMIT if _CAPTURE is not None else limit):
                break
    return out


# --- Gemini / Antigravity -------------------------------------------------------------
AG_EDIT = {"write_file", "edit_file", "write_to_file", "replace_file_content", "multi_replace_file_content"}
AG_READ = {"read_file", "view_file", "view_image", "read_image", "list_dir"}


def _antigravity_workspace(conv_id: str, base: Path | None = None) -> tuple[str, str]:
    """Working folder = first workspace URI, in the conversation's own metadata, that lies in a root.

    Paths mentioned in transcript text never decide ownership (they may name someone else's folder)."""
    scope = _scope()
    base = base or HOME / ".gemini/antigravity-acp"
    db = base / "conversations" / f"{conv_id}.db"
    if db.is_file():
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
            try:
                row = conn.execute("SELECT data FROM trajectory_metadata_blob LIMIT 1").fetchone()
            finally:
                conn.close()
            for raw in re.findall(rb"file://(/[\x21-\x7e]{1,300})", bytes(row[0] or b"") if row else b""):
                for cut in range(len(raw), 0, -1):  # protobuf fields may be glued to the URI; try prefixes
                    cand = raw[:cut].decode("utf-8", "ignore")
                    if scope.contains(cand) and Path(cand).is_dir():
                        return cand, "conversation metadata"
        except sqlite3.Error:
            pass
    for sub in base.glob(f"brain/*/.system_generated/subagents/{conv_id}.json"):
        try:
            uris = json.loads(sub.read_text(encoding="utf-8", errors="ignore")[:20000]).get("workspaceUris") or []
        except (OSError, ValueError, AttributeError):
            continue
        for uri in uris:
            cand = clean_path(uri)
            if cand and scope.contains(cand) and cand != "/":
                return cand, "subagent metadata"
    return "", "unknown"


def antigravity_sessions(limit: int = 8) -> list[dict[str, Any]]:
    if _CAPTURE is not None:
        limit = CAPTURE_SESSION_LIMIT
    dirs = []
    for base in antigravity_bases():  # every installed variant (ACP, IDE, CLI) keeps the same brain layout
        try:
            dirs += [(t.stat().st_mtime, d, base) for d in (base / "brain").iterdir() if d.is_dir()
                     and (t := d / ".system_generated/logs/transcript.jsonl").is_file()]
        except OSError:
            continue
    dirs = sorted(dirs, key=lambda x: x[0], reverse=True)[:limit * 4]
    out = []
    for mtime, d, base in dirs:
        if _CAPTURE is not None and _CAPTURE.unchanged(d / ".system_generated/logs/transcript.jsonl"):
            continue
        workspace, basis = _antigravity_workspace(d.name, base)
        card = _session("antigravity", "Gemini / Antigravity", d.name, workspace, mtime, "gemini", owner_basis=basis)
        if card is None:
            continue  # no workspace inside the operator's folders
        steps: list[dict[str, Any]] = []
        edited: list[str] = []
        read: list[str] = []
        plan: list[dict[str, Any]] = []
        delivered: list[str] = []
        for md in sorted(d.glob("*.md"))[:4]:
            if not is_sensitive_path(str(md)):
                try:
                    plan = plan or _checklist(md.read_text(encoding="utf-8", errors="ignore")[:12000])
                except OSError:
                    pass
        for ln in _lines(d / ".system_generated/logs/transcript.jsonl"):
            try:
                o = json.loads(ln)
            except ValueError:
                continue
            if not isinstance(o, dict):
                continue
            calls = o.get("tool_calls") or []
            if isinstance(calls, str):
                continue
            if o.get("type") == "PLANNER_RESPONSE" and str(o.get("content") or "").strip():
                card["what_done"] = redact(o["content"], 260)
                plan = _checklist(o["content"]) or plan
                card["model"] = _model(o.get("model") or card["model"])
            for c in calls:
                if not isinstance(c, dict):
                    continue
                name, args = str(c.get("name") or "tool"), c.get("args") or {}
                if not isinstance(args, dict):
                    args = {}
                raw_file = args.get("Path") or args.get("TargetFile") or args.get("AbsolutePath")
                fp = _recorded_file(raw_file, card)
                if name in AG_EDIT and fp:
                    edited.append(fp)
                elif name in AG_READ and fp:
                    read.append(fp)
                if name.endswith("attach_files_to_response") and isinstance(args.get("paths"), list):
                    delivered += [str(x) for x in args["paths"]]
                if _tool_key(name) == "tool_call" and isinstance(args.get("arguments"), dict):
                    inner = args["arguments"]
                    if _tool_key(str(args.get("name"))) == "channel_result" and inner.get("text"):
                        card["what_done"] = redact(inner["text"], 260)
                label = args.get("toolSummary") or (_file_label(name, fp or raw_file) if raw_file else "") or \
                    args.get("query") or _tool_key(name).replace("_", " ")
                steps.append(_step(name, str(label).strip('"'), o.get("created_at")))
                if _tool_key(name) in ("run_command", "run_terminal_command", "execute_command") and args.get("CommandLine"):
                    raw_cmd = str(args["CommandLine"]).strip()
                    try:
                        raw_cmd = json.loads(raw_cmd) if raw_cmd.startswith('"') else raw_cmd
                    except ValueError:
                        raw_cmd = raw_cmd.strip('"')
                    steps[-1].update(execution_detail(raw_cmd, c.get("output"), c.get("exit_code")))
                if (name in AG_EDIT or name in AG_READ) and clean_path(fp):
                    steps[-1]["files"] = [clean_path(fp)]
        card["plan"] = plan[:12]
        _provider(card)
        out.append(_finish(card, steps, edited, read, delivered))
        if len(out) >= limit:
            break
    return out


# --- OpenCode --------------------------------------------------------------------------
def _opencode_tools(conn: sqlite3.Connection, sid: str) -> list[sqlite3.Row]:
    # Select typed tool records. Read a tool's output only during an opted-in journal scan.
    messages, parts = (400, CAPTURE_OPENCODE_PARTS) if _CAPTURE is not None else (24, 40)
    max_message = CAPTURE_MAX_RECORD if _CAPTURE is not None else 196_608  # whole messages for the journal
    try:
        return conn.execute("""
            WITH recent AS (
                SELECT seq, time_created, data FROM session_message
                WHERE session_id = ? AND type = 'assistant' ORDER BY seq DESC LIMIT ?
            )
            SELECT m.seq AS seq, CAST(p.key AS INTEGER) AS part, json_extract(p.value, '$.name') AS name,
                   json_extract(p.value, '$.state.status') AS status,
                   coalesce(json_extract(p.value, '$.time.completed'), json_extract(p.value, '$.time.created'),
                            m.time_created) AS stamp,
                   CASE WHEN json_extract(p.value, '$.name') IN ('read', 'edit', 'write')
                        THEN coalesce(json_extract(p.value, '$.state.input.path'),
                                      json_extract(p.value, '$.state.input.filePath')) END AS path,
                   CASE WHEN json_extract(p.value, '$.name') = 'todowrite'
                        THEN json_extract(p.value, '$.state.input.todos') END AS todos,
                   CASE WHEN json_extract(p.value, '$.name') IN ('bash', 'shell')
                        THEN json_extract(p.value, '$.state.input.command') END AS command,
                   CASE WHEN ? AND json_type(p.value, '$.state.output') = 'text'
                        THEN json_extract(p.value, '$.state.output') END AS output,
                   coalesce(json_extract(p.value, '$.state.metadata.exit'),
                            json_extract(p.value, '$.state.metadata.exitCode')) AS exit_code
              FROM recent m, json_each(
                     CASE WHEN length(m.data) <= ? AND json_valid(m.data) THEN m.data ELSE '{}' END,
                     '$.content') p
             WHERE p.type = 'object' AND json_extract(p.value, '$.type') = 'tool'
             ORDER BY m.seq DESC, CAST(p.key AS INTEGER) DESC LIMIT ?
        """, (sid, messages, _CAPTURE is not None and os.environ.get("SWARMCONTROL_SHARE_COMMAND_OUTPUT") == "1",
              max_message, parts)).fetchall()[::-1]
    except sqlite3.Error:
        # Older OpenCode versions store session headers without message parts.
        return []


def _opencode_activity(card: dict[str, Any], rows: list[sqlite3.Row], source: str = "") -> dict[str, Any]:
    global _POS, _POS_N
    steps, edited, read = [], [], []
    for row in rows:
        if source and "seq" in row.keys() and isinstance(row["seq"], int):
            _POS, _POS_N = (source, row["seq"] * 10_000 + int(row["part"] or 0)), 0  # message + part = exact origin
        name, status = row["name"], row["status"]
        if not isinstance(name, str) or status not in {"completed", "error", "running", "pending"}:
            continue
        label = {"read": "Read a file", "edit": "Edit a file", "write": "Write a file", "shell": "Run a command", "bash": "Run a command",
                 "execute": "Run a tool", "webfetch": "Read a web page", "websearch": "Search the web",
                 "grep": "Search files", "todowrite": "Update the plan", "subagent": "Delegate a task"}.get(name, "Use a tool")
        stamp = row["stamp"]
        stamp = stamp / 1000 if isinstance(stamp, (int, float)) and stamp > 1e12 else stamp
        when = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(stamp)) if isinstance(stamp, (int, float)) and 0 < stamp < 1e10 else ""
        step = _step(name, label, when)
        step["status"] = status
        raw_path = row["path"]
        safe = _recorded_file(raw_path, card) if status == "completed" else ""
        if safe:
            (read if name == "read" else edited).append(safe)
            step["files"] = [safe]
            step["label"] = readable(f"{name.capitalize()} {Path(safe).name}", 110)
        if "command" in row.keys() and isinstance(row["command"], str):
            step.update(execution_detail(row["command"], row["output"], row["exit_code"]))
        if status == "completed" and name == "todowrite" and isinstance(row["todos"], str):
            try:
                items = json.loads(row["todos"])
            except ValueError:
                items = []
            if isinstance(items, list):
                card["plan"] = [_plan_item(i.get("status"), i["content"]) for i in items[:12]
                                if isinstance(i, dict) and isinstance(i.get("content"), str)]
        steps.append(step)
    _POS = None
    return _finish(card, steps, edited, read)


def opencode_sessions(limit: int = 6) -> list[dict[str, Any]]:
    if _CAPTURE is not None:
        limit = CAPTURE_SESSION_LIMIT
    db = opencode_db()
    if not db.is_file():
        return []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.5)
        conn.row_factory = sqlite3.Row
        try:
            columns = {r[1] for r in conn.execute("PRAGMA table_info(session_v2)")}
            fields = ("id", "directory", "time_updated", "model", "title", "slug", "tokens_input", "tokens_output",
                      "summary_files", "summary_additions", "summary_deletions")
            projection = ", ".join(field for field in fields if field in columns)
            if not {"id", "time_updated"} <= columns:
                return []
            rows = conn.execute(f"SELECT {projection} FROM session_v2 ORDER BY time_updated DESC LIMIT ?",
                                (limit * 6,)).fetchall()
            scope = _scope()
            rows = [row for row in rows if "directory" in row.keys() and scope.contains(str(row["directory"]))][:limit]
            if _CAPTURE is not None:  # only sessions updated since the last scan
                rows = [row for row in rows if (_CAPTURE.offsets.get(_file_key("opencode:" + str(row["id"]))) or {})
                        .get("offset") != int(float(row["time_updated"] or 0))]
            by_session = {row["id"]: _opencode_tools(conn, row["id"]) for row in rows}
        finally:
            conn.close()
    except sqlite3.Error:
        return []
    out = []
    for r in rows:
        keys = r.keys()
        get = lambda k: r[k] if k in keys else None  # noqa: E731
        ts = float(get("time_updated") or 0)
        ts = ts / 1000.0 if ts > 1e12 else ts
        directory = str(get("directory") or "")
        tokens = int(get("tokens_input") or 0) + int(get("tokens_output") or 0)
        card = _session("opencode", "OpenCode", str(get("id")), directory, ts, str(get("model") or "opencode"), tokens)
        if card is None:
            continue
        try:
            spec = json.loads(get("model") or "{}")
        except (TypeError, ValueError):
            spec = {}
        _provider(card, spec.get("providerID") if isinstance(spec, dict) else None)
        files, adds, dels = (int(get(k) or 0) for k in ("summary_files", "summary_additions", "summary_deletions"))
        title = redact(get("title") or get("slug") or "OpenCode session", 160)
        card["what_done"] = f"{title} · {files} file(s) changed, +{adds}/−{dels} lines" if files else title
        tools = by_session.get(r["id"], [])
        source = _file_key("opencode:" + str(get("id")))
        if _CAPTURE is not None:
            prev = _CAPTURE.offsets.get(source)
            top = max((t["seq"] * 10_000 + int(t["part"] or 0) for t in tools if isinstance(t["seq"], int)), default=0)
            _CAPTURE.note(source, {"inode": 0, "offset": int(float(get("time_updated") or 0)),
                                   "legacy_until": prev["legacy_until"] if prev else (top + 1 if _CAPTURE.first_run else 0)})
        out.append(_opencode_activity(card, tools, source))
    return out


# --- harnesses & workspaces -----------------------------------------------------------
HARNESSES = [
    ("claude-code", "Claude Code", ["claude"], "claude"),
    ("codex", "Codex CLI", ["codex", "codex-code-mode"], "codex"),
    ("antigravity", "Gemini / Antigravity", ["gemini", "antigravity", "agy"], "antigravity"),
    ("opencode", "OpenCode", ["opencode"], "opencode"),
    ("openclaw", "OpenClaw", ["openclaw"], "openclaw"),
    ("paperclip", "Paperclip", ["paperclip"], "paperclip"),
    ("ollama", "Ollama", ["ollama"], None),
]


def harnesses() -> list[dict[str, Any]]:
    try:
        ps = subprocess.run(["ps", "-eo", "comm=,pcpu=,rss="], capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        ps = ""
    procs = []
    for line in ps.splitlines():
        parts = line.rsplit(None, 2)
        if len(parts) == 3:
            try:
                procs.append((parts[0].strip().lower(), float(parts[1]), int(parts[2])))
            except ValueError:
                continue
    known: dict[str, list[str]] = {}
    for adapter in _scope().adapters:  # e.g. versions from a host app's managed runtimes
        try:
            for key, vers in (adapter.runtime_versions(HOME) or {}).items():
                known[key] = sorted({v for v in vers if re.fullmatch(r"[0-9][0-9A-Za-z.+-]{0,39}", str(v))})
        except Exception:
            continue
    out = []
    specs = list(HARNESSES)
    for adapter in _scope().adapters:
        specs = list(getattr(adapter, "HARNESSES", [])) + specs
    for hid, name, names, rt in specs:
        versions = known.get(rt or "", [])
        mine = [p for p in procs if p[0] in names]
        binary = next((shutil.which(n) for n in names if shutil.which(n)), None)
        if not (versions or mine or binary):
            continue
        out.append({"id": hid, "name": name, "version": versions[-1] if versions else "",
                    "status": "running" if mine else "installed", "process_count": len(mine),
                    "cpu_pct": round(sum(p[1] for p in mine), 1), "rss_mb": round(sum(p[2] for p in mine) / 1024, 1),
                    "evidence": ([f"runtime {rt}@{versions[-1]}"] if versions else []) +
                                ([f"binary {binary}"] if binary else []) + ([f"{len(mine)} process(es)"] if mine else [])})
    return out


def _category(path: Path) -> str:
    ext = path.suffix.lower()
    for cat, exts in (("code", {".py", ".js", ".ts", ".tsx", ".go", ".rs", ".sh", ".sql"}),
                      ("ui", {".html", ".css", ".svg"}), ("doc", {".md", ".txt", ".pdf", ".docx"}),
                      ("data", {".json", ".jsonl", ".csv", ".db", ".sqlite", ".yaml", ".yml", ".toml"}),
                      ("asset", {".png", ".jpg", ".jpeg", ".webp", ".gif", ".zip"})):
        if ext in exts:
            return cat
    return "other"


def workspaces(max_files: int = 600) -> list[dict[str, Any]]:
    """One entry per opted-in root. Nothing outside the roots is listed."""
    scope = _scope()
    roots = []
    for root in scope.roots:
        agent_id, label, _ = scope.identity(root)
        roots.append((f"workspace:{agent_id}", label, root, "workspace", agent_id))
    out = []
    for wid, label, path, kind, agent_id in roots:
        files: list[dict[str, Any]] = []
        folders: Counter[str] = Counter()
        total, latest = 0, 0.0
        base_depth = len(path.parts)
        for cur, dirs, names in os.walk(path):
            cur_p = Path(cur)
            depth = len(cur_p.parts) - base_depth
            dirs[:] = sorted(d for d in dirs if depth < 5 and d not in SKIP_WALK_DIRS and not d.startswith(".")
                             and not is_sensitive_path(str(cur_p / d)))
            for n in names:
                fp = cur_p / n
                if n.startswith(".") or is_sensitive_path(str(fp)):
                    continue
                try:
                    st = fp.lstat()
                except OSError:
                    continue
                if not os.path.isfile(fp) or fp.is_symlink():
                    continue
                total += 1
                rel = str(fp.relative_to(path))
                folders[rel.split("/", 1)[0] if "/" in rel else "."] += 1
                latest = max(latest, st.st_mtime)
                files.append({"path": str(fp), "rel_path": rel, "size_kb": round(st.st_size / 1024, 1),
                              "mtime": st.st_mtime, "category": _category(fp)})
                if total >= max_files:
                    break
            if total >= max_files:
                break
        files.sort(key=lambda f: f["mtime"], reverse=True)
        out.append({"id": wid, "host_id": scope.host_id, "label": label, "kind": kind, "agent_id": agent_id,
                    "path": str(path),
                    "file_count": total, "truncated": total >= max_files, "last_modified": latest,
                    "folders": [{"name": k, "files": v} for k, v in folders.most_common(8)],
                    "recent_files": files[:8]})
    out.sort(key=lambda w: w["last_modified"], reverse=True)
    return out


# --- line survival (opt-in): explicit Git evidence for lines a session's commit added ----------------------
# Only commit IDs, file paths inside shared folders and line counts leave the machine; never file contents.
COMMIT_LINE = re.compile(r"^\[[^\]\n]* ([0-9a-f]{7,40})\] ", re.M)       # "[main abc1234] message" printed by git commit
COMMIT_COMMAND = re.compile(r"(?:^|[\s;&|(])git(?:\s+-[cC]\s+\S+)*\s+commit(?:\s|$)")
SURVIVAL_EVERY_SEC = 60.0
SURVIVAL_DAYS = 7
SURVIVAL_MAX_COMMITS = 50
SURVIVAL_MAX_FILES = 150
SURVIVAL_MAX_ITEMS = 300
SURVIVAL_MAX_BYTES = 2_000_000
SURVIVAL_BUDGET_SEC = 20.0
SURVIVAL_MAX_RANGES = 100        # per commit and file; more are reported as truncated, never guessed
_SURVIVAL_LAST: dict[tuple[str, ...], float] = {}
# Repository settings must not run programs or write files while we only read history.
_GIT_SAFE = ("-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
             "-c", "core.untrackedCache=false", "-c", "gc.auto=0", "-c", "maintenance.auto=false")


def line_survival_enabled() -> bool:
    return os.environ.get("SWARMCONTROL_SHARE_LINE_SURVIVAL") == "1"


def recorded_commit(command: Any, output: Any, code: Any) -> str | None:
    """The commit ID a session's own successful `git commit` printed. Anything else is not evidence."""
    if isinstance(command, list):
        command = " ".join(str(c) for c in command)
    if code not in (None, 0) or not isinstance(command, str) or not isinstance(output, str):
        return None
    if not COMMIT_COMMAND.search(command):
        return None
    found = set(COMMIT_LINE.findall(output[:20_000]))
    return found.pop() if len(found) == 1 else None


def _git(repo: Path, *args: str, timeout: float = 10.0) -> str | None:
    git = shutil.which("git")
    if not git:
        return None
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(HOME), "LC_ALL": "C",
           "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1"}
    try:
        done = subprocess.run([git, *_GIT_SAFE, "-C", str(repo), *args], capture_output=True, timeout=timeout,
                              env=env, stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout.decode("utf-8", "replace") if done.returncode == 0 else None


def _survival_root(root: Path, deadline: float, now: float) -> list[dict[str, Any]]:
    top_raw = _git(root, "rev-parse", "--show-toplevel")
    head = _git(root, "rev-parse", "--verify", "-q", "HEAD^{commit}")
    if not top_raw or not head:
        return []
    top, head = Path(top_raw.strip()), head.strip()
    try:
        scope_rel = root.resolve().relative_to(top.resolve()).as_posix() or "."
    except ValueError:
        return []
    log = _git(top, "log", "HEAD", f"--since={SURVIVAL_DAYS}.days", f"-n{SURVIVAL_MAX_COMMITS}", "--no-renames",
               "--no-ext-diff", "--no-textconv", "--numstat", "--format=%x1e%H %ct", "--", f":(literal){scope_rel}")
    if log is None:
        return []
    touches: dict[str, list[tuple[float, str, int]]] = {}       # path -> [(commit time, sha, lines added)]
    for block in log.split("\x1e")[1:]:
        lines = block.strip().splitlines()
        if not lines:
            continue
        sha, _, ct = lines[0].partition(" ")
        for row in lines[1:]:
            added, _, rest = row.partition("\t")
            _, _, path = rest.partition("\t")
            if added.isdigit() and int(added) > 0 and path:
                touches.setdefault(path, []).append((float(ct), sha, int(added)))
    out: list[dict[str, Any]] = []
    for path, hits in sorted(touches.items(), key=lambda kv: -max(t for t, _, _ in kv[1]))[:SURVIVAL_MAX_FILES]:
        if time.monotonic() > deadline or len(out) >= SURVIVAL_MAX_ITEMS:
            break
        absolute = top / path
        rel_parts = Path(path).parts
        if any(p.startswith(".") for p in rel_parts) or is_sensitive_path(path) or not _scope().contains(absolute):
            continue
        size = _git(top, "cat-file", "-s", f"HEAD:{path}")
        exists = size is not None
        counts: Counter = Counter()
        final_lines: dict[str, list[int]] = {}                   # commit -> line numbers at HEAD that blame assigns to it
        if exists and int(size.strip() or 0) <= SURVIVAL_MAX_BYTES:
            blame = _git(top, "blame", "--line-porcelain", "-M", "HEAD", "--", path, timeout=15.0)
            if blame is None:
                continue                                         # binary or unreadable: no measurement, no claim
            for m in re.finditer(r"^([0-9a-f]{40}) \d+ (\d+)", blame, re.M):
                counts[m[1]] += 1
                final_lines.setdefault(m[1], []).append(int(m[2]))
        too_large = exists and int(size.strip() or 0) > SURVIVAL_MAX_BYTES   # reported as such, never guessed
        hits.sort(reverse=True)
        for i, (ct, sha, added) in enumerate(hits):
            if i + 1 < len(hits):
                prev = hits[i + 1][0]
            else:
                prev_raw = _git(top, "log", "-1", "--format=%ct", f"{sha}^", "--", path)
                prev = float(prev_raw.strip()) if prev_raw and prev_raw.strip().isdigit() else 0.0
            item = {"sha": sha, "path": str(absolute), "added": added, "surviving": min(counts.get(sha, 0), added),
                    "exists": exists, "commit_time": ct, "prev_time": prev, "head": head, "measured_at": now,
                    "repo_path": path, **({"too_large": True, "surviving": 0} if too_large else {})}
            # Which lines: HEAD line numbers whose blame origin is this commit. Only when the count agrees with the
            # lines the commit added (otherwise blame and numstat disagree and no line is named).
            lines = sorted(set(final_lines.get(sha, [])))
            if not too_large and lines and len(lines) == counts.get(sha, 0) <= added:
                item["ranges"], item["ranges_truncated"] = line_ranges(lines, SURVIVAL_MAX_RANGES)
            out.append(item)
    return out


def line_ranges(lines: list[int], limit: int) -> tuple[list[list[int]], bool]:
    """[3, 4, 5, 9] -> [[3, 5], [9, 9]]; at most `limit` ranges, with a flag when more exist."""
    out: list[list[int]] = []
    for n in lines:
        if out and n == out[-1][1] + 1:
            out[-1][1] = n
        else:
            out.append([n, n])
    return out[:limit], len(out) > limit


def measure_line_survival(scope: "Scope", force: bool = False) -> list[dict[str, Any]] | None:
    """Recent commits' added lines and how many `git blame` still assigns to them, per file in shared folders.
    At most once a minute per set of folders; None when it is not time yet or sharing is off."""
    if not line_survival_enabled() or not scope.enabled:
        return None
    key = tuple(str(r) for r in scope.roots)
    clock = time.monotonic()
    if not force and clock - _SURVIVAL_LAST.get(key, -SURVIVAL_EVERY_SEC) < SURVIVAL_EVERY_SEC:
        return None
    _SURVIVAL_LAST[key] = clock
    deadline, now, items, seen = clock + SURVIVAL_BUDGET_SEC, time.time(), [], set()
    for root in scope.roots:
        for item in _survival_root(Path(root), deadline, now):
            if (item["sha"], item["path"]) not in seen:
                seen.add((item["sha"], item["path"]))
                items.append(item)
    return items[:SURVIVAL_MAX_ITEMS]


# --- snapshot -----------------------------------------------------------------------------
def collect_activity(scope: Scope | None = None, capture: "Capture | None" = None) -> dict[str, Any]:
    """Map snapshot. With `capture` (the work journal), every session's `capture_steps` holds all steps appended
    since the offsets in `capture`, each with its source position; `capture.read` holds the offsets to persist."""
    global _CURRENT, _CAPTURE, _POS
    t0 = time.perf_counter()
    _CURRENT = scope or load_scope()
    _CAPTURE, _POS = capture, None
    try:
        return _collect(t0)
    finally:
        _CURRENT, _CAPTURE, _POS = None, None, None


def _collect(t0: float) -> dict[str, Any]:
    scope = _scope()
    sessions: list[dict[str, Any]] = []
    for reader in ((codex_sessions, claude_sessions, antigravity_sessions, opencode_sessions, hermes_sessions, pi_sessions) if scope.enabled else ()):
        if _CAPTURE is not None:
            _CAPTURE.reader = reader.__name__
        try:
            sessions += reader()
        except Exception:  # one broken source must not hide the others
            if _CAPTURE is not None:
                _CAPTURE.fail_reader(reader.__name__)  # keep its offsets: the next scan re-reads the same bytes
            continue
    for s in sessions:
        for step in (s.get("steps") or []) + (s.get("capture_steps") or []):
            step.pop("_shell", None)
            step.pop("_cwd", None)
    sessions.sort(key=lambda s: s["updated_at"], reverse=True)
    if _CAPTURE is None:
        sessions = sessions[:20]  # the map shows the most recent; the journal needs every changed session
    ws = workspaces()

    # Which sessions said they edited each file: stronger than a timestamp alone.
    editors: dict[str, list[str]] = {}
    for s in sessions:
        for p in s["files_edited"]:
            editors.setdefault(p, [])
            tag = f"{s['agent_name']} · {s['harness_name']}"
            if tag not in editors[p]:
                editors[p].append(tag)
    for w in ws:
        for f in w["recent_files"]:
            f["edited_by"] = editors.get(f["path"], [])

    agents: dict[str, dict[str, Any]] = {}
    for s in sessions:
        key = s["agent_id"] or f"unattributed:{s['harness']}"
        a = agents.setdefault(key, {"agent_id": s["agent_id"], "host_id": s["host_id"], "name": s["agent_name"], "harnesses": [],
                                    "workspace": s["workspace"], "status": "idle", "last_active": 0.0,
                                    "sessions": 0, "files_edited": 0})
        if s["harness_name"] not in a["harnesses"]:
            a["harnesses"].append(s["harness_name"])
        a["sessions"] += 1
        a["files_edited"] += len(s["files_edited"])
        a["last_active"] = max(a["last_active"], s["updated_at"])
        if s["status"] == "active":
            a["status"] = "active"
    how = Counter()
    for s in sessions:
        how.update(s["how"])
    hs = harnesses()
    now = time.time()
    sources = log_sources() if scope.enabled else []
    return {
        "schema_version": SCHEMA_VERSION, "host": scope.host_id, "host_id": scope.host_id,
        "hostname": socket.gethostname(), "collected_at": now,
        "scan_ms": round((time.perf_counter() - t0) * 1000, 1),
        "activity_enabled": scope.enabled, "activity_roots": [str(r) for r in scope.roots], "sources": sources,
        "hosts": [{"host_id": scope.host_id, "hostname": socket.gethostname(), "updated_at": now,
                   "activity_roots": [str(r) for r in scope.roots], "activity_enabled": scope.enabled, "sources": sources}],
        "summary": {"harnesses_installed": len(hs), "harnesses_running": sum(h["status"] == "running" for h in hs),
                    "agents": len(agents), "agents_active": sum(a["status"] == "active" for a in agents.values()),
                    "sessions": len(sessions), "files_edited": len(editors), "workspaces": len(ws),
                    "how": {CATEGORY_LABEL.get(k, k): v for k, v in how.most_common()}},
        "harnesses": hs,
        "agents": sorted(agents.values(), key=lambda a: a["last_active"], reverse=True),
        "sessions": sessions,
        "workspaces": ws,
        "category_labels": CATEGORY_LABEL,
        **({"line_survival": survival} if (survival := (measure_line_survival(scope) if _CAPTURE is not None else None))
           is not None else {}),
    }


class CachedActivity:
    """Serve one scan to concurrent dashboard polls; rescan after `ttl` seconds."""

    def __init__(self, ttl: float = 15.0, collector=collect_activity):
        self.ttl, self.collector = ttl, collector
        self._lock = threading.Lock()
        self._at, self._snap = 0.0, None

    def get(self) -> dict[str, Any]:
        with self._lock:
            if self._snap is None or time.monotonic() - self._at >= self.ttl:
                self._snap = self.collector()
                self._at = time.monotonic()
            return self._snap


ACTIVITY = CachedActivity()

if __name__ == "__main__":
    print(json.dumps(collect_activity(), indent=2, ensure_ascii=False))
