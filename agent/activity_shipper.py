#!/usr/bin/env python3
"""Opt-In, Folder-Scoped & Locally-Redacted Activity Shipper for NeuroSwarm Agent.

See REMOTE-CONTRACT.md for the observer protocol.
Runs on any remote host (Linux, macOS, Windows, WSL) using Python 3.10+ stdlib only.

Key privacy & portability guarantees:
1. OFF by default: collects nothing unless `activity_roots` are explicitly configured
   by the operator (`SWARMCONTROL_ACTIVITY_ROOTS` or `--activity-roots`).
2. Strict folder boundary: only reports workspaces, files, and sessions whose working
   directory or touched files belong to one of the operator-approved `activity_roots`.
3. Zero hardcoded team UUIDs or installation-specific paths: derives agent/owner labels
   cleanly from workspace folder names or optional user-supplied `SWARMCONTROL_AGENT_LABELS`
   (`id=Name,id2=Name2`).
4. Local 14-pattern secret redaction & credential-path denylist before any data leaves the host.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import socket
import sqlite3
import stat
import sys
import time
from collections import Counter
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from detector import collect_host_snapshot, detect_os_platform  # noqa: E402

ACTIVE_WINDOW_SEC = 900

LOCAL_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("swarmcontrol_token", re.compile(r"\bsc_(?:live|tok|ro)_[A-Za-z0-9_-]{8,}")),
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

INLINE_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pass|secret|api[_-]?key|token|admin[_-]?pass|session[_-]?secret)"
    r"(\s*[:=]\s*)(['\"]?)([^\s'\",;]{6,})"
)

NOISE_TAGS_RE = re.compile(r"</?(?:USER_REQUEST|SYSTEM_MESSAGE|system-reminder|openbot-[a-z_-]+|agent_[a-z_-]+)>", re.I)

SENSITIVE_DIRS = {".vault", "vault", "agent-api-keys", ".farm-connector", ".beszel-access", ".ssh", ".gnupg"}
SENSITIVE_FILE_RE = re.compile(
    r"(?i)(?:^\.env(?:\.|$)|auth\.json$|credentials?\.json$|operator-password$|server-password$|\.pw$|"
    r"admin_credentials|id_rsa|id_ed25519|ssh_ed25519|\.(?:pem|key|p12|pfx|kdbx)$|^cookies(?:\.|$)|"
    r"(?:^|[._-])(?:secret|secrets|passwd|password|credential|credentials|api[_-]?key)(?:$|[._-])|"
    r"(?:^|[._-])token\.(?:txt|json|env|key|secret)$|oauth-token$)"
)
SKIP_WALK_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".cache",
    "Cache",
    "Code Cache",
    "GPUCache",
    "Crashpad",
    "dist",
    "build",
} | SENSITIVE_DIRS


def is_sensitive_path(path_str: str) -> bool:
    p = Path(str(path_str))
    if any(part.lower() in SENSITIVE_DIRS for part in p.parts):
        return True
    return bool(SENSITIVE_FILE_RE.search(p.name))


def redact_local_text(text: Any, max_len: int = 240) -> str:
    if not text:
        return ""
    clean = NOISE_TAGS_RE.sub(" ", str(text))
    clean = re.sub(r"\s+", " ", clean).strip()
    for name, pat in LOCAL_SECRET_PATTERNS:
        clean = pat.sub(f"[redacted:{name}]", clean)
    clean = INLINE_SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", clean)
    if len(clean) > max_len:
        clean = clean[: max_len - 1].rstrip() + "…"
    return clean


def parse_activity_roots(raw_roots: str | list[str] | None) -> list[Path]:
    """Parse colon/comma/semicolon separated folder list into resolved existing directories."""
    if not raw_roots:
        return []
    items: list[str] = []
    if isinstance(raw_roots, str):
        sep = os.pathsep
        for part in raw_roots.split(sep):
            for sub in part.split(","):
                if sub.strip():
                    items.append(sub.strip())
    elif isinstance(raw_roots, list):
        for x in raw_roots:
            if str(x).strip():
                items.append(str(x).strip())

    out: list[Path] = []
    seen: set[str] = set()
    for raw in items:
        try:
            p = Path(os.path.expanduser(raw)).resolve()
        except OSError:
            continue
        if not p.is_dir() or is_sensitive_path(str(p)):
            continue
        key = str(p)
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def _strip_file_uri(raw: str) -> str:
    s = str(raw or "").strip()
    return s[7:] if s.startswith("file://") else s


def _is_within_roots(candidate: str | Path, roots: list[Path]) -> bool:
    if not candidate or not roots:
        return False
    try:
        p = Path(os.path.expanduser(_strip_file_uri(str(candidate)))).resolve()
    except OSError:
        return False
    for r in roots:
        if p == r or r in p.parents:
            return True
    return False


def _filter_allowed_file(raw_path: Any, workspace: str, roots: list[Path]) -> str:
    if not isinstance(raw_path, str) or not raw_path.strip():
        return ""
    cleaned = _strip_file_uri(raw_path.strip().strip('"').strip("'"))
    if not cleaned or ".system_generated/tasks/" in cleaned:
        return ""
    p = Path(cleaned)
    ws_clean = _strip_file_uri(workspace)
    if not p.is_absolute() and ws_clean:
        p = Path(ws_clean) / p
    try:
        resolved = p.resolve()
    except OSError:
        return ""
    if is_sensitive_path(str(resolved)) or not _is_within_roots(resolved, roots):
        return ""
    return str(resolved)


def _infer_provider(model: str, harness: str) -> tuple[str, str, str]:
    m = (model or "").lower()
    if any(k in m for k in ("claude", "sonnet", "opus", "haiku", "anthropic")):
        return "anthropic", "Anthropic", "inferred"
    if any(k in m for k in ("gpt", "o1", "o3", "o4", "codex", "openai")):
        return "openai", "OpenAI", "inferred"
    if any(k in m for k in ("gemini", "antigravity", "argon", "google")):
        return "google", "Google", "inferred"
    if "deepseek" in m:
        return "deepseek", "DeepSeek", "inferred"
    if any(k in m for k in ("glm", "zhipu", "zai")):
        return "zhipu", "Zhipu GLM", "inferred"
    if harness == "claude-code":
        return "anthropic", "Anthropic", "harness"
    if harness == "codex":
        return "openai", "OpenAI", "harness"
    if harness == "antigravity-gemini":
        return "google", "Google", "harness"
    return "generic", "AI Runtime", "harness"


def _tool_key(tool: str) -> str:
    """Strip MCP server namespace (`mcp__<server>__<tool>` or `<server>.<tool>`)."""
    t = str(tool or "").lower()
    t = re.sub(r"^mcp__.+?__", "", t)
    return re.sub(r"^[a-z0-9_-]+\.", "", t)


def _categorize_tool(tool_name: str) -> tuple[str, str]:
    low = _tool_key(tool_name)
    if any(k in low for k in ("plan", "todo", "update_plan", "task_create", "taskcreate", "taskupdate", "manage_task")):
        return "plan", "Update plan"
    if any(k in low for k in ("write", "edit", "patch", "apply_patch", "replace", "notebook")):
        return "file_edit", "Edit file"
    if any(k in low for k in ("read", "view", "list", "grep", "find", "glob")):
        return "file_read", "Read files"
    if any(k in low for k in ("command", "bash", "exec", "shell", "terminal")):
        return "shell", "Run command"
    if any(k in low for k in ("image", "screenshot")):
        return "visual", "Generate visual"
    if any(k in low for k in ("search_web", "web", "browser", "fetch", "url", "search")):
        return "web", "Search or browse"
    if any(k in low for k in ("message", "channel", "subagent", "agent", "mcp", "swarm", "tool_call", "attach")):
        return "coordination", "Coordinate work"
    return "other", "Run tool"


CMD_KIND: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(unittest|pytest|npm (?:run )?test|go test|cargo test)\b"), "Run tests"),
    (re.compile(r"^(?:sudo\s+(?:-n\s+)?)?systemctl\b"), "Manage a service"),
    (re.compile(r"^(?:python3?|python3\.\d+)\b"), "Run a Python script"),
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

PROGRAM_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,39}")
WRAPPERS = {"sudo", "env", "nohup", "time", "timeout", "nice", "exec", "xargs", "stdbuf"}
KEYWORD_PREFIX = {"then", "do", "else", "if", "while", "until", "!", "{"}
SHELL_BUILTINS = {
    "cd", "set", "export", "source", ".", "if", "then", "else", "elif", "fi", "for", "do", "done",
    "while", "until", "case", "esac", "function", "local", "trap", "true", "false", ":", "[", "[[",
    "test", "{", "}", "unset", "shopt", "alias", "eval", "builtin", "umask", "pushd", "popd", "wait", "read",
}
CLI_SECRET_RE = re.compile(
    r"(?i)((?:^|\s)(?:-u|-p|--user|--password|--passwd|--pass|--token|--secret|--api[-_]?key|--auth|--header|-H)\s+)"
    r"(?:\"[^\"]*\"|'[^']*'|\S+)"
)


def command_kind(cmd: Any) -> str:
    """Describe a shell command by its kind only; never return its arguments."""
    c = str(cmd or "").strip()
    c = re.sub(r"^(?:cd\s+\S+\s*(?:&&|;)\s*)+", "", c)
    c = re.sub(r"^(?:[A-Z_][A-Z0-9_]*=\S*\s+)+", "", c)
    for pat, label in CMD_KIND:
        if pat.search(c):
            return label
    return "Run a shell command"


def _shorten_cmd_path(raw: str) -> str:
    parts = [p for p in re.split(r"[\\/]+", raw.strip()) if p]
    return ".../" + "/".join(parts[-2:]) if len(parts) >= 2 else raw


def command_info(cmd: Any) -> dict[str, str]:
    """Extract {'program': <name>} plus redacted opt-in 'command' when SWARMCONTROL_SHARE_COMMANDS=1."""
    c = str(cmd or "").strip()
    unwrapped = re.match(r"""^(?:/\S*/)?(?:ba|z)?sh\s+-l?c\s+(['"])(.*)\1\s*$""", c, re.S)
    if unwrapped:
        c = unwrapped.group(2).strip()
    program = ""
    for segment in re.split(r"\n|;|&&|\|\||\|", c):
        for tok in re.findall(r"[^\s()]+", segment):
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S*", tok) or tok.startswith("-"):
                continue
            name = tok.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
            if name in WRAPPERS or name in KEYWORD_PREFIX or re.fullmatch(r"\d+[smh]?", name):
                continue
            if name not in SHELL_BUILTINS and PROGRAM_RE.fullmatch(name) and not is_sensitive_path(name):
                program = name
            break
        if program:
            break
    out = {"program": program} if program else {}
    if os.environ.get("SWARMCONTROL_SHARE_COMMANDS") == "1" and c:
        shown = re.sub(
            r"(?<![\w.])/(?:var|home|opt|tmp|etc|usr|root|srv|mnt|Users)/\S+",
            lambda m: _shorten_cmd_path(m.group(0)),
            c,
        )
        shown = re.sub(r"(?<![\w.])[A-Za-z]:\\\S+", lambda m: _shorten_cmd_path(m.group(0)), shown)
        shown = CLI_SECRET_RE.sub(r"\1[redacted]", shown)
        shown = redact_local_text(shown, 4000)
        shown = re.sub(
            r"(?<![\w-])[^\s'\"=-][^\s'\"=]*",
            lambda m: "[protected file]" if ("/" in m.group(0) or "\\" in m.group(0) or "." in m.group(0)) and is_sensitive_path(m.group(0)) else m.group(0),
            shown,
        )
        out["command"] = shown if len(shown) <= 160 else shown[:159].rstrip() + "…"
    return out


PRIVATE_STEP_FIELDS = (
    "command_input",
    "command_output",
    "exit_code",
    "output_truncated",
    "image_previews",
    "text_previews",
)
_PREVIEW_TEXT_EXTS = {
    ".md", ".txt", ".py", ".js", ".ts", ".jsx", ".tsx", ".css", ".html", ".json",
    ".toml", ".yaml", ".yml", ".go", ".rs", ".c", ".h", ".cpp", ".sh", ".sql", ".java", ".rb",
}
MAX_IMAGE_PREVIEW_BYTES = 160 * 1024
MAX_IMAGE_PREVIEW_B64 = 4 * ((MAX_IMAGE_PREVIEW_BYTES + 2) // 3)
_EVIDENCE_SECRET_ARGS = re.compile(
    r"""(?ix)(?<![\w.-])(-[upH]|--(?:password|passwd|pass|secret|token|user|api[-_]?key|header|auth))(?:=|\s+)(?:"[^"]*"|'[^']*'|[^\s]+)"""
)
_EVIDENCE_SECRET_VALUE = re.compile(
    r"""(?ix)(\b(?:authorization|cookie|set-cookie|password|passwd|secret|access[_-]?token|api[_-]?key|token)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\r\n,;]+)"""
)
_CONTROL_SEQ = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")


def _strip_private_step(step: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in step.items() if k not in PRIVATE_STEP_FIELDS}


def _redact_secrets_preserve_ws(text: str) -> str:
    clean = NOISE_TAGS_RE.sub(" ", text)
    for name, pat in LOCAL_SECRET_PATTERNS:
        clean = pat.sub(f"[redacted:{name}]", clean)
    return INLINE_SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", clean)


def evidence_text(value: Any, limit: int) -> tuple[str | None, bool]:
    """Bound an explicitly shared text excerpt and preserve line breaks after redaction."""
    if not isinstance(value, str):
        return None, False
    if "PRIVATE KEY-----" in value or "\x00" in value:
        return "[protected content]", False
    value = _CONTROL_SEQ.sub("", value)
    value = _EVIDENCE_SECRET_ARGS.sub(r"\1 [redacted]", value)
    value = _EVIDENCE_SECRET_VALUE.sub(r"\1[redacted]", value)
    cleaned = []
    for line in value.split("\n"):
        safe = "".join(c for c in line if c == "\t" or (c.isprintable() and ord(c) != 127))
        cleaned.append(_redact_secrets_preserve_ws(safe))
    excerpt = "\n".join(cleaned)
    return excerpt[:limit], len(excerpt) > limit


def execution_detail(command: Any, output: Any, code: Any, *, capture_mode: bool = False) -> dict[str, Any]:
    """Build opt-in redacted command input/output and exit_code aligned with activity_inspector."""
    info: dict[str, Any] = command_info(command)
    if not capture_mode:
        return info
    if type(code) is int:
        info["exit_code"] = code
    if os.environ.get("SWARMCONTROL_SHARE_COMMANDS") == "1":
        text, _ = evidence_text(command, 1024)
        if text is not None:
            info["command_input"] = text
    if os.environ.get("SWARMCONTROL_SHARE_COMMAND_OUTPUT") == "1":
        if re.search(r"(?i)(?:^|[;&|\s])(?:env|set|printenv|export)(?:$|[;&|\s])", str(command)) or any(
            not part.startswith("-") and is_sensitive_path(part)
            for raw_tok in str(command).split()
            for part in (raw_tok.strip(" \"'").split("=", 1) if "=" in raw_tok else [raw_tok.strip(" \"'")])
            if part
        ):
            return info
        text, cut = evidence_text(output, 4096)
        if text is not None:
            info.update(command_output=text, output_truncated=cut)
    return info


def _workspace_image(path: str, when: Any, roots: list[Path]) -> dict[str, Any] | None:
    """Capture a small, unchanged raster at collection time inside approved roots. Never follow symlinks."""
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd or not isinstance(when, str):
        return None
    try:
        stamp = datetime.fromisoformat(when.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return None
        resolved = Path(path)
        matched = [r for r in roots if resolved == r or r in resolved.parents]
        if not matched or is_sensitive_path(path):
            return None
        root = max(matched, key=lambda r: len(r.parts))
        parts = resolved.relative_to(root).parts
        if not parts or any(p.startswith(".") for p in parts):
            return None
        mime = {
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".webp": "image/webp",
            ".gif": "image/gif",
        }.get(resolved.suffix.lower())
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
                if (
                    not stat.S_ISREG(before.st_mode)
                    or not 0 < before.st_size <= MAX_IMAGE_PREVIEW_BYTES
                    or max(before.st_mtime, before.st_ctime) > stamp.timestamp()
                ):
                    return None
                data = handle.read(MAX_IMAGE_PREVIEW_BYTES + 1)
                after = os.fstat(handle.fileno())
                if (len(data), after.st_mtime_ns, after.st_ctime_ns) != (
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                ):
                    return None
        signatures = {
            "image/png": (b"\x89PNG\r\n\x1a\n",),
            "image/jpeg": (b"\xff\xd8\xff",),
            "image/gif": (b"GIF87a", b"GIF89a"),
            "image/webp": (b"RIFF",),
        }
        if not data.startswith(signatures[mime]) or (mime == "image/webp" and data[8:12] != b"WEBP"):
            return None
        return {
            "path": path,
            "source": "workspace_snapshot",
            "mime_type": mime,
            "data_base64": base64.b64encode(data).decode("ascii"),
            "captured_at": time.time(),
        }
    except (OSError, ValueError, OverflowError):
        return None


def _tool_result_image(item: dict[str, Any], path: str, *, capture_mode: bool = False) -> list[dict[str, Any]]:
    """Retain only an explicit inert raster image result for this recorded image read."""
    if not capture_mode or os.environ.get("SWARMCONTROL_SHARE_FILE_PREVIEWS") != "1" or not path:
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
            if isinstance(url, str) and url.startswith(
                ("data:image/png;base64,", "data:image/jpeg;base64,", "data:image/gif;base64,", "data:image/webp;base64,")
            ):
                header, data = url.split(",", 1)
                mime = header[5:].split(";")[0]
        elif block.get("type") != "image":
            continue
        if (
            mime in ("image/png", "image/jpeg", "image/gif", "image/webp")
            and isinstance(data, str)
            and 0 < len(data) <= MAX_IMAGE_PREVIEW_B64
        ):
            return [{"path": path, "source": "tool_result", "mime_type": mime, "data_base64": data}]
    return []


def _tool_result_text(result: Any, path: str, *, capture_mode: bool = False) -> list[dict[str, Any]]:
    """Keep redacted text only when the runtime returned it for one explicit source file."""
    if (
        not capture_mode
        or os.environ.get("SWARMCONTROL_SHARE_FILE_PREVIEWS") != "1"
        or not path
        or Path(path).suffix.lower() not in _PREVIEW_TEXT_EXTS
    ):
        return []
    if isinstance(result, dict):
        result = result.get("content")
    if isinstance(result, list):
        lines = [
            block["text"]
            for block in result
            if isinstance(block, dict)
            and block.get("type") in ("text", "input_text")
            and isinstance(block.get("text"), str)
        ]
        result = "\n".join(lines) if lines else None
    text, cut = evidence_text(result, 4096)
    if text is None:
        return []
    return [{"path": path, "source": "tool_result", "text": text, "truncated": cut}]


def _attach_workspace_images(steps: list[dict[str, Any]], roots: list[Path], capture_mode: bool) -> None:
    if not (capture_mode and os.environ.get("SWARMCONTROL_SHARE_FILE_PREVIEWS") == "1"):
        return
    for step in steps:
        if (
            step.get("category") == "file_read"
            and step.get("file_basis") == "confirmed"
            and step.get("status", "completed") == "completed"
            and not step.get("image_previews")
            and len(step.get("files") or []) == 1
        ):
            preview = _workspace_image(step["files"][0], step.get("time"), roots)
            if preview:
                step["image_previews"] = [preview]


DEFAULT_TAIL_CEILING = 4_000_000   # same per-scan budget as activity_core.TAIL_CEILING
DEFAULT_FIRST_SIGHT = 640 * 1024
CAPTURE_OVERLAP = 4096
MAX_RECORD = 32 * 1024 * 1024     # same as activity_core.CAPTURE_MAX_RECORD
BASELINE_KEY = "__baseline__"     # same as activity_core.BASELINE_KEY


def _file_key(path: Any) -> str:
    return hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:20]


class _FallbackCapture:
    """Standalone incremental byte-offset tracker when activity_core is not installed."""

    def __init__(self, offsets: dict[str, dict[str, int]] | None = None, ceiling: int | None = None):
        self.offsets = dict(offsets or {})
        self.ceiling = int(ceiling) if ceiling is not None else DEFAULT_TAIL_CEILING
        self.read: dict[str, dict[str, int]] = {}
        self.gaps: list[dict[str, Any]] = []
        self.backlog: list[str] = []
        self.bytes_read = 0
        self.files_read = 0
        self.first_run = not self.offsets  # any saved offset (with or without baseline) proves an earlier scan
        if self.first_run:
            self.read[BASELINE_KEY] = {"inode": 0, "offset": int(time.time()), "legacy_until": 0}

    def legacy_until(self, key: str) -> int:
        state = self.read.get(key) or self.offsets.get(key) or {}
        return int(state.get("legacy_until", 0) or 0)

    def unchanged(self, path: Path) -> bool:
        try:
            st = path.stat()
        except OSError:
            return True
        prev = self.offsets.get(_file_key(path))
        return bool(prev) and prev.get("inode") == st.st_ino and prev.get("offset") == st.st_size

    def note(self, key: str, state: dict[str, int]) -> None:
        self.read[key] = state

    def iter_lines(self, path: Path, first_sight: int = DEFAULT_FIRST_SIGHT):
        """Same rules as activity_core.Capture.lines: new logs after the baseline are read from their
        first line; records up to MAX_RECORD are read whole; larger ones are skipped and reported as a gap."""
        if not path.is_file() or is_sensitive_path(str(path)):
            return
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
            legacy = int(prev.get("legacy_until", 0) or 0)
        else:
            if prev:
                self.gaps.append({"file": key, "reason": "log rotated or truncated", "path": path.name})
            start = max(0, size - first_sight) if self.first_run else 0
            # Only bytes that existed before the first scan can have been stored by an older journal (exact or
            # same-moment keys). A rotated log or one created later holds only new actions.
            saved, legacy = start, (size if self.first_run else 0)
        budget_end = saved + self.ceiling
        try:
            f = path.open("rb")
        except OSError:
            return
        with f:
            f.seek(start)
            pos = start
            if start > 0:
                while True:
                    chunk = f.readline(1 << 20)
                    if not chunk:
                        return
                    pos += len(chunk)
                    if chunk.endswith(b"\n"):
                        break
            first = pos
            while pos < size:
                if pos >= budget_end:
                    self.backlog.append(key)
                    break
                raw = f.readline(MAX_RECORD + 1)
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    if len(raw) <= MAX_RECORD:
                        break
                    skipped = len(raw)
                    while True:
                        chunk = f.readline(1 << 20)
                        skipped += len(chunk)
                        if not chunk or chunk.endswith(b"\n"):
                            break
                    if not chunk:
                        break
                    self.gaps.append({"file": key, "reason": f"record over {MAX_RECORD // (1 << 20)} MB skipped", "path": path.name})
                    pos += skipped
                    continue
                line_pos = pos
                pos += len(raw)
                yield f"{key}:{line_pos}", raw[:-1].decode("utf-8", errors="ignore")
        self.bytes_read += pos - first
        self.files_read += 1
        self.note(key, {"inode": st.st_ino, "offset": pos, "legacy_until": legacy})


def _tail_lines(path: Path, max_bytes: int = 128_000, max_lines: int = 200) -> list[str]:
    if not path.is_file() or is_sensitive_path(str(path)):
        return []
    try:
        size = path.stat().st_size
        with path.open("rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
                f.readline()
            chunk = f.read().decode("utf-8", errors="ignore")
        return chunk.splitlines()[-max_lines:]
    except Exception:
        return []


def _extract_checklist(text: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for line in (text or "").splitlines():
        m = re.match(r"^\s*[-*]\s*\[([ xX])\]\s+(.+)$", line)
        if m:
            items.append(
                {
                    "status": "completed" if m.group(1).lower() == "x" else "pending",
                    "text": redact_local_text(m.group(2), 140),
                }
            )
    return items[:12]


def _derive_agent_identity(workspace: str, custom_labels: dict[str, str], roots: list[Path] | None = None) -> tuple[str, str]:
    """Derive portable agent_id and agent_name from longest matching root per ACTIVITY-CONTRACT v1."""
    if not workspace:
        return "workspace-agent", "Workspace Agent"
    try:
        p = Path(os.path.expanduser(workspace)).resolve()
    except OSError:
        p = Path(workspace)
    if roots:
        sorted_roots = sorted(roots, key=lambda r: len(r.parts), reverse=True)
        matched = next((r for r in sorted_roots if p == r or r in p.parents), None)
        if matched is not None:
            name_counts = Counter(r.name for r in roots)
            import hashlib
            aid = (
                matched.name
                if name_counts[matched.name] == 1
                else f"{matched.name}-{hashlib.sha256(str(matched).encode()).hexdigest()[:6]}"
            )
            aname = custom_labels.get(str(matched)) or custom_labels.get(matched.name) or matched.name
            return aid, aname
    for part in reversed(p.parts):
        if part in custom_labels:
            return part, custom_labels[part]
    name = p.name or "workspace-agent"
    return name, custom_labels.get(name, name)


def _load_custom_labels() -> dict[str, str]:
    labels: dict[str, str] = {}
    raw = os.environ.get("SWARMCONTROL_AGENT_LABELS", "").strip()
    for pair in raw.split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            if k.strip() and v.strip():
                labels[k.strip()] = redact_local_text(v.strip(), 64)
    return labels


def _iter_source_lines(path: Path, capture: _FallbackCapture | None = None):
    if capture is not None:
        yield from capture.iter_lines(path)
    else:
        for ln in _tail_lines(path):
            yield "", ln


def _collect_codex_sessions(
    roots: list[Path],
    home_dir: Path,
    labels: dict[str, str],
    capture: _FallbackCapture | None = None,
) -> list[dict[str, Any]]:
    sessions: list[dict[str, Any]] = []
    codex_dir = home_dir / ".codex"
    rollout_candidates: list[tuple[float, Path, str, str, int, str]] = []

    state_db = codex_dir / "state_5.sqlite"
    if state_db.is_file():
        try:
            conn = sqlite3.connect(f"file:{state_db}?mode=ro", uri=True, timeout=1.5)
            rows = conn.execute(
                "SELECT id, cwd, model, tokens_used, updated_at, rollout_path FROM threads ORDER BY updated_at DESC LIMIT 20"
            ).fetchall()
            conn.close()
            for tid, cwd, model, tokens, upd_at, rollout in rows:
                if rollout and Path(rollout).is_file():
                    ts = float(upd_at or 0)
                    if ts > 1e12:
                        ts /= 1000.0
                    rollout_candidates.append(
                        (ts, Path(rollout), _strip_file_uri(str(cwd or "")), str(model or "codex"), int(tokens or 0), str(tid or ""))
                    )
        except Exception:
            pass

    if not rollout_candidates and (codex_dir / "sessions").is_dir():
        limit_scan = 40 if capture is not None else 15
        for rp in sorted((codex_dir / "sessions").rglob("rollout-*.jsonl"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit_scan]:
            rollout_candidates.append((rp.stat().st_mtime, rp, "", "codex", 0, rp.stem.removeprefix("rollout-")))

    for ts, rp, cwd, model, tokens, sid in rollout_candidates:
        if capture is not None and capture.unchanged(rp):
            continue
        if not cwd or not sid:
            try:
                with rp.open("rb") as fh:
                    first = json.loads(fh.readline(65536).decode("utf-8", errors="ignore"))
                if first.get("type") == "session_meta":
                    meta_pl = first.get("payload") or {}
                    cwd = cwd or _strip_file_uri(str(meta_pl.get("cwd") or ""))
                    sid = sid or str(meta_pl.get("id") or "")
            except Exception:
                pass
        if not _is_within_roots(cwd, roots):
            continue
        lines = list(_iter_source_lines(rp, capture))

        structured_steps: list[dict[str, Any]] = []
        legacy_steps: list[dict[str, Any]] = []
        edited: list[str] = []
        read_files: list[str] = []
        plan: list[dict[str, Any]] = []
        what_done = ""

        for src_prefix, ln in lines:
            start_s = len(structured_steps)
            start_l = len(legacy_steps)
            try:
                o = json.loads(ln)
            except Exception:
                continue
            pl = o.get("payload")
            if not isinstance(pl, dict):
                continue
            ptype = pl.get("type")
            ev_ts = str(o.get("timestamp") or "")[:36]
            if ptype in {"function_call", "custom_tool_call"}:
                tname = str(pl.get("name") or "tool")
                raw_args = str(pl.get("arguments") or pl.get("input") or "")
                parsed_args: dict[str, Any] = {}
                if raw_args.lstrip().startswith("{"):
                    try:
                        tmp_args = json.loads(raw_args)
                        if isinstance(tmp_args, dict):
                            parsed_args = tmp_args
                    except Exception:
                        parsed_args = {}
                if "update_plan" in tname.lower() or "update_plan" in raw_args:
                    for st in (parsed_args.get("plan") or [])[:12]:
                        if isinstance(st, dict) and st.get("step"):
                            plan.append(
                                {
                                    "status": "completed" if st.get("status") == "completed" else "pending",
                                    "text": redact_local_text(st.get("step"), 140),
                                }
                            )
                if tname == "exec":
                    if re.search(r"tools\.update_plan\(", raw_args):  # a plan change is an action
                        plan_step = {"tool": "update_plan", "category": "plan", "label": "Update the plan", "time": ev_ts,
                                     "status": "completed", "files": [], "file_basis": "recorded"}
                        if src_prefix:
                            plan_step["src"] = f"{src_prefix}:0"
                        structured_steps.append(plan_step)
                    continue
                inner_name = str(parsed_args.get("name") or "") if tname == "tool_call" else ""
                eff_name = inner_name or tname
                cat, lbl = _categorize_tool(eff_name)
                step_files: list[str] = []
                cmd_meta: dict[str, str] = {}
                if cat == "shell":
                    raw_cmd = parsed_args.get("cmd") or parsed_args.get("command") or ""
                    if isinstance(raw_cmd, list):
                        raw_cmd = " ".join(str(x) for x in raw_cmd)
                    raw_cmd = str(raw_cmd).strip()
                    if raw_cmd:
                        lbl = command_kind(raw_cmd)
                        cmd_meta = command_info(raw_cmd)
                elif cat in {"file_edit", "file_read"}:
                    candidates: list[str] = []
                    for key in ("file_path", "path", "Path", "target_file"):
                        if isinstance(parsed_args.get(key), str):
                            candidates.append(parsed_args[key])
                    if isinstance(parsed_args.get("paths"), list):
                        candidates.extend(str(x) for x in parsed_args["paths"] if isinstance(x, str))
                    candidates.extend(re.findall(r"\*\*\* (?:Update|Add|Delete) File:\s*([^\r\n]+)", raw_args))
                    for candidate in candidates:
                        safe_f = _filter_allowed_file(candidate, cwd, roots)
                        if safe_f and safe_f not in step_files:
                            step_files.append(safe_f)
                            if cat == "file_edit" and safe_f not in edited:
                                edited.append(safe_f)
                            elif cat == "file_read" and safe_f not in read_files:
                                read_files.append(safe_f)
                if step_files:
                    lbl = f"{lbl} ({Path(step_files[0]).name})"
                step_obj: dict[str, Any] = {
                    "tool": eff_name,
                    "category": cat,
                    "label": redact_local_text(lbl, 120),
                    "time": ev_ts,
                    "status": "completed",
                    "files": step_files[:6],
                    "file_basis": "confirmed" if step_files else "recorded",
                }
                step_obj.update(cmd_meta)
                legacy_steps.append(step_obj)
            elif ptype == "item_completed" and isinstance(pl.get("item"), dict):
                it = pl["item"]
                itype = it.get("type")
                if itype == "FileChange":
                    changes = it.get("changes") or {}
                    c_files: list[str] = []
                    saw_path = False
                    if isinstance(changes, dict):
                        for raw_f in changes.keys():
                            saw_path = True
                            safe_f = _filter_allowed_file(raw_f, cwd, roots)
                            if safe_f:
                                c_files.append(safe_f)
                                if safe_f not in edited:
                                    edited.append(safe_f)
                    if saw_path:
                        lbl_fc = (
                            (f"Edit {Path(c_files[0]).name}" if len(c_files) == 1 else f"Edit {len(c_files)} files")
                            if c_files
                            else "Edit a protected or unshared file"
                        )
                        structured_steps.append(
                            {
                                "tool": "apply_patch",
                                "category": "file_edit",
                                "label": lbl_fc,
                                "time": ev_ts,
                                "status": str(it.get("status") or "completed").lower(),
                                "files": c_files[:8],
                                "file_basis": "confirmed" if c_files else "recorded",
                            }
                        )
                elif itype == "CommandExecution":
                    parsed_cmds = [c for c in it.get("parsed_cmd") or [] if isinstance(c, dict)]
                    kinds = {c.get("type") for c in parsed_cmds}
                    linked_reads: list[str] = []
                    cmd_cwd = _strip_file_uri(str(it.get("cwd") or cwd))
                    for pc in parsed_cmds:
                        if pc.get("type") == "read" and pc.get("path"):
                            safe_r = _filter_allowed_file(pc["path"], cmd_cwd, roots)
                            if safe_r and safe_r not in linked_reads:
                                linked_reads.append(safe_r)
                                if safe_r not in read_files:
                                    read_files.append(safe_r)
                    raw_cmd = it.get("command")
                    actual_cmd = raw_cmd[-1] if isinstance(raw_cmd, list) and raw_cmd else raw_cmd
                    cmd_str = str((parsed_cmds[0].get("cmd") if parsed_cmds else None) or actual_cmd or "").strip()
                    if kinds == {"read"}:
                        lbl = (
                            "Read " + ", ".join(Path(p).name for p in linked_reads)[:100]
                            if linked_reads
                            else "Read a file outside the shared folders"
                        )
                    elif kinds and kinds <= {"list_files", "search"}:
                        lbl = "List or search files"
                    else:
                        lbl = command_kind(cmd_str)
                    cat = "file_read" if kinds and kinds <= {"read", "list_files", "search"} else "shell"
                    step_obj = {
                        "tool": "exec_command",
                        "category": cat,
                        "label": redact_local_text(lbl, 120),
                        "time": ev_ts,
                        "status": str(it.get("status") or "completed").lower(),
                        "files": linked_reads[:12],
                        "file_basis": "confirmed" if cat == "file_read" and linked_reads else "recorded",
                    }
                    if cmd_cwd:
                        step_obj["cwd"] = cmd_cwd
                    step_obj.update(
                        execution_detail(
                            actual_cmd or cmd_str,
                            it.get("aggregated_output"),
                            it.get("exit_code"),
                            capture_mode=capture is not None,
                        )
                    )
                    structured_steps.append(step_obj)
                elif itype == "DynamicToolCall":
                    d_tool = str(it.get("tool") or "tool")
                    d_args = it.get("arguments") or {}
                    if d_tool == "tool_call" and isinstance(d_args, dict) and d_args.get("name"):
                        d_tool = str(d_args["name"])
                        inner_args = d_args.get("arguments")
                        if isinstance(inner_args, str) and inner_args.lstrip().startswith("{"):
                            try:
                                inner_args = json.loads(inner_args)
                            except Exception:
                                inner_args = {}
                        d_args = inner_args if isinstance(inner_args, dict) else {}
                    cat, lbl = _categorize_tool(d_tool)
                    d_files: list[str] = []
                    d_basis = "recorded"
                    d_status = str(it.get("status") or ("error" if it.get("success") is False else "completed")).lower()
                    d_previews: list[dict[str, Any]] = []
                    d_texts: list[dict[str, Any]] = []
                    if _tool_key(d_tool) in {"view_image", "read_image", "read_file"} and isinstance(d_args, dict):
                        raw_fp = d_args.get("path") or d_args.get("file_path") or d_args.get("Path")
                        safe_r = _filter_allowed_file(raw_fp, cwd, roots)
                        if safe_r:
                            cat = "file_read"
                            d_files = [safe_r]
                            d_basis = "confirmed"
                            lbl = f"Read {Path(safe_r).name}"
                            if safe_r not in read_files:
                                read_files.append(safe_r)
                            if it.get("success") is False:
                                d_status = "error"
                            else:
                                d_previews = _tool_result_image(it, safe_r, capture_mode=capture is not None)
                                if not d_previews and _tool_key(d_tool) == "read_file":
                                    d_texts = _tool_result_text(
                                        it.get("result", it.get("content_items", it.get("output"))),
                                        safe_r,
                                        capture_mode=capture is not None,
                                    )
                    step_obj = {
                        "tool": d_tool,
                        "category": cat,
                        "label": redact_local_text(lbl, 120),
                        "time": ev_ts,
                        "status": d_status,
                        "files": d_files,
                        "file_basis": d_basis,
                    }
                    if d_previews:
                        step_obj["image_previews"] = d_previews
                    if d_texts:
                        step_obj["text_previews"] = d_texts
                    structured_steps.append(step_obj)
            elif ptype == "file_change" or (o.get("type") == "event_msg" and ptype == "patch_apply_end"):
                changes = pl.get("changes") or {}
                c_files = []
                saw_path = False
                if isinstance(changes, dict):
                    for raw_f in changes.keys():
                        saw_path = True
                        safe_f = _filter_allowed_file(raw_f, cwd, roots)
                        if safe_f:
                            c_files.append(safe_f)
                            if safe_f not in edited:
                                edited.append(safe_f)
                if saw_path:
                    lbl_fc = (
                        (f"Edit {Path(c_files[0]).name}" if len(c_files) == 1 else f"Edit {len(c_files)} files")
                        if c_files
                        else "Edit a protected or unshared file"
                    )
                    structured_steps.append(
                        {
                            "tool": "apply_patch",
                            "category": "file_edit",
                            "label": lbl_fc,
                            "time": ev_ts,
                            "status": "completed",
                            "files": c_files[:8],
                            "file_basis": "confirmed" if c_files else "recorded",
                        }
                    )
            elif ptype in {"message", "agent_message", "task_complete"}:
                txt = str(pl.get("message") or pl.get("last_agent_message") or "")
                if not txt and isinstance(pl.get("content"), list):
                    txt = " ".join(str(b.get("text") or "") for b in pl["content"] if isinstance(b, dict))
                if txt.strip():
                    chk = _extract_checklist(txt)
                    if chk:
                        plan = chk
                    what_done = redact_local_text(txt, 220)
            if src_prefix:
                for step_pos, st_item in enumerate(structured_steps[start_s:]):
                    st_item["src"] = f"{src_prefix}:{step_pos}"
                for step_pos, st_item in enumerate(legacy_steps[start_l:]):
                    st_item["src"] = f"{src_prefix}:{step_pos}"

        steps = structured_steps or legacy_steps
        _attach_workspace_images(steps, roots, capture is not None)
        shown = [_strip_private_step(s) for s in steps[-10:]]
        agent_id, agent_name = _derive_agent_identity(cwd, labels, roots)
        prov, prov_label, prov_basis = _infer_provider(model, "codex")
        how = dict(Counter(s["category"] for s in steps))
        substantive = [s for s in shown if s["category"] in {"file_edit", "shell", "shell_exec", "file_read", "web", "web_research", "visual", "visual_asset"}]
        latest_action = shown[-1] if shown else None
        latest_work = substantive[-1] if substantive else latest_action
        full_sid = sid or rp.stem.removeprefix("rollout-")

        card = {
            "session_id": f"codex:{full_sid}"[:96],
            "legacy_session_id": f"codex:{full_sid[:12]}",
            "harness": "codex",
            "harness_name": "Codex CLI",
            "provider": prov,
            "provider_label": prov_label,
            "provider_basis": prov_basis,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "owner_basis": "workspace",
            "workspace": cwd,
            "model": model,
            "tokens_used": tokens,
            "updated_at": ts,
            "status": "active" if (time.time() - ts) < ACTIVE_WINDOW_SEC else "idle",
            "what_done": what_done or "Active Codex session in configured workspace.",
            "plan": plan[:10],
            "how": how,
            "steps": shown,
            "latest_action": latest_action,
            "latest_work": latest_work,
            "files_edited": edited[-12:],
            "files_read": [f for f in read_files if f not in edited][-8:],
            "files_delivered": [],
        }
        if capture is not None:
            card["capture_steps"] = steps
        sessions.append(card)
    return sessions if capture is not None else sessions[:10]


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


def _collect_claude_sessions(
    roots: list[Path],
    home_dir: Path,
    labels: dict[str, str],
    capture: _FallbackCapture | None = None,
) -> list[dict[str, Any]]:
    projects_root = home_dir / ".claude" / "projects"
    if not projects_root.is_dir():
        return []
    sessions: list[dict[str, Any]] = []
    limit_scan = 40 if capture is not None else 12
    found = list(projects_root.glob("*/*.jsonl")) + list(projects_root.glob("*/*/subagents/*.jsonl"))  # Claude Code sub-agents too
    for jf in sorted(found, key=lambda x: x.stat().st_mtime, reverse=True)[:limit_scan]:
        if is_sensitive_path(str(jf)):
            continue
        if capture is not None and capture.unchanged(jf):
            continue
        lines = list(_iter_source_lines(jf, capture))
        cwd = ""
        model = "claude"
        recorded_calls: dict[str, tuple[dict[str, Any], str | None]] = {}
        steps: list[dict[str, Any]] = []
        edited: list[str] = []
        read_files: list[str] = []
        plan: list[dict[str, Any]] = []
        what_done = ""

        for src_prefix, ln in lines:
            start_idx = len(steps)
            try:
                o = json.loads(ln)
            except Exception:
                continue
            if o.get("cwd"):
                cwd = str(o["cwd"])
            msg = o.get("message")
            if o.get("type") == "user" and isinstance(msg, dict) and capture is not None:
                for result in msg.get("content") or []:
                    if not isinstance(result, dict) or result.get("type") != "tool_result":
                        continue
                    uid = result.get("tool_use_id")
                    pair = recorded_calls.pop(uid, None) if isinstance(uid, str) else None
                    if pair is None:
                        continue
                    paired_step, paired_cmd = pair
                    paired_step["status"] = "error" if result.get("is_error") else "completed"
                    payload = result.get("content")
                    if paired_cmd is not None:
                        if isinstance(payload, list):
                            payload = "\n".join(
                                block["text"]
                                for block in payload
                                if isinstance(block, dict)
                                and block.get("type") == "text"
                                and isinstance(block.get("text"), str)
                            )
                        paired_step.update(execution_detail(paired_cmd, payload, None, capture_mode=True))
                    elif paired_step.get("files") and paired_step["status"] == "completed":
                        previews = _tool_result_image({"result": payload}, paired_step["files"][0], capture_mode=True)
                        if previews:
                            paired_step["image_previews"] = previews
                        else:
                            snippets = _tool_result_text(payload, paired_step["files"][0], capture_mode=True)
                            if snippets:
                                paired_step["text_previews"] = snippets
                continue
            if o.get("type") != "assistant" or not isinstance(msg, dict):
                continue
            if msg.get("model"):
                model = str(msg["model"])
            content = msg.get("content")
            if isinstance(content, list):
                for blk in content:
                    if not isinstance(blk, dict):
                        continue
                    if blk.get("type") == "text":
                        txt = str(blk.get("text") or "").strip()
                        if txt:
                            chk = _extract_checklist(txt)
                            if chk and not plan:
                                plan = chk
                            what_done = redact_local_text(txt, 220)
                        continue
                    if blk.get("type") == "tool_use":
                        tname = str(blk.get("name") or "tool")
                        cat, lbl = _categorize_tool(tname)
                        inp = blk.get("input") if isinstance(blk.get("input"), dict) else {}
                        step_files: list[str] = []
                        cmd_meta: dict[str, Any] = {}
                        raw_fp = ""
                        for k in ("file_path", "notebook_path", "path", "Path"):
                            if isinstance(inp.get(k), str) and inp.get(k):
                                raw_fp = raw_fp or inp[k]
                            safe_f = _filter_allowed_file(inp.get(k), cwd, roots)
                            if safe_f and safe_f not in step_files:
                                step_files.append(safe_f)
                                if cat == "file_edit" and safe_f not in edited:
                                    edited.append(safe_f)
                                elif cat == "file_read" and safe_f not in read_files:
                                    read_files.append(safe_f)
                        if tname == "TodoWrite" and isinstance(inp.get("todos"), list):
                            plan = [
                                {
                                    "status": "completed" if t.get("status") == "completed" else "pending",
                                    "text": redact_local_text(t.get("content"), 140),
                                }
                                for t in inp["todos"][:10]
                                if isinstance(t, dict) and t.get("content")
                            ]
                        raw_cmd = ""
                        if cat == "shell" and inp.get("command"):
                            raw_cmd = str(inp["command"])
                            cmd_meta = execution_detail(raw_cmd, None, None, capture_mode=capture is not None)
                            lbl = str(inp["description"]) if inp.get("description") else command_kind(raw_cmd)
                        if step_files:
                            lbl = f"{lbl} ({Path(step_files[0]).name})"
                        elif cat in {"file_edit", "file_read"} and raw_fp:
                            verb = "Edit" if cat == "file_edit" else "Read"
                            lbl = f"{verb} a protected file" if is_sensitive_path(raw_fp) else f"{verb} a file outside the shared folders"
                        step_obj: dict[str, Any] = {
                            "tool": tname,
                            "category": cat,
                            "label": redact_local_text(lbl, 120),
                            "time": str(o.get("timestamp") or "")[:36],
                            "status": "completed",
                            "files": step_files[:6],
                            "file_basis": "confirmed" if cat in {"file_edit", "file_read"} and step_files else "recorded",
                        }
                        step_obj.update(cmd_meta)
                        steps.append(step_obj)
                        if (
                            capture is not None
                            and isinstance(blk.get("id"), str)
                            and ((cat == "shell" and raw_cmd) or cat == "file_read")
                            and (
                                os.environ.get("SWARMCONTROL_SHARE_COMMAND_OUTPUT") == "1"
                                or os.environ.get("SWARMCONTROL_SHARE_FILE_PREVIEWS") == "1"
                            )
                        ):
                            recorded_calls[blk["id"]] = (step_obj, raw_cmd if cat == "shell" else None)
            if src_prefix:
                for step_pos, st_item in enumerate(steps[start_idx:]):
                    st_item["src"] = f"{src_prefix}:{step_pos}"

        launch = _claude_launch_cwd(jf) or cwd
        if not _is_within_roots(launch, roots) and not _is_within_roots(cwd, roots) and not edited:
            continue
        if _is_within_roots(launch, roots):
            effective_ws = launch
        elif _is_within_roots(cwd, roots):
            effective_ws = cwd
        else:
            effective_ws = str(Path(edited[0]).parent)
        agent_id, agent_name = _derive_agent_identity(effective_ws, labels, roots)
        prov, prov_label, prov_basis = _infer_provider(model, "claude-code")
        _attach_workspace_images(steps, roots, capture is not None)
        shown = [_strip_private_step(s) for s in steps[-10:]]
        how = dict(Counter(s["category"] for s in steps))
        substantive = [s for s in shown if s["category"] in {"file_edit", "shell", "shell_exec", "file_read", "web", "web_research", "visual", "visual_asset"}]
        latest_action = shown[-1] if shown else None
        latest_work = substantive[-1] if substantive else latest_action
        mtime = jf.stat().st_mtime

        card: dict[str, Any] = {
            "session_id": f"claude-code:{jf.stem}"[:96],
            "legacy_session_id": f"claude-code:{jf.stem[:12]}",
            "harness": "claude-code",
            "harness_name": "Claude Code",
            "provider": prov,
            "provider_label": prov_label,
            "provider_basis": prov_basis,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "owner_basis": "workspace",
            "workspace": effective_ws,
            "model": model,
            "tokens_used": 0,
            "updated_at": mtime,
            "status": "active" if (time.time() - mtime) < ACTIVE_WINDOW_SEC else "idle",
            "what_done": what_done or "Active Claude Code session in configured workspace.",
            "plan": plan[:10],
            "how": how,
            "steps": shown,
            "latest_action": latest_action,
            "latest_work": latest_work,
            "files_edited": edited[-12:],
            "files_read": [f for f in read_files if f not in edited][-8:],
            "files_delivered": [],
        }
        if cwd and cwd != effective_ws and _is_within_roots(cwd, roots):
            card["current_folder"] = cwd
        if capture is not None:
            card["capture_steps"] = steps
        sessions.append(card)
    return sessions if capture is not None else sessions[:8]


def _collect_opencode_sessions(
    roots: list[Path],
    home_dir: Path,
    labels: dict[str, str],
    capture: _FallbackCapture | None = None,
) -> list[dict[str, Any]]:
    db_path = home_dir / ".local/share/opencode/opencode.db"
    if not db_path.is_file():
        return []
    sessions: list[dict[str, Any]] = []
    conn = None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=1.5)
        conn.row_factory = sqlite3.Row
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "session_v2" not in tables:
            return []
        columns = {r[1] for r in conn.execute("PRAGMA table_info(session_v2)")}
        fields = ("id", "directory", "time_updated", "model", "title", "slug", "tokens_input", "tokens_output",
                  "summary_files", "summary_additions", "summary_deletions")
        projection = ", ".join(f for f in fields if f in columns)
        if not {"id", "time_updated"} <= columns:
            return []
        limit_rows = 40 if capture is not None else 15
        rows = conn.execute(f"SELECT {projection} FROM session_v2 ORDER BY time_updated DESC LIMIT ?", (limit_rows,)).fetchall()
        has_msg = "session_message" in tables
        for r in rows:
            keys = r.keys()
            directory = str(r["directory"] or "") if "directory" in keys else ""
            if not _is_within_roots(directory, roots):
                continue
            upd_ms = float(r["time_updated"] or 0)
            upd_sec = upd_ms / 1000.0 if upd_ms > 1e12 else upd_ms
            sid = str(r["id"])
            source_key = _file_key(f"opencode:{sid}")
            prev = capture.offsets.get(source_key) if capture is not None else None
            if capture is not None and prev and int(prev.get("offset", 0)) == int(upd_ms):
                continue

            tools: list[sqlite3.Row] = []
            if has_msg:
                msg_lim, part_lim = (400, 1200) if capture is not None else (24, 40)
                try:
                    tools = conn.execute(
                        """
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
                                 CASE WHEN length(m.data) <= 33554432 AND json_valid(m.data) THEN m.data ELSE '{}' END,
                                 '$.content') p
                         WHERE p.type = 'object' AND json_extract(p.value, '$.type') = 'tool'
                         ORDER BY m.seq DESC, CAST(p.key AS INTEGER) DESC LIMIT ?
                        """,
                        (sid, msg_lim, capture is not None and os.environ.get("SWARMCONTROL_SHARE_COMMAND_OUTPUT") == "1", part_lim),
                    ).fetchall()[::-1]
                except sqlite3.Error:
                    tools = []

            if capture is not None:
                top = max((t["seq"] * 10_000 + int(t["part"] or 0) for t in tools if isinstance(t["seq"], int)), default=0)
                capture.files_read += 1
                capture.note(
                    source_key,
                    {
                        "inode": 0,
                        "offset": int(upd_ms),
                        "legacy_until": int(prev.get("legacy_until", 0) or 0) if prev else (top + 1 if capture.first_run else 0),
                    },
                )

            steps: list[dict[str, Any]] = []
            edited: list[str] = []
            read_files: list[str] = []
            plan: list[dict[str, Any]] = []
            for row in tools:
                name, status = row["name"], row["status"]
                if not isinstance(name, str) or status not in {"completed", "error", "running", "pending"}:
                    continue
                cat, default_lbl = _categorize_tool(name)
                if name in {"bash", "shell"}:
                    cat, default_lbl = "shell", "Run a command"
                elif name == "webfetch":
                    cat, default_lbl = "web", "Read a web page"
                elif name == "websearch":
                    cat, default_lbl = "web", "Search the web"
                elif name == "grep":
                    cat, default_lbl = "file_read", "Search files"
                elif name == "todowrite":
                    cat, default_lbl = "plan", "Update the plan"
                elif name in {"read", "edit", "write"}:
                    cat = "file_read" if name == "read" else "file_edit"
                    default_lbl = f"{name.capitalize()} a file"
                stamp = row["stamp"]
                stamp = stamp / 1000.0 if isinstance(stamp, (int, float)) and stamp > 1e12 else stamp
                when = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(stamp)) if isinstance(stamp, (int, float)) and 0 < stamp < 1e10 else ""
                raw_path = row["path"]
                safe_f = _filter_allowed_file(raw_path, directory, roots) if (raw_path and status == "completed") else ""
                step_files: list[str] = []
                lbl = default_lbl
                if safe_f:
                    step_files = [safe_f]
                    (read_files if cat == "file_read" else edited).append(safe_f)
                    lbl = f"{name.capitalize()} {Path(safe_f).name}"
                step_obj: dict[str, Any] = {
                    "tool": name,
                    "category": cat,
                    "label": redact_local_text(lbl, 120),
                    "time": when,
                    "status": status,
                    "files": step_files,
                    "file_basis": "confirmed" if step_files else "recorded",
                }
                if "command" in row.keys() and isinstance(row["command"], str):
                    cmd_str = row["command"]
                    if cat == "shell":
                        step_obj["label"] = command_kind(cmd_str)
                    step_obj.update(
                        execution_detail(cmd_str, row["output"], row["exit_code"], capture_mode=capture is not None)
                    )
                if status == "completed" and name == "todowrite" and isinstance(row["todos"], str):
                    try:
                        todos = json.loads(row["todos"])
                    except ValueError:
                        todos = []
                    if isinstance(todos, list):
                        plan = [
                            {
                                "status": "completed" if i.get("status") == "completed" else "pending",
                                "text": redact_local_text(i["content"], 140),
                            }
                            for i in todos[:10]
                            if isinstance(i, dict) and isinstance(i.get("content"), str)
                        ]
                if capture is not None and isinstance(row["seq"], int):
                    step_obj["src"] = f"{source_key}:{row['seq'] * 10_000 + int(row['part'] or 0)}:0"
                steps.append(step_obj)

            agent_id, agent_name = _derive_agent_identity(directory, labels, roots)
            model = str(r["model"] or "opencode") if "model" in keys else "opencode"
            try:
                spec = json.loads(model)
                prov_rec = spec.get("providerID") if isinstance(spec, dict) else None
            except ValueError:
                prov_rec = None
            prov, prov_label, prov_basis = _infer_provider(str(prov_rec or model), "opencode")
            toks = (int(r["tokens_input"] or 0) if "tokens_input" in keys else 0) + (
                int(r["tokens_output"] or 0) if "tokens_output" in keys else 0
            )
            title = redact_local_text((r["title"] if "title" in keys else None) or (r["slug"] if "slug" in keys else None) or "OpenCode session", 160)
            _attach_workspace_images(steps, roots, capture is not None)
            shown = [_strip_private_step(s) for s in steps[-10:]]
            how = dict(Counter(s["category"] for s in steps))
            substantive = [s for s in shown if s["category"] in {"file_edit", "shell", "file_read", "web", "visual"}]
            latest_action = shown[-1] if shown else None
            latest_work = substantive[-1] if substantive else latest_action
            card: dict[str, Any] = {
                "session_id": f"opencode:{sid}"[:96],
                "legacy_session_id": f"opencode:{sid[:12]}",
                "harness": "opencode",
                "harness_name": "OpenCode",
                "provider": prov,
                "provider_label": prov_label,
                "provider_basis": prov_basis,
                "agent_id": agent_id,
                "agent_name": agent_name,
                "owner_basis": "workspace",
                "workspace": directory,
                "model": model,
                "tokens_used": toks,
                "updated_at": upd_sec,
                "status": "active" if (time.time() - upd_sec) < ACTIVE_WINDOW_SEC else "idle",
                "what_done": title,
                "plan": plan,
                "how": how,
                "steps": shown,
                "latest_action": latest_action,
                "latest_work": latest_work,
                "files_edited": edited[-12:],
                "files_read": [f for f in read_files if f not in edited][-8:],
                "files_delivered": [],
            }
            if capture is not None:
                card["capture_steps"] = steps
            sessions.append(card)
    except Exception:
        return []
    finally:
        if conn is not None:
            conn.close()
    return sessions if capture is not None else sessions[:8]


def _unquote_json_scalar(val: Any) -> str:
    if isinstance(val, (dict, list)):
        return ""
    s = str(val or "").strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        try:
            parsed = json.loads(s)
            if isinstance(parsed, str):
                return parsed
        except ValueError:
            pass
        return s.strip('"')
    return s


def _antigravity_workspace(home_dir: Path, conv_id: str, roots: list[Path]) -> tuple[str, str]:
    base = home_dir / ".gemini/antigravity-acp"
    db = base / "conversations" / f"{conv_id}.db"
    if db.is_file():
        try:
            conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
            try:
                row = conn.execute("SELECT data FROM trajectory_metadata_blob LIMIT 1").fetchone()
            finally:
                conn.close()
            blob = bytes(row[0] or b"") if row else b""
            for raw in re.findall(rb"file://(/[\x21-\x7e]{1,300})", blob):
                for cut in range(len(raw), 0, -1):
                    cand = raw[:cut].decode("utf-8", "ignore")
                    if _is_within_roots(cand, roots) and Path(cand).is_dir():
                        return cand, "conversation metadata"
        except sqlite3.Error:
            pass
    for sub in base.glob(f"brain/*/.system_generated/subagents/{conv_id}.json"):
        try:
            uris = json.loads(sub.read_text(encoding="utf-8", errors="ignore")[:20000]).get("workspaceUris") or []
        except (OSError, ValueError, AttributeError):
            continue
        for uri in uris:
            cand = _strip_file_uri(str(uri or ""))
            if cand and _is_within_roots(cand, roots):
                return cand, "subagent metadata"
    return "", "unknown"


def _collect_antigravity_sessions(
    roots: list[Path],
    home_dir: Path,
    labels: dict[str, str],
    capture: _FallbackCapture | None = None,
) -> list[dict[str, Any]]:
    brain = home_dir / ".gemini/antigravity-acp/brain"
    if not brain.is_dir():
        return []
    limit_scan = 40 if capture is not None else 8
    try:
        candidates = sorted(
            (
                (d / ".system_generated/logs/transcript.jsonl", d)
                for d in brain.iterdir()
                if d.is_dir() and (d / ".system_generated/logs/transcript.jsonl").is_file()
            ),
            key=lambda item: item[0].stat().st_mtime,
            reverse=True,
        )[:limit_scan]
    except OSError:
        return []

    sessions: list[dict[str, Any]] = []
    for tr, d in candidates:
        if capture is not None and capture.unchanged(tr):
            continue
        workspace, owner_basis = _antigravity_workspace(home_dir, d.name, roots)
        if not workspace or not _is_within_roots(workspace, roots):
            continue
        lines = list(_iter_source_lines(tr, capture))
        steps: list[dict[str, Any]] = []
        edited: list[str] = []
        read_files: list[str] = []
        plan: list[dict[str, Any]] = []
        what_done = ""
        model = "gemini"

        for src_prefix, ln in lines:
            start_idx = len(steps)
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
                what_done = redact_local_text(o["content"], 260)
                chk = _extract_checklist(o["content"])
                if chk:
                    plan = chk
                if o.get("model"):
                    model = str(o["model"])
            for c in calls:
                if not isinstance(c, dict):
                    continue
                tname = str(c.get("name") or "tool")
                args = c.get("args") if isinstance(c.get("args"), dict) else {}
                eff_name = tname
                if _tool_key(tname) == "tool_call":
                    raw_arg_json = args.get("arguments")
                    parsed_inner: dict[str, Any] = {}
                    if isinstance(raw_arg_json, dict):
                        parsed_inner = raw_arg_json
                    elif isinstance(raw_arg_json, str):
                        try:
                            tmp = json.loads(raw_arg_json)
                            if isinstance(tmp, dict):
                                parsed_inner = tmp
                        except ValueError:
                            parsed_inner = {}
                    if parsed_inner.get("name"):
                        eff_name = str(parsed_inner["name"])

                cat, lbl = _categorize_tool(eff_name)
                fp_raw = _unquote_json_scalar(args.get("Path") or args.get("TargetFile") or args.get("AbsolutePath"))
                step_files: list[str] = []
                if fp_raw:
                    safe_f = _filter_allowed_file(fp_raw, workspace, roots)
                    if safe_f:
                        step_files = [safe_f]
                        if cat == "file_edit" and safe_f not in edited:
                            edited.append(safe_f)
                        elif cat == "file_read" and safe_f not in read_files:
                            read_files.append(safe_f)
                summary_arg = _unquote_json_scalar(args.get("toolSummary"))
                if summary_arg:
                    lbl = summary_arg
                elif step_files:
                    lbl = f"{lbl} ({Path(step_files[0]).name})"
                elif cat in {"file_edit", "file_read"} and fp_raw:
                    verb = "Edit" if cat == "file_edit" else "Read"
                    lbl = f"{verb} a protected file" if is_sensitive_path(fp_raw) else f"{verb} a file outside the shared folders"

                step_obj: dict[str, Any] = {
                    "tool": eff_name,
                    "category": cat,
                    "label": redact_local_text(lbl, 120),
                    "time": str(o.get("created_at") or "")[:36],
                    "status": "completed",
                    "files": step_files[:6],
                    "file_basis": "confirmed" if cat in {"file_edit", "file_read"} and step_files else "recorded",
                }
                if _tool_key(eff_name) in {"run_command", "run_terminal_command", "execute_command"} and args.get("CommandLine"):
                    raw_cmd = _unquote_json_scalar(args["CommandLine"])
                    if not summary_arg:
                        step_obj["label"] = command_kind(raw_cmd)
                    step_obj.update(
                        execution_detail(raw_cmd, c.get("output"), c.get("exit_code"), capture_mode=capture is not None)
                    )
                steps.append(step_obj)
            if src_prefix:
                for step_pos, st_item in enumerate(steps[start_idx:]):
                    st_item["src"] = f"{src_prefix}:{step_pos}"

        agent_id, agent_name = _derive_agent_identity(workspace, labels, roots)
        prov, prov_label, prov_basis = _infer_provider(model, "antigravity")
        mtime = tr.stat().st_mtime
        _attach_workspace_images(steps, roots, capture is not None)
        shown = [_strip_private_step(s) for s in steps[-10:]]
        how = dict(Counter(s["category"] for s in steps))
        substantive = [s for s in shown if s["category"] in {"file_edit", "shell", "file_read", "web", "visual"}]
        latest_action = shown[-1] if shown else None
        latest_work = substantive[-1] if substantive else latest_action
        card: dict[str, Any] = {
            "session_id": f"antigravity:{d.name}"[:96],
            "legacy_session_id": f"antigravity:{d.name[:12]}",
            "harness": "antigravity",
            "harness_name": "Gemini / Antigravity",
            "provider": prov,
            "provider_label": prov_label,
            "provider_basis": prov_basis,
            "agent_id": agent_id,
            "agent_name": agent_name,
            "owner_basis": owner_basis,
            "workspace": workspace,
            "model": model,
            "tokens_used": 0,
            "updated_at": mtime,
            "status": "active" if (time.time() - mtime) < ACTIVE_WINDOW_SEC else "idle",
            "what_done": what_done or "Active Antigravity session in configured workspace.",
            "plan": plan[:10],
            "how": how,
            "steps": shown,
            "latest_action": latest_action,
            "latest_work": latest_work,
            "files_edited": edited[-12:],
            "files_read": [f for f in read_files if f not in edited][-8:],
            "files_delivered": [],
        }
        if capture is not None:
            card["capture_steps"] = steps
        sessions.append(card)
    return sessions if capture is not None else sessions[:8]


def _categorize_file(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
        return "image"
    if ext in {".py", ".js", ".ts", ".tsx", ".go", ".rs", ".sh", ".ps1", ".sql"}:
        return "code"
    if ext in {".html", ".css", ".svg"}:
        return "ui"
    if ext in {".md", ".txt", ".pdf"}:
        return "doc"
    if ext in {".json", ".jsonl", ".csv", ".yaml", ".yml", ".toml"}:
        return "data"
    return "other"


def _collect_workspaces(
    roots: list[Path], sessions: list[dict[str, Any]], host_id: str, max_files: int = 400
) -> list[dict[str, Any]]:
    editors: dict[str, list[str]] = {}
    for s in sessions:
        for fp in s.get("files_edited") or []:
            editors.setdefault(fp, [])
            tag = f"{s['agent_name']} · {s['harness_name']}"
            if tag not in editors[fp]:
                editors[fp].append(tag)

    out: list[dict[str, Any]] = []
    for root in roots:
        files: list[dict[str, Any]] = []
        folders: Counter[str] = Counter()
        total = 0
        latest = root.stat().st_mtime
        base_depth = len(root.parts)

        for cur, dirs, names in os.walk(root):
            cur_p = Path(cur)
            depth = len(cur_p.parts) - base_depth
            dirs[:] = sorted(
                d
                for d in dirs
                if depth < 4 and d not in SKIP_WALK_DIRS and not d.startswith(".") and not is_sensitive_path(str(cur_p / d))
            )
            for n in names:
                if n.startswith("."):
                    continue
                fp = cur_p / n
                if is_sensitive_path(str(fp)):
                    continue
                try:
                    st = fp.lstat()
                except OSError:
                    continue
                if not os.path.isfile(fp) or fp.is_symlink():
                    continue
                total += 1
                rel = str(fp.relative_to(root))
                folders[rel.split("/", 1)[0] if "/" in rel else "."] += 1
                latest = max(latest, st.st_mtime)
                full_str = str(fp.resolve())
                files.append(
                    {
                        "path": full_str,
                        "rel_path": rel,
                        "size_kb": round(st.st_size / 1024.0, 1),
                        "mtime": st.st_mtime,
                        "category": _categorize_file(fp),
                        "edited_by": editors.get(full_str, []),
                    }
                )
                if total >= max_files:
                    break
            if total >= max_files:
                break

        files.sort(key=lambda f: f["mtime"], reverse=True)
        out.append(
            {
                "id": f"workspace:{host_id}:{root.name}",
                "host_id": host_id,
                "label": root.name,
                "kind": "workspace",
                "agent_id": "",
                "path": str(root),
                "file_count": total,
                "truncated": total >= max_files,
                "last_modified": latest,
                "folders": [{"name": k, "files": v} for k, v in folders.most_common(8)],
                "recent_files": files[:10],
            }
        )
    out.sort(key=lambda w: w["last_modified"], reverse=True)
    return out


def _load_activity_core():
    """Import activity_core.py (or backend/activity_inspector.py in-repo) if available."""
    for cand_dir in (Path(__file__).resolve().parent, Path(__file__).resolve().parent.parent / "backend"):
        if (cand_dir / "activity_core.py").is_file() or (cand_dir / "activity_inspector.py").is_file():
            if str(cand_dir) not in sys.path:
                sys.path.insert(0, str(cand_dir))
    try:
        import activity_core as _core  # type: ignore

        return _core
    except ImportError:
        try:
            import activity_inspector as _core  # type: ignore

            return _core
        except ImportError:
            return None


def collect_remote_activity_payload(
    raw_roots: str | list[str] | None = None,
    host_id: str | None = None,
    home_dir: Path | None = None,
) -> dict[str, Any] | None:
    """Collect locally-redacted, folder-scoped activity payload for POST /api/v1/ingest/activity.

    Returns None when no activity roots are configured (privacy opt-in by default).
    """
    t0 = time.perf_counter()
    configured = raw_roots if raw_roots is not None else os.environ.get("SWARMCONTROL_ACTIVITY_ROOTS", "")
    roots = parse_activity_roots(configured)
    if not roots:
        return None

    hostname = socket.gethostname()
    resolved_host_id = host_id or os.environ.get("SWARMCONTROL_HOST_ID") or hostname
    resolved_home = home_dir or Path(os.environ.get("SWARMCONTROL_ACTIVITY_HOME") or Path.home())
    labels = _load_custom_labels()

    # If activity_core.py (or backend/activity_inspector.py) is available and default home_dir is used,
    # delegate to its Scope collector so remote hosts get identical Antigravity + longest-root attribution.
    if home_dir is None:
        _core = _load_activity_core()
        if _core is not None:
            scope = _core.Scope(roots=roots, labels=labels, host_id=resolved_host_id)
            snap = _core.collect_activity(scope)
            snap["os_name"] = detect_os_platform()
            snap["arch"] = platform.machine() or "unknown"
            snap["capture_reader"] = "core"
            return snap
        if os.environ.get("SWARMCONTROL_ALLOW_FALLBACK") != "1":
            raise RuntimeError("activity_core.py is required for activity collection")

    host_snap = collect_host_snapshot(host_id=resolved_host_id)
    sessions = (
        _collect_codex_sessions(roots, resolved_home, labels)
        + _collect_claude_sessions(roots, resolved_home, labels)
        + _collect_opencode_sessions(roots, resolved_home, labels)
        + _collect_antigravity_sessions(roots, resolved_home, labels)
    )
    sessions.sort(key=lambda s: float(s.get("updated_at") or 0.0), reverse=True)
    for s in sessions:
        s["host_id"] = resolved_host_id

    workspaces = _collect_workspaces(roots, sessions, resolved_host_id)
    scan_ms = round((time.perf_counter() - t0) * 1000.0, 2)

    return {
        "schema_version": "1.0",
        "host_id": resolved_host_id,
        "hostname": hostname,
        "os_name": detect_os_platform(),
        "arch": platform.machine() or "unknown",
        "collected_at": time.time(),
        "scan_ms": scan_ms,
        "capture_reader": "fallback",
        "fallback_reason": "explicit_home_dir" if home_dir is not None else "activity_core_missing",
        "activity_roots": [str(r) for r in roots],
        "harnesses": host_snap.get("harnesses") or [],
        "sessions": sessions[:24],
        "workspaces": workspaces[:16],
    }


def collect_incremental_activity(
    raw_roots: str | list[str] | None = None,
    host_id: str | None = None,
    home_dir: Path | None = None,
    offsets: dict[str, dict[str, int]] | None = None,
    ceiling: int | None = None,
    use_core: bool | None = None,
) -> tuple[dict[str, Any] | None, dict[str, dict[str, int]], bool]:
    """Collect incremental activity since `offsets` and return (payload, next_offsets, has_backlog)."""
    t0 = time.perf_counter()
    configured = raw_roots if raw_roots is not None else os.environ.get("SWARMCONTROL_ACTIVITY_ROOTS", "")
    roots = parse_activity_roots(configured)
    prior_offsets = dict(offsets or {})
    if not roots:
        return None, prior_offsets, False

    hostname = socket.gethostname()
    resolved_host_id = host_id or os.environ.get("SWARMCONTROL_HOST_ID") or hostname
    resolved_home = Path(home_dir) if home_dir is not None else Path(os.environ.get("SWARMCONTROL_ACTIVITY_HOME") or Path.home())
    labels = _load_custom_labels()

    fallback_reason = "explicit_fallback"
    if use_core is not False:
        try_core = _load_activity_core()
        if try_core is not None:
            prev_home = getattr(try_core, "HOME", None)
            try:
                if home_dir is not None and hasattr(try_core, "HOME"):
                    try_core.HOME = resolved_home
                scope = try_core.Scope(roots=roots, labels=labels, host_id=resolved_host_id)
                cap = (
                    try_core.Capture(prior_offsets)
                    if ceiling is None
                    else try_core.Capture(prior_offsets, ceiling=ceiling)
                )
                snap = try_core.collect_activity(scope, cap)
                merged_offsets = {**prior_offsets, **cap.read}
                steps_seen = sum(len(s.get("capture_steps", s.get("steps", []))) for s in snap.get("sessions", []))
                snap["os_name"] = detect_os_platform()
                snap["arch"] = platform.machine() or "unknown"
                snap["activity_roots"] = [str(r) for r in roots]
                snap["activity_enabled"] = True
                snap["capture_reader"] = "core"
                snap["map_update"] = bool(snap.get("sessions")) or not prior_offsets
                if cap.gaps:
                    snap["capture_gaps"] = [
                        {"file": str(g.get("file") or ""), "reason": str(g.get("reason") or "log rotated")}
                        for g in cap.gaps
                    ]
                legacy_map = {
                    k: int(v.get("legacy_until", 0) or 0)
                    for k, v in merged_offsets.items()
                    if int(v.get("legacy_until", 0) or 0) > 0
                }
                if legacy_map:
                    snap["capture_legacy_until"] = legacy_map
                snap["capture_metrics"] = {
                    "steps_seen": steps_seen,
                    "pending": 0,
                    "files_read": cap.files_read,
                    "bytes_read": cap.bytes_read,
                    "backlog_files": len(cap.backlog),
                    "ms": snap.get("scan_ms", 0.0),
                }
                return snap, merged_offsets, bool(cap.backlog)
            finally:
                if prev_home is not None and hasattr(try_core, "HOME"):
                    try_core.HOME = prev_home
        if use_core is True or os.environ.get("SWARMCONTROL_ALLOW_FALLBACK") != "1":
            raise RuntimeError(
                "activity_core.py is required for incremental capture; upgrade observer or set SWARMCONTROL_ALLOW_FALLBACK=1"
            )
        fallback_reason = "activity_core_missing"

    cap_fb = _FallbackCapture(prior_offsets, ceiling=ceiling)
    host_snap = collect_host_snapshot(host_id=resolved_host_id)
    sessions = (
        _collect_codex_sessions(roots, resolved_home, labels, capture=cap_fb)
        + _collect_claude_sessions(roots, resolved_home, labels, capture=cap_fb)
        + _collect_opencode_sessions(roots, resolved_home, labels, capture=cap_fb)
        + _collect_antigravity_sessions(roots, resolved_home, labels, capture=cap_fb)
    )
    sessions.sort(key=lambda s: float(s.get("updated_at") or 0.0), reverse=True)
    for s in sessions:
        s["host_id"] = resolved_host_id

    workspaces = _collect_workspaces(roots, sessions, resolved_host_id)
    scan_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    merged_offsets = {**prior_offsets, **cap_fb.read}
    steps_seen = sum(len(s.get("capture_steps", s.get("steps", []))) for s in sessions)

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "host_id": resolved_host_id,
        "hostname": hostname,
        "os_name": detect_os_platform(),
        "arch": platform.machine() or "unknown",
        "collected_at": time.time(),
        "scan_ms": scan_ms,
        "activity_enabled": True,
        "activity_roots": [str(r) for r in roots],
        "capture_reader": "fallback",
        "fallback_reason": fallback_reason,
        "harnesses": host_snap.get("harnesses") or [],
        "sessions": sessions[:100],
        "workspaces": workspaces[:16],
        "map_update": bool(sessions) or not prior_offsets,
        "capture_metrics": {
            "steps_seen": steps_seen,
            "pending": 0,
            "files_read": cap_fb.files_read,
            "bytes_read": cap_fb.bytes_read,
            "backlog_files": len(cap_fb.backlog),
            "ms": scan_ms,
        },
    }
    if cap_fb.gaps:
        payload["capture_gaps"] = [
            {"file": str(g.get("file") or ""), "reason": str(g.get("reason") or "log rotated")}
            for g in cap_fb.gaps
        ]
    legacy_map = {
        k: int(v.get("legacy_until", 0) or 0)
        for k, v in merged_offsets.items()
        if int(v.get("legacy_until", 0) or 0) > 0
    }
    if legacy_map:
        payload["capture_legacy_until"] = legacy_map
    return payload, merged_offsets, bool(cap_fb.backlog)


def _json_bytes(obj: Any) -> int:
    return len(json.dumps(obj).encode("utf-8"))


def _legacy_for_steps(steps: list[dict[str, Any]], full_legacy: dict[str, int]) -> dict[str, int]:
    if not full_legacy:
        return {}
    out: dict[str, int] = {}
    for st in steps:
        src = st.get("src")
        if isinstance(src, str) and ":" in src:
            fk = src.split(":", 1)[0]
            if fk in full_legacy:
                out[fk] = full_legacy[fk]
    return out


def chunk_activity_payload(payload: dict[str, Any], max_bytes: int = 320_000) -> list[dict[str, Any]]:
    """Split a large activity payload into ordered chunks strictly under `max_bytes` UTF-8 JSON."""
    sessions = payload.get("sessions") or []
    total_cap = sum(len(s.get("capture_steps") or []) for s in sessions)
    if _json_bytes(payload) <= max_bytes and total_cap <= 1500 and len(sessions) <= 200:
        return [payload]

    full_legacy = dict(payload.get("capture_legacy_until") or {})
    capture_gaps = list(payload.get("capture_gaps") or [])
    capture_metrics = payload.get("capture_metrics")

    chunks: list[dict[str, Any]] = []

    if payload.get("map_update", True):
        map_sessions = []
        for s in sessions[:24]:
            ms = {k: v for k, v in s.items() if k != "capture_steps"}
            ms["capture_steps"] = []
            if isinstance(ms.get("steps"), list):
                ms["steps"] = [_strip_private_step(st) if isinstance(st, dict) else st for st in ms["steps"]]
            for lk in ("latest_action", "latest_work"):
                if isinstance(ms.get(lk), dict):
                    ms[lk] = _strip_private_step(ms[lk])
            map_sessions.append(ms)
        map_chunk: dict[str, Any] = {
            "schema_version": payload.get("schema_version", "1.0"),
            "host_id": payload["host_id"],
            "hostname": payload.get("hostname", payload["host_id"]),
            "os_name": payload.get("os_name", "unknown"),
            "arch": payload.get("arch", "unknown"),
            "collected_at": payload.get("collected_at", time.time()),
            "scan_ms": payload.get("scan_ms", 0.0),
            "activity_enabled": bool(payload.get("activity_enabled", True)),
            "activity_roots": list(payload.get("activity_roots") or []),
            "harnesses": list(payload.get("harnesses") or []),
            "sessions": map_sessions,
            "workspaces": list(payload.get("workspaces") or []),
            "map_update": True,
            **({"capture_reader": payload["capture_reader"]} if payload.get("capture_reader") else {}),
            **({"fallback_reason": payload["fallback_reason"]} if payload.get("fallback_reason") else {}),
        }
        while _json_bytes(map_chunk) > max_bytes and map_chunk["workspaces"]:
            map_chunk["workspaces"].pop()
        while _json_bytes(map_chunk) > max_bytes and len(map_chunk["sessions"]) > 1:
            map_chunk["sessions"].pop()
        chunks.append(map_chunk)

    def _base_delta() -> dict[str, Any]:
        return {
            "schema_version": payload.get("schema_version", "1.0"),
            "host_id": payload["host_id"],
            "hostname": payload.get("hostname", payload["host_id"]),
            "os_name": payload.get("os_name", "unknown"),
            "arch": payload.get("arch", "unknown"),
            "collected_at": payload.get("collected_at", time.time()),
            "scan_ms": payload.get("scan_ms", 0.0),
            "activity_enabled": bool(payload.get("activity_enabled", True)),
            "activity_roots": list(payload.get("activity_roots") or []),
            "harnesses": [],
            "sessions": [],
            "workspaces": [],
            "map_update": False,
            **({"capture_reader": payload["capture_reader"]} if payload.get("capture_reader") else {}),
            **({"fallback_reason": payload["fallback_reason"]} if payload.get("fallback_reason") else {}),
        }

    meta_keys = (
        "session_id",
        "host_id",
        "harness",
        "harness_name",
        "agent_id",
        "agent_name",
        "owner_basis",
        "workspace",
        "current_folder",
        "model",
        "tokens_used",
        "updated_at",
        "status",
    )

    cur = _base_delta()
    cur_steps = 0

    def _flush_cur() -> None:
        nonlocal cur, cur_steps
        if cur["sessions"]:
            all_st = [st for sess in cur["sessions"] for st in sess.get("capture_steps") or []]
            leg = _legacy_for_steps(all_st, full_legacy)
            if leg:
                cur["capture_legacy_until"] = leg
            chunks.append(cur)
        cur = _base_delta()
        cur_steps = 0

    def _fit_single_step(step: dict[str, Any], cur: dict[str, Any], entry: dict[str, Any], budget: int) -> dict[str, Any] | None:
        cand = dict(step)
        previews = cand.get("image_previews")
        if isinstance(previews, list) and len(previews) > 1:
            for keep in range(len(previews) - 1, 0, -1):
                cand["image_previews"] = previews[:keep]
                entry["capture_steps"] = [cand]
                if _json_bytes(cur) <= budget:
                    return cand
        if "image_previews" in cand:
            cand.pop("image_previews", None)
            entry["capture_steps"] = [cand]
            if _json_bytes(cur) <= budget:
                return cand
        if "text_previews" in cand:
            cand.pop("text_previews", None)
            entry["capture_steps"] = [cand]
            if _json_bytes(cur) <= budget:
                return cand
        out_val = cand.get("command_output")
        if isinstance(out_val, str) and out_val:
            lo_len, hi_len, best_len = 0, len(out_val), -1
            cand["output_truncated"] = True
            while lo_len <= hi_len:
                mid_len = (lo_len + hi_len) // 2
                cand["command_output"] = out_val[:mid_len]
                entry["capture_steps"] = [cand]
                if _json_bytes(cur) <= budget:
                    best_len = mid_len
                    lo_len = mid_len + 1
                else:
                    hi_len = mid_len - 1
            if best_len >= 0:
                cand["command_output"] = out_val[:best_len]
                entry["capture_steps"] = [cand]
                return cand
            cand.pop("command_output", None)
            entry["capture_steps"] = [cand]
            if _json_bytes(cur) <= budget:
                return cand
        return None

    for s in sessions:
        cap_steps = list(s.get("capture_steps") if s.get("capture_steps") is not None else s.get("steps") or [])
        if not cap_steps:
            continue
        stub = {k: s[k] for k in meta_keys if k in s}
        stub["steps"] = []
        idx = 0
        while idx < len(cap_steps):
            if len(cur["sessions"]) >= 180 or cur_steps >= 1500:
                _flush_cur()
            rem = cap_steps[idx:]
            # Binary search largest slice of rem that fits in cur under max_bytes - 2048
            budget = max(4096, max_bytes - 2048)
            entry = {**stub, "capture_steps": []}
            cur["sessions"].append(entry)
            base_sz = _json_bytes(cur)
            if base_sz > budget and len(cur["sessions"]) > 1:
                cur["sessions"].pop()
                _flush_cur()
                entry = {**stub, "capture_steps": []}
                cur["sessions"].append(entry)

            lo, hi, best = 1, min(len(rem), 1500 - cur_steps), 0
            while lo <= hi:
                mid = (lo + hi) // 2
                entry["capture_steps"] = rem[:mid]
                if _json_bytes(cur) <= budget:
                    best = mid
                    lo = mid + 1
                else:
                    hi = mid - 1

            if best == 0:
                if len(cur["sessions"]) > 1:
                    cur["sessions"].pop()
                    _flush_cur()
                    continue
                fitted = _fit_single_step(rem[0], cur, entry, budget)
                if fitted is not None:
                    entry["capture_steps"] = [fitted]
                    cur_steps += 1
                    idx += 1
                    _flush_cur()
                    continue
                cur["sessions"].pop()
                idx += 1
                continue

            entry["capture_steps"] = rem[:best]
            cur_steps += best
            idx += best
            if best < len(rem):
                _flush_cur()

    _flush_cur()

    if not chunks:
        chunks.append(_base_delta())

    tail = chunks[-1]
    if capture_gaps:
        tail["capture_gaps"] = capture_gaps
    if capture_metrics is not None:
        tail["capture_metrics"] = capture_metrics
    if _json_bytes(tail) > max_bytes:
        tail.pop("capture_gaps", None)
        tail.pop("capture_metrics", None)
        meta_tail = _base_delta()
        if capture_gaps:
            meta_tail["capture_gaps"] = capture_gaps
        if capture_metrics is not None:
            meta_tail["capture_metrics"] = capture_metrics
        chunks.append(meta_tail)

    return chunks


if __name__ == "__main__":
    roots_arg = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SWARMCONTROL_ACTIVITY_ROOTS", "")
    res = collect_remote_activity_payload(roots_arg)
    print(json.dumps(res or {"activity_shipping": "disabled (no SWARMCONTROL_ACTIVITY_ROOTS set)"}, indent=2))
