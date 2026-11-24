"""Zero-dependency client for emitting structured events to NeuroSwarm.

Design guarantees:
- Standard library only (Python 3.10+).
- Token is read from SWARMCONTROL_TOKEN or agent.env (never required in argv).
- host_id defaults to SWARMCONTROL_HOST_ID or socket.gethostname(), matching
  agent/detector.py so host-bound agent tokens remain consistent.
- Secret-like patterns are redacted locally before leaving the host.
- Fail-open by default so monitoring outages never block agent execution.
"""

from __future__ import annotations

import dataclasses
import json
import math
import os
import re
import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

INTEGRATION_VERSION = "0.2.0"
DEFAULT_SERVER_URL = "http://127.0.0.1:8790"
DEFAULT_TIMEOUT_SEC = 2.5
DEFAULT_ENV_FILE = Path.home() / ".local" / "share" / "swarmcontrol" / "agent.env"
VALID_SEVERITIES = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})
MAX_METADATA_BYTES = 7680  # Stay safely under backend's 8 KB metadata limit
PRIORITY_METADATA_KEYS = (
    "task_id",
    "http_status",
    "progress",
    "source",
    "tool_name",
    "hook_event",
    "exit_code",
    "command",
    "duration_ms",
    "local_redacted_patterns",
)

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b")),
    ("generic_bearer", re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{24,}")),
]

# Explicit HTTP 429 / provider rate-limit signals without matching ordinary numbers
# like "Batch 42980", "429 rows saved", or "HTTP 4299".
RATE_LIMIT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)\bHTTP(?:/\d+(?:\.\d+)?)?\s+(?:status\s+)?429\b"),
    re.compile(r"(?i)\b429\s+too\s+many\s+requests\b"),
    re.compile(r"(?i)\b(?:status[_\s-]?code|http[_\s-]?status|error[_\s-]?code)\s*[:=]\s*429\b"),
    re.compile(r"(?i)\btoo\s+many\s+requests\b"),
    re.compile(r"(?i)\brate[_\s-]?limit(?:ed|ing|_error|_exceeded|\s+(?:exceeded|reached|error))\b"),
    re.compile(r"(?i)\b(?:quota|tokens?\s+per\s+minute|requests?\s+per\s+minute)\s+(?:exceeded|exhausted)\b"),
    re.compile(r"\bRESOURCE_EXHAUSTED\b"),
]

GENERIC_HTTP_STATUS_PATTERN = re.compile(
    r"(?i)\b(?:HTTP(?:/\d+(?:\.\d+)?)?\s+(?:status\s+)?|(?:status[_\s-]?code|http[_\s-]?status)\s*[:=]\s*)([45]\d{2})\b"
)

_VOLATILE_REPLACEMENTS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"),
        "<ts>",
    ),
    (
        re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
        "<uuid>",
    ),
    (
        re.compile(r"(?i)\b((?:req|request|trace|corr)[_-]?(?:id)?\s*[:=]\s*)[A-Za-z0-9._-]{6,}\b"),
        r"\1<id>",
    ),
    (
        re.compile(r"(?i)\b(retry[- ]?after\s*[:=]?\s*)\d+(?:\.\d+)?s?\b"),
        r"\1<n>",
    ),
]


@dataclasses.dataclass(frozen=True)
class ClientConfig:
    server: str
    token: str
    host_id: str
    timeout: float = DEFAULT_TIMEOUT_SEC


@dataclasses.dataclass(frozen=True)
class EmitResult:
    ok: bool
    status_code: int | None
    response: dict[str, Any] | None
    error: str | None
    payload: dict[str, Any]


def parse_env_file(path: Path) -> dict[str, str]:
    """Read KEY=VALUE pairs from an agent.env file without failing on missing files."""
    values: dict[str, str] = {}
    try:
        if not path.is_file():
            return values
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return values

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in {"'", '"'}:
            val = val[1:-1]
        if key:
            values[key] = val
    return values


def load_config(
    *,
    server: str | None = None,
    token: str | None = None,
    host_id: str | None = None,
    timeout: float | None = None,
    env_file: str | Path | None = None,
) -> ClientConfig:
    """Resolve NeuroSwarm configuration: explicit arg > env var > agent.env > default."""
    file_vals: dict[str, str] = {}
    chosen_env = env_file if env_file is not None else os.environ.get("SWARMCONTROL_ENV_FILE")
    if chosen_env is None:
        file_vals = parse_env_file(DEFAULT_ENV_FILE)
    elif str(chosen_env).strip():
        file_vals = parse_env_file(Path(os.path.expanduser(str(chosen_env))))

    def _pick(explicit: str | None, env_key: str, default: str = "") -> str:
        if explicit is not None and explicit.strip():
            return explicit.strip()
        env_val = os.environ.get(env_key, "").strip()
        if env_val:
            return env_val
        file_val = file_vals.get(env_key, "").strip()
        if file_val:
            return file_val
        return default

    resolved_server = _pick(server, "SWARMCONTROL_SERVER", DEFAULT_SERVER_URL).rstrip("/")
    resolved_token = _pick(token, "SWARMCONTROL_TOKEN", "")
    resolved_host = _pick(host_id, "SWARMCONTROL_HOST_ID", "") or socket.gethostname()

    resolved_timeout = DEFAULT_TIMEOUT_SEC
    if timeout is not None:
        resolved_timeout = max(0.2, float(timeout))
    else:
        raw_timeout = _pick(None, "SWARMCONTROL_TIMEOUT", "")
        if raw_timeout:
            try:
                resolved_timeout = max(0.2, float(raw_timeout))
            except ValueError:
                resolved_timeout = DEFAULT_TIMEOUT_SEC

    return ClientConfig(
        server=resolved_server,
        token=resolved_token,
        host_id=resolved_host[:128],
        timeout=resolved_timeout,
    )


def redact_text(text: str) -> tuple[str, list[str]]:
    """Redact secret-like tokens from a string and report matched pattern names."""
    found: list[str] = []
    redacted = text
    for name, pattern in SECRET_PATTERNS:
        if pattern.search(redacted):
            found.append(name)
            redacted = pattern.sub(f"[REDACTED_LOCAL:{name}]", redacted)
    return redacted, found


def redact_secrets(value: Any) -> tuple[Any, list[str]]:
    """Recursively redact secret-like tokens from strings, lists, and dicts."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        out_list: list[Any] = []
        found: set[str] = set()
        for item in value:
            clean_item, item_found = redact_secrets(item)
            out_list.append(clean_item)
            found.update(item_found)
        return out_list, sorted(found)
    if isinstance(value, dict):
        out_dict: dict[str, Any] = {}
        found_dict: set[str] = set()
        for k, v in value.items():
            clean_v, v_found = redact_secrets(v)
            out_dict[str(k)] = clean_v
            found_dict.update(v_found)
        return out_dict, sorted(found_dict)
    return value, []


def detect_rate_limit(text: str) -> bool:
    """Return True if text indicates an HTTP 429 or provider rate-limit/quota exhaustion error."""
    if not text:
        return False
    return any(pat.search(text) for pat in RATE_LIMIT_PATTERNS)


def extract_http_status(text: str) -> int | None:
    """Extract an HTTP 4xx/5xx error status from text, prioritizing rate-limit 429 signals."""
    if not text:
        return None
    if detect_rate_limit(text):
        return 429
    match = GENERIC_HTTP_STATUS_PATTERN.search(text)
    if match:
        try:
            code = int(match.group(1))
            if 400 <= code <= 599:
                return code
        except ValueError:
            return None
    return None


def normalize_error_signature(text: str, max_len: int = 240) -> str:
    """Normalize volatile fields (timestamps, UUIDs, request IDs) for loop signature stability."""
    if not text:
        return ""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    sample = lines[0] if lines else text.strip()
    for pat, repl in _VOLATILE_REPLACEMENTS:
        sample = pat.sub(repl, sample)
    sample = re.sub(r"\s+", " ", sample).strip()
    if len(sample) > max_len:
        sample = sample[: max_len - 3].rstrip() + "..."
    return sample


def _sanitize_json_value(value: Any, *, depth: int = 0) -> Any:
    """Convert NaN/Infinity floats to None and ensure strict JSON compatibility."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return None if (math.isnan(value) or math.isinf(value)) else value
    if depth >= 6:
        return str(value)[:256]
    if isinstance(value, dict):
        return {str(k)[:128]: _sanitize_json_value(v, depth=depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_json_value(item, depth=depth + 1) for item in value[:64]]
    return str(value)[:256]


def _json_size_bytes(obj: Any) -> int:
    return len(json.dumps(obj, allow_nan=False, separators=(",", ":")).encode("utf-8"))


def _bound_metadata(meta: dict[str, Any], max_bytes: int = MAX_METADATA_BYTES) -> dict[str, Any]:
    """Ensure metadata serializes under max_bytes while preserving guardrail-critical keys."""
    clean = _sanitize_json_value(meta)
    if not isinstance(clean, dict):
        return {}
    if _json_size_bytes(clean) <= max_bytes:
        return clean

    # Pass 1: truncate long string values
    trimmed: dict[str, Any] = {}
    for k, v in clean.items():
        if isinstance(v, str) and len(v) > 256:
            trimmed[k] = v[:253] + "..."
        else:
            trimmed[k] = v
    trimmed["metadata_truncated"] = True
    if _json_size_bytes(trimmed) <= max_bytes:
        return trimmed

    # Pass 2: retain priority keys first, then fit remaining keys while budget allows
    bounded: dict[str, Any] = {"metadata_truncated": True}
    for key in PRIORITY_METADATA_KEYS:
        if key in trimmed:
            candidate = {**bounded, key: trimmed[key]}
            if _json_size_bytes(candidate) <= max_bytes:
                bounded = candidate
    for key, val in trimmed.items():
        if key in bounded:
            continue
        candidate = {**bounded, key: val}
        if _json_size_bytes(candidate) <= max_bytes:
            bounded = candidate
    return bounded


class SwarmEventClient:
    """Thin HTTP client for POST /api/v1/ingest/event."""

    def __init__(self, config: ClientConfig | None = None, *, local_redact: bool = True) -> None:
        self.config = config or load_config()
        self.local_redact = local_redact

    def build_payload(
        self,
        *,
        harness: str,
        agent_name: str,
        event_type: str,
        message: str,
        severity: str = "INFO",
        metadata: dict[str, Any] | None = None,
        host_id: str | None = None,
    ) -> dict[str, Any]:
        meta: dict[str, Any] = dict(metadata or {})
        clean_msg = str(message)
        found_patterns: set[str] = set()

        if self.local_redact:
            clean_msg, msg_found = redact_text(clean_msg)
            meta, meta_found = redact_secrets(meta)
            found_patterns.update(msg_found)
            found_patterns.update(meta_found)
            if found_patterns:
                meta["local_redacted_patterns"] = sorted(found_patterns)

        meta = _bound_metadata(meta)
        norm_sev = str(severity or "INFO").upper().strip()[:16]
        if norm_sev not in VALID_SEVERITIES:
            norm_sev = "INFO"

        return {
            "host_id": str(host_id or self.config.host_id)[:128],
            "harness": str(harness or "generic")[:64],
            "agent_name": str(agent_name or "worker")[:128],
            "event_type": str(event_type or "info")[:64],
            "severity": norm_sev,
            "message": clean_msg[:1000],
            "metadata": meta,
        }

    def emit(
        self,
        *,
        harness: str,
        agent_name: str,
        event_type: str,
        message: str,
        severity: str = "INFO",
        metadata: dict[str, Any] | None = None,
        host_id: str | None = None,
        dry_run: bool = False,
        raise_on_error: bool = False,
    ) -> EmitResult:
        payload = self.build_payload(
            harness=harness,
            agent_name=agent_name,
            event_type=event_type,
            message=message,
            severity=severity,
            metadata=metadata,
            host_id=host_id,
        )
        if dry_run:
            return EmitResult(ok=True, status_code=None, response={"dry_run": True}, error=None, payload=payload)

        if not self.config.token:
            err = "SWARMCONTROL_TOKEN is not configured"
            if raise_on_error:
                raise RuntimeError(err)
            return EmitResult(ok=False, status_code=None, response=None, error=err, payload=payload)

        url = f"{self.config.server}/api/v1/ingest/event"
        body = json.dumps(payload, allow_nan=False).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.config.token}",
                "User-Agent": f"NeuroSwarm-Integrations/{INTEGRATION_VERSION}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                parsed = json.loads(raw) if raw else {"ok": True}
                return EmitResult(
                    ok=200 <= resp.status < 300,
                    status_code=resp.status,
                    response=parsed if isinstance(parsed, dict) else {"raw": parsed},
                    error=None,
                    payload=payload,
                )
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            parsed_err: dict[str, Any] | None = None
            try:
                tmp = json.loads(raw)
                if isinstance(tmp, dict):
                    parsed_err = tmp
            except Exception:
                parsed_err = None
            err = f"HTTP {exc.code}: {parsed_err.get('error') if parsed_err else raw[:200]}"
            if raise_on_error:
                raise RuntimeError(err) from exc
            return EmitResult(ok=False, status_code=exc.code, response=parsed_err, error=err, payload=payload)
        except Exception as exc:
            err = str(exc)
            if raise_on_error:
                raise RuntimeError(err) from exc
            return EmitResult(ok=False, status_code=None, response=None, error=err, payload=payload)
