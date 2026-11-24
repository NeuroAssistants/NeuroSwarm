"""NeuroSwarm structured event integrations (Claude Code hooks & generic CLI wrapper)."""

from .client import (
    ClientConfig,
    EmitResult,
    SwarmEventClient,
    detect_rate_limit,
    extract_http_status,
    load_config,
    normalize_error_signature,
    redact_secrets,
)

__all__ = [
    "ClientConfig",
    "EmitResult",
    "SwarmEventClient",
    "detect_rate_limit",
    "extract_http_status",
    "load_config",
    "normalize_error_signature",
    "redact_secrets",
]
