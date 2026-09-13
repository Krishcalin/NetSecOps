"""Structured logging with central secret scrubbing (NFR-LOG-01, C-2).

Constraint C-2 says secrets must never appear in logs. Relying on every call site to
remember that is how secrets leak, so scrubbing happens once here, in a processor every
log record passes through. Two layers:

1. Key-based redaction — any mapping key that looks secret-bearing is replaced wholesale.
2. Pattern-based redaction — free text is scanned for config idioms that carry secrets
   (``snmp-server community X``, ``key 7 ...``, ``set password ...``), because device
   configuration is exactly the kind of text this platform handles all day.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import MutableMapping
from contextvars import ContextVar
from typing import Any

import structlog
from structlog.types import EventDict, Processor

from netsecops.core.config import get_settings

REDACTED = "***REDACTED***"

#: Correlation id shared across API request → job → device session (NFR-LOG-01).
correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)

#: Mapping keys whose values are never safe to log.
SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pass",
        "secret",
        "secret_key",
        "enable_secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "api_token",
        "authorization",
        "auth",
        "cookie",
        "set_cookie",
        "private_key",
        "passphrase",
        "community",
        "snmp_community",
        "shared_secret",
        "psk",
        "pre_shared_key",
        "master_key",
        "encryption_key",
        "data_key",
        "mfa_secret",
        "totp_secret",
        "otp",
        "credential",
        "credentials",
        "session_id",
        "sid",
        "x-chkp-sid",
    }
)

#: Device-config and HTTP idioms that embed a secret in otherwise loggable text.
SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(snmp-server\s+community\s+)(\S+)", re.IGNORECASE),
    re.compile(r"((?:enable\s+)?(?:secret|password)\s+(?:\d\s+)?)(\S+)", re.IGNORECASE),
    re.compile(r"(\bkey\s+(?:\d\s+)?)(\S+)", re.IGNORECASE),
    re.compile(r"(set\s+(?:password|passwd|secret)\s+)(\S+)", re.IGNORECASE),
    re.compile(
        r"(\"?(?:password|secret|token|api_key|apikey)\"?\s*[:=]\s*\"?)([^\s\",}]+)", re.IGNORECASE
    ),
    re.compile(r"(Authorization:\s*(?:Bearer|Basic)\s+)(\S+)", re.IGNORECASE),
    re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)([\s\S]*?)(-----END [A-Z ]*PRIVATE KEY-----)"),
)


def _scrub_value(value: Any, depth: int = 0) -> Any:
    """Recursively redact secrets from an arbitrary log value."""
    if depth > 6:  # defensive: don't walk pathological structures
        return value
    if isinstance(value, MutableMapping):
        return {k: _scrub_mapping_item(k, v, depth) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        scrubbed = [_scrub_value(v, depth + 1) for v in value]
        return type(value)(scrubbed) if not isinstance(value, set) else set(scrubbed)
    if isinstance(value, str):
        return _scrub_text(value)
    return value


def _scrub_mapping_item(key: Any, value: Any, depth: int) -> Any:
    if isinstance(key, str) and key.lower().strip("_") in SENSITIVE_KEYS:
        return REDACTED
    return _scrub_value(value, depth + 1)


def _scrub_text(text: str) -> str:
    for pattern in SENSITIVE_PATTERNS:
        if pattern.groups == 3:  # PEM block: keep the delimiters, drop the body
            text = pattern.sub(rf"\1{REDACTED}\3", text)
        else:
            text = pattern.sub(rf"\1{REDACTED}", text)
    return text


def scrub_secrets(_logger: Any, _method: str, event_dict: EventDict) -> EventDict:
    """structlog processor implementing NFR-LOG-01 / C-2."""
    return {k: _scrub_mapping_item(k, v, 0) for k, v in event_dict.items()}


def add_correlation_id(_logger: Any, _method: str, event_dict: EventDict) -> EventDict:
    if (cid := correlation_id.get()) is not None:
        event_dict["correlation_id"] = cid
    return event_dict


def configure_logging() -> None:
    """Install the structlog pipeline. Idempotent — safe to call from app factory and CLI."""
    settings = get_settings()

    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        add_correlation_id,
        # Scrubbing runs last before rendering so it also covers anything the
        # processors above injected.
        scrub_secrets,
    ]

    renderer: Processor = (
        structlog.processors.JSONRenderer()
        if settings.log_format == "json"
        else structlog.dev.ConsoleRenderer(colors=True)
    )

    structlog.configure(
        processors=[*shared, structlog.processors.format_exc_info, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping()[settings.log_level]
        ),
        # A stdlib factory, not PrintLoggerFactory: `add_logger_name` reads `.name` off
        # the underlying logger, which only stdlib loggers have. It also means
        # application and library logs share one handler and one destination.
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Route stdlib loggers (uvicorn, sqlalchemy) through the same pipeline.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=logging.getLevelNamesMapping()[settings.log_level],
        force=True,
    )
    for noisy in ("uvicorn.access", "uvicorn.error", "sqlalchemy.engine"):
        logging.getLogger(noisy).handlers.clear()
        logging.getLogger(noisy).propagate = True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]
