"""RFC 5424 syslog to a SIEM, over TLS (FR-INT-02).

Two formats, because customers have both kinds of collector: CEF for ArcSight-lineage
tooling, and JSON for everything newer. The framing and transport are identical; only the
MSG differs.

**TLS uses octet-counting framing (RFC 6587), not newline delimiting.** A stream
collector needs to know where each message ends, and a JSON payload or a CEF extension
can legally contain a newline. Newline framing therefore splits records at arbitrary
points, and the SIEM sees a stream of fragments that parse as nothing — while the
transport reports every byte delivered. Octet counting prefixes each message with its
length and has no such ambiguity.

**The priority field inverts.** Syslog severity runs 0 (emergency) to 7 (debug), so lower
is worse — the opposite of CEF's 0–10. A table written by analogy sends critical events
as `debug`, they are dropped by the first relay filtering on severity, and the
integration looks perfectly healthy while the only events nobody sees are the urgent ones.

**A SIEM outage is not a NetSecOps outage.** Sends are bounded by a timeout and a failure
is reported to the caller to record; nothing is queued indefinitely and nothing is
retried in a loop.
"""

from __future__ import annotations

import asyncio
import json
import ssl
from dataclasses import dataclass
from datetime import UTC
from enum import StrEnum
from typing import Final

from netsecops.core.logging import get_logger
from netsecops.integrations.cef import format_event as format_cef
from netsecops.integrations.events import SYSLOG_SEVERITY, Event

log = get_logger(__name__)

#: `local0`, the conventional facility for application events.
DEFAULT_FACILITY: Final[int] = 16

#: RFC 5424 sets no maximum, but collectors do and 8 KiB is the common floor.
MAX_MESSAGE_BYTES: Final[int] = 8 * 1024

CONNECT_TIMEOUT: Final[float] = 10.0
SEND_TIMEOUT: Final[float] = 10.0

#: The ASCII BOM RFC 5424 requires before a UTF-8 MSG. Without it a strict collector is
#: entitled to treat the payload as unknown bytes, which some do by discarding it.
BOM: Final[str] = "﻿"


class SyslogFormat(StrEnum):
    CEF = "cef"
    JSON = "json"


def priority(severity_value: int, facility: int = DEFAULT_FACILITY) -> int:
    """PRI = facility × 8 + severity, per RFC 5424 §6.2.1."""
    return facility * 8 + severity_value


def _sanitise(value: str | None, *, limit: int = 255) -> str:
    """A header field, or `-` for absent.

    RFC 5424 header fields are printable ASCII without spaces, and `-` is the NILVALUE.
    An empty string is not legal there, and a collector that meets one usually discards
    the whole message.
    """
    if not value:
        return "-"
    cleaned = "".join(ch for ch in value if 33 <= ord(ch) <= 126)
    return cleaned[:limit] or "-"


def format_message(
    event: Event,
    *,
    fmt: SyslogFormat,
    hostname: str,
    app_name: str = "netsecops",
    facility: int = DEFAULT_FACILITY,
) -> str:
    """One RFC 5424 message, without framing."""
    clean = event.scrubbed()
    pri = priority(SYSLOG_SEVERITY[clean.severity], facility)
    timestamp = (
        clean.occurred_at.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    )

    if fmt is SyslogFormat.CEF:
        body = format_cef(clean)
    else:
        body = json.dumps(clean.as_dict(), separators=(",", ":"), ensure_ascii=False)

    header = (
        f"<{pri}>1 {timestamp} {_sanitise(hostname)} {_sanitise(app_name)} - "
        f"{_sanitise(clean.kind.value, limit=32)} -"
    )
    message = f"{header} {BOM}{body}"

    encoded = message.encode()
    if len(encoded) > MAX_MESSAGE_BYTES:
        # Truncated on a character boundary, then marked. A message cut mid-multibyte
        # arrives as invalid UTF-8 and is dropped whole by a strict collector — losing
        # the event entirely rather than losing its tail.
        message = encoded[:MAX_MESSAGE_BYTES].decode(errors="ignore") + "…[truncated]"

    return message


def frame(message: str) -> bytes:
    """Octet-counted framing (RFC 6587 §3.4.1): ``<length> <message>``."""
    payload = message.encode()
    return f"{len(payload)} ".encode() + payload


@dataclass(frozen=True, slots=True)
class SyslogTarget:
    host: str
    port: int = 6514
    fmt: SyslogFormat = SyslogFormat.CEF
    use_tls: bool = True
    #: Verify the collector's certificate. Defaults on, and turning it off is a decision
    #: an operator has to make explicitly — audit records and findings are being shipped
    #: to whatever answers on that address.
    verify: bool = True
    ca_file: str | None = None
    facility: int = DEFAULT_FACILITY


class SyslogForwarder:
    """Send events to a SIEM.

    A connection per batch rather than a long-lived one. A persistent TLS socket to a
    collector that silently goes away is the classic failure here — writes succeed into a
    dead half-open connection for as long as the send buffer holds — and reconnecting per
    batch trades a little overhead for knowing whether anything arrived.
    """

    def __init__(self, target: SyslogTarget, *, hostname: str = "netsecops") -> None:
        self.target = target
        self.hostname = hostname

    def _ssl_context(self) -> ssl.SSLContext | None:
        if not self.target.use_tls:
            return None
        context = ssl.create_default_context(cafile=self.target.ca_file)
        if not self.target.verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            log.warning("integrations.syslog_tls_unverified", host=self.target.host)
        return context

    async def send(self, events: list[Event]) -> int:
        """Send a batch. Returns how many were written; raises if the target is unusable."""
        if not events:
            return 0

        payload = b"".join(
            frame(
                format_message(
                    event,
                    fmt=self.target.fmt,
                    hostname=self.hostname,
                    facility=self.target.facility,
                )
            )
            for event in events
        )

        # Syslog is one-directional; the collector sends nothing back to read.
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.target.host, self.target.port, ssl=self._ssl_context()),
            timeout=CONNECT_TIMEOUT,
        )
        try:
            writer.write(payload)
            await asyncio.wait_for(writer.drain(), timeout=SEND_TIMEOUT)
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=SEND_TIMEOUT)
            except (TimeoutError, OSError):
                # The bytes are already on the wire; a collector that does not close
                # politely is not a delivery failure.
                log.debug("integrations.syslog_close_timeout", host=self.target.host)

        log.info(
            "integrations.syslog_sent",
            host=self.target.host,
            count=len(events),
            format=self.target.fmt.value,
        )
        return len(events)


__all__ = [
    "BOM",
    "CONNECT_TIMEOUT",
    "DEFAULT_FACILITY",
    "MAX_MESSAGE_BYTES",
    "SyslogFormat",
    "SyslogForwarder",
    "SyslogTarget",
    "format_message",
    "frame",
    "priority",
]
