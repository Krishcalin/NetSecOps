"""The four notification transports FR-INT-01 names.

E-mail over SMTP/TLS, a generic HMAC-signed webhook, and Slack and Teams incoming
webhooks. Each is a small class with one method, because the interesting decisions are
about *what* is sent and *how failure is reported*, not about plumbing.

**A failure raises.** No channel swallows an error or returns a boolean nobody checks.
The dispatcher records the reason on the delivery row and schedules a retry, and a
notification that silently did not arrive is the worst outcome available here — worse
than an obvious outage, because nobody investigates it.

**Nothing formats a raw event.** Every channel renders from `Event.scrubbed()`, so a
finding quoting a device's SNMP community does not post that community into a Slack
channel with two hundred members in it.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Final, Protocol

import httpx

from netsecops.core.logging import get_logger
from netsecops.integrations.events import Event, EventSeverity

log = get_logger(__name__)

SEND_TIMEOUT: Final[float] = 30.0

#: Colours for the Slack attachment and Teams card, by severity. Cosmetic, but the reason
#: these channels are chosen over e-mail is that a red bar is readable at a glance.
COLOURS: Final[dict[EventSeverity, str]] = {
    EventSeverity.CRITICAL: "#b3261e",
    EventSeverity.HIGH: "#c2410c",
    EventSeverity.MEDIUM: "#a16207",
    EventSeverity.LOW: "#1d4ed8",
    EventSeverity.INFO: "#4b5563",
}


class ChannelError(RuntimeError):
    """A send failed, with a reason fit to show an operator."""


class Channel(Protocol):
    async def send(self, event: Event) -> None: ...


# ═══════════════════════════════ e-mail ══════════════════════════════════════


@dataclass(frozen=True, slots=True)
class EmailChannel:
    """SMTP with TLS (FR-INT-01).

    `smtplib` is synchronous and there is no async SMTP client in the dependency set, so
    the send runs in a worker thread. That is deliberate rather than lazy: adding
    `aiosmtplib` to reach an event loop that is not the bottleneck here — a notification
    batch is tens of messages, not thousands — would widen the dependency surface of a
    product whose whole pitch is being careful about what it runs.

    STARTTLS by default, implicit TLS on request. Cleartext is possible only by setting
    both off, which an operator has to do explicitly.
    """

    host: str
    port: int = 587
    username: str | None = None
    password: str | None = None
    use_starttls: bool = True
    use_ssl: bool = False
    sender: str = "netsecops@localhost"
    recipients: tuple[str, ...] = ()

    def _build(self, event: Event) -> EmailMessage:
        clean = event.scrubbed()
        message = EmailMessage()
        message["Subject"] = f"[NetSecOps {clean.severity.value.upper()}] {clean.title}"
        message["From"] = self.sender
        message["To"] = ", ".join(self.recipients)

        lines = [clean.title, ""]
        if clean.message:
            lines += [clean.message, ""]
        if clean.device_hostname:
            lines.append(f"Device:   {clean.device_hostname}")
        lines.append(f"Event:    {clean.signature_id}")
        lines.append(f"Severity: {clean.severity.value}")
        lines.append(f"Occurred: {clean.occurred_at.isoformat()}")
        for key, value in sorted(clean.attributes.items()):
            lines.append(f"{key}: {value}")

        message.set_content("\n".join(lines))
        return message

    def _send_blocking(self, message: EmailMessage) -> None:
        context = ssl.create_default_context()
        try:
            if self.use_ssl:
                server: smtplib.SMTP = smtplib.SMTP_SSL(
                    self.host, self.port, timeout=SEND_TIMEOUT, context=context
                )
            else:
                server = smtplib.SMTP(self.host, self.port, timeout=SEND_TIMEOUT)
            with server:
                if self.use_starttls and not self.use_ssl:
                    server.starttls(context=context)
                if self.username:
                    server.login(self.username, self.password or "")
                server.send_message(message)
        except (smtplib.SMTPException, OSError) as exc:
            raise ChannelError(f"SMTP to {self.host}:{self.port} failed: {exc}") from exc

    async def send(self, event: Event) -> None:
        if not self.recipients:
            raise ChannelError("This e-mail channel has no recipients configured.")
        await asyncio.to_thread(self._send_blocking, self._build(event))
        log.info("integrations.email_sent", host=self.host, recipients=len(self.recipients))


# ═══════════════════════════════ webhook ═════════════════════════════════════


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """The HMAC a receiver verifies.

    Signed over ``timestamp.body`` rather than the body alone, so a captured request
    cannot be replayed indefinitely: the receiver rejects a timestamp outside its
    tolerance, and the signature is bound to the one it was sent with. Signing only the
    body makes every delivery replayable forever, which for "a critical finding opened"
    means an attacker can re-raise old alerts until the channel is ignored.
    """
    payload = timestamp.encode() + b"." + body
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class WebhookChannel:
    """A JSON POST, HMAC-signed (FR-INT-01)."""

    url: str
    secret: str | None = None
    verify_tls: bool = True

    async def send(self, event: Event) -> None:
        body = json.dumps(event.scrubbed().as_dict(), separators=(",", ":")).encode()
        timestamp = str(int(event.occurred_at.timestamp()))

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "NetSecOps/1.0",
            "X-NetSecOps-Timestamp": timestamp,
            "X-NetSecOps-Event": event.kind.value,
        }
        if self.secret:
            headers["X-NetSecOps-Signature"] = f"sha256={sign(self.secret, timestamp, body)}"

        try:
            async with httpx.AsyncClient(timeout=SEND_TIMEOUT, verify=self.verify_tls) as client:
                response = await client.post(self.url, content=body, headers=headers)
        except httpx.HTTPError as exc:
            raise ChannelError(f"Webhook POST failed: {exc}") from exc

        if response.status_code >= 400:
            raise ChannelError(f"Webhook returned HTTP {response.status_code}.")


# ════════════════════════════ Slack and Teams ════════════════════════════════


@dataclass(frozen=True, slots=True)
class SlackChannel:
    """A Slack incoming webhook.

    The URL *is* the credential — anyone holding it can post into that channel — which is
    why it is sealed in the channel row rather than stored in its config.
    """

    url: str

    def _payload(self, event: Event) -> dict[str, Any]:
        clean = event.scrubbed()
        fields = [
            {"title": "Severity", "value": clean.severity.value, "short": True},
            {"title": "Event", "value": clean.signature_id, "short": True},
        ]
        if clean.device_hostname:
            fields.append({"title": "Device", "value": clean.device_hostname, "short": True})

        return {
            "text": f"*{clean.title}*",
            "attachments": [
                {
                    "color": COLOURS[clean.severity],
                    "text": clean.message or "",
                    "fields": fields,
                    "ts": int(clean.occurred_at.timestamp()),
                }
            ],
        }

    async def send(self, event: Event) -> None:
        await _post_json(self.url, self._payload(event), "Slack")


@dataclass(frozen=True, slots=True)
class TeamsChannel:
    """A Microsoft Teams incoming webhook.

    Teams takes a MessageCard rather than Slack's shape, and its colour field is a bare
    hex string with no leading `#`. Posting Slack's payload here returns HTTP 200 with a
    body saying the card was invalid — so a naive implementation looks like it works and
    delivers nothing, which is why the response body is checked and not just the status.
    """

    url: str

    def _payload(self, event: Event) -> dict[str, Any]:
        clean = event.scrubbed()
        facts = [
            {"name": "Severity", "value": clean.severity.value},
            {"name": "Event", "value": clean.signature_id},
            {"name": "Occurred", "value": clean.occurred_at.isoformat()},
        ]
        if clean.device_hostname:
            facts.append({"name": "Device", "value": clean.device_hostname})

        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": clean.title,
            "themeColor": COLOURS[clean.severity].lstrip("#"),
            "title": clean.title,
            "sections": [{"text": clean.message or "", "facts": facts}],
        }

    async def send(self, event: Event) -> None:
        await _post_json(self.url, self._payload(event), "Teams")


async def _post_json(url: str, payload: dict[str, Any], label: str) -> None:
    try:
        async with httpx.AsyncClient(timeout=SEND_TIMEOUT) as client:
            response = await client.post(url, json=payload)
    except httpx.HTTPError as exc:
        raise ChannelError(f"{label} POST failed: {exc}") from exc

    if response.status_code >= 400:
        raise ChannelError(f"{label} returned HTTP {response.status_code}.")

    # Both services answer 200 with an error *body* for a malformed card, so the status
    # alone is not evidence of delivery.
    body = (response.text or "").strip()
    if body and body.lower() not in {"ok", "1", "success"}:
        raise ChannelError(f"{label} accepted the request but reported: {body[:200]}")


__all__ = [
    "COLOURS",
    "SEND_TIMEOUT",
    "Channel",
    "ChannelError",
    "EmailChannel",
    "SlackChannel",
    "TeamsChannel",
    "WebhookChannel",
    "sign",
]
