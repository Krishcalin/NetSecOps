"""Raising, routing and delivering notifications (FR-INT-01).

Three steps, kept apart on purpose.

**Raise** writes a delivery row per matching subscription and returns. It is called from
inside the transaction that produced the event — an assessment, a job, a feed sync — and
must therefore never touch the network: a slow SMTP server would otherwise slow the
assessment, and a dead one would roll it back.

**Dispatch** claims due deliveries and sends them. It runs in the worker, so a receiver's
outage costs a background job rather than the thing that raised the alert.

**Retry** is bounded, with a terminal state. Retrying forever turns one receiver's outage
into an unbounded queue — a second outage caused by the first. Dropping silently loses
the alert, which is worse, because notifications exist precisely for the cases nobody is
watching a screen. So attempts back off, stop at :data:`MAX_ATTEMPTS`, and the row lands
in `dead` where a person can see and re-queue it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.crypto import SecretVault
from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.db.models.notifications import (
    ChannelType,
    DeliveryStatus,
    NotificationChannel,
    NotificationDelivery,
    NotificationSubscription,
)
from netsecops.integrations.channels import (
    Channel,
    EmailChannel,
    SlackChannel,
    TeamsChannel,
    WebhookChannel,
)
from netsecops.integrations.events import Event, EventKind, EventSeverity

log = get_logger(__name__)

#: How many times a delivery is attempted before it is left for a person.
MAX_ATTEMPTS: Final[int] = 5

#: Backoff between attempts. Explicit rather than computed so the total window is
#: obvious: roughly half an hour, which covers a service restart without holding a
#: "critical finding" alert back for a working day.
BACKOFF: Final[tuple[timedelta, ...]] = (
    timedelta(seconds=30),
    timedelta(minutes=2),
    timedelta(minutes=5),
    timedelta(minutes=20),
)

#: Severity order, least to most severe, for the `min_severity` comparison.
RANK: Final[dict[EventSeverity, int]] = {
    EventSeverity.INFO: 0,
    EventSeverity.LOW: 1,
    EventSeverity.MEDIUM: 2,
    EventSeverity.HIGH: 3,
    EventSeverity.CRITICAL: 4,
}

#: Deliveries claimed per dispatch run.
BATCH = 100


@dataclass(slots=True)
class DispatchResult:
    sent: int = 0
    failed: int = 0
    dead: int = 0


def wants(subscription: NotificationSubscription, event: Event) -> bool:
    """Whether this subscription wants this event.

    Kind *and* severity, and an empty kind list means every kind — but that is not the
    same as "no filter", because the severity floor still applies. The two questions are
    independent and both are things operators actually ask: "everything critical" and
    "every KEV match, however it is scored".
    """
    if not subscription.enabled:
        return False
    if subscription.event_kinds and event.kind.value not in subscription.event_kinds:
        return False

    floor = RANK.get(EventSeverity(subscription.min_severity), RANK[EventSeverity.MEDIUM])
    return RANK[event.severity] >= floor


def build_channel(row: NotificationChannel, secret: dict[str, Any]) -> Channel:
    """Turn a stored channel into something that can send.

    The secret half arrives already opened by the caller, so this function has no access
    to the vault and cannot be made to decrypt something by accident.
    """
    config = row.config or {}
    kind = ChannelType(row.channel_type)

    if kind is ChannelType.EMAIL:
        return EmailChannel(
            host=str(config.get("host") or ""),
            port=int(config.get("port") or 587),
            username=config.get("username"),
            password=secret.get("password"),
            use_starttls=bool(config.get("starttls", True)),
            use_ssl=bool(config.get("ssl", False)),
            sender=str(config.get("from") or "netsecops@localhost"),
            recipients=tuple(config.get("recipients") or ()),
        )

    if kind is ChannelType.WEBHOOK:
        url = secret.get("url") or config.get("url")
        if not url:
            raise ValidationProblem(f"Channel {row.name!r} has no webhook URL.")
        return WebhookChannel(
            url=str(url),
            secret=secret.get("secret"),
            verify_tls=bool(config.get("verify_tls", True)),
        )

    # Slack and Teams keep the URL in the sealed half: it is a bearer credential, and
    # anyone holding it can post into that channel.
    url = secret.get("url")
    if not url:
        raise ValidationProblem(f"Channel {row.name!r} has no incoming-webhook URL.")
    return SlackChannel(url=str(url)) if kind is ChannelType.SLACK else TeamsChannel(url=str(url))


class NotificationService:
    """Raise events, and get them delivered."""

    def __init__(
        self, session: AsyncSession, *, vault: SecretVault | None = None, org_id: int = 1
    ) -> None:
        self.session = session
        self.vault = vault
        self.org_id = org_id

    # ── raising ─────────────────────────────────────────────────────────

    async def raise_event(self, event: Event) -> int:
        """Queue this event to every subscription that wants it.

        Returns how many deliveries were written. Zero is an ordinary outcome — nobody
        subscribed — and is not an error: a product that failed when notifications were
        unconfigured would be unusable on day one.

        No network call happens here. This runs inside whatever transaction produced the
        event, and a notification must never be able to fail an assessment.
        """
        rows = (
            await self.session.execute(
                select(NotificationSubscription, NotificationChannel)
                .join(
                    NotificationChannel,
                    NotificationSubscription.channel_id == NotificationChannel.id,
                )
                .where(
                    NotificationSubscription.org_id == self.org_id,
                    NotificationChannel.enabled.is_(True),
                )
            )
        ).all()

        clean = event.scrubbed()
        queued = 0
        for subscription, channel in rows:
            if not wants(subscription, clean):
                continue
            self.session.add(
                NotificationDelivery(
                    org_id=self.org_id,
                    channel_id=channel.id,
                    event_kind=clean.kind.value,
                    severity=clean.severity.value,
                    title=clean.title[:300],
                    # Stored scrubbed and whole, so a retry sends what was raised at the
                    # time rather than re-reading rows that may since have changed — a
                    # finding resolved between the failure and the retry should still
                    # deliver the alert it caused.
                    payload=clean.as_dict(),
                    status=DeliveryStatus.QUEUED.value,
                    attempts=0,
                    # Set from the *application* clock, not left to the column's
                    # `clock_timestamp()` default. The dispatcher compares this against
                    # `datetime.now(UTC)`, and mixing the two clocks means a database
                    # server a few milliseconds ahead makes every freshly queued
                    # delivery invisible until the skew elapses — which presents as a
                    # notification system that works, slowly and unpredictably.
                    next_attempt_at=datetime.now(UTC),
                )
            )
            queued += 1

        if queued:
            await self.session.flush()
            # `event_kind`, not `event`: structlog takes the message as `event`, so that
            # keyword collides with it.
            log.info("notifications.raised", event_kind=clean.kind.value, deliveries=queued)
        return queued

    # ── dispatching ─────────────────────────────────────────────────────

    async def dispatch(
        self,
        *,
        now: datetime | None = None,
        limit: int = BATCH,
        channel_factory: Any = None,
    ) -> DispatchResult:
        """Send everything due. Runs in the worker, never in a request."""
        moment = now or datetime.now(UTC)
        result = DispatchResult()

        due = (
            await self.session.execute(
                select(NotificationDelivery, NotificationChannel)
                .join(
                    NotificationChannel,
                    NotificationDelivery.channel_id == NotificationChannel.id,
                )
                .where(
                    NotificationDelivery.org_id == self.org_id,
                    NotificationDelivery.status.in_(
                        [DeliveryStatus.QUEUED.value, DeliveryStatus.RETRYING.value]
                    ),
                    NotificationDelivery.next_attempt_at <= moment,
                    NotificationChannel.enabled.is_(True),
                )
                .order_by(NotificationDelivery.next_attempt_at)
                .limit(limit)
                .with_for_update(of=NotificationDelivery, skip_locked=True)
            )
        ).all()

        for delivery, channel in due:
            delivery.attempts += 1
            try:
                sender = (channel_factory or self._channel)(channel)
                await sender.send(Event(**_event_kwargs(delivery.payload)))
            except Exception as exc:
                reason = f"{type(exc).__name__}: {exc}"
                delivery.last_error = reason[:2000]
                channel.last_failure_at = moment
                channel.last_error = reason[:2000]

                if delivery.attempts >= MAX_ATTEMPTS:
                    # Terminal, and visible. Not deleted: an alert nobody was told about
                    # is exactly the thing somebody needs to find afterwards.
                    delivery.status = DeliveryStatus.DEAD.value
                    delivery.next_attempt_at = None
                    result.dead += 1
                    log.warning(
                        "notifications.delivery_dead",
                        channel=channel.name,
                        attempts=delivery.attempts,
                        error=reason,
                    )
                else:
                    delivery.status = DeliveryStatus.RETRYING.value
                    delivery.next_attempt_at = (
                        moment + BACKOFF[min(delivery.attempts - 1, len(BACKOFF) - 1)]
                    )
                    result.failed += 1
                continue

            delivery.status = DeliveryStatus.SENT.value
            delivery.sent_at = moment
            delivery.next_attempt_at = None
            delivery.last_error = None
            channel.last_success_at = moment
            channel.last_error = None
            result.sent += 1

        await self.session.flush()
        return result

    def _channel(self, row: NotificationChannel) -> Channel:
        secret: dict[str, Any] = {}
        if row.encrypted_blob and self.vault:
            import json

            secret = json.loads(self.vault.open(row.encrypted_blob, aad=str(row.id)))
        return build_channel(row, secret)

    # ── re-queueing ─────────────────────────────────────────────────────

    async def requeue(self, delivery_id: uuid.UUID) -> NotificationDelivery:
        """Put a dead delivery back in the queue.

        The attempt count resets, because the reason it died is usually a configuration
        error somebody has just fixed, and making them wait out the old backoff to find
        out would be pointless.
        """
        delivery = (
            await self.session.execute(
                select(NotificationDelivery).where(
                    NotificationDelivery.id == delivery_id,
                    NotificationDelivery.org_id == self.org_id,
                )
            )
        ).scalar_one_or_none()
        if delivery is None:
            raise ValidationProblem(f"No notification delivery with id {delivery_id}.")

        delivery.status = DeliveryStatus.QUEUED.value
        delivery.attempts = 0
        delivery.next_attempt_at = datetime.now(UTC)
        delivery.last_error = None
        await self.session.flush()
        return delivery


def _event_kwargs(payload: dict[str, Any]) -> dict[str, Any]:
    """Rebuild an Event from a stored delivery payload."""
    device = payload.get("device") or {}
    obj = payload.get("object") or {}
    return {
        "kind": EventKind(payload.get("event", EventKind.AUDIT.value)),
        "severity": EventSeverity(payload.get("severity", EventSeverity.INFO.value)),
        "title": payload.get("title") or "",
        "message": payload.get("message") or "",
        "occurred_at": datetime.fromisoformat(
            payload.get("occurred_at") or datetime.now(UTC).isoformat()
        ),
        "device_id": uuid.UUID(device["id"]) if device.get("id") else None,
        "device_hostname": device.get("hostname"),
        "device_ip": device.get("ip"),
        "object_type": obj.get("type"),
        "object_id": obj.get("id"),
        "attributes": payload.get("attributes") or {},
        "signature": payload.get("signature"),
    }


__all__ = [
    "BACKOFF",
    "BATCH",
    "MAX_ATTEMPTS",
    "RANK",
    "DispatchResult",
    "NotificationService",
    "build_channel",
    "wants",
]
