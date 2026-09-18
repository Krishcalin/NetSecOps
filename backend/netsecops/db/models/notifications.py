"""Notification channels, subscriptions and the delivery queue (FR-INT-01).

Three tables, and the shape of each is a decision about what happens when something goes
wrong.

**A channel holds its secret sealed, like a device credential.** A Slack or Teams
incoming-webhook URL *is* a bearer credential — anyone holding it can post into that
channel — and so are an SMTP password and a webhook HMAC key. Putting any of them in the
config JSONB would make them readable by every API that returns a channel, which is the
whole reason `credentials` has an `encrypted_blob` rather than a `password` column.

**A delivery is a durable row, not an in-process retry.** The notifications that matter
most are the ones raised when something is badly wrong — a KEV match, a host key that
changed — and those are exactly the moments a process is most likely to be restarted. An
`asyncio` retry loop loses them silently.

**Retry has a ceiling and a terminal `dead` state.** Retrying forever turns a receiver's
outage into an unbounded queue, which is a second outage. Dropping silently loses the
alert. A dead delivery is visible and re-queueable, so a person decides.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    ARRAY,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netsecops.db.base import Base, OrgMixin, TimestampMixin, UUIDPrimaryKeyMixin


class ChannelType(StrEnum):
    """The transports FR-INT-01 names."""

    EMAIL = "email"
    #: A generic JSON POST, HMAC-signed so the receiver can verify the sender.
    WEBHOOK = "webhook"
    SLACK = "slack"
    TEAMS = "teams"


class DeliveryStatus(StrEnum):
    QUEUED = "queued"
    SENT = "sent"
    #: Failed and will be tried again.
    RETRYING = "retrying"
    #: Failed its last attempt. Terminal until a person re-queues it.
    DEAD = "dead"


class NotificationChannel(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Somewhere notifications can be sent."""

    __tablename__ = "notification_channels"
    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_notification_channels_org_name"),)

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    channel_type: Mapped[str] = mapped_column(String(16), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    #: Non-secret half: SMTP host and port, the from address, recipients, a webhook's
    #: method. Anything here may be shown in the UI, so nothing secret may be put here —
    #: the same contract as `credentials.metadata`.
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    #: Envelope-encrypted secret payload, AAD-bound to this row's id. Holds the SMTP
    #: password, the webhook signing key, or the Slack/Teams URL.
    encrypted_blob: Mapped[bytes | None] = mapped_column()
    key_id: Mapped[str | None] = mapped_column(String(64))

    #: Whether the last attempt worked, so the console can show a channel that has been
    #: quietly failing since somebody rotated a password.
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)

    subscriptions: Mapped[list[NotificationSubscription]] = relationship(
        back_populates="channel", cascade="all, delete-orphan"
    )


class NotificationSubscription(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Which events reach which channel.

    Filtering is by kind *and* by severity because both questions are legitimate and
    neither subsumes the other: "everything critical, whatever it is" and "every KEV
    match, however it is scored" are different subscriptions a real operator wants.
    """

    __tablename__ = "notification_subscriptions"
    __table_args__ = (Index("ix_notification_subscriptions_channel", "org_id", "channel_id"),)

    channel_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("notification_channels.id", ondelete="CASCADE"),
        nullable=False,
    )
    #: Empty means every kind. Stored as a list rather than a bitmask so a new event kind
    #: does not silently join existing subscriptions.
    event_kinds: Mapped[list[str]] = mapped_column(ARRAY(String(48)), nullable=False, default=list)
    #: The least severe event this subscription wants. `info` means everything.
    min_severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    channel: Mapped[NotificationChannel] = relationship(back_populates="subscriptions")


class NotificationDelivery(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """One attempt to get one event to one channel.

    Kept after success as well as failure. "Was anybody told?" is asked after an incident,
    and a table holding only the failures cannot answer it.
    """

    __tablename__ = "notification_deliveries"
    __table_args__ = (
        Index("ix_notification_deliveries_pending", "org_id", "status", "next_attempt_at"),
    )

    channel_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("notification_channels.id", ondelete="CASCADE"),
        nullable=False,
    )

    event_kind: Mapped[str] = mapped_column(String(48), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    #: The whole event, already scrubbed, so a retry does not have to reconstruct it from
    #: rows that may since have changed — a finding resolved between the failure and the
    #: retry should still send the alert that was raised at the time.
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    status: Mapped[str] = mapped_column(String(16), nullable=False, default=DeliveryStatus.QUEUED)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), server_default=text("clock_timestamp()")
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)


__all__ = [
    "ChannelType",
    "DeliveryStatus",
    "NotificationChannel",
    "NotificationDelivery",
    "NotificationSubscription",
]
