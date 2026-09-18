"""Notification channel, subscription and delivery schemas (FR-INT-01)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from netsecops.integrations.events import EventKind, EventSeverity

ChannelKind = Literal["email", "webhook", "slack", "teams"]


class ChannelCreate(BaseModel):
    """A new channel.

    ``secret`` is write-only and never echoed. It carries whichever secret the transport
    needs — an SMTP password, a webhook signing key, or a Slack/Teams incoming-webhook
    URL — and is sealed on arrival.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=150)
    channel_type: ChannelKind
    enabled: bool = True
    #: Non-secret settings only. Anything here is returned by the read endpoints.
    config: dict[str, Any] = Field(default_factory=dict)
    secret: dict[str, str] | None = None


class ChannelUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=150)
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    #: Replaces the sealed half entirely. Omit to leave it untouched.
    secret: dict[str, str] | None = None


class ChannelRead(BaseModel):
    """What a channel looks like from outside.

    There is deliberately no field through which the sealed half can be read back. A
    Slack URL is a bearer credential, and an API that returns it turns every reader of
    the channel list into someone who can post as NetSecOps.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    channel_type: str
    enabled: bool
    config: dict[str, Any]
    #: Whether a secret is stored, without saying what it is.
    has_secret: bool = False
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    last_error: str | None = None


class SubscriptionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel_id: uuid.UUID
    #: Empty means every kind — but the severity floor below still applies.
    event_kinds: list[EventKind] = Field(default_factory=list)
    min_severity: EventSeverity = EventSeverity.MEDIUM
    enabled: bool = True


class SubscriptionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    channel_id: uuid.UUID
    event_kinds: list[str]
    min_severity: str
    enabled: bool


class DeliveryRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    channel_id: uuid.UUID
    event_kind: str
    severity: str
    title: str
    status: str
    attempts: int
    next_attempt_at: datetime | None = None
    sent_at: datetime | None = None
    last_error: str | None = None


__all__ = [
    "ChannelCreate",
    "ChannelKind",
    "ChannelRead",
    "ChannelUpdate",
    "DeliveryRead",
    "SubscriptionCreate",
    "SubscriptionRead",
]
