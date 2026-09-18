"""Notification channels, subscriptions and deliveries (FR-INT-01).

Managing these is platform administration, not device work, so everything sits behind
`integration:read` / `integration:write` rather than any device permission. The people
who operate the switches are not the people who decide where security alerts are sent.

**No endpoint returns a channel's secret.** `ChannelRead` has no field for it and the
service never opens the sealed blob for a read path. A Slack incoming-webhook URL is a
bearer credential: an API that echoed it would turn everyone who can list channels into
someone who can post as NetSecOps.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import select

from netsecops.api.deps import PrincipalDep, SessionDep, VaultDep, require, verify_csrf
from netsecops.core.errors import NotFoundError
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.db.models.audit import AuditAction
from netsecops.db.models.notifications import (
    NotificationChannel,
    NotificationDelivery,
    NotificationSubscription,
)
from netsecops.schemas.notifications import (
    ChannelCreate,
    ChannelRead,
    ChannelUpdate,
    DeliveryRead,
    SubscriptionCreate,
    SubscriptionRead,
)
from netsecops.services.audit import AuditService
from netsecops.services.notifications import NotificationService

log = get_logger(__name__)
router = APIRouter(tags=["notifications"])


def _as_read(row: NotificationChannel) -> ChannelRead:
    read = ChannelRead.model_validate(row)
    read.has_secret = row.encrypted_blob is not None
    return read


async def _channel(session: SessionDep, channel_id: uuid.UUID) -> NotificationChannel:
    row = (
        await session.execute(
            select(NotificationChannel).where(NotificationChannel.id == channel_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise NotFoundError(f"No notification channel with id {channel_id}.")
    return row


# ───────────────────────────────── channels ──────────────────────────────────


@router.get(
    "/notifications/channels",
    response_model=list[ChannelRead],
    dependencies=[Depends(require(Permission.INTEGRATION_READ))],
    summary="Notification channels (FR-INT-01)",
)
async def list_channels(session: SessionDep) -> list[ChannelRead]:
    rows = (
        (await session.execute(select(NotificationChannel).order_by(NotificationChannel.name)))
        .scalars()
        .all()
    )
    return [_as_read(row) for row in rows]


@router.post(
    "/notifications/channels",
    response_model=ChannelRead,
    status_code=201,
    dependencies=[Depends(require(Permission.INTEGRATION_WRITE)), Depends(verify_csrf)],
    summary="Add a notification channel",
)
async def create_channel(
    body: ChannelCreate, session: SessionDep, principal: PrincipalDep, vault: VaultDep
) -> ChannelRead:
    row = NotificationChannel(
        org_id=1,
        name=body.name,
        channel_type=body.channel_type,
        enabled=body.enabled,
        config=body.config,
    )
    session.add(row)
    # Flushed before sealing: the AAD is this row's id, exactly as for a device
    # credential, so the ciphertext cannot be lifted into another row.
    await session.flush()

    if body.secret:
        row.encrypted_blob = vault.seal(json.dumps(body.secret), aad=str(row.id))
        row.key_id = vault.current_key_id()
        await session.flush()

    await AuditService(session).record(
        AuditAction.SETTINGS_CHANGED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="notification_channel",
        object_id=row.id,
        details={"name": row.name, "channel_type": row.channel_type},
    )
    return _as_read(row)


@router.patch(
    "/notifications/channels/{channel_id}",
    response_model=ChannelRead,
    dependencies=[Depends(require(Permission.INTEGRATION_WRITE)), Depends(verify_csrf)],
    summary="Change a notification channel",
)
async def update_channel(
    channel_id: uuid.UUID,
    body: ChannelUpdate,
    session: SessionDep,
    principal: PrincipalDep,
    vault: VaultDep,
) -> ChannelRead:
    row = await _channel(session, channel_id)

    if body.name is not None:
        row.name = body.name
    if body.enabled is not None:
        row.enabled = body.enabled
    if body.config is not None:
        row.config = body.config
    if body.secret is not None:
        row.encrypted_blob = vault.seal(json.dumps(body.secret), aad=str(row.id))
        row.key_id = vault.current_key_id()

    await session.flush()
    await AuditService(session).record(
        AuditAction.SETTINGS_CHANGED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="notification_channel",
        object_id=row.id,
        details={"name": row.name, "secret_replaced": body.secret is not None},
    )
    return _as_read(row)


@router.delete(
    "/notifications/channels/{channel_id}",
    status_code=204,
    dependencies=[Depends(require(Permission.INTEGRATION_WRITE)), Depends(verify_csrf)],
    summary="Remove a notification channel",
)
async def delete_channel(
    channel_id: uuid.UUID, session: SessionDep, principal: PrincipalDep
) -> Response:
    row = await _channel(session, channel_id)
    await session.delete(row)
    await session.flush()

    await AuditService(session).record(
        AuditAction.SETTINGS_CHANGED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="notification_channel",
        object_id=channel_id,
        details={"deleted": True},
    )
    return Response(status_code=204)


@router.post(
    "/notifications/channels/{channel_id}/test",
    response_model=DeliveryRead,
    status_code=202,
    dependencies=[Depends(require(Permission.INTEGRATION_WRITE)), Depends(verify_csrf)],
    summary="Queue a test notification",
)
async def test_channel(
    channel_id: uuid.UUID, session: SessionDep, principal: PrincipalDep
) -> DeliveryRead:
    """Queue a test event for one channel.

    Queued rather than sent inline, deliberately. Sending here would hold the request
    open against a remote service and would exercise a *different* path from the one real
    notifications take — so a test that passed would prove very little. This puts a real
    delivery through the real queue; the result appears in the delivery list.
    """
    from netsecops.integrations.events import Event, EventKind, EventSeverity

    row = await _channel(session, channel_id)

    delivery = NotificationDelivery(
        org_id=row.org_id,
        channel_id=row.id,
        event_kind=EventKind.JOB_COMPLETED.value,
        severity=EventSeverity.INFO.value,
        title="NetSecOps test notification",
        payload=Event(
            kind=EventKind.JOB_COMPLETED,
            severity=EventSeverity.INFO,
            title="NetSecOps test notification",
            message=f"Requested by {principal.username}.",
        ).as_dict(),
        status="queued",
        attempts=0,
        # From the application clock, for the same reason `raise_event` does it: the
        # dispatcher compares this against `datetime.now(UTC)`, and the column's
        # `clock_timestamp()` default is the *database's* clock.
        next_attempt_at=datetime.now(UTC),
    )
    session.add(delivery)
    await session.flush()
    return DeliveryRead.model_validate(delivery)


# ────────────────────────────── subscriptions ────────────────────────────────


@router.get(
    "/notifications/subscriptions",
    response_model=list[SubscriptionRead],
    dependencies=[Depends(require(Permission.INTEGRATION_READ))],
    summary="Which events reach which channel",
)
async def list_subscriptions(session: SessionDep) -> list[SubscriptionRead]:
    rows = (await session.execute(select(NotificationSubscription))).scalars().all()
    return [SubscriptionRead.model_validate(row) for row in rows]


@router.post(
    "/notifications/subscriptions",
    response_model=SubscriptionRead,
    status_code=201,
    dependencies=[Depends(require(Permission.INTEGRATION_WRITE)), Depends(verify_csrf)],
    summary="Subscribe a channel to events",
)
async def create_subscription(
    body: SubscriptionCreate, session: SessionDep, principal: PrincipalDep
) -> SubscriptionRead:
    await _channel(session, body.channel_id)

    row = NotificationSubscription(
        org_id=1,
        channel_id=body.channel_id,
        event_kinds=[kind.value for kind in body.event_kinds],
        min_severity=body.min_severity.value,
        enabled=body.enabled,
    )
    session.add(row)
    await session.flush()

    await AuditService(session).record(
        AuditAction.SETTINGS_CHANGED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="notification_subscription",
        object_id=row.id,
        details={"min_severity": row.min_severity, "event_kinds": row.event_kinds},
    )
    return SubscriptionRead.model_validate(row)


@router.delete(
    "/notifications/subscriptions/{subscription_id}",
    status_code=204,
    dependencies=[Depends(require(Permission.INTEGRATION_WRITE)), Depends(verify_csrf)],
    summary="Remove a subscription",
)
async def delete_subscription(
    subscription_id: uuid.UUID, session: SessionDep, principal: PrincipalDep
) -> Response:
    row = (
        await session.execute(
            select(NotificationSubscription).where(NotificationSubscription.id == subscription_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise NotFoundError(f"No subscription with id {subscription_id}.")

    await session.delete(row)
    await session.flush()
    await AuditService(session).record(
        AuditAction.SETTINGS_CHANGED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="notification_subscription",
        object_id=subscription_id,
        details={"deleted": True},
    )
    return Response(status_code=204)


# ──────────────────────────────── deliveries ─────────────────────────────────


@router.get(
    "/notifications/deliveries",
    response_model=list[DeliveryRead],
    dependencies=[Depends(require(Permission.INTEGRATION_READ))],
    summary="Notification delivery history, including what never arrived",
)
async def list_deliveries(
    session: SessionDep,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[DeliveryRead]:
    """Successes as well as failures.

    "Was anybody actually told?" is asked after an incident, and a list holding only the
    failures cannot answer it.
    """
    stmt = (
        select(NotificationDelivery).order_by(NotificationDelivery.created_at.desc()).limit(limit)
    )
    if status_filter:
        stmt = stmt.where(NotificationDelivery.status == status_filter)

    rows = (await session.execute(stmt)).scalars().all()
    return [DeliveryRead.model_validate(row) for row in rows]


@router.post(
    "/notifications/deliveries/{delivery_id}/requeue",
    response_model=DeliveryRead,
    dependencies=[Depends(require(Permission.INTEGRATION_WRITE)), Depends(verify_csrf)],
    summary="Try a dead delivery again",
)
async def requeue_delivery(
    delivery_id: uuid.UUID, session: SessionDep, principal: PrincipalDep
) -> DeliveryRead:
    """Put a delivery that gave up back in the queue.

    The attempt count resets: what killed it is usually a configuration error somebody has
    just corrected, and making them wait out the old backoff to find out would help
    nobody.
    """
    row = await NotificationService(session).requeue(delivery_id)
    await AuditService(session).record(
        AuditAction.SETTINGS_CHANGED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="notification_delivery",
        object_id=row.id,
        details={"requeued": True},
    )
    return DeliveryRead.model_validate(row)


__all__ = ["router"]
