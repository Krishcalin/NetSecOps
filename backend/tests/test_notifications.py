"""Raising, routing and delivering notifications (FR-INT-01).

Channels are fakes; nothing opens a socket or an SMTP session.

The assertions concentrate on the two ends of the retry policy, because both failure
modes are ones a reasonable implementation gets wrong. Retry forever and one unreachable
Slack workspace becomes an unbounded queue — a second outage caused by the first. Drop
after the last attempt and the alert is gone, which is worse: notifications exist
precisely for the cases where nobody is watching a screen.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.db.models.notifications import (
    ChannelType,
    DeliveryStatus,
    NotificationChannel,
    NotificationDelivery,
    NotificationSubscription,
)
from netsecops.integrations.channels import sign
from netsecops.integrations.events import Event, EventKind, EventSeverity
from netsecops.services.notifications import (
    BACKOFF,
    MAX_ATTEMPTS,
    NotificationService,
    wants,
)


class FakeChannel:
    def __init__(self, *, fail: int = 0) -> None:
        #: How many of the next sends should fail. -1 means always.
        self.fail = fail
        self.sent: list[Event] = []

    async def send(self, event: Event) -> None:
        if self.fail != 0:
            if self.fail > 0:
                self.fail -= 1
            raise ConnectionError("channel unavailable")
        self.sent.append(event)


def event(**overrides) -> Event:
    base = {
        "kind": EventKind.FINDING_OPENED,
        "severity": EventSeverity.HIGH,
        "title": "Telnet enabled",
        "message": "management.services.telnet.enabled is true",
        "occurred_at": datetime(2026, 9, 18, 12, 0, tzinfo=UTC),
        "device_hostname": "core-sw-01",
    }
    return Event(**{**base, **overrides})


async def make_channel(
    session: AsyncSession, *, name: str = "ops-slack", enabled: bool = True
) -> NotificationChannel:
    channel = NotificationChannel(
        org_id=1,
        name=name,
        channel_type=ChannelType.SLACK.value,
        enabled=enabled,
        config={},
    )
    session.add(channel)
    await session.flush()
    return channel


async def subscribe(
    session: AsyncSession,
    channel: NotificationChannel,
    *,
    kinds: list[str] | None = None,
    min_severity: str = "medium",
    enabled: bool = True,
) -> NotificationSubscription:
    subscription = NotificationSubscription(
        org_id=1,
        channel_id=channel.id,
        event_kinds=kinds or [],
        min_severity=min_severity,
        enabled=enabled,
    )
    session.add(subscription)
    await session.flush()
    return subscription


@pytest.fixture
def service(session: AsyncSession) -> NotificationService:
    return NotificationService(session)


async def deliveries(session: AsyncSession) -> list[NotificationDelivery]:
    return list((await session.execute(select(NotificationDelivery))).scalars())


# ═══════════════════════════════ routing ═════════════════════════════════════


def spec(*, kinds: list[str] | None = None, floor: str = "medium", enabled: bool = True):
    """A subscription built in memory, with every field set explicitly.

    `enabled` in particular: the model's `default=True` is a SQLAlchemy *insert* default,
    so an object constructed without touching the database has `enabled=None`, and a test
    that leaves it out is testing None-handling rather than the filter it meant to.
    """
    return NotificationSubscription(
        org_id=1,
        channel_id=uuid.uuid4(),
        event_kinds=kinds or [],
        min_severity=floor,
        enabled=enabled,
    )


class TestRouting:
    def test_severity_floor_applies_even_with_no_kind_filter(self) -> None:
        # "Every kind" is not the same as "no filter": the severity floor still applies.
        subscription = spec(floor="critical")
        assert wants(subscription, event(severity=EventSeverity.CRITICAL)) is True
        assert wants(subscription, event(severity=EventSeverity.HIGH)) is False

    def test_kind_filter_applies_even_at_high_severity(self) -> None:
        subscription = spec(kinds=[EventKind.KEV_MATCHED.value], floor="info")
        assert wants(subscription, event(kind=EventKind.KEV_MATCHED)) is True
        assert wants(subscription, event(kind=EventKind.FINDING_OPENED)) is False

    def test_a_low_floor_admits_a_low_severity_event(self) -> None:
        # The other legitimate subscription: "every KEV match, however it is scored".
        subscription = spec(kinds=[EventKind.KEV_MATCHED.value], floor="info")
        assert wants(subscription, event(kind=EventKind.KEV_MATCHED, severity=EventSeverity.LOW))

    def test_a_disabled_subscription_wants_nothing(self) -> None:
        assert (
            wants(spec(floor="info", enabled=False), event(severity=EventSeverity.CRITICAL))
            is False
        )


# ═══════════════════════════════ raising ═════════════════════════════════════


class TestRaising:
    async def test_one_delivery_per_matching_subscription(
        self, service: NotificationService, session: AsyncSession
    ) -> None:
        first = await make_channel(session, name="slack-a")
        second = await make_channel(session, name="slack-b")
        await subscribe(session, first)
        await subscribe(session, second)

        assert await service.raise_event(event()) == 2

    async def test_no_subscribers_is_not_an_error(self, service: NotificationService) -> None:
        # A product that failed when notifications were unconfigured would be unusable on
        # day one.
        assert await service.raise_event(event()) == 0

    async def test_a_disabled_channel_receives_nothing(
        self, service: NotificationService, session: AsyncSession
    ) -> None:
        channel = await make_channel(session, enabled=False)
        await subscribe(session, channel)

        assert await service.raise_event(event()) == 0

    async def test_the_payload_is_stored_scrubbed(
        self, service: NotificationService, session: AsyncSession
    ) -> None:
        """A secret must not reach the queue, never mind the channel.

        The delivery row outlives the send and is readable by anyone who can read the
        database, so scrubbing at send time would be too late.
        """
        channel = await make_channel(session)
        await subscribe(session, channel)

        await service.raise_event(event(message="snmp-server community S3cretStr1ng RO"))

        stored = (await deliveries(session))[0]
        assert "S3cretStr1ng" not in str(stored.payload)

    async def test_raising_touches_no_network(
        self, service: NotificationService, session: AsyncSession
    ) -> None:
        # Asserted by construction: `raise_event` is given no channel factory and cannot
        # build one. If it ever sends, this test hangs or errors rather than passing.
        channel = await make_channel(session)
        await subscribe(session, channel)

        await service.raise_event(event())
        assert [d.status for d in await deliveries(session)] == [DeliveryStatus.QUEUED.value]


# ═══════════════════════════════ delivery ════════════════════════════════════


class TestDispatch:
    async def test_a_queued_delivery_is_sent_and_marked(
        self, service: NotificationService, session: AsyncSession
    ) -> None:
        channel = await make_channel(session)
        await subscribe(session, channel)
        await service.raise_event(event())

        fake = FakeChannel()
        result = await service.dispatch(channel_factory=lambda _row: fake)

        assert result.sent == 1
        assert [e.title for e in fake.sent] == ["Telnet enabled"]
        assert (await deliveries(session))[0].status == DeliveryStatus.SENT.value

    async def test_a_sent_delivery_is_not_sent_again(
        self, service: NotificationService, session: AsyncSession
    ) -> None:
        channel = await make_channel(session)
        await subscribe(session, channel)
        await service.raise_event(event())

        fake = FakeChannel()
        await service.dispatch(channel_factory=lambda _row: fake)
        await service.dispatch(channel_factory=lambda _row: fake)

        assert len(fake.sent) == 1

    async def test_the_event_survives_the_round_trip(
        self, service: NotificationService, session: AsyncSession
    ) -> None:
        # The payload is rebuilt from JSONB, so anything the reconstruction drops is
        # silently missing from every notification.
        channel = await make_channel(session)
        await subscribe(session, channel)
        await service.raise_event(event(severity=EventSeverity.CRITICAL))

        fake = FakeChannel()
        await service.dispatch(channel_factory=lambda _row: fake)

        delivered = fake.sent[0]
        assert delivered.kind is EventKind.FINDING_OPENED
        assert delivered.severity is EventSeverity.CRITICAL
        assert delivered.device_hostname == "core-sw-01"


class TestRetry:
    async def test_a_failure_schedules_a_retry_rather_than_dying(
        self, service: NotificationService, session: AsyncSession
    ) -> None:
        channel = await make_channel(session)
        await subscribe(session, channel)
        await service.raise_event(event())

        moment = datetime.now(UTC)
        result = await service.dispatch(
            channel_factory=lambda _row: FakeChannel(fail=-1), now=moment
        )

        stored = (await deliveries(session))[0]
        assert result.failed == 1
        assert stored.status == DeliveryStatus.RETRYING.value
        assert stored.next_attempt_at is not None
        assert stored.next_attempt_at > moment

    async def test_the_backoff_grows(
        self, service: NotificationService, session: AsyncSession
    ) -> None:
        # A fixed interval hammers a struggling receiver; growing gives it room.
        channel = await make_channel(session)
        await subscribe(session, channel)
        await service.raise_event(event())

        gaps = []
        moment = datetime.now(UTC)
        for _ in range(3):
            await service.dispatch(channel_factory=lambda _row: FakeChannel(fail=-1), now=moment)
            stored = (await deliveries(session))[0]
            gaps.append(stored.next_attempt_at - moment)
            moment = stored.next_attempt_at

        assert gaps == sorted(gaps), f"backoff did not grow: {gaps}"
        assert gaps[0] == BACKOFF[0]

    async def test_a_recovered_channel_delivers_the_held_event(
        self, service: NotificationService, session: AsyncSession
    ) -> None:
        channel = await make_channel(session)
        await subscribe(session, channel)
        await service.raise_event(event())

        fake = FakeChannel(fail=1)
        await service.dispatch(channel_factory=lambda _row: fake)

        later = datetime.now(UTC) + BACKOFF[0] + timedelta(seconds=1)
        await service.dispatch(channel_factory=lambda _row: fake, now=later)

        assert len(fake.sent) == 1
        assert (await deliveries(session))[0].status == DeliveryStatus.SENT.value

    async def test_it_gives_up_into_dead_rather_than_retrying_forever(
        self, service: NotificationService, session: AsyncSession
    ) -> None:
        """An unbounded queue is a second outage caused by the first."""
        channel = await make_channel(session)
        await subscribe(session, channel)
        await service.raise_event(event())

        moment = datetime.now(UTC)
        for _ in range(MAX_ATTEMPTS):
            await service.dispatch(channel_factory=lambda _row: FakeChannel(fail=-1), now=moment)
            moment += timedelta(hours=1)

        stored = (await deliveries(session))[0]
        assert stored.status == DeliveryStatus.DEAD.value
        assert stored.attempts == MAX_ATTEMPTS
        assert stored.next_attempt_at is None

    async def test_a_dead_delivery_is_kept_not_deleted(
        self, service: NotificationService, session: AsyncSession
    ) -> None:
        # An alert nobody was told about is exactly the thing somebody needs to find
        # afterwards.
        channel = await make_channel(session)
        await subscribe(session, channel)
        await service.raise_event(event())

        moment = datetime.now(UTC)
        for _ in range(MAX_ATTEMPTS):
            await service.dispatch(channel_factory=lambda _row: FakeChannel(fail=-1), now=moment)
            moment += timedelta(hours=1)

        stored = (await deliveries(session))[0]
        assert stored.last_error is not None
        assert stored.title == "Telnet enabled"

    async def test_a_dead_delivery_can_be_requeued(
        self, service: NotificationService, session: AsyncSession
    ) -> None:
        channel = await make_channel(session)
        await subscribe(session, channel)
        await service.raise_event(event())

        moment = datetime.now(UTC)
        for _ in range(MAX_ATTEMPTS):
            await service.dispatch(channel_factory=lambda _row: FakeChannel(fail=-1), now=moment)
            moment += timedelta(hours=1)

        stored = (await deliveries(session))[0]
        await service.requeue(stored.id)

        fake = FakeChannel()
        await service.dispatch(channel_factory=lambda _row: fake, now=moment)
        assert len(fake.sent) == 1

    async def test_the_channel_records_its_last_failure(
        self, service: NotificationService, session: AsyncSession
    ) -> None:
        # So the console can show a channel that has been quietly failing since somebody
        # rotated a password.
        channel = await make_channel(session)
        await subscribe(session, channel)
        await service.raise_event(event())

        await service.dispatch(channel_factory=lambda _row: FakeChannel(fail=-1))

        await session.refresh(channel)
        assert channel.last_error is not None
        assert channel.last_failure_at is not None


# ══════════════════════════ webhook signing ══════════════════════════════════


class TestWebhookSignature:
    def test_the_timestamp_is_inside_the_signature(self) -> None:
        """Otherwise every delivery is replayable forever.

        For "a critical finding opened" that means an attacker can re-raise old alerts
        until the channel is ignored, which is a denial of attention rather than of
        service.
        """
        body = b'{"event":"finding.opened"}'
        assert sign("k", "1000", body) != sign("k", "2000", body)

    def test_a_different_key_gives_a_different_signature(self) -> None:
        body = b'{"event":"finding.opened"}'
        assert sign("key-a", "1000", body) != sign("key-b", "1000", body)

    def test_it_is_stable_for_the_same_inputs(self) -> None:
        body = b'{"event":"finding.opened"}'
        assert sign("k", "1000", body) == sign("k", "1000", body)
