"""Forwarding findings and audit records to a SIEM (FR-INT-02).

The collector is a fake that records what it was handed, so these assert *what would go
on the wire* rather than that a send returned. Nothing here opens a socket.

Most of the weight is on the watermarks, because every way they can be wrong is silent.
Advance them on a failed send and the events are gone with no error anywhere. Advance the
finding watermark to the present and rows still committing are skipped. Neither shows up
at the sending end; both show up months later as "the SIEM never had that finding".
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.config import Settings
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.audit import AuditAction, Setting
from netsecops.db.models.collection import Finding
from netsecops.db.models.inventory import Device, DeviceClass, Vendor
from netsecops.integrations.events import Event, EventKind, EventSeverity
from netsecops.integrations.forwarding import (
    COMMIT_LAG,
    WATERMARK_AUDIT,
    WATERMARK_FINDINGS,
    SiemForwardingService,
    target_from,
)
from netsecops.integrations.syslog import SyslogFormat
from netsecops.services.audit import AuditService
from netsecops.services.inventory import InventoryService
from tests.conftest import make_user


class FakeCollector:
    """Records batches instead of sending them; can be told to fail."""

    def __init__(self, *, fail: bool = False) -> None:
        self.batches: list[list[Event]] = []
        self.fail = fail

    async def send(self, events: list[Event]) -> int:
        if self.fail:
            raise ConnectionRefusedError("collector is down")
        self.batches.append(list(events))
        return len(events)

    @property
    def events(self) -> list[Event]:
        return [e for batch in self.batches for e in batch]


def settings(**overrides) -> Settings:
    base = {
        "secret_key": "x" * 48,
        "master_key": "y" * 48,
        "database_url": "postgresql+asyncpg://u:p@localhost/db",
        "siem_syslog_host": "siem.internal",
    }
    return Settings(**{**base, **overrides})


async def add_audit(session: AsyncSession, action: str, *, actor: str = "alice") -> None:
    """Write through the service, not the table.

    `audit_logs` is hash-chained and its triggers reject anything that does not extend
    the chain, so a raw insert fails — which is the protection working.
    """
    await AuditService(session).record(
        AuditAction(action),
        actor_id=None,
        actor_username=actor,
        object_type="device",
        org_id=1,
    )
    await session.flush()


def findings_in(collector: FakeCollector) -> list[Event]:
    """Only the finding events.

    Creating the `device` fixture writes a `device.created` audit record, which is
    forwarded like any other — so a bare "nothing was sent" assertion would fail for a
    reason that has nothing to do with the finding under test.
    """
    return [e for e in collector.events if e.kind is EventKind.FINDING_OPENED]


@pytest.fixture
async def principal(session: AsyncSession) -> Principal:
    user = await make_user(session, username="siem_forwarder", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
async def device(session: AsyncSession, principal: Principal) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip="10.20.30.40",
        actor=principal,
        hostname="sw-siem",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )


async def add_finding(
    session: AsyncSession,
    device: Device,
    *,
    title: str,
    severity: str = "high",
    age: timedelta = timedelta(minutes=5),
) -> Finding:
    finding = Finding(
        org_id=1,
        device_id=device.id,
        kind="check",
        fingerprint=title,
        title=title,
        description="",
        severity=severity,
        status="new",
        created_at=datetime.now(UTC) - age,
    )
    session.add(finding)
    await session.flush()
    return finding


@pytest.fixture
def service(session: AsyncSession) -> SiemForwardingService:
    return SiemForwardingService(session)


# ═══════════════════════════ configuration ═══════════════════════════════════


class TestTarget:
    def test_no_host_means_forwarding_is_off(self) -> None:
        assert target_from(settings(siem_syslog_host=None)) is None

    def test_the_default_port_is_the_tls_one(self) -> None:
        # 514 is the cleartext port. Defaulting to it would ship the audit trail in the
        # clear for anyone who set only a hostname.
        assert target_from(settings()).port == 6514

    def test_tls_verification_is_on_by_default(self) -> None:
        assert target_from(settings()).verify is True

    def test_the_format_is_configurable(self) -> None:
        assert target_from(settings(siem_syslog_format="json")).fmt is SyslogFormat.JSON

    async def test_a_run_with_no_target_is_not_a_failure(
        self, service: SiemForwardingService
    ) -> None:
        # Failing would fill the job history with red for a feature the deployment has
        # deliberately not turned on.
        result = await service.forward(settings=settings(siem_syslog_host=None))
        assert (result.disabled, result.error) == (True, None)


# ══════════════════════════ the two streams ══════════════════════════════════


class TestWhatGetsForwarded:
    async def test_audit_records_carry_their_real_action_as_the_signature(
        self, service: SiemForwardingService, session: AsyncSession
    ) -> None:
        """A SIEM rule keys on `login.failure`, not on `audit`.

        Collapsing every action in the trail into one signature makes correlation
        impossible, which is most of why a SOC wants the feed at all.
        """
        await add_audit(session, "login.failure")
        collector = FakeCollector()

        await service.forward(settings=settings(), forwarder=collector)

        sent = collector.events[0]
        assert sent.kind is EventKind.AUDIT
        assert sent.signature_id == "login.failure"

    async def test_security_relevant_actions_are_raised_above_the_routine_trail(
        self, service: SiemForwardingService, session: AsyncSession
    ) -> None:
        await add_audit(session, "token.reuse_detected")
        await add_audit(session, "device.created")
        collector = FakeCollector()

        await service.forward(settings=settings(), forwarder=collector)
        by_action = {e.signature_id: e.severity for e in collector.events}

        assert by_action["token.reuse_detected"] is EventSeverity.CRITICAL
        assert by_action["device.created"] is EventSeverity.INFO

    async def test_findings_are_forwarded_with_their_severity(
        self, service: SiemForwardingService, session: AsyncSession, device: Device
    ) -> None:
        await add_finding(session, device, title="Telnet enabled", severity="critical")
        collector = FakeCollector()

        await service.forward(settings=settings(), forwarder=collector)
        finding_events = findings_in(collector)

        assert len(finding_events) == 1
        assert finding_events[0].severity is EventSeverity.CRITICAL

    async def test_nothing_new_sends_nothing(self, service: SiemForwardingService) -> None:
        collector = FakeCollector()
        result = await service.forward(settings=settings(), forwarder=collector)

        assert collector.batches == []
        assert result.total == 0


# ════════════════════════════ the watermarks ═════════════════════════════════


class TestWatermarks:
    async def test_a_record_is_not_forwarded_twice(
        self, service: SiemForwardingService, session: AsyncSession
    ) -> None:
        await add_audit(session, "login.success")
        collector = FakeCollector()

        await service.forward(settings=settings(), forwarder=collector)
        await service.forward(settings=settings(), forwarder=collector)

        assert len(collector.events) == 1

    async def test_the_next_run_picks_up_where_the_last_stopped(
        self, service: SiemForwardingService, session: AsyncSession
    ) -> None:
        await add_audit(session, "login.success")
        collector = FakeCollector()
        await service.forward(settings=settings(), forwarder=collector)

        await add_audit(session, "login.failure")
        await service.forward(settings=settings(), forwarder=collector)

        assert [e.signature_id for e in collector.events] == ["login.success", "login.failure"]

    async def test_a_failed_send_does_not_advance_the_watermark(
        self, service: SiemForwardingService, session: AsyncSession
    ) -> None:
        """The single most important behaviour here.

        Advancing on failure loses the events with no error anywhere downstream: they
        stay in the database, unreferenced, and the SIEM simply never receives them.
        """
        await add_audit(session, "login.failure")

        failed = await service.forward(settings=settings(), forwarder=FakeCollector(fail=True))
        assert failed.error is not None
        assert failed.audit_forwarded == 0

        # The collector comes back; the event is still delivered.
        recovered = FakeCollector()
        await service.forward(settings=settings(), forwarder=recovered)
        assert [e.signature_id for e in recovered.events] == ["login.failure"]

    async def test_a_finding_younger_than_the_commit_lag_waits(
        self, service: SiemForwardingService, session: AsyncSession, device: Device
    ) -> None:
        """The race the lag exists for.

        A row whose `created_at` is T can commit *after* a batch that already advanced
        past T, and would then never be forwarded. Staying behind the present means any
        transaction that produced a row has certainly committed before it is read.
        """
        await add_finding(session, device, title="Too fresh", age=timedelta(seconds=1))
        collector = FakeCollector()

        await service.forward(settings=settings(), forwarder=collector)
        assert findings_in(collector) == []

    async def test_it_is_forwarded_once_it_is_old_enough(
        self, service: SiemForwardingService, session: AsyncSession, device: Device
    ) -> None:
        await add_finding(session, device, title="Now eligible", age=timedelta(seconds=1))
        collector = FakeCollector()

        # Same row, read from a moment past the lag rather than by waiting.
        await service.forward(
            settings=settings(),
            forwarder=collector,
            now=datetime.now(UTC) + COMMIT_LAG + timedelta(seconds=5),
        )
        assert [e.title for e in findings_in(collector)] == ["Now eligible"]

    async def test_the_watermarks_are_stored_where_settings_live(
        self, service: SiemForwardingService, session: AsyncSession
    ) -> None:
        from sqlalchemy import select

        await add_audit(session, "login.success")
        await service.forward(settings=settings(), forwarder=FakeCollector())

        keys = set(
            (await session.execute(select(Setting.key).where(Setting.org_id == 1))).scalars()
        )
        assert WATERMARK_AUDIT in keys
        assert WATERMARK_FINDINGS not in keys, "no findings were sent, so no watermark"


# ═════════════════════════ nothing leaves unscrubbed ═════════════════════════


class TestScrubbing:
    async def test_a_secret_in_a_finding_description_does_not_reach_the_collector(
        self, service: SiemForwardingService, session: AsyncSession, device: Device
    ) -> None:
        finding = await add_finding(session, device, title="Weak SNMP")
        finding.description = "snmp-server community S3cretStr1ng RO"
        await session.flush()

        collector = FakeCollector()
        await service.forward(settings=settings(), forwarder=collector)

        # The scrub happens when the event is rendered, so this asserts against the
        # formatted output rather than the event object.
        from netsecops.integrations.cef import format_event

        rendered = " ".join(format_event(e) for e in collector.events)
        assert "S3cretStr1ng" not in rendered
