"""Device sessions against a real SSH server (SRS §8, FR-COL-02/04, FR-AUD-01).

The conformance tests in ``test_readonly.py`` check what the guard *decides*. These
check what actually reaches a device — a fake one that records every byte it receives.
Together they close the loop: a guard that approved the right things would still be
worthless if a session could route around it.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.adapters.policies import CISCO_IOS
from netsecops.adapters.readonly import ReadOnlyGuard
from netsecops.adapters.recorder import AuditingRecorder
from netsecops.adapters.session import DeviceSession, NullRecorder
from netsecops.adapters.transport import (
    DeviceAuthError,
    DeviceUnreachableError,
    HostKeyChangedError,
    SSHCredentials,
    SSHTransport,
)
from netsecops.core.errors import ReadOnlyViolationError
from netsecops.db.models import AuditLog
from netsecops.services.audit import AuditService
from tests.fake_device import fake_device

DEVICE_USER = "netsecops"
DEVICE_PASSWORD = "device-pass"


@pytest.fixture
async def device():
    async for server in fake_device(username=DEVICE_USER, password=DEVICE_PASSWORD):
        yield server


def transport_for(server, **kwargs) -> SSHTransport:
    return SSHTransport(
        server.host,
        SSHCredentials(username=DEVICE_USER, password=DEVICE_PASSWORD),
        port=server.port,
        **kwargs,
    )


def session_for(server, recorder=None, **kwargs) -> DeviceSession:
    return DeviceSession(
        transport_for(server, **kwargs),
        ReadOnlyGuard(CISCO_IOS),
        recorder=recorder or NullRecorder(),
        device_id=uuid.uuid4(),
    )


class TestConnectivity:
    async def test_permitted_command_reaches_the_device(self, device) -> None:
        async with session_for(device) as session:
            result = await session.run("show version")

        assert "Cisco IOS XE Software" in result.output
        assert device.received == ["show version"]

    async def test_several_commands_run_in_order(self, device) -> None:
        async with session_for(device) as session:
            await session.run_all(["terminal length 0", "show version", "show clock"])

        assert device.received == ["terminal length 0", "show version", "show clock"]

    async def test_bad_password_is_reported_as_auth_failure(self, device) -> None:
        transport = SSHTransport(
            device.host,
            SSHCredentials(username=DEVICE_USER, password="wrong"),
            port=device.port,
        )
        session = DeviceSession(transport, ReadOnlyGuard(CISCO_IOS))

        with pytest.raises(DeviceAuthError):
            await session.__aenter__()

    async def test_unreachable_host_is_reported_distinctly(self) -> None:
        """FR-COL-07 classifies failures; unreachable and auth-failed need different fixes."""
        transport = SSHTransport(
            "127.0.0.1",
            SSHCredentials(username="x", password="y"),
            port=1,  # nothing listens here
            connect_timeout=2,
        )
        session = DeviceSession(transport, ReadOnlyGuard(CISCO_IOS))

        with pytest.raises(DeviceUnreachableError):
            await session.__aenter__()

    async def test_session_closes_even_when_the_body_raises(self, device) -> None:
        """SRS §8.1.6 — sessions are closed cleanly even on failure."""
        session = session_for(device)

        with pytest.raises(RuntimeError):
            async with session:
                await session.run("show version")
                raise RuntimeError("collection blew up")

        assert session._connected is False


class TestGuardIsNotBypassable:
    """The point of the whole design: no unchecked path to a device."""

    async def test_forbidden_command_never_reaches_the_device(self, device) -> None:
        async with session_for(device) as session:
            with pytest.raises(ReadOnlyViolationError):
                await session.run("configure terminal")

        assert device.received == [], "a forbidden command was transmitted"

    async def test_injection_never_reaches_the_device(self, device) -> None:
        async with session_for(device) as session:
            with pytest.raises(ReadOnlyViolationError):
                await session.run("show version; reload")

        assert device.received == []

    async def test_unlisted_command_never_reaches_the_device(self, device) -> None:
        async with session_for(device) as session:
            with pytest.raises(ReadOnlyViolationError):
                await session.run("show tech-support")

        assert device.received == []

    async def test_a_violation_stops_the_batch(self, device) -> None:
        """run_all must not carry on past a violation."""
        async with session_for(device) as session:
            with pytest.raises(ReadOnlyViolationError):
                await session.run_all(["show version", "reload", "show clock"])

        assert device.received == ["show version"], (
            "commands after the violation should not have been sent"
        )

    async def test_no_write_verb_ever_reaches_the_device(self, device) -> None:
        write_attempts = [
            "configure terminal",
            "write memory",
            "copy running-config startup-config",
            "reload",
            "erase startup-config",
            "no shutdown",
            "debug ip packet",
        ]

        async with session_for(device) as session:
            for command in write_attempts:
                with pytest.raises(ReadOnlyViolationError):
                    await session.run(command)

        device.assert_never_received("config", "write", "copy", "reload", "erase", "debug")
        assert device.received == []

    async def test_violations_are_counted_separately_from_sends(self, device) -> None:
        async with session_for(device) as session:
            await session.run("show version")
            with pytest.raises(ReadOnlyViolationError):
                await session.run("reload")

            assert session.commands_sent == 1


class TestHostKeyPolicy:
    """FR-COL-10 — pin on first use, refuse on change."""

    async def test_first_connection_records_the_fingerprint(self, device) -> None:
        transport = transport_for(device)
        session = DeviceSession(transport, ReadOnlyGuard(CISCO_IOS))

        async with session:
            assert transport.observed_fingerprint is not None
            assert transport.observed_fingerprint.startswith("SHA256:")

    async def test_matching_fingerprint_is_accepted(self, device) -> None:
        probe = transport_for(device)
        async with DeviceSession(probe, ReadOnlyGuard(CISCO_IOS)):
            pinned = probe.observed_fingerprint

        transport = transport_for(device, known_fingerprint=pinned)
        async with DeviceSession(transport, ReadOnlyGuard(CISCO_IOS)) as session:
            assert (await session.run("show version")).succeeded

    async def test_changed_fingerprint_is_refused_under_strict_policy(self, device) -> None:
        transport = transport_for(device, known_fingerprint="SHA256:definitely-not-the-key")
        session = DeviceSession(transport, ReadOnlyGuard(CISCO_IOS))

        with pytest.raises(HostKeyChangedError, match="has changed"):
            await session.__aenter__()

    async def test_accept_and_record_mode_connects_but_warns(self, device) -> None:
        transport = transport_for(device, known_fingerprint="SHA256:stale", strict_host_key=False)
        async with DeviceSession(transport, ReadOnlyGuard(CISCO_IOS)) as session:
            assert (await session.run("show version")).succeeded


class TestAuditTrail:
    """SRS §8.1.8 — customers see exactly what was executed."""

    async def test_each_command_becomes_an_audit_record(
        self, device, session: AsyncSession
    ) -> None:
        device_id = uuid.uuid4()
        recorder = AuditingRecorder(AuditService(session))

        netsecops_session = DeviceSession(
            transport_for(device),
            ReadOnlyGuard(CISCO_IOS),
            recorder=recorder,
            device_id=device_id,
        )
        async with netsecops_session:
            await netsecops_session.run_all(["show version", "show clock"])
        await session.flush()

        rows = (
            (
                await session.execute(
                    select(AuditLog)
                    .where(AuditLog.action == "device.command")
                    .order_by(AuditLog.id)
                )
            )
            .scalars()
            .all()
        )

        assert [r.command_text for r in rows] == ["show version", "show clock"]
        assert all(r.device_id == device_id for r in rows)

    async def test_device_output_is_not_recorded(self, device, session: AsyncSession) -> None:
        """The fake config contains an SNMP community; it must not reach the audit log."""
        recorder = AuditingRecorder(AuditService(session))
        netsecops_session = DeviceSession(
            transport_for(device),
            ReadOnlyGuard(CISCO_IOS),
            recorder=recorder,
            device_id=uuid.uuid4(),
        )

        async with netsecops_session:
            result = await netsecops_session.run("show running-config")
        await session.flush()

        assert "S3cr3tRO" in result.output, "precondition: the device did return a secret"

        rows = (
            (await session.execute(select(AuditLog).where(AuditLog.action == "device.command")))
            .scalars()
            .all()
        )
        for row in rows:
            assert "S3cr3tRO" not in (row.command_text or "")
            assert "S3cr3tRO" not in str(row.details)

    async def test_a_violation_is_recorded_as_critical(self, device, session: AsyncSession) -> None:
        recorder = AuditingRecorder(AuditService(session))
        netsecops_session = DeviceSession(
            transport_for(device),
            ReadOnlyGuard(CISCO_IOS),
            recorder=recorder,
            device_id=uuid.uuid4(),
        )

        async with netsecops_session:
            with pytest.raises(ReadOnlyViolationError):
                await netsecops_session.run("reload")
        await session.flush()

        row = (
            await session.execute(
                select(AuditLog).where(AuditLog.action == "device.readonly_violation")
            )
        ).scalar_one()

        assert row.outcome == "denied"
        assert row.command_text == "reload"

    async def test_audit_chain_stays_intact_across_a_collection(
        self, device, session: AsyncSession
    ) -> None:
        audit = AuditService(session)
        netsecops_session = DeviceSession(
            transport_for(device),
            ReadOnlyGuard(CISCO_IOS),
            recorder=AuditingRecorder(audit),
            device_id=uuid.uuid4(),
        )

        async with netsecops_session:
            await netsecops_session.run_all(["show version", "show clock", "show inventory"])
        await session.flush()

        result = await audit.verify_chain()
        assert result.valid and result.total >= 3
