"""Running a discovery scope end to end (FR-DISC-05).

The executor is the piece that turns four inert components into a feature, so these tests
are about the joins rather than the parts: that exclusions never reach a probe, that a
cancel stops the run rather than being noticed after it, that a silent address leaves no
trace, and that what a run could *not* do survives into the record.

Every test injects ``probe_host``, so no socket is opened. That is not a convenience —
it is the only way the batching, the counters, the cancellation path and auto-onboard get
covered at all, since a test that probed real addresses could only ever probe the
loopback and would prove nothing about a scope.

The mutation worth trying here: make ``_record_batch`` count every address as a host
found rather than only the responding ones. Several tests still pass; the counter tests
do not, and they are the ones a report is assembled from.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ValidationProblem
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device
from netsecops.db.models.discovery import (
    DiscoveredHost,
    DiscoveredHostStatus,
    DiscoveryRun,
    DiscoveryRunStatus,
    DiscoveryScope,
)
from netsecops.discovery.executor import SNMP_UNAVAILABLE_NOTE, DiscoveryExecutor
from netsecops.discovery.fingerprint import Signal, read_text
from netsecops.discovery.probes import ProbeViolationError
from netsecops.discovery.transport import HostResult
from tests.conftest import make_user


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="discovery_operator", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def make_scope(session: AsyncSession, **overrides: object) -> DiscoveryScope:
    defaults: dict[str, object] = {
        "org_id": 1,
        "name": "lab",
        "targets": ["198.51.100.0/29"],
        "exclusions": [],
        "tcp_ports": [22, 443],
        "rate_limit_per_second": 1000,
        "snmp_configured": False,
        "auto_onboard": False,
        "enabled": True,
    }
    scope = DiscoveryScope(**{**defaults, **overrides})  # type: ignore[arg-type]
    session.add(scope)
    await session.flush()
    return scope


def silent(address: str) -> HostResult:
    """What almost every address in a scope does."""
    return HostResult(address=address, responded=False, probes_sent=3)


def cisco_switch(address: str) -> HostResult:
    return HostResult(
        address=address,
        responded=True,
        open_ports=(22,),
        evidence=[read_text(Signal.SSH_BANNER, "SSH-2.0-Cisco-1.25")],
        probes_sent=4,
    )


def something(address: str) -> HostResult:
    """Answered, and nothing about it says what it is."""
    return HostResult(
        address=address,
        responded=True,
        open_ports=(22,),
        evidence=[read_text(Signal.SSH_BANNER, "SSH-2.0-OpenSSH_8.2")],
        probes_sent=4,
    )


class Recorder:
    """A stand-in prober that records every address it was asked to contact."""

    def __init__(self, responder=silent) -> None:
        self.responder = responder
        self.probed: list[str] = []

    async def __call__(self, address: str) -> HostResult:
        self.probed.append(address)
        return self.responder(address)


# ════════════════════ what gets contacted, and what does not ═════════════════


class TestTheScopeIsWhatIsProbed:
    async def test_every_address_in_the_scope_is_probed(self, session, actor) -> None:
        scope = await make_scope(session, targets=["198.51.100.0/29"])
        recorder = Recorder()

        await DiscoveryExecutor(session, probe_host=recorder).run(scope, actor=actor)

        # A /29 is eight addresses less network and broadcast.
        assert recorder.probed == [f"198.51.100.{n}" for n in range(1, 7)]

    async def test_an_excluded_address_is_never_contacted(self, session, actor) -> None:
        """The property `scopes.py` subtracts rather than filters in order to guarantee.

        Filtering at probe time would leave an excluded host one missing `continue` away
        from being contacted. This is the test that would notice if the subtraction were
        replaced by a filter that someone later got wrong.
        """
        scope = await make_scope(session, targets=["198.51.100.0/29"], exclusions=["198.51.100.3"])
        recorder = Recorder()

        await DiscoveryExecutor(session, probe_host=recorder).run(scope, actor=actor)

        assert "198.51.100.3" not in recorder.probed
        assert len(recorder.probed) == 5

    async def test_a_disabled_scope_is_refused_before_anything_is_sent(
        self, session, actor
    ) -> None:
        scope = await make_scope(session, enabled=False)
        recorder = Recorder()

        with pytest.raises(ValidationProblem):
            await DiscoveryExecutor(session, probe_host=recorder).run(scope, actor=actor)

        assert recorder.probed == []

    async def test_batching_does_not_lose_or_repeat_an_address(self, session, actor) -> None:
        """A /24 across batches of three. Off-by-one in the chunking is invisible at 8."""
        scope = await make_scope(session, targets=["198.51.100.0/24"])
        recorder = Recorder()

        summary = await DiscoveryExecutor(session, concurrency=3, probe_host=recorder).run(
            scope, actor=actor
        )

        assert len(recorder.probed) == 254
        assert len(set(recorder.probed)) == 254
        assert summary.addresses_probed == 254


# ══════════════════════════ what is recorded ═════════════════════════════════


class TestWhatTheRunRecords:
    async def test_a_responding_host_lands_in_the_review_queue(self, session, actor) -> None:
        scope = await make_scope(session, targets=["198.51.100.1"])

        await DiscoveryExecutor(session, probe_host=Recorder(cisco_switch)).run(scope, actor=actor)

        hosts = (await session.execute(select(DiscoveredHost))).scalars().all()
        assert len(hosts) == 1
        assert str(hosts[0].address) == "198.51.100.1"
        assert hosts[0].vendor == "cisco"
        assert hosts[0].status == DiscoveredHostStatus.PENDING.value

    async def test_silence_leaves_no_row(self, session, actor) -> None:
        """A row per dead address would bury the queue under the network's empty space."""
        scope = await make_scope(session, targets=["198.51.100.0/29"])

        await DiscoveryExecutor(session, probe_host=Recorder(silent)).run(scope, actor=actor)

        assert (await session.execute(select(DiscoveredHost))).scalars().all() == []

    async def test_found_and_unidentified_are_counted_separately(self, session, actor) -> None:
        """A run that found forty things and recognised none is a different outcome.

        Collapsing them makes a successful sweep of an estate full of unknown hardware
        read exactly like a successful sweep that identified everything.
        """
        scope = await make_scope(session, targets=["198.51.100.0/30"])

        def mixed(address: str) -> HostResult:
            return cisco_switch(address) if address.endswith(".1") else something(address)

        summary = await DiscoveryExecutor(session, probe_host=Recorder(mixed)).run(
            scope, actor=actor
        )

        assert summary.hosts_found == 2
        assert summary.hosts_unidentified == 1

    async def test_the_run_row_closes_with_its_counters(self, session, actor) -> None:
        scope = await make_scope(session, targets=["198.51.100.0/30"])

        summary = await DiscoveryExecutor(session, probe_host=Recorder(cisco_switch)).run(
            scope, actor=actor
        )

        run = (
            await session.execute(select(DiscoveryRun).where(DiscoveryRun.id == summary.run_id))
        ).scalar_one()
        assert run.status == DiscoveryRunStatus.SUCCEEDED.value
        assert run.finished_at is not None
        assert run.addresses_probed == 2
        assert run.hosts_found == 2

    async def test_a_second_run_refreshes_rather_than_duplicates(self, session, actor) -> None:
        """A host seen by three runs is one queue entry, not three things to triage."""
        scope = await make_scope(session, targets=["198.51.100.1"])
        executor = DiscoveryExecutor(session, probe_host=Recorder(cisco_switch))

        await executor.run(scope, actor=actor)
        await executor.run(scope, actor=actor)

        hosts = (await session.execute(select(DiscoveredHost))).scalars().all()
        assert len(hosts) == 1
        assert hosts[0].first_seen_at is not None
        assert hosts[0].last_seen_at is not None


# ═══════════════════ what the run could not do ═══════════════════════════════


class TestCaveatsSurvive:
    async def test_a_scope_asking_for_snmp_says_it_was_not_read(self, session, actor) -> None:
        """The gap that would otherwise look like a quiet network.

        sysObjectID is the heaviest signal there is (weight 50 against a banner's 25). A
        run without it finds the same hosts and identifies fewer of them, and with no
        note the operator reads that as an estate of unrecognisable hardware rather than
        as a missing capability.
        """
        scope = await make_scope(session, targets=["198.51.100.1"], snmp_configured=True)

        summary = await DiscoveryExecutor(session, probe_host=Recorder(cisco_switch)).run(
            scope, actor=actor
        )

        assert SNMP_UNAVAILABLE_NOTE in summary.notes

        run = (
            await session.execute(select(DiscoveryRun).where(DiscoveryRun.id == summary.run_id))
        ).scalar_one()
        assert SNMP_UNAVAILABLE_NOTE in run.notes

    async def test_a_scope_not_asking_for_snmp_gets_no_such_note(self, session, actor) -> None:
        scope = await make_scope(session, targets=["198.51.100.1"], snmp_configured=False)

        summary = await DiscoveryExecutor(session, probe_host=Recorder(cisco_switch)).run(
            scope, actor=actor
        )

        assert SNMP_UNAVAILABLE_NOTE not in summary.notes


# ════════════════════════════ stopping ═══════════════════════════════════════


class TestCancellation:
    async def test_a_cancel_stops_the_remaining_addresses_being_probed(
        self, session, actor
    ) -> None:
        """Honoured between batches, which is what makes it mean anything.

        A cancel that is only observed at the end of the run is not a cancel; the whole
        point is that the packets stop.
        """
        scope = await make_scope(session, targets=["198.51.100.0/24"])
        recorder = Recorder()
        batches = {"seen": 0}

        async def stop_after_one_batch() -> bool:
            batches["seen"] += 1
            return batches["seen"] > 1

        summary = await DiscoveryExecutor(session, concurrency=4, probe_host=recorder).run(
            scope, actor=actor, should_stop=stop_after_one_batch
        )

        assert len(recorder.probed) == 4
        assert summary.status == DiscoveryRunStatus.PARTIAL.value

    async def test_a_cancelled_run_keeps_what_it_already_found(self, session, actor) -> None:
        """Partial, not discarded: those hosts were really contacted and really answered."""
        scope = await make_scope(session, targets=["198.51.100.0/24"])
        stop = {"calls": 0}

        async def after_one() -> bool:
            stop["calls"] += 1
            return stop["calls"] > 1

        summary = await DiscoveryExecutor(
            session, concurrency=2, probe_host=Recorder(cisco_switch)
        ).run(scope, actor=actor, should_stop=after_one)

        run = (
            await session.execute(select(DiscoveryRun).where(DiscoveryRun.id == summary.run_id))
        ).scalar_one()
        assert run.status == DiscoveryRunStatus.PARTIAL.value
        assert run.hosts_found == 2
        assert len((await session.execute(select(DiscoveredHost))).scalars().all()) == 2


# ════════════════════════ the safety boundary ════════════════════════════════


class TestAutoOnboard:
    async def test_it_is_off_by_default(self, session, actor) -> None:
        """FR-DISC-04 makes review the norm. A run creates no devices."""
        scope = await make_scope(session, targets=["198.51.100.1"])

        await DiscoveryExecutor(session, probe_host=Recorder(cisco_switch)).run(scope, actor=actor)

        assert (await session.execute(select(Device))).scalars().all() == []

    async def test_an_opted_in_scope_onboards_an_identified_host(self, session, actor) -> None:
        scope = await make_scope(session, targets=["198.51.100.1"], auto_onboard=True)

        summary = await DiscoveryExecutor(session, probe_host=Recorder(cisco_switch)).run(
            scope, actor=actor
        )

        devices = (await session.execute(select(Device))).scalars().all()
        assert len(devices) == 1
        assert summary.hosts_onboarded == 1

    async def test_an_unidentified_host_still_queues_on_an_opted_in_scope(
        self, session, actor
    ) -> None:
        """The escape hatch refuses what it is not sure about.

        Auto-onboarding a host nothing could identify is how the exception turns into the
        thing FR-DISC-04 was written to prevent: a device row with no vendor, no parser
        and a credential inherited from whatever group it lands in.
        """
        scope = await make_scope(session, targets=["198.51.100.1"], auto_onboard=True)

        summary = await DiscoveryExecutor(session, probe_host=Recorder(something)).run(
            scope, actor=actor
        )

        assert (await session.execute(select(Device))).scalars().all() == []
        assert summary.hosts_onboarded == 0

        host = (await session.execute(select(DiscoveredHost))).scalar_one()
        assert host.status == DiscoveredHostStatus.PENDING.value


# ═══════════════════════ an allow-list breach ════════════════════════════════


class TestAProbeViolationAbortsTheRun:
    async def test_it_is_not_counted_as_a_host_that_did_not_answer(self, session, actor) -> None:
        """The one failure that must not be swallowed.

        Every other probe failure is ordinary — an address refuses, a host is off. A
        violation means the platform tried to send something it guarantees it does not
        send, and treating that as "no response" would let a breach of FR-DISC-02 look
        like an empty subnet.
        """
        scope = await make_scope(session, targets=["198.51.100.0/29"])

        async def breach(address: str) -> HostResult:
            raise ProbeViolationError("Port 8080 is not on this scope's list.")

        executor = DiscoveryExecutor(session, probe_host=breach)

        with pytest.raises(ProbeViolationError):
            await executor.run(scope, actor=actor)

    async def test_the_run_is_recorded_as_failed_with_the_reason(self, session, actor) -> None:
        scope = await make_scope(session, targets=["198.51.100.0/29"])

        async def breach(address: str) -> HostResult:
            raise ProbeViolationError("Port 8080 is not on this scope's list.")

        with pytest.raises(ProbeViolationError):
            await DiscoveryExecutor(session, probe_host=breach).run(scope, actor=actor)

        run = (await session.execute(select(DiscoveryRun))).scalar_one()
        assert run.status == DiscoveryRunStatus.FAILED.value
        assert run.error_message is not None
        assert "8080" in run.error_message

    async def test_an_ordinary_probe_failure_does_not_abandon_the_scope(
        self, session, actor
    ) -> None:
        """One unreachable address must not cost the other five.

        The same bargain as a device failure not failing a collection job: a scope will
        always have addresses that behave oddly, and abandoning the run on the first one
        means discovery never completes on a real network.
        """
        scope = await make_scope(session, targets=["198.51.100.0/29"])
        seen: list[str] = []

        async def one_bad_address(address: str) -> HostResult:
            seen.append(address)
            if address.endswith(".2"):
                raise OSError("Network is unreachable")
            return cisco_switch(address)

        summary = await DiscoveryExecutor(session, probe_host=one_bad_address).run(
            scope, actor=actor
        )

        assert len(seen) == 6
        assert summary.addresses_probed == 6
        assert summary.hosts_found == 5
