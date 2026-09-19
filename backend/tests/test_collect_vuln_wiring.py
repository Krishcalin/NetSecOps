"""Vulnerability matching runs after a collection (FR-VUL-03, FR-JOB-01).

The defect these cover: `VulnAssessmentService` was reachable only from the
`VULN_REMATCH` branch of the runner, and nothing creates a job of that type — no
scheduler entry, no API route, no UI control. So the whole Phase 6 engine, built and
unit-tested, never ran in normal operation. A device could be collected, assessed
against policy and reported on without a single advisory ever being weighed against it.

The two triggers answer different halves of one question, which is why both are needed:
a rematch asks "the catalogue changed, is anything newly exposed?" and is created by a
feed import; a collection asks "this device changed, is it exposed?" and had no answer
at all.

These drive the real collection path against the fake SSH device rather than calling
the new function directly, because the bug was never in the matcher — it was in the
wiring, and only an end-to-end run proves wiring.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.adapters.policies import CISCO_IOS
from netsecops.adapters.readonly import ReadOnlyGuard
from netsecops.adapters.session import DeviceSession, NullRecorder
from netsecops.adapters.transport import SSHCredentials, SSHTransport
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, User
from netsecops.db.models.collection import Finding, FindingKind
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.db.models.jobs import Job, JobType
from netsecops.db.models.vulnerability import VulnAdvisory
from netsecops.services.inventory import InventoryService
from netsecops.workers.runner import _collect_profile
from tests.conftest import make_user
from tests.fake_device import fake_device

DEVICE_USER = "netsecops"
DEVICE_PASSWORD = "device-pass"


@pytest.fixture
async def server():
    async for running in fake_device(username=DEVICE_USER, password=DEVICE_PASSWORD):
        yield running


@pytest.fixture
async def principal(session: AsyncSession) -> Principal:
    user: User = await make_user(session, username="collect_vuln", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def make_device(session: AsyncSession, principal: Principal, *, ip: str) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=principal,
        hostname="sw-collect-vuln",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )


async def make_job(session: AsyncSession, device: Device, job_type: JobType) -> Job:
    job = Job(
        org_id=device.org_id,
        job_type=job_type.value,
        status="running",
        started_at=datetime.now(UTC),
    )
    session.add(job)
    await session.flush()
    return job


async def seed_advisory(session: AsyncSession, advisory_id: str = "cisco-sa-wiring-01") -> None:
    """A whole-product advisory, so the test turns on wiring and not version parsing.

    Version comparison has its own tests. Using a version-bounded constraint here would
    make this fail for two quite different reasons and teach us nothing about either.
    """
    affected: list[dict[str, Any]] = [
        {
            "vendor": "Cisco",
            "product": "IOS",
            "product_id": "CSAFPID-0001",
            "constraint": {"kind": "all", "raw": "*"},
        }
    ]
    session.add(
        VulnAdvisory(
            org_id=1,
            source="cisco",
            advisory_id=advisory_id,
            cve_ids=["CVE-2026-40001"],
            affected=affected,
            fixed=[],
            scores=[{"version": "3.1", "base_score": 8.6, "severity": "high"}],
        )
    )
    await session.flush()


def session_for(running) -> DeviceSession:
    return DeviceSession(
        SSHTransport(
            running.host,
            SSHCredentials(username=DEVICE_USER, password=DEVICE_PASSWORD),
            port=running.port,
        ),
        ReadOnlyGuard(CISCO_IOS),
        recorder=NullRecorder(),
        device_id=uuid.uuid4(),
    )


async def vuln_findings(session: AsyncSession, device: Device) -> list[Finding]:
    rows = await session.execute(
        select(Finding).where(
            Finding.device_id == device.id,
            Finding.kind == FindingKind.VULN.value,
        )
    )
    return list(rows.scalars().all())


class TestACollectionWeighsTheCatalogue:
    async def test_a_collect_and_assess_run_opens_a_vulnerability_finding(
        self, session: AsyncSession, principal: Principal, server, vault
    ) -> None:
        """The regression. Before the fix this returned an empty list.

        Nothing else about the run changes: the same snapshot is stored and the same
        policy checks run. The only difference is that the advisory catalogue is now
        consulted, which is the entire point of having one.
        """
        device = await make_device(session, principal, ip="10.91.0.1")
        await seed_advisory(session)
        job = await make_job(session, device, JobType.COLLECT_AND_ASSESS)

        async with session_for(server) as device_session:
            outcome = await _collect_profile(
                session, job, device, device_session, "cisco_ios", vault=vault
            )

        assert outcome.succeeded is True
        assert await vuln_findings(session, device) != []

    async def test_vulnerability_findings_add_to_the_policy_count(
        self, session: AsyncSession, principal: Principal, server, vault
    ) -> None:
        """They are counted alongside the policy findings, not instead of them.

        An assignment where there should be an increment leaves the total looking
        plausible — a smaller number is not obviously wrong — while silently discarding
        every config finding the same run produced. The device is new, so everything
        found was opened by this run and the two can be compared exactly.
        """
        device = await make_device(session, principal, ip="10.91.0.7")
        await seed_advisory(session)
        job = await make_job(session, device, JobType.COLLECT_AND_ASSESS)

        async with session_for(server) as device_session:
            outcome = await _collect_profile(
                session, job, device, device_session, "cisco_ios", vault=vault
            )

        opened = await session.execute(select(Finding).where(Finding.device_id == device.id))
        rows = list(opened.scalars().all())

        assert outcome.findings_opened == len(rows)
        # And the total really is a mixture, so the equality above is not two zeroes
        # or one kind counted twice.
        assert {FindingKind.CONFIG.value, FindingKind.VULN.value} <= {r.kind for r in rows}

    async def test_the_outcome_says_how_many_advisories_were_weighed(
        self, session: AsyncSession, principal: Principal, server, vault
    ) -> None:
        """Zero considered means an empty catalogue, not a clean device.

        A run that reports nothing at all cannot distinguish the two, and the estate
        that most needs to know its catalogue is empty is the one that has never
        imported a feed.
        """
        device = await make_device(session, principal, ip="10.91.0.2")
        await seed_advisory(session)
        job = await make_job(session, device, JobType.COLLECT_AND_ASSESS)

        async with session_for(server) as device_session:
            outcome = await _collect_profile(
                session, job, device, device_session, "cisco_ios", vault=vault
            )

        assert "1 advisories" in outcome.output
        assert "confirmed" in outcome.output

    async def test_an_empty_catalogue_is_reported_rather_than_silent(
        self, session: AsyncSession, principal: Principal, server, vault
    ) -> None:
        device = await make_device(session, principal, ip="10.91.0.3")
        job = await make_job(session, device, JobType.COLLECT_AND_ASSESS)

        async with session_for(server) as device_session:
            outcome = await _collect_profile(
                session, job, device, device_session, "cisco_ios", vault=vault
            )

        assert "0 advisories" in outcome.output
        assert await vuln_findings(session, device) == []


class TestItDoesNotOverreach:
    async def test_a_collect_only_job_does_not_assess(
        self, session: AsyncSession, principal: Principal, server, vault
    ) -> None:
        """`COLLECT` means collect. Assessment is a separate scope under FR-JOB-01.

        Without this, the two job types become the same job and the distinction the
        requirement draws stops existing.
        """
        device = await make_device(session, principal, ip="10.91.0.4")
        await seed_advisory(session)
        job = await make_job(session, device, JobType.COLLECT)

        async with session_for(server) as device_session:
            outcome = await _collect_profile(
                session, job, device, device_session, "cisco_ios", vault=vault
            )

        assert outcome.succeeded is True
        assert "advisories" not in outcome.output
        assert await vuln_findings(session, device) == []


class TestAFailingMatcherDoesNotLoseTheCollection:
    async def test_the_snapshot_survives_a_matcher_failure(
        self, session: AsyncSession, principal: Principal, server, vault, monkeypatch
    ) -> None:
        """The configuration arrived and the policy ran; both are worth keeping.

        A malformed advisory row is the realistic trigger, and discarding a successful
        collection because one row in a third-party feed would not rebuild is a poor
        trade.
        """
        from netsecops.services import vuln_assessment

        async def explode(self, device):  # type: ignore[no-untyped-def]
            raise RuntimeError("advisory row would not rebuild")

        monkeypatch.setattr(vuln_assessment.VulnAssessmentService, "assess_device", explode)

        device = await make_device(session, principal, ip="10.91.0.5")
        job = await make_job(session, device, JobType.COLLECT_AND_ASSESS)

        async with session_for(server) as device_session:
            outcome = await _collect_profile(
                session, job, device, device_session, "cisco_ios", vault=vault
            )

        assert outcome.succeeded is True
        assert outcome.snapshot_id is not None

    async def test_the_failure_is_recorded_not_swallowed(
        self, session: AsyncSession, principal: Principal, server, vault, monkeypatch
    ) -> None:
        """ "Nothing found" and "the matcher did not run" are the same empty report.

        Only one of them is good news, so the outcome has to say which.
        """
        from netsecops.services import vuln_assessment

        async def explode(self, device):  # type: ignore[no-untyped-def]
            raise RuntimeError("advisory row would not rebuild")

        monkeypatch.setattr(vuln_assessment.VulnAssessmentService, "assess_device", explode)

        device = await make_device(session, principal, ip="10.91.0.6")
        job = await make_job(session, device, JobType.COLLECT_AND_ASSESS)

        async with session_for(server) as device_session:
            outcome = await _collect_profile(
                session, job, device, device_session, "cisco_ios", vault=vault
            )

        assert "vulnerability matching failed" in outcome.output
