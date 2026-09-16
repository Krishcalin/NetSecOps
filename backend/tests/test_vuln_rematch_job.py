"""The vuln_rematch job branch (FR-JOB-01, FR-VUL-03).

`JobType.VULN_REMATCH` has existed in the enum since the Phase 6 migration and the
runner had no branch for it, so a job of that type fell through to the collection path:
it resolved credentials and opened a session against the device. A re-match is the one
job that must *not* touch a device — what changed is the advisory catalogue, not the
configuration. A feed imported on Tuesday can make Monday's unmoved software
exploitable, and finding that out should not require a collection window across five
hundred devices.

`JobType.DISCOVERY` had the same hole and the same consequence, and is refused
explicitly until FR-DISC-05 exists rather than being allowed to fall through into a
device session.
"""

from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, User
from netsecops.db.models.collection import Snapshot
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.db.models.jobs import Job, JobDevice, JobType
from netsecops.db.models.vulnerability import VulnAdvisory
from netsecops.services.inventory import InventoryService
from netsecops.workers.runner import _run_one_device
from tests.conftest import make_user


@pytest.fixture
async def analyst(session: AsyncSession) -> User:
    return await make_user(session, username="rematch_analyst", roles={Role.SECURITY_ANALYST})


@pytest.fixture
async def principal(analyst: User) -> Principal:
    return Principal(
        id=analyst.id, username=analyst.username, roles=analyst.role_set, scope=Scope.all()
    )


async def make_device(session: AsyncSession, principal: Principal, *, ip: str) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=principal,
        hostname="sw-rematch",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )


async def make_snapshot(session: AsyncSession, device: Device, version: str) -> Snapshot:
    ncm: dict[str, Any] = {
        "device": {"vendor": "cisco", "platform": "cisco_ios", "version": version},
    }
    digest = sha256(f"{device.id}{version}".encode()).hexdigest()
    row = Snapshot(
        org_id=device.org_id,
        device_id=device.id,
        ncm=ncm,
        config_redacted="",
        config_hash=digest,
        normalized_hash=digest,
        parser_platform="cisco_ios",
    )
    session.add(row)
    await session.flush()
    return row


async def make_job(session: AsyncSession, device: Device, job_type: JobType) -> tuple[Job, JobDevice]:
    job = Job(
        org_id=device.org_id,
        job_type=job_type.value,
        status="running",
        started_at=datetime.now(UTC),
    )
    session.add(job)
    await session.flush()

    job_device = JobDevice(org_id=device.org_id, job_id=job.id, device_id=device.id)
    session.add(job_device)
    await session.flush()
    return job, job_device


class TestRematchDoesNotTouchTheDevice:
    async def test_a_device_with_no_credential_still_rematches(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """The proof that no session is opened.

        The device has no credential assigned. On the collection path that is an
        AUTH_FAILED outcome before anything else happens; a re-match neither needs nor
        resolves one.
        """
        device = await make_device(session, principal, ip="10.90.0.1")
        snapshot = await make_snapshot(session, device, "15.2(7)E3")
        job, job_device = await make_job(session, device, JobType.VULN_REMATCH)

        outcome = await _run_one_device(session, job, job_device)

        assert outcome.succeeded is True
        assert outcome.snapshot_id == snapshot.id

    async def test_the_outcome_reports_what_was_weighed(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """Zero advisories considered means an empty catalogue, not a clean device."""
        device = await make_device(session, principal, ip="10.90.0.2")
        await make_snapshot(session, device, "15.2(7)E3")
        session.add(
            VulnAdvisory(
                org_id=1,
                source="nvd",
                advisory_id="CVE-2024-99999",
                cve_ids=["CVE-2024-99999"],
                affected=[],
                fixed=[],
            )
        )
        await session.flush()
        job, job_device = await make_job(session, device, JobType.VULN_REMATCH)

        outcome = await _run_one_device(session, job, job_device)

        assert "advisories considered" in (outcome.output or "")
        assert "1 advisories" in (outcome.output or "")

    async def test_a_device_with_no_snapshot_fails_rather_than_reporting_clean(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """"Nothing matched" and "nothing to match against" are the same empty result.

        Only one of them means the device is fine, so the job says which.
        """
        device = await make_device(session, principal, ip="10.90.0.3")
        job, job_device = await make_job(session, device, JobType.VULN_REMATCH)

        outcome = await _run_one_device(session, job, job_device)

        assert outcome.succeeded is False
        assert "no configuration snapshot" in (outcome.error_message or "")


class TestDiscoveryJobsAreRefused:
    async def test_a_discovery_job_does_not_fall_through_to_a_device_session(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """Without the branch this resolved credentials and opened an SSH session —
        the opposite of what a discovery job is for."""
        device = await make_device(session, principal, ip="10.90.0.4")
        job, job_device = await make_job(session, device, JobType.DISCOVERY)

        outcome = await _run_one_device(session, job, job_device)

        assert outcome.succeeded is False
        assert "No probe was sent" in (outcome.error_message or "")
        assert "FR-DISC-05" in (outcome.error_message or "")
