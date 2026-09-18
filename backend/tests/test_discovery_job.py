"""A discovery run as a job (FR-DISC-05, FR-JOB-03).

The executor probes; the job engine is what gives it a queue to be picked off, a cancel
signal, a correlation id and somewhere for an operator to watch it. Joining the two is
the part that is easy to get subtly wrong, because the job engine is built around devices
and a discovery job has none.

Two properties are worth more than the rest:

- **A discovery job reaches no device.** ``_run_one_device`` resolves credentials and
  opens an authenticated session. A discovery job that fell into that loop would
  authenticate to a host nobody has approved, which is precisely what FR-DISC-04 exists
  to prevent. The branch above the loop is what stops it, and the refusal inside the loop
  is the backstop.
- **An empty device table does not mean success.** ``complete()`` picks a job's status
  from its per-device outcomes. A discovery job has none, so the rule reads "nothing
  failed" and would call an aborted run a success.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.discovery import DiscoveredHost, DiscoveryRun, DiscoveryScope
from netsecops.db.models.jobs import Job, JobStatus, JobType
from netsecops.discovery.executor import DiscoveryExecutor
from netsecops.discovery.fingerprint import Signal, read_text
from netsecops.discovery.transport import HostResult
from netsecops.services.jobs import JobService
from netsecops.workers.runner import execute_job
from tests.conftest import make_user


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="discovery_job_runner", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
async def scope_row(session: AsyncSession) -> DiscoveryScope:
    row = DiscoveryScope(
        org_id=1,
        name="job-lab",
        targets=["198.51.100.0/30"],
        tcp_ports=[22],
        rate_limit_per_second=1000,
    )
    session.add(row)
    await session.flush()
    return row


@pytest.fixture
def answering(monkeypatch: pytest.MonkeyPatch):
    """Force the executor the runner builds to use a stub instead of a socket.

    Patched rather than injected, because the seam would otherwise exist only for tests:
    the runner should build its own executor, and a factory parameter threaded through it
    would be a production API with one caller.
    """
    probed: list[str] = []

    async def probe(address: str) -> HostResult:
        probed.append(address)
        return HostResult(
            address=address,
            responded=True,
            open_ports=(22,),
            evidence=[read_text(Signal.SSH_BANNER, "SSH-2.0-Cisco-1.25")],
            probes_sent=2,
        )

    class Stubbed(DiscoveryExecutor):
        def __init__(self, session, **kwargs):  # type: ignore[no-untyped-def]
            kwargs.setdefault("probe_host", probe)
            super().__init__(session, **kwargs)

    monkeypatch.setattr("netsecops.discovery.executor.DiscoveryExecutor", Stubbed)
    return probed


class TestADiscoveryJobRuns:
    async def test_it_probes_the_scope_and_succeeds(
        self, session: AsyncSession, actor, scope_row, answering
    ) -> None:
        job = await JobService(session).create_discovery(
            discovery_scope_id=scope_row.id, actor=actor
        )

        completed = await execute_job(session, job.id)

        assert completed.status == JobStatus.SUCCEEDED.value
        assert answering == ["198.51.100.1", "198.51.100.2"]

    async def test_the_summary_replaces_the_borrowed_device_counts(
        self, session: AsyncSession, actor, scope_row, answering
    ) -> None:
        """Written after ``complete()``, which merges zeroed device counts over stats.

        Without that ordering, ``/jobs`` reports "succeeded: 0" for a run that found two
        switches — a number borrowed from a device table this job type never populates.
        """
        job = await JobService(session).create_discovery(
            discovery_scope_id=scope_row.id, actor=actor
        )

        completed = await execute_job(session, job.id)

        assert completed.stats["addresses_probed"] == 2
        assert completed.stats["hosts_found"] == 2
        assert "discovery_run_id" in completed.stats

    async def test_the_run_row_points_back_at_its_job(
        self, session: AsyncSession, actor, scope_row, answering
    ) -> None:
        """Both directions are queryable: the job carries the run id, the run the job id."""
        job = await JobService(session).create_discovery(
            discovery_scope_id=scope_row.id, actor=actor
        )

        completed = await execute_job(session, job.id)

        run = (await session.execute(select(DiscoveryRun))).scalars().one()
        assert run.job_id == job.id
        assert str(run.id) == completed.stats["discovery_run_id"]

    async def test_what_it_found_is_in_the_review_queue(
        self, session: AsyncSession, actor, scope_row, answering
    ) -> None:
        job = await JobService(session).create_discovery(
            discovery_scope_id=scope_row.id, actor=actor
        )

        await execute_job(session, job.id)

        hosts = (await session.execute(select(DiscoveredHost))).scalars().all()
        assert {str(host.address) for host in hosts} == {"198.51.100.1", "198.51.100.2"}


class TestItNeverReachesADevice:
    async def test_the_job_is_created_with_no_devices(
        self, session: AsyncSession, actor, scope_row
    ) -> None:
        """The structural guarantee, asserted where it is made.

        ``create_discovery`` writes no ``job_devices`` rows, and nothing else does
        either. A row here is the only route by which discovery could reach the
        credential resolver.
        """
        from netsecops.db.models.jobs import JobDevice

        job = await JobService(session).create_discovery(
            discovery_scope_id=scope_row.id, actor=actor
        )

        rows = (
            (await session.execute(select(JobDevice).where(JobDevice.job_id == job.id)))
            .scalars()
            .all()
        )
        assert rows == []

    # The backstop for the case above — a discovery job that somehow *did* carry a device
    # — is exercised by `test_vuln_rematch_job.py::TestDiscoveryJobsAreRefused`, which is
    # where the runner's other per-device refusals are tested and already has the
    # fixtures for building one.


class TestItFailsHonestly:
    async def test_a_job_naming_no_scope_fails_rather_than_succeeding_emptily(
        self, session: AsyncSession, actor
    ) -> None:
        """The case ``complete()``'s device-count rule gets backwards.

        No devices means nothing failed means succeeded — so without the override this
        job reports success having probed nothing at all.
        """
        job = Job(
            org_id=1,
            job_type=JobType.DISCOVERY.value,
            status=JobStatus.QUEUED.value,
            scope={},
            requested_by_id=actor.id,
            stats={},
        )
        session.add(job)
        await session.flush()

        completed = await execute_job(session, job.id)

        assert completed.status == JobStatus.FAILED.value
        assert "names no scope" in (completed.error_message or "")

    async def test_a_deleted_scope_fails_rather_than_guessing(
        self, session: AsyncSession, actor, scope_row
    ) -> None:
        """The scope is the only record of which addresses consent was given for."""
        jobs = JobService(session)
        job = await jobs.create_discovery(discovery_scope_id=scope_row.id, actor=actor)
        await session.delete(scope_row)
        await session.flush()

        completed = await execute_job(session, job.id)

        assert completed.status == JobStatus.FAILED.value
        assert "no longer exists" in (completed.error_message or "")

    async def test_a_cancelled_job_ends_cancelled(
        self, session: AsyncSession, actor, scope_row, answering
    ) -> None:
        """Cancel wins over the executor's own view of how it went (FR-JOB-03)."""
        jobs = JobService(session)
        job = await jobs.create_discovery(discovery_scope_id=scope_row.id, actor=actor)
        await jobs.cancel(job, actor=actor)

        completed = await execute_job(session, job.id)

        assert completed.status == JobStatus.CANCELLED.value
        assert answering == []
