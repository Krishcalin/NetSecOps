"""The job worker (FR-JOB-05).

Its absence is what made every scheduled job sit `queued` for ever: the scheduler creates
job rows and enqueues nothing, and `deploy/docker-compose.yml` referenced a command that
did not exist. So the property under test is simply that a queued job gets run — and the
two ways a worker silently stops being useful: claiming a job twice, and dying on one bad
job.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ValidationProblem
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.jobs import Job, JobStatus, JobType
from netsecops.services.jobs import JobService
from netsecops.workers import worker
from tests.conftest import make_user


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="worker_runner", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def queued_job(session: AsyncSession, actor: Principal) -> Job:
    """A device-less job, so running it needs no credentials or sockets."""
    job = await JobService(session).create_siem_forward(actor=actor)
    await session.flush()
    return job


class TestClaiming:
    async def test_a_queued_job_is_claimed_and_marked_running(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        job = await queued_job(session, actor)

        claimed = await worker.claim_next(session)

        assert claimed is not None
        assert claimed.id == job.id
        assert claimed.status == JobStatus.RUNNING.value

    async def test_a_claimed_job_is_not_claimed_again(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """Otherwise two workers run the same collection against the same estate."""
        await queued_job(session, actor)

        assert await worker.claim_next(session) is not None
        assert await worker.claim_next(session) is None

    async def test_an_empty_queue_yields_nothing(self, session: AsyncSession) -> None:
        assert await worker.claim_next(session) is None

    async def test_jobs_are_claimed_oldest_first(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        # A queue that serves newest-first starves the backlog it exists to drain.
        first = await JobService(session).create_siem_forward(actor=actor, idempotency_key="first")
        second = await JobService(session).create_siem_forward(
            actor=actor, idempotency_key="second"
        )
        await session.flush()

        assert (await worker.claim_next(session)).id == first.id
        assert (await worker.claim_next(session)).id == second.id
        assert second.id != first.id


class TestRunning:
    async def test_it_runs_a_queued_job_to_completion(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        job = await queued_job(session, actor)

        assert await worker.run_once(session) == 1

        await session.refresh(job)
        assert JobStatus(job.status).is_terminal

    async def test_an_empty_pass_reports_nothing_run(self, session: AsyncSession) -> None:
        assert await worker.run_once(session) == 0

    async def test_one_failing_job_does_not_stop_the_pass(
        self, session: AsyncSession, actor: Principal, monkeypatch
    ) -> None:
        """One unreachable estate must not halt notification delivery for everyone else."""
        await JobService(session).create_siem_forward(actor=actor, idempotency_key="bad")
        await JobService(session).create_siem_forward(actor=actor, idempotency_key="good")
        await session.flush()

        calls: list[int] = []

        async def flaky(session_, job_id):  # type: ignore[no-untyped-def]
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("collector exploded")
            return None

        from netsecops.workers import runner

        monkeypatch.setattr(runner, "execute_job", flaky)

        assert await worker.run_once(session) == 2, "the worker stopped at the first failure"
        assert len(calls) == 2

    async def test_a_crashed_job_is_marked_failed_not_left_running(
        self, session: AsyncSession, actor: Principal, monkeypatch
    ) -> None:
        """`running` for ever is the one state nobody investigates."""
        job = await queued_job(session, actor)

        async def explode(session_, job_id):  # type: ignore[no-untyped-def]
            raise RuntimeError("collector exploded")

        from netsecops.workers import runner

        monkeypatch.setattr(runner, "execute_job", explode)
        await worker.run_once(session)

        await session.refresh(job)
        assert job.status == JobStatus.FAILED.value
        assert "exploded" in (job.error_message or "")


class TestTheScheduledPath:
    async def test_a_scheduler_created_job_is_picked_up(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The gap this command exists to close.

        The scheduler writes a job row and enqueues nothing, so without a worker every
        scheduled collection, feed sync, notification dispatch and report stays queued
        for ever — showing in the console as a job that never starts rather than an error.
        """
        job = await JobService(session).create_notify(actor=actor)
        await session.flush()

        assert job.job_type == JobType.NOTIFY.value
        assert job.status == JobStatus.QUEUED.value

        assert await worker.run_once(session) == 1
        await session.refresh(job)
        assert job.status != JobStatus.QUEUED.value

    async def test_every_deviceless_job_type_is_runnable(
        self, session: AsyncSession, actor: Principal, monkeypatch
    ) -> None:
        """Each of these has its own branch in the runner.

        A type without one falls through to the device loop, finds no `job_devices` rows,
        and completes instantly having done nothing — which looks exactly like success.

        The feed fetch is stubbed. Left real, this test reaches CISA, FIRST and NVD with a
        two-minute timeout each — which is both rude and the reason an earlier version of
        it appeared to hang rather than fail.
        """
        from netsecops.services.feeds import FeedImportService

        async def no_network(self, source_name, *, actor, settings, client=None):
            raise ValidationProblem(f"{source_name}: stubbed, no network in tests")

        monkeypatch.setattr(FeedImportService, "sync_online", no_network)

        jobs = JobService(session)
        created = [
            await jobs.create_feed_sync(sources=["kev"], actor=actor, idempotency_key="f"),
            await jobs.create_siem_forward(actor=actor, idempotency_key="s"),
            await jobs.create_notify(actor=actor, idempotency_key="n"),
        ]
        await session.flush()

        assert await worker.run_once(session) == len(created)

        for job in created:
            await session.refresh(job)
            assert JobStatus(job.status).is_terminal

    async def test_stale_rows_do_not_accumulate(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        await queued_job(session, actor)
        await worker.run_once(session)

        remaining = (
            (await session.execute(select(Job).where(Job.status == JobStatus.QUEUED.value)))
            .scalars()
            .all()
        )
        assert remaining == []
