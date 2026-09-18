"""The job worker (FR-JOB-05).

`deploy/docker-compose.yml` has referenced `netsecops-cli worker` under the `workers`
profile since Phase 1 and no such command existed, so that profile could not start. That
mattered little while every job was created by an API request — `InlineQueue` runs those
in-process — and it stopped being harmless the moment the scheduler arrived: the scheduler
*creates* job rows and never enqueues them, so a scheduled collection, feed sync,
notification dispatch or report sat `queued` for ever with nothing to notice.

**This claims from the database rather than from a broker.** A job is already a durable
row with a status, so the table is the queue; adding Procrastinate to deliver a message
about a row that is already there would put two sources of truth one restart apart.
ADR-001 keeps the option open — `ProcrastinateQueue` is still the seam — and this is what
makes the shipped deployment work without it.

**`FOR UPDATE SKIP LOCKED`, so running several is safe.** Two workers never claim the
same job: the second passes over what the first holds rather than blocking on it, which
is the same mechanism the scheduler uses for due schedules.

**A job that fails does not stop the worker.** One unreachable estate must not halt
notification delivery for everyone else, so a failure is recorded on its job and the loop
continues.
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import correlation_id, get_logger
from netsecops.db.models.jobs import Job, JobStatus
from netsecops.db.session import session_scope

log = get_logger(__name__)

#: How long to wait before looking again when there was nothing to do.
#:
#: Five seconds rather than one: a scheduled job's punctuality is measured in minutes, and
#: a tighter loop is a query per second per worker for the life of the deployment.
IDLE_SECONDS: Final[float] = 5.0

#: Jobs claimed per pass. Bounded so one worker cannot take an entire backlog and leave
#: its peers idle.
BATCH: Final[int] = 5


async def claim_next(session: AsyncSession) -> Job | None:
    """Take one queued job, or None.

    The session is passed in rather than opened here, for the same reason `execute_job`
    takes one: it is what lets a test drive the worker inside its own transaction, and it
    keeps one pass on one session instead of opening a connection per claim.
    """
    job = (
        await session.execute(
            select(Job)
            .where(Job.status == JobStatus.QUEUED.value)
            .order_by(Job.created_at)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
    ).scalar_one_or_none()

    if job is None:
        return None

    # Marked before the job runs, so a second worker looking at the same moment sees it
    # taken rather than free.
    job.status = JobStatus.RUNNING.value
    await session.flush()
    return job


async def run_once(session: AsyncSession) -> int:
    """Claim and run up to :data:`BATCH` jobs. Returns how many ran."""
    from netsecops.workers import runner

    ran = 0
    for _ in range(BATCH):
        job = await claim_next(session)
        if job is None:
            break

        if job.correlation_id:
            correlation_id.set(job.correlation_id)

        try:
            # Resolved through the module rather than imported by name, so a test can
            # substitute it — and so this picks up any future wrapper rather than binding
            # to the function at import time.
            await runner.execute_job(session, job.id)
        except Exception as exc:
            log.warning("worker.job_failed", job_id=str(job.id), error=str(exc))
            await _mark_failed(session, job.id, str(exc))
        ran += 1

    return ran


async def _mark_failed(session: AsyncSession, job_id: uuid.UUID, message: str) -> None:
    """Record a crash on the job.

    Without this a job that raised before `execute_job` could close it stays `running`
    for ever, which reads in the console as a job still in progress — the one state an
    operator will not investigate.
    """
    with contextlib.suppress(Exception):
        job = (await session.execute(select(Job).where(Job.id == job_id))).scalar_one_or_none()
        if job is not None and not JobStatus(job.status).is_terminal:
            job.status = JobStatus.FAILED.value
            job.error_message = message[:2000]
            await session.flush()


async def run(*, idle_seconds: float = IDLE_SECONDS) -> None:  # pragma: no cover - a loop
    """Run until cancelled."""
    log.info("worker.started", idle_seconds=idle_seconds)
    while True:
        try:
            async with session_scope() as session:
                if await run_once(session):
                    continue
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("worker.pass_failed", error=str(exc))

        await asyncio.sleep(idle_seconds)


__all__ = ["BATCH", "IDLE_SECONDS", "claim_next", "run", "run_once"]
