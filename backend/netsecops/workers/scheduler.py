"""The scheduler loop (FR-JOB-02).

A long-running process that wakes on a fixed interval, fires whatever is due, and goes
back to sleep. Deliberately not a cron daemon on the host and not an in-process
background task in the API:

- A host cron would put the schedule in two places — the database and the crontab — and
  the one an operator edits in the console would not be the one that runs.
- An asyncio task inside the API server would tie the estate's assessment cadence to
  however many API replicas happen to be running, and fire every schedule once per
  replica.

So it is its own process with its own database session, claiming work with ``FOR UPDATE
SKIP LOCKED``. Running two of them is safe and does nothing useful; running none means
schedules simply do not fire, which the console shows as a `next_run_at` in the past.

**It creates jobs; it does not run them.** Firing enqueues through the same path the API
uses, so a scheduled collection and a manual one are the same job travelling the same
road. That is what keeps the scheduler from becoming a second, subtly different execution
engine.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime

from netsecops.core.logging import get_logger
from netsecops.db.session import session_scope
from netsecops.services.schedules import ScheduleService

log = get_logger(__name__)

#: How often to look for due schedules.
#:
#: Cron's finest granularity is the minute, so checking more often than that finds
#: nothing new. Checking much less often makes every schedule late by up to the interval,
#: and "runs at 02:00" meaning "some time in the next ten minutes" is a surprise an
#: operator discovers from a change window they have already missed.
TICK_SECONDS = 30


async def tick_once() -> int:
    """One pass. Returns how many schedules fired.

    Its own session and its own transaction: a tick that failed halfway must not leave a
    schedule advanced but its job uncreated, and must not hold a connection open between
    passes.
    """
    async with session_scope() as session:
        results = await ScheduleService(session).tick()

    for result in results:
        if result.late_seconds > TICK_SECONDS * 2:
            # Worth its own line. A job that ran six hours after its window is a
            # different fact from one that ran on time, and the job row itself cannot
            # say so — it only knows when it started.
            log.warning(
                "scheduler.late",
                schedule=result.name,
                late_seconds=result.late_seconds,
                job_id=str(result.job_id) if result.job_id else None,
            )

    return sum(1 for result in results if result.job_id)


async def run(*, interval: float = TICK_SECONDS, stop: asyncio.Event | None = None) -> None:
    """Loop until stopped.

    ``stop`` is injected so a test can run the loop for real and end it deterministically,
    rather than the loop owning a signal handler that a test would have to fake.
    """
    log.info("scheduler.started", interval_seconds=interval)
    halt = stop or asyncio.Event()

    while not halt.is_set():
        started = datetime.now(UTC)
        try:
            fired = await tick_once()
            if fired:
                log.info("scheduler.fired", count=fired)
        except Exception as exc:
            # A failing tick must not end the process. The most likely cause is the
            # database being briefly unreachable, and a scheduler that exits on the first
            # blip stops every recurring assessment until somebody notices — which, being
            # unattended work, is exactly what nobody notices.
            log.error("scheduler.tick_failed", error=str(exc), exc_info=True)

        elapsed = (datetime.now(UTC) - started).total_seconds()
        with contextlib.suppress(TimeoutError):
            # Sleeps the remainder of the interval, and wakes immediately on stop.
            await asyncio.wait_for(halt.wait(), timeout=max(0.0, interval - elapsed))

    log.info("scheduler.stopped")


__all__ = ["TICK_SECONDS", "run", "tick_once"]
