"""Load test for the job queue (NFR-PERF-01, ADR-001).

ADR-001 chose Procrastinate over Celery + Redis provisionally, and said the choice would
be re-confirmed by a load test. This is that test.

**What the requirement actually asks for.** NFR-PERF-01 is 500 devices in ≤60 minutes
with 20 workers. That is 500 ÷ 3600 s = **0.139 device-claims per second** sustained.
It is worth writing the arithmetic down, because it reframes the question: at that rate
the queue is nowhere near the bottleneck. A collection spends tens of seconds inside an
SSH session, and the queue's share of it is one row claim and one status write.

**What this measures, and what it does not.** It measures the claim/complete cycle —
`FOR UPDATE SKIP LOCKED` contention across concurrent workers sharing one job — against
a real PostgreSQL. That is the part the queue technology decides. It deliberately does
*not* measure SSH: device round-trip time is a property of the customer's network and
their equipment, and no choice between Procrastinate and Celery changes it.

So a pass here means "the queue can sustain many times the required rate", not "500 real
devices complete in an hour". The second claim needs real hardware and belongs in the
Phase 7 performance harness.

Marked `performance` and excluded from the default run: it writes real rows outside the
usual rolled-back session, and takes seconds rather than milliseconds.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from netsecops.core.rbac import Principal, Scope
from netsecops.db.models.inventory import Vendor
from netsecops.db.models.jobs import DeviceJobStatus, JobDevice, JobType
from netsecops.services.inventory import InventoryService
from netsecops.services.jobs import JobScope, JobService
from tests.conftest import make_user

pytestmark = pytest.mark.performance

#: NFR-PERF-01, restated as a rate.
REQUIRED_DEVICES = 500
REQUIRED_SECONDS = 60 * 60
REQUIRED_RATE = REQUIRED_DEVICES / REQUIRED_SECONDS  # ≈ 0.139 claims/second

#: The concurrency NFR-PERF-01 names.
WORKERS = 20

#: How many devices this test actually queues. Smaller than 500 deliberately: the figure
#: being measured is a *rate*, and a rate is established just as well by 200 claims as by
#: 500. Keeping the test under a minute is what stops it being skipped.
DEVICE_COUNT = int(os.environ.get("PERF_DEVICE_COUNT", "200"))


@dataclass(slots=True)
class ClaimMeasurement:
    devices: int
    workers: int
    seconds: float

    @property
    def rate(self) -> float:
        return self.devices / self.seconds if self.seconds else float("inf")

    @property
    def headroom(self) -> float:
        return self.rate / REQUIRED_RATE

    @property
    def projected_seconds_for_500(self) -> float:
        return REQUIRED_DEVICES / self.rate if self.rate else float("inf")

    def describe(self) -> str:
        return (
            f"{self.devices} devices claimed and completed by {self.workers} workers in "
            f"{self.seconds:.2f}s = {self.rate:.1f} claims/s. "
            f"NFR-PERF-01 needs {REQUIRED_RATE:.3f} claims/s, so headroom is "
            f"{self.headroom:.0f}×. Projected queue time for 500 devices: "
            f"{self.projected_seconds_for_500:.1f}s against a 3600s budget."
        )


@pytest.fixture
async def perf_engine(database_ready: str):
    """A pooled engine, because this test needs genuinely concurrent connections.

    The ordinary `session` fixture binds everything to one connection inside a
    transaction that is rolled back. That is exactly wrong here: SKIP LOCKED contention
    cannot be observed on a single connection, and measuring it on one would produce a
    number that means nothing.
    """
    engine = create_async_engine(database_ready, poolclass=NullPool)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
async def perf_session(perf_engine) -> AsyncSession:
    maker = async_sessionmaker(bind=perf_engine, expire_on_commit=False, class_=AsyncSession)
    async with maker() as session:
        yield session


async def _cleanup(engine, marker: str) -> None:
    """Remove what this test wrote. It commits for real, so it must tidy up."""
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "DELETE FROM job_devices WHERE device_id IN "
                "(SELECT id FROM devices WHERE notes = :m)"
            ),
            {"m": marker},
        )
        await conn.execute(text("DELETE FROM jobs WHERE correlation_id = :m"), {"m": marker})
        await conn.execute(text("DELETE FROM devices WHERE notes = :m"), {"m": marker})
        await conn.execute(text("DELETE FROM users WHERE username LIKE :m"), {"m": "perf\\_%"})


class TestJobQueueThroughput:
    async def test_claim_rate_exceeds_the_requirement(self, perf_engine) -> None:
        """The measurement ADR-001 deferred."""
        marker = f"perf-{uuid.uuid4().hex[:8]}"
        maker = async_sessionmaker(bind=perf_engine, expire_on_commit=False, class_=AsyncSession)

        try:
            # ── set up: one job fanned out over DEVICE_COUNT devices ─────
            async with maker() as session:
                user = await make_user(session, username=f"perf_{uuid.uuid4().hex[:6]}")
                actor = Principal(
                    id=user.id, username=user.username, roles=user.role_set, scope=Scope.all()
                )
                inventory = InventoryService(session)

                device_ids = []
                for n in range(DEVICE_COUNT):
                    device = await inventory.create_device(
                        # 198.51.100.0/24 is TEST-NET-2; these are never contacted.
                        mgmt_ip=f"198.51.{100 + n // 250}.{n % 250 + 1}",
                        actor=actor,
                        vendor=Vendor.CISCO,
                        platform="cisco_ios",
                        notes=marker,
                    )
                    device_ids.append(device.id)

                job = await JobService(session).create(
                    job_type=JobType.COLLECT,
                    scope=JobScope(device_ids=tuple(device_ids)),
                    actor=actor,
                )
                job.correlation_id = marker
                await session.commit()
                job_id = job.id

            # ── measure: 20 workers sharing the job ──────────────────────
            claimed = [0] * WORKERS

            async def worker(index: int) -> None:
                """One worker's claim loop, with its own connection.

                No device contact: this isolates the queue. A worker that also opened an
                SSH session would be measuring asyncssh, not Procrastinate.
                """
                async with maker() as session:
                    jobs = JobService(session)
                    job_row = await jobs.get(job_id)
                    while True:
                        job_device = await jobs.claim_next_device(job_row)
                        if job_device is None:
                            break
                        await jobs.finish_device(job_device, succeeded=True, command_count=1)
                        await session.commit()
                        claimed[index] += 1

            started = time.perf_counter()
            await asyncio.gather(*(worker(i) for i in range(WORKERS)))
            elapsed = time.perf_counter() - started

            measurement = ClaimMeasurement(devices=DEVICE_COUNT, workers=WORKERS, seconds=elapsed)
            print(f"\n{measurement.describe()}")

            # ── assert ───────────────────────────────────────────────────
            async with maker() as session:
                remaining = (
                    (
                        await session.execute(
                            select(JobDevice).where(
                                JobDevice.job_id == job_id,
                                JobDevice.status == DeviceJobStatus.PENDING.value,
                            )
                        )
                    )
                    .scalars()
                    .all()
                )

            assert not remaining, f"{len(remaining)} devices were never claimed"
            assert sum(claimed) == DEVICE_COUNT, (
                f"workers claimed {sum(claimed)} devices for a job of {DEVICE_COUNT} — "
                "SKIP LOCKED handed the same device to two workers, or dropped one"
            )

            # The margin the decision rests on. A 10× floor rather than 1× because a
            # queue running at its limit has no room for the retries, schedule ticks and
            # concurrent jobs a real deployment also carries.
            assert measurement.headroom > 10, measurement.describe()

            # Every worker did some of the work: a result where one worker claimed
            # everything would meet the rate while proving nothing about contention.
            assert sum(1 for c in claimed if c > 0) >= WORKERS // 2, (
                f"only {sum(1 for c in claimed if c > 0)} of {WORKERS} workers claimed "
                f"anything: {claimed}"
            )

        finally:
            await _cleanup(perf_engine, marker)

    async def test_no_device_is_claimed_twice_under_contention(self, perf_engine) -> None:
        """FR-COL-06. The correctness half of the same mechanism.

        Throughput is worthless if concurrency lets two workers collect the same device:
        the audit trail would show two sessions where the operator authorised one.
        """
        marker = f"perf-{uuid.uuid4().hex[:8]}"
        maker = async_sessionmaker(bind=perf_engine, expire_on_commit=False, class_=AsyncSession)

        try:
            async with maker() as session:
                user = await make_user(session, username=f"perf_{uuid.uuid4().hex[:6]}")
                actor = Principal(
                    id=user.id, username=user.username, roles=user.role_set, scope=Scope.all()
                )
                inventory = InventoryService(session)
                device_ids = [
                    (
                        await inventory.create_device(
                            mgmt_ip=f"198.51.110.{n + 1}",
                            actor=actor,
                            vendor=Vendor.CISCO,
                            platform="cisco_ios",
                            notes=marker,
                        )
                    ).id
                    for n in range(40)
                ]
                job = await JobService(session).create(
                    job_type=JobType.COLLECT,
                    scope=JobScope(device_ids=tuple(device_ids)),
                    actor=actor,
                )
                job.correlation_id = marker
                await session.commit()
                job_id = job.id

            seen: list[uuid.UUID] = []
            lock = asyncio.Lock()

            async def worker() -> None:
                async with maker() as session:
                    jobs = JobService(session)
                    job_row = await jobs.get(job_id)
                    while True:
                        job_device = await jobs.claim_next_device(job_row)
                        if job_device is None:
                            break
                        async with lock:
                            seen.append(job_device.device_id)
                        await jobs.finish_device(job_device, succeeded=True, command_count=1)
                        await session.commit()

            await asyncio.gather(*(worker() for _ in range(WORKERS)))

            assert len(seen) == len(set(seen)), (
                "a device was claimed by more than one worker — SKIP LOCKED is not "
                "doing what FR-COL-06 depends on"
            )
            assert set(seen) == set(device_ids)

        finally:
            await _cleanup(perf_engine, marker)
