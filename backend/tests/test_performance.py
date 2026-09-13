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


# ────────────────── firewall rule analysis (NFR-PERF-03) ────────────────────

#: NFR-PERF-03: rule relationship analysis for a 5,000-rule rulebase in ≤ 2 minutes.
RULEBASE_SIZE = 5_000
RULEBASE_BUDGET_SECONDS = 120.0


def _synthetic_rulebase(count: int, *, seed: int = 7) -> dict:
    """A rulebase shaped like a real one.

    Mostly /24s drawn from a pool of objects, a scattering of genuinely broad rules,
    some disabled, spread over six zones. The shape matters: a rulebase where nothing
    overlaps would exercise only the prefilter and prove nothing.
    """
    import random

    rng = random.Random(seed)
    zones = ["trust", "untrust", "dmz", "guest", "mgmt", "partner"]

    address_objects = [
        {"name": f"net-{n}", "type": "subnet", "value": f"10.{n // 256}.{n % 256}.0/24"}
        for n in range(200)
    ]
    address_groups = [
        {
            "name": f"grp-{g}",
            "type": "group",
            "members": [f"net-{rng.randrange(200)}" for _ in range(5)],
        }
        for g in range(20)
    ]
    services = [
        {"name": "web", "type": "tcp", "value": "tcp/443"},
        {"name": "http", "type": "tcp", "value": "tcp/80"},
        {"name": "ssh", "type": "tcp", "value": "tcp/22"},
        {"name": "db", "type": "tcp", "value": "tcp/1433-1435"},
        {"name": "dns", "type": "udp", "value": "udp/53"},
        {"name": "high", "type": "tcp", "value": "tcp/1024-65535"},
    ]

    rules = []
    for i in range(count):
        broad = rng.random() < 0.02
        rules.append(
            {
                "order": i + 1,
                "name": f"rule-{i + 1}",
                "enabled": rng.random() > 0.05,
                "src_zones": [rng.choice(zones)],
                "dst_zones": [rng.choice(zones)],
                "src": ["any"]
                if broad
                else [rng.choice([f"net-{rng.randrange(200)}", f"grp-{rng.randrange(20)}"])],
                "dst": ["any"] if broad else [f"net-{rng.randrange(200)}"],
                "services": ["any"] if broad else [rng.choice(services)["name"]],
                "action": "allow" if rng.random() > 0.25 else "deny",
                "log_end": rng.random() > 0.2,
                "profiles": {} if rng.random() < 0.3 else {"ips": "strict"},
            }
        )

    return {
        "address_objects": address_objects,
        "address_groups": address_groups,
        "service_objects": services,
        "service_groups": [],
        "security_rules": rules,
    }


def _adversarial_rulebase(count: int) -> dict:
    """The shape that defeats every prefilter.

    One zone pair, every source overlapping so the address signature never rejects,
    alternating actions and no containment so nothing is shadowed and the early break
    never fires. All n(n-1)/2 pairs go through the full set arithmetic. No real rulebase
    looks like this, which is exactly why it is the number worth quoting.
    """
    rules = []
    for i in range(count):
        lo = i % 200
        rules.append(
            {
                "order": i + 1,
                "name": f"rule-{i + 1}",
                "enabled": True,
                "src_zones": ["trust"],
                "dst_zones": ["untrust"],
                "src": [f"10.{lo}.0.0-10.{lo + 40}.255.255"],
                "dst": [f"172.16.{lo % 100}.0-172.16.{(lo % 100) + 50}.255"],
                "services": [f"tcp/{1000 + (i % 50) * 10}-{1400 + (i % 50) * 10}"],
                "action": "allow" if i % 2 else "deny",
                "log_end": True,
            }
        )
    return {
        "address_objects": [],
        "address_groups": [],
        "service_objects": [],
        "service_groups": [],
        "security_rules": rules,
    }


class TestFirewallAnalysisPerformance:
    """NFR-PERF-03, and the Phase 4 acceptance criterion."""

    def test_a_realistic_five_thousand_rule_rulebase(self) -> None:
        from netsecops.firewall.analysis import analyse
        from netsecops.firewall.model import resolve_rulebase

        firewall = _synthetic_rulebase(RULEBASE_SIZE)

        started = time.perf_counter()
        rules, _ = resolve_rulebase(firewall)
        result = analyse(rules, max_relationships=10_000_000)
        elapsed = time.perf_counter() - started

        print(
            f"\nrealistic: {RULEBASE_SIZE} rules in {elapsed:.2f}s of "
            f"{RULEBASE_BUDGET_SECONDS:.0f}s "
            f"({elapsed / RULEBASE_BUDGET_SECONDS * 100:.1f}% of budget); "
            f"{result.pairs_considered:,} pairs considered, "
            f"{result.pairs_compared:,} fully compared, "
            f"{result.total_found:,} relationships"
        )

        assert elapsed < RULEBASE_BUDGET_SECONDS, (
            f"{RULEBASE_SIZE} rules took {elapsed:.1f}s against a "
            f"{RULEBASE_BUDGET_SECONDS:.0f}s budget"
        )
        assert result.rules_analysed > RULEBASE_SIZE * 0.9
        # The prefilters must actually be filtering. If nearly every pair reached full
        # comparison, the measurement above is luck rather than design.
        assert result.pairs_compared < result.pairs_considered * 0.05

    def test_the_adversarial_worst_case_also_fits(self) -> None:
        """The number worth quoting, because it does not depend on the rulebase being
        well behaved."""
        from netsecops.firewall.analysis import analyse
        from netsecops.firewall.model import resolve_rulebase

        firewall = _adversarial_rulebase(RULEBASE_SIZE)

        started = time.perf_counter()
        rules, _ = resolve_rulebase(firewall)
        # The production cap is 2,000; this materialises everything so the cost is the
        # full traversal rather than how quickly the analysis can give up.
        result = analyse(rules, max_relationships=50_000_000)
        elapsed = time.perf_counter() - started

        print(
            f"\nadversarial: {RULEBASE_SIZE} rules in {elapsed:.2f}s of "
            f"{RULEBASE_BUDGET_SECONDS:.0f}s "
            f"({elapsed / RULEBASE_BUDGET_SECONDS * 100:.1f}% of budget); "
            f"{result.pairs_considered:,} pairs, {result.total_found:,} relationships"
        )

        assert elapsed < RULEBASE_BUDGET_SECONDS, (
            f"the adversarial {RULEBASE_SIZE}-rule case took {elapsed:.1f}s against a "
            f"{RULEBASE_BUDGET_SECONDS:.0f}s budget"
        )
        # Every pair really was examined — otherwise this is not the worst case.
        expected_pairs = RULEBASE_SIZE * (RULEBASE_SIZE - 1) // 2
        assert result.pairs_considered == expected_pairs

    def test_the_production_cap_keeps_a_pathological_rulebase_fast(self) -> None:
        """With the shipped cap, even the adversarial case returns quickly — and the
        counts stay truthful about how much was found."""
        from netsecops.firewall.analysis import MAX_RELATIONSHIPS, analyse
        from netsecops.firewall.model import resolve_rulebase

        rules, _ = resolve_rulebase(_adversarial_rulebase(RULEBASE_SIZE))

        started = time.perf_counter()
        result = analyse(rules)
        elapsed = time.perf_counter() - started

        assert elapsed < RULEBASE_BUDGET_SECONDS
        assert len(result.relationships) == MAX_RELATIONSHIPS
        assert result.truncated
        assert result.total_found > MAX_RELATIONSHIPS
