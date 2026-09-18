"""Recurring assessments (FR-JOB-02).

The `schedules` table, its migration and its API schemas shipped in Phase 1 and nothing
ever read them. Three requirements point at the gap — FR-JOB-02, FR-DISC-05's second half
and FR-RPT-04 — so it is built once.

Four behaviours carry the weight, and in each the obvious implementation is the wrong
one:

- **A missed schedule fires once.** A scheduler down for a day owes an hourly job
  twenty-four runs. Paying that debt would open twenty-four sessions to every device in
  scope the moment the process recovered, which is a self-inflicted outage at the worst
  possible moment.
- **A blackout skips, it does not defer.** Deferring stacks every skipped schedule onto
  the same minute, which is the load problem again in a smaller box.
- **Two schedulers never fire the same schedule.** Claiming is `FOR UPDATE SKIP LOCKED`.
- **An impossible schedule is disabled, not silently skipped.** One that looks active in
  the console and has never run is worse than one that is visibly off.

Time is injected everywhere rather than slept through: a scheduler tested against the
wall clock is either slow or tested with a tolerance wide enough to pass with the logic
removed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ValidationProblem
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.db.models.jobs import Job, JobType, Schedule
from netsecops.services.inventory import InventoryService
from netsecops.services.schedules import ScheduleService, next_occurrence, validate_cron
from tests.conftest import make_user

# A Wednesday, 02:00 UTC.
WEDNESDAY = datetime(2026, 9, 16, 2, 0, tzinfo=UTC)


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="schedule_owner", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
def schedules(session: AsyncSession) -> ScheduleService:
    return ScheduleService(session)


@pytest.fixture
async def device(session: AsyncSession, actor: Principal):
    return await InventoryService(session).create_device(
        mgmt_ip="10.77.0.1",
        actor=actor,
        hostname="sched-sw",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )


async def make(schedules: ScheduleService, actor: Principal, device, **overrides) -> Schedule:
    defaults: dict = {
        "name": "nightly",
        "job_type": JobType.COLLECT_AND_ASSESS,
        "scope": {"device_ids": [str(device.id)], "group_ids": [], "tags": []},
        "cron": "0 2 * * *",
        "actor": actor,
    }
    return await schedules.create(**{**defaults, **overrides})


async def job_count(session: AsyncSession) -> int:
    from sqlalchemy import func, select

    return (await session.execute(select(func.count()).select_from(Job))).scalar_one()


# ═══════════════════════════ cron and timezones ══════════════════════════════


class TestCron:
    def test_a_bad_expression_is_refused_with_an_example(self) -> None:
        with pytest.raises(ValidationProblem) as raised:
            validate_cron("every tuesday please")

        assert "0 2 * * *" in str(raised.value)

    async def test_the_next_run_is_computed_before_the_row_is_stored(
        self, schedules, actor, device
    ) -> None:
        """The only way to notice a cron that means something other than intended, and
        the first thing anybody looks at."""
        schedule = await make(schedules, actor, device)

        assert schedule.next_run_at is not None
        assert schedule.next_run_at > datetime.now(UTC)

    async def test_the_cron_is_read_in_the_schedules_own_timezone(
        self, schedules, actor, device
    ) -> None:
        """`0 2 * * *` means two in the morning where the operator is. Evaluating it in
        UTC would shift every schedule silently by the offset — five and a half hours for
        an Indian estate, which is the difference between a maintenance window and the
        middle of the working day."""
        india = await make(
            schedules, actor, device, name="india", timezone="Asia/Kolkata", cron="0 2 * * *"
        )
        utc = await make(schedules, actor, device, name="utc", timezone="UTC", cron="0 2 * * *")

        assert india.next_run_at != utc.next_run_at

    async def test_an_unknown_timezone_is_refused(self, schedules, actor, device) -> None:
        with pytest.raises(ValidationProblem):
            await make(schedules, actor, device, timezone="Mars/Olympus_Mons")


# ═════════════════════════════ the missed-fire rule ══════════════════════════


class TestAMissedScheduleFiresOnce:
    async def test_a_day_of_missed_hourly_runs_produces_one_job(
        self, session: AsyncSession, schedules, actor, device
    ) -> None:
        """**The assertion this file exists for.**

        Twenty-four occurrences went by while the scheduler was down. Firing them all
        would open twenty-four sessions to every device in scope the moment it came back.
        """
        schedule = await make(schedules, actor, device, cron="0 * * * *")
        schedule.next_run_at = WEDNESDAY - timedelta(days=1)
        await session.flush()

        results = await schedules.tick(now=WEDNESDAY)

        assert len(results) == 1
        assert await job_count(session) == 1

    async def test_the_lateness_is_recorded_rather_than_repaid(
        self, session: AsyncSession, schedules, actor, device
    ) -> None:
        """A job that ran six hours after its window is a different fact from one that
        ran on time, and the job row cannot say so — it only knows when it started."""
        schedule = await make(schedules, actor, device, cron="0 * * * *")
        schedule.next_run_at = WEDNESDAY - timedelta(hours=6)
        await session.flush()

        [result] = await schedules.tick(now=WEDNESDAY)

        assert result.late_seconds == pytest.approx(6 * 3600, abs=60)

    async def test_the_next_run_is_computed_from_now_not_from_the_missed_time(
        self, session: AsyncSession, schedules, actor, device
    ) -> None:
        """Otherwise the next tick is immediately due again, and the catch-up becomes the
        tight loop it was meant to avoid."""
        schedule = await make(schedules, actor, device, cron="0 * * * *")
        schedule.next_run_at = WEDNESDAY - timedelta(days=1)
        await session.flush()

        await schedules.tick(now=WEDNESDAY)

        assert schedule.next_run_at is not None
        assert schedule.next_run_at > WEDNESDAY


# ═════════════════════════════════ blackouts ═════════════════════════════════


class TestBlackouts:
    async def test_a_weekday_blackout_moves_the_next_run_off_it(
        self, schedules, actor, device
    ) -> None:
        """Saturday and Sunday, ISO 6 and 7."""
        schedule = await make(
            schedules, actor, device, cron="0 2 * * *", blackout={"weekdays": [6, 7]}
        )

        assert schedule.next_run_at is not None
        assert schedule.next_run_at.isoweekday() not in (6, 7)

    async def test_an_hours_blackout_wrapping_midnight_is_honoured(
        self, schedules, actor, device
    ) -> None:
        """The window people actually protect — overnight, or the working day — crosses
        midnight, so `start > end` has to mean "wraps" rather than "empty".

        Asserted from a fixed moment *inside* the window rather than from whatever the
        clock says. An earlier version checked only that the next run fell outside 22–06,
        which passes by luck whenever the test happens to run in the afternoon: with the
        wrap logic deleted nothing is blocked at all, and the next hourly occurrence is
        in range more often than not. The mutation survived, which is how that was found.
        """
        schedule = await make(
            schedules,
            actor,
            device,
            cron="0 * * * *",
            blackout={"hours": {"start": "22:00", "end": "06:00"}},
        )

        # 23:00 on a Wednesday: deep inside the window, and the hour *after* it is too.
        when, problem = next_occurrence(schedule, after=datetime(2026, 9, 16, 23, 0, tzinfo=UTC))

        assert problem is None
        assert when is not None
        assert when.hour == 6
        assert when.date().isoformat() == "2026-09-17"

    async def test_a_date_freeze_is_honoured(
        self, session: AsyncSession, schedules, actor, device
    ) -> None:
        schedule = await make(
            schedules,
            actor,
            device,
            cron="0 2 * * *",
            blackout={"dates": [{"from": "2026-12-20", "to": "2027-01-02"}]},
        )
        when, problem = next_occurrence(schedule, after=datetime(2026, 12, 19, 12, tzinfo=UTC))

        assert problem is None
        assert when is not None and when.date().isoformat() > "2027-01-02"

    async def test_a_schedule_with_no_possible_slot_is_disabled_not_looped(
        self, session: AsyncSession, schedules, actor, device
    ) -> None:
        """A blackout covering every occurrence is a configuration error. Searching
        forever would hang the tick; skipping silently would leave a schedule that looks
        active in the console and has never run."""
        schedule = await make(
            schedules,
            actor,
            device,
            cron="0 2 * * *",
            blackout={"weekdays": [1, 2, 3, 4, 5, 6, 7]},
        )
        schedule.next_run_at = WEDNESDAY - timedelta(minutes=1)
        schedule.enabled = True
        await session.flush()

        [result] = await schedules.tick(now=WEDNESDAY)

        assert schedule.enabled is False
        assert schedule.next_run_at is None
        assert result.skipped is not None and "blackout" in result.skipped

    async def test_firing_inside_a_blackout_skips_rather_than_running(
        self, session: AsyncSession, schedules, actor, device
    ) -> None:
        """Happens when the scheduler was down across the window's start: the schedule is
        due, but the moment it actually arrived is inside the blackout."""
        saturday = datetime(2026, 9, 19, 2, 0, tzinfo=UTC)
        schedule = await make(
            schedules, actor, device, cron="0 2 * * *", blackout={"weekdays": [6, 7]}
        )
        schedule.next_run_at = saturday - timedelta(minutes=5)
        await session.flush()

        [result] = await schedules.tick(now=saturday)

        assert result.job_id is None
        assert result.skipped is not None
        assert await job_count(session) == 0


# ═══════════════════════════════ firing ══════════════════════════════════════


class TestFiring:
    async def test_a_due_schedule_creates_a_job_linked_back_to_it(
        self, session: AsyncSession, schedules, actor, device
    ) -> None:
        from sqlalchemy import select

        schedule = await make(schedules, actor, device)
        schedule.next_run_at = WEDNESDAY - timedelta(minutes=1)
        await session.flush()

        [result] = await schedules.tick(now=WEDNESDAY)

        job = (await session.execute(select(Job))).scalars().one()
        assert job.schedule_id == schedule.id
        assert schedule.last_job_id == job.id
        assert result.job_id == job.id

    async def test_a_schedule_not_yet_due_does_not_fire(
        self, session: AsyncSession, schedules, actor, device
    ) -> None:
        schedule = await make(schedules, actor, device)
        schedule.next_run_at = WEDNESDAY + timedelta(hours=1)
        await session.flush()

        assert await schedules.tick(now=WEDNESDAY) == []
        assert await job_count(session) == 0

    async def test_a_disabled_schedule_does_not_fire(
        self, session: AsyncSession, schedules, actor, device
    ) -> None:
        schedule = await make(schedules, actor, device, enabled=False)
        schedule.next_run_at = WEDNESDAY - timedelta(minutes=1)
        await session.flush()

        assert await schedules.tick(now=WEDNESDAY) == []

    async def test_a_scope_that_matches_nothing_advances_rather_than_retrying(
        self, session: AsyncSession, schedules, actor
    ) -> None:
        """A schedule that stayed due after failing would be retried every tick, turning
        one broken schedule into a tight loop against the estate."""
        schedule = await schedules.create(
            name="orphan",
            job_type=JobType.COLLECT_AND_ASSESS,
            scope={"device_ids": [str(uuid.uuid4())], "group_ids": [], "tags": []},
            cron="0 2 * * *",
            actor=actor,
        )
        schedule.next_run_at = WEDNESDAY - timedelta(minutes=1)
        await session.flush()

        [result] = await schedules.tick(now=WEDNESDAY)

        assert result.job_id is None
        assert result.skipped is not None
        assert schedule.next_run_at is not None and schedule.next_run_at > WEDNESDAY

    async def test_the_job_is_attributed_to_whoever_created_the_schedule(
        self, session: AsyncSession, schedules, actor, device
    ) -> None:
        """Work that touches five hundred devices at two in the morning should trace back
        to a person, and the schedule is the only record of which one."""
        from sqlalchemy import select

        schedule = await make(schedules, actor, device)
        schedule.next_run_at = WEDNESDAY - timedelta(minutes=1)
        await session.flush()

        await schedules.tick(now=WEDNESDAY)

        job = (await session.execute(select(Job))).scalars().one()
        assert job.requested_by_id == actor.id


class TestDiscoverySchedules:
    async def test_a_discovery_schedule_creates_a_discovery_job(
        self, session: AsyncSession, schedules, actor
    ) -> None:
        """FR-DISC-05's second half. The run executor already exists; this is the half
        that was owed."""
        from sqlalchemy import select

        from netsecops.db.models.discovery import DiscoveryScope

        scope = DiscoveryScope(
            org_id=1, name="nightly-sweep", targets=["198.51.100.0/30"], tcp_ports=[22]
        )
        session.add(scope)
        await session.flush()

        schedule = await schedules.create(
            name="sweep",
            job_type=JobType.DISCOVERY,
            scope={"discovery_scope_id": str(scope.id)},
            cron="0 3 * * *",
            actor=actor,
        )
        schedule.next_run_at = WEDNESDAY - timedelta(minutes=1)
        await session.flush()

        await schedules.tick(now=WEDNESDAY)

        job = (await session.execute(select(Job))).scalars().one()
        assert job.job_type == JobType.DISCOVERY.value
        assert job.scope == {"discovery_scope_id": str(scope.id)}

    async def test_a_discovery_schedule_naming_no_scope_does_not_fire(
        self, session: AsyncSession, schedules, actor
    ) -> None:
        schedule = await schedules.create(
            name="broken-sweep",
            job_type=JobType.DISCOVERY,
            scope={},
            cron="0 3 * * *",
            actor=actor,
        )
        schedule.next_run_at = WEDNESDAY - timedelta(minutes=1)
        await session.flush()

        [result] = await schedules.tick(now=WEDNESDAY)

        assert result.job_id is None
        assert await job_count(session) == 0


class TestMaintenance:
    async def test_editing_the_cron_moves_the_next_run(self, schedules, actor, device) -> None:
        """An operator who fixes a wrong cron expects the next run to move. Leaving the
        old one would fire at the time they just corrected."""
        schedule = await make(schedules, actor, device, cron="0 2 * * *")
        before = schedule.next_run_at

        await schedules.update(schedule, actor=actor, cron="30 14 * * *")

        assert schedule.next_run_at != before

    async def test_a_bad_cron_on_edit_is_refused(self, schedules, actor, device) -> None:
        schedule = await make(schedules, actor, device)

        with pytest.raises(ValidationProblem):
            await schedules.update(schedule, actor=actor, cron="nope")

    async def test_creating_and_deleting_are_audited(
        self, session: AsyncSession, schedules, actor, device
    ) -> None:
        """A schedule is a standing instruction to touch the estate unattended, so the
        trail has to answer "who set this up" without inferring it from the first job."""
        from sqlalchemy import select

        from netsecops.db.models import AuditLog

        schedule = await make(schedules, actor, device)
        await schedules.delete(schedule, actor=actor)

        actions = (await session.execute(select(AuditLog.action))).scalars().all()
        assert "schedule.created" in actions
        assert "schedule.deleted" in actions
