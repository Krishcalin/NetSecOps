"""Recurring assessments (FR-JOB-02, and FR-DISC-05's second half).

The `schedules` table, its migration and its API schemas have existed since Phase 1 with
nothing reading them. Three separate requirements point at this one gap — recurring
assessments (FR-JOB-02), schedulable discovery (FR-DISC-05) and scheduled reporting
(FR-RPT-04) — which is why it is built once here rather than three times.

Four decisions shape everything below, and each is a place where the obvious behaviour is
wrong.

**A missed schedule fires once, not once per occurrence missed.** A scheduler down for a
day owes an hourly job twenty-four runs. Firing them would open twenty-four sessions to
every device in the scope the moment the process came back — a self-inflicted outage at
exactly the moment somebody is already dealing with one. So a due schedule fires once,
`next_run_at` advances past every occurrence already behind us, and the lateness is
recorded rather than repaid.

**A blackout skips the occurrence, it does not defer it.** Blackouts here are about load,
not change risk: NetSecOps never writes to a device, so a change freeze is no reason to
avoid reading one — but a business-hours window is a real reason not to open five hundred
SSH sessions. Deferring to the end of the window would stack every skipped schedule onto
the same minute, which is the load problem again in a smaller box.

**Two schedulers must not both fire one schedule.** Claiming is `SELECT … FOR UPDATE SKIP
LOCKED` and the row is advanced inside the same transaction, so a second process sees a
schedule that is no longer due rather than waiting for the first to finish.

**A schedule whose cron cannot be parsed is disabled, not skipped.** Skipping it silently
would leave an operator with a schedule that looks active in the console and has never
run. It is switched off with the reason recorded, which is visible.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import croniter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import NotFoundError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Principal, Scope
from netsecops.db.models.audit import AuditAction
from netsecops.db.models.jobs import Job, JobType, Schedule
from netsecops.services.audit import AuditService
from netsecops.services.jobs import JobScope, JobService
from netsecops.vuln.fetch import DEFAULT_SOURCES

log = get_logger(__name__)

#: How many occurrences to step past when looking for one outside a blackout.
#:
#: A blackout that covers every occurrence is a configuration error, not a schedule that
#: should be searched forever. The bound turns an infinite loop into a schedule that
#: reports it cannot find a slot.
MAX_BLACKOUT_SKIPS = 366


@dataclass(slots=True)
class FireResult:
    """What one tick did to one schedule."""

    schedule_id: uuid.UUID
    name: str
    job_id: uuid.UUID | None = None
    #: Set when the schedule was due and deliberately not run.
    skipped: str | None = None
    #: How late the fire was, in seconds. Non-zero means the scheduler was not running
    #: when the occurrence came due — worth surfacing, because a job that runs six hours
    #: after its window is a different thing from one that runs on time.
    late_seconds: int = 0


def validate_cron(expression: str) -> None:
    if not croniter.is_valid(expression):
        raise ValidationProblem(
            f"{expression!r} is not a valid cron expression. Five fields: minute, hour, "
            "day of month, month, day of week — for example `0 2 * * *` for 02:00 daily."
        )


def zone_for(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(name or "UTC")
    except (ZoneInfoNotFoundError, ValueError):
        raise ValidationProblem(
            f"{name!r} is not a time zone this system knows. Use an IANA name such as "
            "`Europe/London` or `Asia/Kolkata`."
        ) from None


def _blocked(moment: datetime, blackout: dict[str, Any] | None) -> str | None:
    """Whether a moment falls inside a blackout, and which rule caught it.

    Three independent rules, any of which blocks:

    - ``weekdays``: ISO numbers, Monday 1 to Sunday 7.
    - ``hours``: ``{"start": "22:00", "end": "06:00"}``, wrapping past midnight when the
      end is earlier than the start — which is the common case, since the window people
      actually want to protect is the working day or the night.
    - ``dates``: ``[{"from": "2026-12-20", "to": "2027-01-02"}]`` inclusive, for a freeze.
    """
    if not blackout:
        return None

    weekdays = blackout.get("weekdays")
    if isinstance(weekdays, list) and moment.isoweekday() in weekdays:
        return f"{moment:%A} is a blackout day"

    hours = blackout.get("hours")
    if isinstance(hours, dict):
        start, end = _as_time(hours.get("start")), _as_time(hours.get("end"))
        if start is not None and end is not None:
            current = moment.timetz().replace(tzinfo=None)
            inside = start <= current < end if start <= end else current >= start or current < end
            if inside:
                return (
                    f"{moment:%H:%M} is inside the {hours.get('start')}–{hours.get('end')} blackout"
                )

    for window in blackout.get("dates") or []:
        if not isinstance(window, dict):
            continue
        begins, ends = _as_date(window.get("from")), _as_date(window.get("to"))
        if begins and ends and begins <= moment.date() <= ends:
            return f"{moment:%Y-%m-%d} is inside the {begins}–{ends} freeze"

    return None


def _as_time(value: Any) -> time | None:
    try:
        return time.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _as_date(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def next_occurrence(
    schedule: Schedule, *, after: datetime, skip_blackouts: bool = True
) -> tuple[datetime | None, str | None]:
    """The next time this schedule should run after ``after``.

    Returns ``(when, reason_it_could_not)``. The cron is evaluated in the schedule's own
    time zone — `0 2 * * *` means two in the morning where the operator lives, and
    evaluating it in UTC would silently shift every schedule by the offset.
    """
    zone = zone_for(schedule.timezone)
    cursor = croniter(schedule.cron, after.astimezone(zone))

    for _ in range(MAX_BLACKOUT_SKIPS):
        candidate: datetime = cursor.get_next(datetime)
        if not skip_blackouts or _blocked(candidate, schedule.blackout) is None:
            return candidate.astimezone(UTC), None

    return None, (
        f"Every occurrence in the next {MAX_BLACKOUT_SKIPS} is inside a blackout window, "
        "so this schedule has no slot to run in. Widen the window or loosen the blackout."
    )


class ScheduleService:
    """Create, maintain and fire recurring jobs."""

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id
        self.audit = AuditService(session)

    # ── maintenance ─────────────────────────────────────────────────────

    async def create(
        self,
        *,
        name: str,
        job_type: JobType,
        scope: dict[str, Any],
        cron: str,
        actor: Principal,
        timezone: str = "UTC",
        description: str | None = None,
        enabled: bool = True,
        blackout: dict[str, Any] | None = None,
    ) -> Schedule:
        validate_cron(cron)
        zone_for(timezone)

        schedule = Schedule(
            org_id=self.org_id,
            name=name,
            description=description,
            job_type=job_type.value,
            scope=scope,
            cron=cron,
            timezone=timezone,
            blackout=blackout,
            enabled=enabled,
            created_by_id=actor.id,
        )
        # Computed before the row is stored, so a schedule is never visible without the
        # answer to "when does this next run" — which is the first thing anyone asks and
        # the only way to notice a cron that means something other than intended.
        schedule.next_run_at, _ = next_occurrence(schedule, after=datetime.now(UTC))

        self.session.add(schedule)
        await self.session.flush()

        await self.audit.record(
            AuditAction.SCHEDULE_CREATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="schedule",
            object_id=schedule.id,
            details={"name": name, "cron": cron, "job_type": job_type.value},
            org_id=self.org_id,
        )
        return schedule

    async def update(self, schedule: Schedule, *, actor: Principal, **changes: Any) -> Schedule:
        if (cron := changes.get("cron")) is not None:
            validate_cron(cron)
        if (timezone := changes.get("timezone")) is not None:
            zone_for(timezone)

        for field, value in changes.items():
            if value is not None:
                setattr(schedule, field, value)

        # Recomputed on every edit: an operator who fixes a wrong cron expects the next
        # run to move, and leaving the old one would fire at the time they just corrected.
        schedule.next_run_at, _ = next_occurrence(schedule, after=datetime.now(UTC))
        await self.session.flush()

        await self.audit.record(
            AuditAction.SCHEDULE_UPDATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="schedule",
            object_id=schedule.id,
            details={k: v for k, v in changes.items() if v is not None},
            org_id=self.org_id,
        )
        return schedule

    async def get(self, schedule_id: uuid.UUID) -> Schedule:
        schedule = (
            await self.session.execute(
                select(Schedule).where(Schedule.org_id == self.org_id, Schedule.id == schedule_id)
            )
        ).scalar_one_or_none()
        if schedule is None:
            raise NotFoundError(f"No schedule {schedule_id}.")
        return schedule

    # Not `list`: a method of that name shadows the builtin inside the class body, and
    # `-> list[FireResult]` further down then resolves to the method rather than the type.
    async def list_all(self) -> Sequence[Schedule]:
        return (
            (
                await self.session.execute(
                    select(Schedule).where(Schedule.org_id == self.org_id).order_by(Schedule.name)
                )
            )
            .scalars()
            .all()
        )

    async def delete(self, schedule: Schedule, *, actor: Principal) -> None:
        await self.audit.record(
            AuditAction.SCHEDULE_DELETED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="schedule",
            object_id=schedule.id,
            details={"name": schedule.name},
            org_id=self.org_id,
        )
        await self.session.delete(schedule)
        await self.session.flush()

    # ── the tick ────────────────────────────────────────────────────────

    async def due(self, *, now: datetime | None = None) -> Sequence[Schedule]:
        """Schedules whose time has come, claimed for this process.

        ``FOR UPDATE SKIP LOCKED`` so a second scheduler passes over anything this one is
        already holding rather than blocking on it — two processes must never fire the
        same schedule, and must not serialise either.
        """
        moment = now or datetime.now(UTC)
        return (
            (
                await self.session.execute(
                    select(Schedule)
                    .where(
                        Schedule.org_id == self.org_id,
                        Schedule.enabled.is_(True),
                        Schedule.next_run_at.isnot(None),
                        Schedule.next_run_at <= moment,
                    )
                    .order_by(Schedule.next_run_at)
                    .with_for_update(skip_locked=True)
                )
            )
            .scalars()
            .all()
        )

    async def fire(self, schedule: Schedule, *, now: datetime | None = None) -> FireResult:
        """Run one due schedule, and set its next time.

        ``next_run_at`` is advanced whatever happens — including when the job could not be
        created. A schedule that stayed due after failing would be retried on every tick,
        which turns one broken schedule into a tight loop against the estate.
        """
        moment = now or datetime.now(UTC)
        result = FireResult(schedule_id=schedule.id, name=schedule.name)

        if schedule.next_run_at is not None:
            late = (moment - schedule.next_run_at).total_seconds()
            result.late_seconds = max(0, int(late))

        if (reason := _blocked(moment, schedule.blackout)) is not None:
            # Due, but the moment it actually arrived is inside a blackout — which
            # happens when the scheduler was down across the window's start.
            result.skipped = reason
        else:
            try:
                result.job_id = (await self._create_job(schedule)).id
            except ValidationProblem as exc:
                # A scope that no longer matches any device, most often. Recorded on the
                # schedule rather than raised: one broken schedule must not stop the tick
                # from running the others.
                result.skipped = str(exc)
                log.warning("schedule.job_not_created", schedule=schedule.name, error=str(exc))

        schedule.last_run_at = moment
        if result.job_id is not None:
            schedule.last_job_id = result.job_id

        # Advanced from *now*, not from the missed time: a scheduler that was down for a
        # day owes one run, not a day's worth.
        following, problem = next_occurrence(schedule, after=moment)
        if following is None:
            schedule.enabled = False
            schedule.next_run_at = None
            result.skipped = problem
            log.warning("schedule.disabled", schedule=schedule.name, reason=problem)
        else:
            schedule.next_run_at = following

        await self.session.flush()

        log.info(
            "schedule.fired",
            schedule=schedule.name,
            job_id=str(result.job_id) if result.job_id else None,
            skipped=result.skipped,
            late_seconds=result.late_seconds,
            next_run_at=schedule.next_run_at.isoformat() if schedule.next_run_at else None,
        )
        return result

    async def _create_job(self, schedule: Schedule) -> Job:
        jobs = JobService(self.session)
        job_type = JobType(schedule.job_type)

        if job_type is JobType.DISCOVERY:
            raw = (schedule.scope or {}).get("discovery_scope_id")
            if not raw:
                raise ValidationProblem(
                    f"Schedule {schedule.name!r} runs discovery but names no scope."
                )
            return await jobs.create_discovery(
                discovery_scope_id=uuid.UUID(str(raw)),
                actor=_scheduler_principal(schedule),
                schedule_id=schedule.id,
                org_id=self.org_id,
            )

        if job_type is JobType.REPORT:
            scope = schedule.scope or {}
            template = scope.get("template")
            if not template:
                raise ValidationProblem(
                    f"Schedule {schedule.name!r} generates a report but names no template."
                )
            return await jobs.create_report(
                template=str(template),
                deliver_to=scope.get("deliver_to"),
                fmt=str(scope.get("format") or "pdf"),
                actor=_scheduler_principal(schedule),
                schedule_id=schedule.id,
                org_id=self.org_id,
            )

        if job_type is JobType.NOTIFY:
            return await jobs.create_notify(
                actor=_scheduler_principal(schedule),
                schedule_id=schedule.id,
                org_id=self.org_id,
            )

        if job_type is JobType.SIEM_FORWARD:
            return await jobs.create_siem_forward(
                actor=_scheduler_principal(schedule),
                schedule_id=schedule.id,
                org_id=self.org_id,
            )

        if job_type is JobType.FEED_SYNC:
            # An empty or absent list means every known source, which is what a schedule
            # called "nightly feed sync" is asking for. Naming sources stays possible for
            # the estate that mirrors one feed and fetches the rest.
            sources = (schedule.scope or {}).get("feed_sources") or sorted(DEFAULT_SOURCES)
            return await jobs.create_feed_sync(
                sources=[str(name) for name in sources],
                actor=_scheduler_principal(schedule),
                schedule_id=schedule.id,
                org_id=self.org_id,
            )

        return await jobs.create(
            job_type=job_type,
            scope=JobScope.from_json(schedule.scope or {}),
            actor=_scheduler_principal(schedule),
            principal_scope=Scope.all(),
            schedule_id=schedule.id,
            org_id=self.org_id,
        )

    async def tick(self, *, now: datetime | None = None) -> list[FireResult]:
        """Fire everything currently due. One pass."""
        moment = now or datetime.now(UTC)
        results = [await self.fire(schedule, now=moment) for schedule in await self.due(now=moment)]

        if results:
            log.info(
                "scheduler.tick",
                fired=sum(1 for r in results if r.job_id),
                skipped=sum(1 for r in results if r.skipped),
            )
        return results


def _scheduler_principal(schedule: Schedule) -> Principal:
    """The actor recorded for work a schedule started.

    Attributed to whoever created the schedule, not to an anonymous system account: a job
    that touches five hundred devices at two in the morning should trace back to a person,
    and the schedule is the only record of which one.
    """
    from netsecops.core.rbac import Role

    return Principal(
        id=schedule.created_by_id or uuid.UUID(int=0),
        username="scheduler",
        roles=frozenset({Role.API_SERVICE}),
        scope=Scope.all(),
    )


__all__ = [
    "MAX_BLACKOUT_SKIPS",
    "FireResult",
    "ScheduleService",
    "next_occurrence",
    "validate_cron",
    "zone_for",
]
