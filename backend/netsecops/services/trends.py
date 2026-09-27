"""Is the estate getting better? (FR-FIND-05, FR-CHK-09)

Every number a dashboard shows answers a question, and this file's question is the one
nobody could ask until now: not "how many findings are open" but "were there more last
month". The data to answer it has been accumulating since Phase 3 — `risk_scores` keeps
a row per computation on purpose, and `findings.first_seen_at` is written once and never
cleared — and nothing has ever read either as a series.

**What is not here matters as much as what is.** FR-FIND-05 asks for "open findings by
severity over time", and that cannot be reconstructed from what this schema stores. A
finding is one row per device and fingerprint, carrying its *current* status; when a
problem comes back the row is reopened and `resolved_at` is set back to NULL, so the
earlier resolution leaves no trace. There is no transition log — `FINDING_STATUS_CHANGED`
is audited only when a person changes a status by hand, never when an assessment does.

So a retrospective open-count would be a curve drawn through points the database cannot
vouch for: every finding that was fixed and came back would read as open throughout, and
the chart would be most wrong exactly where an estate is most interesting. It is not
offered. What is offered is the part that is exact:

* **First seen per day** — `first_seen_at` is set at creation and never touched again,
  so this series is true for all time.
* **Resolutions that still stand** — resolutions of findings that are resolved *now*.
  Stated in those words rather than as "resolved per day", because a resolution that was
  later undone is not in it, and `reopened` alongside says how much that is.
* **Time to resolve** — from first sighting to the resolution that still stands, so a
  problem fixed twice is measured over the whole saga rather than the second attempt.
* **Risk over time** — exact, because `risk_scores` is append-only.

Making the open-count answerable needs an append-only transition log written wherever a
finding changes state. That is a schema change and a write-path change across six
services, and it can only ever describe time *after* it ships, so it is worth doing
deliberately rather than as a side effect of drawing a chart.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import get_logger
from netsecops.core.rbac import Scope
from netsecops.db.models.collection import Finding, FindingSeverity, FindingStatus
from netsecops.db.models.inventory import Device, DeviceGroupMember
from netsecops.db.models.policy import RiskScore

log = get_logger(__name__)

#: Longest window a caller may ask for. A year of daily buckets is 365 rows, which is
#: more than any chart draws legibly and more than this schema can be trusted to
#: describe — most deployments have not been running that long.
MAX_DAYS = 365
DEFAULT_DAYS = 90

SEVERITIES = [s.value for s in FindingSeverity]


@dataclass(frozen=True, slots=True)
class DayPoint:
    """One day. `first_seen` and `resolved` are counts of events, not of state."""

    day: date
    first_seen: int
    resolved: int
    #: First sightings split by the finding's severity *now*. Severity can be revised by
    #: a later assessment, so this is "how bad we currently think those were" rather
    #: than what was believed on the day — the row does not keep the old value.
    first_seen_by_severity: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class FindingTrend:
    days: int
    since: date
    points: list[DayPoint]
    #: Open right now, by severity. The honest counterpart to the series above: a
    #: current fact rather than a reconstructed one.
    open_by_severity: dict[str, int]
    #: Findings that were resolved and have since come back. The size of what the
    #: `resolved` series cannot see.
    reopened_now: int
    #: Median and mean days from first sighting to a resolution that still stands.
    #: None when nothing in the window has been resolved — not zero, which would read
    #: as "fixed instantly".
    median_days_to_resolve: float | None
    mean_days_to_resolve: float | None
    resolved_in_window: int

    @property
    def total_first_seen(self) -> int:
        return sum(p.first_seen for p in self.points)

    @property
    def total_resolved(self) -> int:
        return sum(p.resolved for p in self.points)


@dataclass(frozen=True, slots=True)
class RiskPoint:
    at: datetime
    score: int
    checks_evaluated: int


@dataclass(frozen=True, slots=True)
class RiskTrend:
    device_id: uuid.UUID
    points: list[RiskPoint]

    @property
    def direction(self) -> str:
        """`improving`, `worsening`, `steady`, or `unknown` with fewer than two points.

        Named rather than left to the caller to infer from a slope, so the console and
        a report cannot disagree about what the same two numbers mean.
        """
        if len(self.points) < 2:
            return "unknown"
        first, last = self.points[0].score, self.points[-1].score
        if last < first:
            return "improving"
        if last > first:
            return "worsening"
        return "steady"


class TrendService:
    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id

    def _scoped(
        self, statement: Select[Any], scope: Scope, group_id: uuid.UUID | None
    ) -> Select[Any]:
        """Narrow to the devices this caller may see, and to one group if asked.

        Both are applied here rather than by the caller, because a trend is an aggregate
        — an unscoped one leaks the *shape* of devices a group-restricted operator
        cannot list, which is a slower version of leaking the devices.
        """
        # `select_from` explicitly: every statement here selects aggregates rather than
        # entities, so SQLAlchemy has no column to infer the left side of the join from
        # and refuses rather than guessing.
        statement = (
            statement.select_from(Finding)
            .join(Device, Finding.device_id == Device.id)
            .where(Device.org_id == self.org_id)
        )

        if not scope.unrestricted:
            statement = statement.where(
                Device.id.in_(
                    select(DeviceGroupMember.device_id).where(
                        DeviceGroupMember.group_id.in_(scope.device_group_ids)
                    )
                )
            )

        if group_id is not None:
            statement = statement.where(
                Device.id.in_(
                    select(DeviceGroupMember.device_id).where(
                        DeviceGroupMember.group_id == group_id
                    )
                )
            )

        return statement

    async def findings(
        self,
        *,
        scope: Scope,
        days: int = DEFAULT_DAYS,
        group_id: uuid.UUID | None = None,
        now: datetime | None = None,
    ) -> FindingTrend:
        days = max(1, min(days, MAX_DAYS))
        now = now or datetime.now(UTC)
        since = (now - timedelta(days=days - 1)).date()
        since_at = datetime.combine(since, datetime.min.time(), tzinfo=UTC)

        first_seen_day = func.date(Finding.first_seen_at)
        seen_rows = (
            await self.session.execute(
                self._scoped(
                    select(first_seen_day, Finding.severity, func.count()), scope, group_id
                )
                .where(Finding.first_seen_at >= since_at)
                .group_by(first_seen_day, Finding.severity)
            )
        ).all()

        resolved_day = func.date(Finding.resolved_at)
        resolved_rows = (
            await self.session.execute(
                self._scoped(select(resolved_day, func.count()), scope, group_id)
                .where(
                    Finding.resolved_at >= since_at,
                    Finding.status == FindingStatus.RESOLVED.value,
                )
                .group_by(resolved_day)
            )
        ).all()

        open_rows = (
            await self.session.execute(
                self._scoped(select(Finding.severity, func.count()), scope, group_id)
                .where(Finding.status.in_(FindingStatus.active_values()))
                .group_by(Finding.severity)
            )
        ).all()

        reopened = (
            await self.session.execute(
                self._scoped(select(func.count()), scope, group_id).where(
                    Finding.status == FindingStatus.REOPENED.value
                )
            )
        ).scalar_one()

        # Every day in the window, including the ones nothing happened on. A series with
        # gaps is drawn as a line between two distant points, which reads as a gradual
        # change rather than as no data.
        seen_by_day: dict[date, dict[str, int]] = {}
        for day, severity, count in seen_rows:
            seen_by_day.setdefault(_as_date(day), {})[severity] = count
        resolved_by_day = {_as_date(day): count for day, count in resolved_rows}

        points = []
        for offset in range(days):
            day = since + timedelta(days=offset)
            by_severity = seen_by_day.get(day, {})
            points.append(
                DayPoint(
                    day=day,
                    first_seen=sum(by_severity.values()),
                    resolved=resolved_by_day.get(day, 0),
                    first_seen_by_severity={s: by_severity.get(s, 0) for s in SEVERITIES},
                )
            )

        median, mean, resolved_count = await self._time_to_resolve(
            scope=scope, group_id=group_id, since_at=since_at
        )

        return FindingTrend(
            days=days,
            since=since,
            points=points,
            open_by_severity=dict.fromkeys(SEVERITIES, 0)
            | {str(severity): int(count) for severity, count in open_rows},
            reopened_now=int(reopened),
            median_days_to_resolve=median,
            mean_days_to_resolve=mean,
            resolved_in_window=resolved_count,
        )

    async def _time_to_resolve(
        self, *, scope: Scope, group_id: uuid.UUID | None, since_at: datetime
    ) -> tuple[float | None, float | None, int]:
        """Median and mean days from first sighting to a resolution that still stands.

        The median is reported first because one finding that sat open for two years
        drags a mean somewhere no individual finding has ever been, and the mean is kept
        beside it so that skew is visible rather than hidden by whichever was chosen.
        """
        elapsed = (
            func.extract(
                "epoch",
                Finding.resolved_at - func.coalesce(Finding.first_seen_at, Finding.created_at),
            )
            / 86400.0
        )

        row = (
            await self.session.execute(
                self._scoped(
                    select(
                        func.percentile_cont(0.5).within_group(elapsed),
                        func.avg(elapsed),
                        func.count(),
                    ),
                    scope,
                    group_id,
                ).where(
                    Finding.resolved_at >= since_at,
                    Finding.status == FindingStatus.RESOLVED.value,
                )
            )
        ).one()

        median, mean, count = row
        if not count:
            return None, None, 0
        return (
            round(float(median), 1) if median is not None else None,
            round(float(mean), 1) if mean is not None else None,
            int(count),
        )

    async def risk(
        self,
        device_id: uuid.UUID,
        *,
        days: int = DEFAULT_DAYS,
        limit: int = 200,
        now: datetime | None = None,
    ) -> RiskTrend:
        """A device's risk score as it was recorded, oldest first.

        No bucketing by day: the points are the assessments, and an estate assessed
        weekly would otherwise be drawn as a line with six empty days between each
        reading. The caller who wants a date axis has the timestamps.
        """
        days = max(1, min(days, MAX_DAYS))
        since_at = (now or datetime.now(UTC)) - timedelta(days=days)

        rows = (
            (
                await self.session.execute(
                    select(RiskScore)
                    .where(RiskScore.device_id == device_id, RiskScore.created_at >= since_at)
                    .order_by(RiskScore.created_at.asc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )

        return RiskTrend(
            device_id=device_id,
            points=[
                RiskPoint(at=row.created_at, score=row.score, checks_evaluated=row.checks_evaluated)
                for row in rows
            ],
        )


def _as_date(value: object) -> date:
    """`func.date()` gives a `date` on asyncpg and a string on some drivers."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value))


__all__ = [
    "DEFAULT_DAYS",
    "MAX_DAYS",
    "SEVERITIES",
    "DayPoint",
    "FindingTrend",
    "RiskPoint",
    "RiskTrend",
    "TrendService",
]
