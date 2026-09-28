"""Letter grades and closure priorities (FR-CHK-09, FR-FIND-03).

**Neither of these is a new measurement, and that is the whole design.** A product that
prints a letter beside a firewall's name has made a claim about that firewall, and the
only defensible way to make it is to derive it from something already computed,
documented and stored — not to invent a second scale that happens to look authoritative.

So:

* **A grade is the risk score in a band.** `risk.score_device` produces 0–100 with its
  formula written down beside it; `GRADES` slices that range into six and names what
  each slice means. Nothing is recomputed, so a device's grade and its score can never
  disagree, and a change to the formula moves the grades with it.

* **A priority is the two numbers the score is already built from.** A finding's
  severity weight (`Severity.weight`) multiplied by its device's criticality multiplier
  (`risk.CRITICALITY_MULTIPLIER`) — the same product the score sums — read against four
  thresholds. There is no second matrix to maintain, and `priority_matrix()` *computes*
  the grid rather than restating it, so what the console shows a reader is what the code
  actually does.

**A device that has never been assessed has no grade.** Not A, which would say it is
clean, and not F, which would say it is broken. `grade_for(None)` is `None`, and every
count here keeps the ungraded separate — the same distinction `GET /devices/{id}/risk`
already makes, for the same reason.

**What the thresholds were chosen to say.** Severity weights are 40/20/8/3/0 and
criticality multipliers 1.5/1.2/1.0/0.8, so the product runs from 0 to 60. The bands
are placed so that every Critical finding is P1 wherever it sits, and criticality then
lifts exactly one band at each severity below that: a High on a critical device joins
the P1s, a Medium on one joins the P2s, a Low on one joins the P3s. Criticality as a
tie-breaker rather than a full axis is deliberate — a `criticality` column is set once
at import and rarely revisited, and a scheme that let a stale field demote a Critical
finding would be wrong in the direction that matters.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, overload

from sqlalchemy import Select, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import get_logger
from netsecops.core.rbac import Scope
from netsecops.db.models.collection import Finding, FindingSeverity, FindingStatus
from netsecops.db.models.inventory import Criticality, Device, DeviceStatus
from netsecops.db.models.policy import RiskScore
from netsecops.services.inventory import InventoryService
from netsecops.services.risk import CRITICALITY_MULTIPLIER, roll_up, severity_weight

log = get_logger(__name__)


# ────────────────────────────────── grades ──────────────────────────────────


@dataclass(frozen=True, slots=True)
class GradeBand:
    """One letter, and the span of the risk score that earns it."""

    letter: str
    #: Inclusive bounds on the 0–100 risk score, in which **0 is clean**. The letters
    #: therefore run the other way from the number, which is the point of having them.
    floor: int
    ceiling: int
    #: What a device has to look like to land here, in words rather than arithmetic.
    #: Shown next to the letter, because a grade nobody can cash out into a fact about
    #: the device is decoration.
    meaning: str


#: Six bands over 0–100, contiguous and exhaustive — `test_grading.py` fails if they
#: ever leave a gap or overlap, which is the failure that would make a score land on no
#: letter at all.
#:
#: The boundaries are placed at the scores real single findings produce, so each letter
#: names a recognisable state rather than a decile: one Medium on an ordinary device
#: scores 7, one High scores 17, one Critical scores 33, one Critical on a critical
#: device scores 50, and two of those saturate at 100.
GRADES: tuple[GradeBand, ...] = (
    GradeBand("A", 0, 4, "Clean, or a single low-severity warning."),
    GradeBand("B", 5, 14, "A medium-severity failure, or a few minor ones."),
    GradeBand("C", 15, 29, "A high-severity failure."),
    GradeBand("D", 30, 49, "A critical failure, or several high ones."),
    GradeBand("E", 50, 74, "A critical failure on a device that matters."),
    GradeBand("F", 75, 100, "More than one critical failure."),
)

#: The letters, worst first — the order a distribution is read in.
GRADE_LETTERS: tuple[str, ...] = tuple(band.letter for band in reversed(GRADES))


@overload
def grade_for(score: int) -> str: ...
@overload
def grade_for(score: None) -> None: ...
@overload
def grade_for(score: int | None) -> str | None: ...


def grade_for(score: int | None) -> str | None:
    """The letter for a risk score, or `None` for a device nobody has assessed.

    `None` rather than a letter is load-bearing: an unassessed device is not clean and
    is not broken, and either letter would be a statement the database cannot support.

    Overloaded so a caller that has already excluded `None` gets a `str` back, rather
    than having to re-check for a case the signature would otherwise keep alive — a
    branch that can never run is a branch no test can cover.
    """
    if score is None:
        return None
    for band in GRADES:
        if score <= band.ceiling:
            return band.letter
    return GRADES[-1].letter


# ───────────────────────────────── priorities ────────────────────────────────


@dataclass(frozen=True, slots=True)
class PriorityBand:
    """One closure priority, and the weight at which a finding reaches it."""

    code: str
    #: What the band asks somebody to do. The code alone tells an operator the order;
    #: this tells them the expectation, which is the part they act on.
    label: str
    #: Inclusive lower bound on severity weight × criticality multiplier.
    floor: float
    meaning: str


#: Ordered worst first, so `priority_for` can take the first band a weight clears.
PRIORITIES: tuple[PriorityBand, ...] = (
    PriorityBand(
        "P1", "Fix now", 30.0, "Any critical finding, or a high one on a critical device."
    ),
    PriorityBand(
        "P2", "Fix this cycle", 12.0, "Any high finding, or a medium one on a critical device."
    ),
    PriorityBand(
        "P3", "Planned work", 4.0, "Any medium finding, or a low one on a critical device."
    ),
    PriorityBand("P4", "Backlog", 0.0, "Low and informational findings."),
)

PRIORITY_CODES: tuple[str, ...] = tuple(band.code for band in PRIORITIES)


def priority_weight(severity: str, criticality: str) -> float:
    """The product the risk score is summed from, for one finding on one device."""
    return severity_weight(severity) * CRITICALITY_MULTIPLIER.get(criticality, 1.0)


def priority_for(severity: str, criticality: str) -> str:
    weight = priority_weight(severity, criticality)
    for band in PRIORITIES:
        if weight >= band.floor:
            return band.code
    return PRIORITIES[-1].code


@dataclass(frozen=True, slots=True)
class MatrixCell:
    severity: str
    criticality: str
    weight: float
    priority: str


def priority_matrix() -> list[MatrixCell]:
    """Every severity against every criticality, computed rather than written out.

    Served to the console so the grid a reader is shown is the function that assigns
    their findings, not a table beside it that is free to drift. Twenty cells, so it is
    cheaper to compute than to cache.
    """
    return [
        MatrixCell(
            severity=severity.value,
            criticality=criticality.value,
            weight=round(priority_weight(severity.value, criticality.value), 2),
            priority=priority_for(severity.value, criticality.value),
        )
        for severity in FindingSeverity
        for criticality in Criticality
    ]


# ────────────────────────────────── reports ──────────────────────────────────


@dataclass(frozen=True, slots=True)
class DeviceGrade:
    device_id: uuid.UUID
    #: Both, rather than one resolved label: every other list in the console falls back
    #: from hostname to management address itself, and a server that did the fallback
    #: here would be a second convention for the same thing.
    hostname: str | None
    mgmt_ip: str
    device_class: str
    criticality: str
    #: `None` when the device has never been assessed, which `grade` mirrors.
    score: int | None
    grade: str | None
    assessed_at: datetime | None
    open_findings: int
    #: The highest closure priority among this device's open findings, or `None` when
    #: it has none. A graded device with no open findings and a graded device nobody
    #: has looked at read very differently, and the grade alone cannot separate them.
    worst_priority: str | None


@dataclass(frozen=True, slots=True)
class GradeReport:
    #: The worst `limit` devices, not necessarily all of them — `total_devices` says
    #: how many there were, so a truncated table can say so rather than looking
    #: complete. Everything below this line is computed over the whole scope.
    devices: list[DeviceGrade]
    total_devices: int
    #: Letter → count, worst first. Ungraded devices are counted separately rather
    #: than folded into A.
    by_grade: dict[str, int]
    ungraded: int
    #: The estate figure `risk.roll_up` produces from the graded devices — weighted
    #: towards the worst, so one catastrophic firewall cannot be averaged away.
    estate_score: int | None
    estate_grade: str | None


@dataclass(frozen=True, slots=True)
class PriorityBucket:
    code: str
    open: int
    #: Distinct devices with at least one open finding in this band.
    devices: int
    oldest_first_seen: datetime | None
    #: Mean age of the band's open findings. Exact: the mean of a set of timestamps
    #: combines across groups, so this is computed from sums rather than estimated.
    #: No median is offered, because medians do not combine and claiming one from
    #: per-group medians would be arithmetic that looks right and is not.
    mean_age_days: float | None
    #: `due_at` is only ever set by hand (there is no rule that assigns one), so both
    #: figures are reported: without the first, a nought in the second reads as
    #: "nothing is late" when it usually means "nobody sets dates".
    with_due_date: int
    overdue: int


@dataclass(frozen=True, slots=True)
class PriorityReport:
    buckets: list[PriorityBucket]
    total_open: int
    matrix: list[MatrixCell]


class GradingService:
    """Where the estate stands, as opposed to whether it is improving.

    Separate from `TrendService` for that reason: that service answers "were there more
    last month", this one answers "which box is worst and what gets fixed first". Both
    scope through `InventoryService`, so the two agree about which devices a
    group-restricted operator can see.
    """

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id
        self.inventory = InventoryService(session)

    async def grades(
        self, *, scope: Scope, device_class: str | None = None, limit: int | None = None
    ) -> GradeReport:
        """Every active device with its latest score, worst first (FR-CHK-09).

        Archived and pending-review devices are excluded: the first is not part of the
        estate any more, and the second has never been assessed by definition, so
        including either would pad the ungraded count with devices nobody expects a
        grade for.
        """
        # DISTINCT ON is Postgres-specific, which this schema already is (ltree, JSONB,
        # asyncpg). A window function would portably do the same and read worse.
        latest = (
            select(
                RiskScore.device_id.label("device_id"),
                RiskScore.score.label("score"),
                RiskScore.created_at.label("assessed_at"),
            )
            .distinct(RiskScore.device_id)
            .order_by(RiskScore.device_id, RiskScore.created_at.desc())
            .subquery()
        )

        def over_devices(*columns: Any) -> Select[Any]:
            stmt = (
                select(*columns)
                .select_from(Device)
                .outerjoin(latest, latest.c.device_id == Device.id)
                .where(Device.org_id == self.org_id, Device.status == DeviceStatus.ACTIVE.value)
            )
            return stmt.where(Device.device_class == device_class) if device_class else stmt

        # Two queries rather than one, because the distribution has to describe the
        # whole scope while the table is capped. Computing both from the capped rows
        # would give a 2,000-device estate a grade distribution of its worst 200 —
        # which is not a summary of anything, and would look like one.
        spread_stmt = await self.inventory.scoped(over_devices(latest.c.score), scope)
        all_scores: list[int | None] = list((await self.session.execute(spread_stmt)).scalars())

        listed_stmt = await self.inventory.scoped(
            over_devices(Device, latest.c.score, latest.c.assessed_at), scope
        )
        # Worst first, and never-assessed last: a reader opening this page is looking
        # for the bad ones, and devices with no reading are a different question.
        listed_stmt = listed_stmt.order_by(
            latest.c.score.desc().nullslast(),
            Device.hostname.asc().nullslast(),
            Device.mgmt_ip.asc(),
        )
        if limit is not None:
            listed_stmt = listed_stmt.limit(limit)
        rows = (await self.session.execute(listed_stmt)).all()

        findings = await self._open_by_device(
            scope=scope, device_ids=[device.id for device, _, _ in rows]
        )

        devices = [
            DeviceGrade(
                device_id=device.id,
                hostname=device.hostname,
                mgmt_ip=str(device.mgmt_ip),
                device_class=device.device_class,
                criticality=device.criticality,
                score=score,
                grade=grade_for(score),
                assessed_at=assessed_at,
                open_findings=findings.get(device.id, (0, None))[0],
                worst_priority=findings.get(device.id, (0, None))[1],
            )
            for device, score, assessed_at in rows
        ]

        by_grade = dict.fromkeys(GRADE_LETTERS, 0)
        graded: list[int] = []
        for score in all_scores:
            if score is None:
                continue
            by_grade[grade_for(score)] += 1
            graded.append(int(score))

        estate_score = roll_up(graded) if graded else None
        return GradeReport(
            devices=devices,
            total_devices=len(all_scores),
            by_grade=by_grade,
            ungraded=len(all_scores) - len(graded),
            estate_score=estate_score,
            estate_grade=grade_for(estate_score),
        )

    async def _open_by_device(
        self, *, scope: Scope, device_ids: list[uuid.UUID]
    ) -> dict[uuid.UUID, tuple[int, str | None]]:
        """Open findings per device, with the worst closure priority among them.

        Grouped by severity and criticality rather than banded in SQL, so `priority_for`
        stays the only thing that assigns a band. A CASE expression here would be a
        second copy of the thresholds, in a language where nothing tests it.

        Narrowed to the devices actually being listed: the scope restriction is still
        applied, because an id list from one query is not an authorisation and a later
        caller passing ids from somewhere else would otherwise read straight past it.
        """
        if not device_ids:
            return {}

        stmt = (
            select(Finding.device_id, Finding.severity, Device.criticality, func.count())
            .select_from(Finding)
            .join(Device, Finding.device_id == Device.id)
            .where(
                Device.org_id == self.org_id,
                Device.id.in_(device_ids),
                Finding.status.in_(FindingStatus.active_values()),
            )
            .group_by(Finding.device_id, Finding.severity, Device.criticality)
        )

        rows = (await self.session.execute(await self.inventory.scoped(stmt, scope))).all()

        out: dict[uuid.UUID, tuple[int, str | None]] = {}
        for device_id, severity, criticality, count in rows:
            band = priority_for(severity, criticality)
            total, worst = out.get(device_id, (0, None))
            out[device_id] = (
                total + int(count),
                band
                if worst is None or PRIORITY_CODES.index(band) < PRIORITY_CODES.index(worst)
                else worst,
            )
        return out

    async def priorities(
        self,
        *,
        scope: Scope,
        device_class: str | None = None,
        now: datetime | None = None,
    ) -> PriorityReport:
        """Open findings bucketed P1–P4, with how long each band has been waiting.

        One query, grouped by device, severity and criticality — at most twenty rows per
        device, which folds in Python into exact totals, exact distinct device counts
        and an exact mean age. Banding in SQL would be faster and would put the
        thresholds somewhere `test_grading.py` cannot reach them.
        """
        now = now or datetime.now(UTC)
        first_seen = func.coalesce(Finding.first_seen_at, Finding.created_at)

        stmt = (
            select(
                Finding.device_id,
                Finding.severity,
                Device.criticality,
                func.count(),
                func.min(first_seen),
                # Sum of epochs rather than of ages: a mean of timestamps combines
                # across groups, and `now - mean` at the end is the same number with
                # one fewer expression bound into the query.
                func.sum(func.extract("epoch", first_seen)),
                func.count(Finding.due_at),
                func.sum(case((Finding.due_at < now, 1), else_=0)),
            )
            .select_from(Finding)
            .join(Device, Finding.device_id == Device.id)
            .where(
                Device.org_id == self.org_id,
                Device.status == DeviceStatus.ACTIVE.value,
                Finding.status.in_(FindingStatus.active_values()),
            )
            .group_by(Finding.device_id, Finding.severity, Device.criticality)
        )
        if device_class:
            stmt = stmt.where(Device.device_class == device_class)

        rows = (await self.session.execute(await self.inventory.scoped(stmt, scope))).all()

        counts = dict.fromkeys(PRIORITY_CODES, 0)
        devices: dict[str, set[uuid.UUID]] = {code: set() for code in PRIORITY_CODES}
        oldest: dict[str, datetime | None] = dict.fromkeys(PRIORITY_CODES, None)
        epochs = dict.fromkeys(PRIORITY_CODES, 0.0)
        dated = dict.fromkeys(PRIORITY_CODES, 0)
        late = dict.fromkeys(PRIORITY_CODES, 0)

        for device_id, severity, criticality, count, first, epoch_sum, due, overdue in rows:
            band = priority_for(severity, criticality)
            counts[band] += int(count)
            devices[band].add(device_id)
            epochs[band] += float(epoch_sum or 0)
            dated[band] += int(due or 0)
            late[band] += int(overdue or 0)
            if first is not None and (oldest[band] is None or first < oldest[band]):
                oldest[band] = first

        buckets = []
        for code in PRIORITY_CODES:
            total = counts[code]
            buckets.append(
                PriorityBucket(
                    code=code,
                    open=total,
                    devices=len(devices[code]),
                    oldest_first_seen=oldest[code],
                    mean_age_days=(
                        round((now.timestamp() - epochs[code] / total) / 86400.0, 1)
                        if total
                        else None
                    ),
                    with_due_date=dated[code],
                    overdue=late[code],
                )
            )

        return PriorityReport(
            buckets=buckets,
            total_open=sum(counts.values()),
            matrix=priority_matrix(),
        )


__all__ = [
    "GRADES",
    "GRADE_LETTERS",
    "PRIORITIES",
    "PRIORITY_CODES",
    "DeviceGrade",
    "GradeBand",
    "GradeReport",
    "GradingService",
    "MatrixCell",
    "PriorityBand",
    "PriorityBucket",
    "PriorityReport",
    "grade_for",
    "priority_for",
    "priority_matrix",
    "priority_weight",
]
