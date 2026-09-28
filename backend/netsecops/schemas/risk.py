"""Grade, priority and estate-trend response models (FR-CHK-09, FR-FIND-03, FR-FIND-05).

Every model here carries its own legend. `GradeReportRead` ships the six bands it
graded against and `PriorityReportRead` ships the twenty-cell matrix it bucketed with,
both computed by `services.grading` at the moment of the request rather than written
down here. That is more bytes than a console strictly needs, and it buys the one thing
that matters about a letter beside a firewall's name: a reader can see exactly what
earned it, from the same function that assigned it, without a second copy in the
front end that is free to drift.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime

from pydantic import BaseModel, Field


class GradeBandRead(BaseModel):
    """One letter and the span of the risk score that earns it."""

    letter: str
    floor: int
    ceiling: int
    meaning: str


class DeviceGradeRead(BaseModel):
    device_id: uuid.UUID
    #: Both, unresolved: every list in the console falls back from hostname to
    #: management address itself, and resolving it here would be a second convention.
    hostname: str | None
    mgmt_ip: str
    device_class: str
    criticality: str
    #: `None` for a device nobody has assessed — not nought, which would read as clean.
    #: `grade` is `None` in exactly the same case.
    score: int | None
    grade: str | None
    assessed_at: datetime | None
    open_findings: int
    worst_priority: str | None


class GradeReportRead(BaseModel):
    """A letter for every device, and what the letters mean (FR-CHK-09)."""

    #: The worst devices, capped by the request's `limit`. `total_devices` is how many
    #: are in scope, so a table that has been cut short can say so — everything below
    #: this line describes the whole scope, not the returned slice.
    devices: list[DeviceGradeRead]
    total_devices: int
    #: Letter → count, worst first. Sums to the number of *graded* devices; the rest
    #: are in `ungraded`, which is deliberately not folded into A.
    by_grade: dict[str, int]
    ungraded: int
    #: `risk.roll_up` over the graded devices — weighted towards the worst, so one bad
    #: firewall cannot be averaged away by a hundred clean switches.
    estate_score: int | None
    estate_grade: str | None
    bands: list[GradeBandRead]


class MatrixCellRead(BaseModel):
    severity: str
    criticality: str
    #: Severity weight × criticality multiplier: the same product the risk score sums.
    weight: float
    priority: str


class PriorityBandRead(BaseModel):
    code: str
    label: str
    floor: float
    meaning: str


class PriorityBucketRead(BaseModel):
    code: str
    open: int
    devices: int
    oldest_first_seen: datetime | None
    #: Mean age in days. Exact, not sampled. No median is offered: medians do not
    #: combine across groups, and one derived from per-group medians would be a
    #: plausible-looking number that is not the median of anything.
    mean_age_days: float | None
    #: A due date is only ever set by hand. Both figures are given so a nought in
    #: `overdue` can be read correctly — nothing late, or nobody setting dates.
    with_due_date: int
    overdue: int


class PriorityReportRead(BaseModel):
    """Open findings bucketed P1–P4, with the grid that bucketed them (FR-FIND-03)."""

    buckets: list[PriorityBucketRead]
    total_open: int
    bands: list[PriorityBandRead]
    #: Every severity against every criticality, computed by the same function that
    #: assigned the buckets above.
    matrix: list[MatrixCellRead]


class EstateRiskPointRead(BaseModel):
    day: date
    #: `None` before anything in scope had been assessed — drawn as a break in the
    #: line, never as a clean nought.
    score: int | None
    grade: str | None
    devices: int
    #: Assessments recorded on this day; nought means the score was carried forward.
    assessed: int


class EstateRiskTrendRead(BaseModel):
    """The estate's risk score day by day (FR-CHK-09).

    Exact history: `risk_scores` keeps a row per computation. Each day is a roll-up of
    every device's most recent reading as at that day, because a risk score is a level
    that held until the next assessment replaced it rather than an event on the day it
    was computed.
    """

    days: int
    since: date
    points: list[EstateRiskPointRead] = Field(default_factory=list)
    #: `improving`, `worsening`, `steady`, or `unknown` below two readings — measured
    #: between the first and last day that have one, so a window opening before the
    #: first assessment does not read as a change.
    direction: str
    latest_score: int | None
    latest_grade: str | None


__all__ = [
    "DeviceGradeRead",
    "EstateRiskPointRead",
    "EstateRiskTrendRead",
    "GradeBandRead",
    "GradeReportRead",
    "MatrixCellRead",
    "PriorityBandRead",
    "PriorityBucketRead",
    "PriorityReportRead",
]
