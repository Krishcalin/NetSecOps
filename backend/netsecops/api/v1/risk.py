"""Estate risk: trend, closure priority and device grades (FR-CHK-09, FR-FIND-03/05).

Three reads over data three earlier phases have been writing. Nothing here computes a
new measurement — the estate trend rolls up stored `risk_scores`, the grades band those
same scores, and the priorities are the severity weight and criticality multiplier the
score is already built from, read as a product. See `services/grading.py` for why that
constraint is the design rather than a limitation of it.

Separate from `checks.py`, which owns the per-device risk endpoints, because those
answer "how is this device" and these answer "where does the estate stand". The paths
are all literal and all under `/risk/`, so there is no UUID sibling to shadow.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from netsecops.api.deps import PrincipalDep, SessionDep, require
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.db.models.inventory import DeviceClass
from netsecops.schemas.risk import (
    DeviceGradeRead,
    EstateRiskPointRead,
    EstateRiskTrendRead,
    GradeBandRead,
    GradeReportRead,
    MatrixCellRead,
    PriorityBandRead,
    PriorityBucketRead,
    PriorityReportRead,
)
from netsecops.services.grading import GRADES, PRIORITIES, GradingService, grade_for
from netsecops.services.trends import DEFAULT_DAYS, MAX_DAYS, TrendService

log = get_logger(__name__)
router = APIRouter(prefix="/risk", tags=["risk"])

#: How many devices a grade table returns by default. The console asks for the worst
#: first, so a cap truncates the tail rather than the part anyone opened the page for —
#: and an estate of two thousand devices should not arrive as one JSON document because
#: somebody clicked a nav entry.
DEFAULT_GRADE_LIMIT = 200
MAX_GRADE_LIMIT = 2000

DeviceClassQuery = Annotated[
    DeviceClass | None,
    Query(description="Restrict to one class of appliance — firewall, switch, router…"),
]


@router.get(
    "/trend",
    response_model=EstateRiskTrendRead,
    dependencies=[Depends(require(Permission.FINDING_READ))],
    summary="The estate's risk score over time (FR-CHK-09)",
)
async def estate_risk_trend(
    session: SessionDep,
    principal: PrincipalDep,
    days: Annotated[int, Query(ge=1, le=MAX_DAYS)] = DEFAULT_DAYS,
    group_id: uuid.UUID | None = None,
) -> EstateRiskTrendRead:
    """One roll-up per day, carrying each device's last reading forward.

    Exact, unlike the findings trend beside it on the same page: `risk_scores` is
    append-only, so every point here is arithmetic over rows that were written at the
    time rather than a reconstruction of a state the schema does not keep.
    """
    trend = await TrendService(session).estate_risk(
        scope=principal.scope, days=days, group_id=group_id
    )
    latest = next((p.score for p in reversed(trend.points) if p.score is not None), None)

    return EstateRiskTrendRead(
        days=trend.days,
        since=trend.since,
        points=[
            EstateRiskPointRead(
                day=p.day,
                score=p.score,
                grade=grade_for(p.score),
                devices=p.devices,
                assessed=p.assessed,
            )
            for p in trend.points
        ],
        direction=trend.direction,
        latest_score=latest,
        latest_grade=grade_for(latest),
    )


@router.get(
    "/priorities",
    response_model=PriorityReportRead,
    dependencies=[Depends(require(Permission.FINDING_READ))],
    summary="Open findings bucketed P1–P4 (FR-FIND-03)",
)
async def closure_priorities(
    session: SessionDep,
    principal: PrincipalDep,
    device_class: DeviceClassQuery = None,
) -> PriorityReportRead:
    """What to fix first, and the grid that decided it.

    The matrix travels with the buckets rather than being documented elsewhere: a
    priority is a claim about somebody's week, and one they cannot check is one they
    will quietly stop believing.
    """
    report = await GradingService(session).priorities(
        scope=principal.scope,
        device_class=device_class.value if device_class else None,
    )

    return PriorityReportRead(
        buckets=[
            PriorityBucketRead(
                code=b.code,
                open=b.open,
                devices=b.devices,
                oldest_first_seen=b.oldest_first_seen,
                mean_age_days=b.mean_age_days,
                with_due_date=b.with_due_date,
                overdue=b.overdue,
            )
            for b in report.buckets
        ],
        total_open=report.total_open,
        bands=[
            PriorityBandRead(code=b.code, label=b.label, floor=b.floor, meaning=b.meaning)
            for b in PRIORITIES
        ],
        matrix=[
            MatrixCellRead(
                severity=c.severity,
                criticality=c.criticality,
                weight=c.weight,
                priority=c.priority,
            )
            for c in report.matrix
        ],
    )


@router.get(
    "/grades",
    response_model=GradeReportRead,
    dependencies=[Depends(require(Permission.FINDING_READ))],
    summary="An A–F rating for every device (FR-CHK-09)",
)
async def device_grades(
    session: SessionDep,
    principal: PrincipalDep,
    device_class: DeviceClassQuery = None,
    limit: Annotated[int, Query(ge=1, le=MAX_GRADE_LIMIT)] = DEFAULT_GRADE_LIMIT,
) -> GradeReportRead:
    """Worst first, with never-assessed devices last and ungraded.

    The letter is a band of the stored risk score and nothing more, so it cannot
    disagree with the score on the device's own page. A device with no score has no
    letter — `A` would call it clean and `F` would call it broken, and the only true
    statement is that nobody has looked.
    """
    report = await GradingService(session).grades(
        scope=principal.scope,
        device_class=device_class.value if device_class else None,
        limit=limit,
    )

    return GradeReportRead(
        devices=[
            DeviceGradeRead(
                device_id=d.device_id,
                hostname=d.hostname,
                mgmt_ip=d.mgmt_ip,
                device_class=d.device_class,
                criticality=d.criticality,
                score=d.score,
                grade=d.grade,
                assessed_at=d.assessed_at,
                open_findings=d.open_findings,
                worst_priority=d.worst_priority,
            )
            for d in report.devices
        ],
        total_devices=report.total_devices,
        by_grade=report.by_grade,
        ungraded=report.ungraded,
        estate_score=report.estate_score,
        estate_grade=report.estate_grade,
        bands=[
            GradeBandRead(letter=b.letter, floor=b.floor, ceiling=b.ceiling, meaning=b.meaning)
            for b in GRADES
        ],
    )
