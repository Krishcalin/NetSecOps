"""Report endpoints (SRS §4.2, FR-RPT-02, FR-RPT-03).

Reports are **dated artefacts, not views**. `GET /reports/{id}` six months from now
returns exactly what the report said when it was generated — that is the feature, and
the reason the content is stored rather than recomputed. An operator wanting current
state has the console; an auditor wanting March's position has March's report.

Generating is a write and sits behind `report:generate`; reading and downloading sit
behind `report:read`, which every read role holds. An auditor who cannot pull the
evidence independently has to take it from the team being audited.

All nine catalogued templates assemble. Four formats: JSON, CSV, XLSX and PDF
(FR-RPT-03).

**Retention is reported, never enforced.** `expires_at` marks a report as past its
retention date and `retention_expired` surfaces that on every row, but nothing deletes
an artefact. An auditor who asks for March's evidence must not be told a background job
removed it — the decision to destroy evidence belongs to a person who can be asked why.

Not here, and deliberately: scheduling and e-mail delivery (FR-RPT-04). That is not a
reporting gap but an infrastructure one — there is no scheduler in the product (the
`Schedule` model exists and nothing reads it) and no outbound mail at all until
FR-INT-01. Building half of it here would put a cron loop and an SMTP client in the
reporting module, which is where neither belongs.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, status

from netsecops.api.deps import PrincipalDep, SessionDep, require, verify_csrf
from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.db.models.audit import AuditAction
from netsecops.db.models.reporting import ReportFormat, ReportTemplate
from netsecops.schemas.reporting import (
    PaginatedReports,
    ReportCreate,
    ReportDetail,
    ReportRead,
    TemplateRead,
)
from netsecops.services.audit import AuditService
from netsecops.services.report_render import content_type_for, filename_for, render
from netsecops.services.reporting import TEMPLATE_CATALOGUE, ReportingService

log = get_logger(__name__)
router = APIRouter(tags=["reports"])

#: Templates `_assemble` can build. All nine now do, but the gate stays: adding a
#: template to the catalogue without assembling it must refuse loudly rather than
#: return an empty document, because an empty compliance report reads as a clean one.
IMPLEMENTED: frozenset[str] = frozenset(t.value for t in ReportTemplate)

#: Templates that need something beyond a template name, and what they need. Checked
#: before generation so the operator gets the requirement rather than a failed report
#: they have to open to understand.
REQUIRED_PARAMETERS: dict[str, tuple[str, str]] = {
    ReportTemplate.DEVICE_DETAIL.value: (
        "scope_device_id",
        "a device detail report is about one device",
    ),
    ReportTemplate.FIREWALL_RULEBASE.value: (
        "scope_device_id",
        "a rulebase belongs to one device",
    ),
    ReportTemplate.GROUP_COMPLIANCE.value: (
        "scope_group_id",
        "a group compliance report is about one group",
    ),
    ReportTemplate.TREND.value: (
        "compare_to_id",
        "a trend report compares against an earlier report",
    ),
}


def reporting(session: SessionDep) -> ReportingService:
    return ReportingService(session)


ReportsDep = Annotated[ReportingService, Depends(reporting)]


@router.get(
    "/reports/templates",
    response_model=list[TemplateRead],
    dependencies=[Depends(require(Permission.REPORT_READ))],
    summary="The report templates, and which can be generated (FR-RPT-02)",
)
async def list_templates() -> list[TemplateRead]:
    return [
        TemplateRead(
            id=template.value,
            title=entry["title"],
            audience=entry["audience"],
            description=entry["description"],
            implemented=template.value in IMPLEMENTED,
        )
        for template, entry in TEMPLATE_CATALOGUE.items()
    ]


@router.get(
    "/reports",
    response_model=PaginatedReports,
    dependencies=[Depends(require(Permission.REPORT_READ))],
    summary="Generated reports, newest first",
)
async def list_reports(
    reports: ReportsDep,
    template: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedReports:
    rows, total = await reports.list_reports(template=template, limit=limit, offset=offset)
    return PaginatedReports(
        data=[ReportRead.model_validate(row) for row in rows],
        meta={"total": total, "limit": limit, "offset": offset},
    )


@router.post(
    "/reports",
    response_model=ReportDetail,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.REPORT_GENERATE)), Depends(verify_csrf)],
    summary="Generate a report and freeze it (FR-RPT-02)",
)
async def create_report(
    payload: ReportCreate,
    reports: ReportsDep,
    session: SessionDep,
    principal: PrincipalDep,
) -> ReportDetail:
    """Assemble the report from the estate as it is now, and store what it saw.

    The result is immutable. Regenerating produces a second report rather than updating
    this one, because the first one is the record of a different moment.
    """
    try:
        template = ReportTemplate(payload.template)
    except ValueError:
        known = ", ".join(sorted(t.value for t in ReportTemplate))
        raise ValidationProblem(
            f"{payload.template!r} is not a report template. Known templates: {known}."
        ) from None

    if template.value not in IMPLEMENTED:
        raise ValidationProblem(
            f"The {template.value!r} template is catalogued but not implemented yet. "
            "`GET /reports/templates` marks which can be generated."
        )

    # Checked here as well as in the service. The service must refuse regardless, since
    # it is callable from the worker; refusing at the edge is what turns "your report
    # failed, open it to find out why" into a 422 that names the missing field.
    required = REQUIRED_PARAMETERS.get(template.value)
    if required and getattr(payload, required[0]) is None:
        field, because = required
        raise ValidationProblem(f"`{field}` is required: {because}.")

    report = await reports.generate(
        template,
        actor=principal,
        scope_device_id=payload.scope_device_id,
        scope_group_id=payload.scope_group_id,
        compare_to_id=payload.compare_to_id,
        framework=payload.framework,
        title=payload.title,
    )

    await AuditService(session).record(
        AuditAction.REPORT_GENERATED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="report",
        object_id=report.id,
        details={
            "template": report.template,
            "status": report.status,
            "content_hash": report.content_hash,
        },
    )
    return ReportDetail.model_validate(report)


@router.get(
    "/reports/{report_id}",
    response_model=ReportDetail,
    dependencies=[Depends(require(Permission.REPORT_READ))],
    summary="One report, exactly as it was generated",
)
async def get_report(report_id: uuid.UUID, reports: ReportsDep) -> ReportDetail:
    return ReportDetail.model_validate(await reports.get(report_id))


@router.get(
    "/reports/{report_id}/download",
    dependencies=[Depends(require(Permission.REPORT_READ))],
    summary="Download a report as a file (FR-RPT-03)",
    response_class=Response,
)
async def download_report(
    report_id: uuid.UUID,
    reports: ReportsDep,
    session: SessionDep,
    principal: PrincipalDep,
    fmt: Annotated[str, Query(alias="format")] = "json",
) -> Response:
    """Render the stored report. Never re-reads the estate.

    Every format of one report carries the same `content_hash`, because they are one
    report rendered differently rather than three assessments.
    """
    try:
        wanted = ReportFormat(fmt.lower())
    except ValueError:
        known = ", ".join(f.value for f in ReportFormat)
        raise ValidationProblem(f"{fmt!r} is not a report format. Available: {known}.") from None

    report = await reports.get(report_id)
    body = render(report, wanted)

    # Downloading is what puts an artefact outside the product, so it is audited
    # separately from generating it.
    await AuditService(session).record(
        AuditAction.REPORT_DOWNLOADED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="report",
        object_id=report.id,
        details={"format": wanted.value, "content_hash": report.content_hash},
    )

    return Response(
        content=body,
        media_type=content_type_for(wanted),
        headers={"Content-Disposition": f'attachment; filename="{filename_for(report, wanted)}"'},
    )
