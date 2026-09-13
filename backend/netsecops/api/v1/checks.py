"""Check library, policy, finding and exception endpoints (FR-CHK, FR-FIND)."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func, select

from netsecops.api.deps import PrincipalDep, SessionDep, require, verify_csrf
from netsecops.checks.engine import DeviceContext, evaluate
from netsecops.checks.loader import get_registry
from netsecops.checks.schema import CheckDefinition, LogicType, Outcome
from netsecops.core.errors import NotFoundError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.db.models.audit import AuditAction
from netsecops.db.models.collection import Finding, FindingStatus
from netsecops.db.models.policy import CheckResult, ExceptionScope
from netsecops.schemas.checks import (
    AssessmentPreview,
    CheckDetail,
    CheckResultRead,
    CheckSummary,
    ComplianceRead,
    CustomCheckCreate,
    CustomCheckRead,
    ExceptionCreate,
    ExceptionRead,
    FindingDetail,
    FindingRead,
    FindingUpdate,
    FrameworkControl,
    PaginatedFindings,
    PolicyAssign,
    PolicyCheckRead,
    PolicyCheckUpdate,
    PolicyCreate,
    PolicyDetail,
    PolicyRead,
    RiskRead,
)
from netsecops.services.assessment import AssessmentService
from netsecops.services.audit import AuditService
from netsecops.services.inventory import InventoryService
from netsecops.services.policies import PolicyService
from netsecops.services.snapshots import SnapshotService

log = get_logger(__name__)
router = APIRouter(tags=["checks"])


def policy_service(session: SessionDep) -> PolicyService:
    return PolicyService(session)


def assessment_service(session: SessionDep) -> AssessmentService:
    return AssessmentService(session)


PolicyDep = Annotated[PolicyService, Depends(policy_service)]
AssessmentDep = Annotated[AssessmentService, Depends(assessment_service)]


def _summary(definition: CheckDefinition, *, is_custom: bool = False) -> CheckSummary:
    return CheckSummary(
        id=definition.id,
        title=definition.title,
        severity=definition.severity,
        description=definition.description,
        tags=definition.tags,
        logic_type=definition.logic.type.value,
        vendors=definition.applicability.vendors,
        platforms=definition.applicability.platforms,
        frameworks=definition.references.frameworks(),
        enabled_by_default=definition.enabled_by_default,
        is_custom=is_custom,
    )


def _detail(definition: CheckDefinition, *, is_custom: bool = False) -> CheckDetail:
    logic = definition.logic
    expression = logic.expression if logic.type is LogicType.NCM else logic.pattern
    if logic.type is LogicType.PYTHON:
        expression = f"python:{logic.function}"

    return CheckDetail(
        **_summary(definition, is_custom=is_custom).model_dump(),
        rationale=definition.rationale,
        remediation=definition.remediation,
        device_classes=definition.applicability.device_classes,
        references=definition.references.model_dump(),
        version=definition.version,
        expression=expression,
    )


# ────────────────────────────── the library ─────────────────────────────────


@router.get(
    "/checks",
    response_model=list[CheckSummary],
    dependencies=[Depends(require(Permission.CHECK_READ))],
    summary="The check library, shipped and custom (FR-CHK-04)",
)
async def list_checks(
    policies: PolicyDep,
    platform: Annotated[str | None, Query(description="Only checks applicable here")] = None,
    framework: Annotated[str | None, Query(description="Only checks mapped to this")] = None,
    tag: str | None = None,
) -> list[CheckSummary]:
    registry = policies.registry
    definitions = registry.for_platform(platform) if platform else registry.definitions()

    if framework:
        mapped = {c.id for c in registry.by_framework(framework)}
        definitions = [d for d in definitions if d.id in mapped]
    if tag:
        definitions = [d for d in definitions if tag in d.tags]

    summaries = [_summary(d) for d in definitions]

    for row in await policies.list_custom_checks():
        try:
            summaries.append(
                _summary(CheckDefinition.model_validate(row.definition), is_custom=True)
            )
        except Exception as exc:
            log.warning("checks.custom_invalid", check=row.check_id, error=str(exc))

    return sorted(summaries, key=lambda c: c.id)


@router.get(
    "/checks/{check_id}",
    response_model=CheckDetail,
    dependencies=[Depends(require(Permission.CHECK_READ))],
    summary="One check, with its rationale and remediation",
)
async def get_check(check_id: str, policies: PolicyDep) -> CheckDetail:
    definition = policies.registry.get(check_id)
    if definition is not None:
        return _detail(definition)

    for row in await policies.list_custom_checks():
        if row.check_id == check_id:
            return _detail(CheckDefinition.model_validate(row.definition), is_custom=True)

    raise NotFoundError(f"No check with id {check_id!r} exists.")


@router.post(
    "/checks",
    response_model=CustomCheckRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.CHECK_WRITE)), Depends(verify_csrf)],
    summary="Create a custom check (FR-CHK-06)",
)
async def create_custom_check(
    payload: CustomCheckCreate, policies: PolicyDep, principal: PrincipalDep
) -> CustomCheckRead:
    row = await policies.create_custom_check(payload.definition, actor=principal)
    await policies.session.commit()
    return CustomCheckRead.model_validate(row)


@router.post(
    "/checks/{check_id}/preview",
    response_model=AssessmentPreview,
    dependencies=[Depends(require(Permission.CHECK_READ)), Depends(verify_csrf)],
    summary="Run a check against a device's latest snapshot without storing anything",
)
async def preview_check(
    check_id: str,
    device_id: Annotated[uuid.UUID, Query(description="The device to test against")],
    policies: PolicyDep,
    principal: PrincipalDep,
) -> AssessmentPreview:
    """The FR-CHK-06 dry run.

    Nothing is written: no result row, no finding, no risk score. An operator
    tuning a check should be able to iterate without leaving a trail of findings
    that were never real.
    """
    definition = policies.registry.get(check_id)
    if definition is None:
        for row in await policies.list_custom_checks():
            if row.check_id == check_id:
                definition = CheckDefinition.model_validate(row.definition)
                break
    if definition is None:
        raise NotFoundError(f"No check with id {check_id!r} exists.")

    device = await InventoryService(policies.session).get_device(device_id, scope=principal.scope)
    snapshot = await SnapshotService(policies.session).latest(device)
    if snapshot is None:
        raise ValidationProblem(
            "This device has no configuration snapshot to test against. Collect from "
            "it, or upload a configuration, first."
        )

    result = evaluate(
        definition,
        snapshot.ncm,
        device=DeviceContext.from_ncm(
            snapshot.ncm, device_class=device.device_class, hostname=device.hostname
        ),
        config_text=snapshot.config_redacted,
    )

    from netsecops.services.assessment import _evidence_payload

    return AssessmentPreview(
        check_id=result.check_id,
        outcome=result.outcome,
        severity=result.severity,
        message=result.message,
        reason=result.reason,
        evidence=_evidence_payload(result),
    )


# ─────────────────────────────── policies ───────────────────────────────────


@router.get(
    "/policies",
    response_model=list[PolicyRead],
    dependencies=[Depends(require(Permission.POLICY_READ))],
    summary="Policies defined in this installation (FR-CHK-05)",
)
async def list_policies(policies: PolicyDep) -> list[PolicyRead]:
    return [PolicyRead.model_validate(p) for p in await policies.list_policies()]


@router.post(
    "/policies",
    response_model=PolicyRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.POLICY_WRITE)), Depends(verify_csrf)],
    summary="Create a policy",
)
async def create_policy(
    payload: PolicyCreate, policies: PolicyDep, principal: PrincipalDep
) -> PolicyRead:
    policy = await policies.create(
        name=payload.name,
        check_ids=payload.check_ids,
        description=payload.description,
        frameworks=payload.frameworks,
        actor=principal,
    )
    await policies.session.commit()
    return PolicyRead.model_validate(policy)


@router.get(
    "/policies/{policy_id}",
    response_model=PolicyDetail,
    dependencies=[Depends(require(Permission.POLICY_READ))],
    summary="A policy and the checks it contains",
)
async def get_policy(policy_id: uuid.UUID, policies: PolicyDep) -> PolicyDetail:
    policy = await policies.get(policy_id)
    return PolicyDetail(
        **PolicyRead.model_validate(policy).model_dump(),
        entries=[PolicyCheckRead.model_validate(e) for e in policy.entries],
    )


@router.put(
    "/policies/{policy_id}/checks/{check_id}",
    response_model=PolicyCheckRead,
    dependencies=[Depends(require(Permission.POLICY_WRITE)), Depends(verify_csrf)],
    summary="Enable, disable or re-grade a check within a policy (FR-CHK-06)",
)
async def update_policy_check(
    policy_id: uuid.UUID,
    check_id: str,
    payload: PolicyCheckUpdate,
    policies: PolicyDep,
    principal: PrincipalDep,
) -> PolicyCheckRead:
    policy = await policies.get(policy_id)
    entry = await policies.set_check(
        policy,
        check_id,
        enabled=payload.enabled,
        severity_override=payload.severity_override,
        actor=principal,
    )
    await policies.session.commit()
    return PolicyCheckRead.model_validate(entry)


@router.post(
    "/policies/{policy_id}/assignments",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.POLICY_WRITE)), Depends(verify_csrf)],
    summary="Apply a policy to a device group",
)
async def assign_policy(
    policy_id: uuid.UUID,
    payload: PolicyAssign,
    policies: PolicyDep,
    principal: PrincipalDep,
) -> None:
    policy = await policies.get(policy_id)
    await policies.assign(policy, payload.device_group_id, actor=principal)
    await policies.session.commit()


@router.post(
    "/policies/{policy_id}/default",
    response_model=PolicyRead,
    dependencies=[Depends(require(Permission.POLICY_WRITE)), Depends(verify_csrf)],
    summary="Make this the policy for devices no assignment covers",
)
async def set_default_policy(
    policy_id: uuid.UUID, policies: PolicyDep, principal: PrincipalDep
) -> PolicyRead:
    policy = await policies.get(policy_id)
    await policies.set_default(policy, actor=principal)
    await policies.session.commit()
    return PolicyRead.model_validate(policy)


# ─────────────────────────────── findings ───────────────────────────────────


@router.get(
    "/findings",
    response_model=PaginatedFindings,
    dependencies=[Depends(require(Permission.FINDING_READ))],
    summary="Findings, filterable and sortable (FR-FIND-03)",
)
async def list_findings(
    session: SessionDep,
    principal: PrincipalDep,
    device_id: uuid.UUID | None = None,
    severity: str | None = None,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    kind: str | None = None,
    check_id: str | None = None,
    active_only: bool = True,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedFindings:
    stmt = select(Finding)

    if device_id is not None:
        # Resolved through the device so Device Group scope is applied in the query,
        # not left to the caller (FR-AUTH-05).
        device = await InventoryService(session).get_device(device_id, scope=principal.scope)
        stmt = stmt.where(Finding.device_id == device.id)
    elif not principal.scope.unrestricted:
        visible = await InventoryService(session).visible_device_ids(principal.scope)
        stmt = stmt.where(Finding.device_id.in_(visible))

    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if status_filter:
        stmt = stmt.where(Finding.status == status_filter)
    elif active_only:
        stmt = stmt.where(Finding.status.in_([s.value for s in FindingStatus if s.is_active]))
    if kind:
        stmt = stmt.where(Finding.kind == kind)
    if check_id:
        stmt = stmt.where(Finding.check_id == check_id)

    total = int(
        (await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    )

    # Severity is a string column, so ordering it alphabetically would put "low" above
    # "critical". The case expression makes the list open with what matters most.
    from sqlalchemy import case

    order = case(
        {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
        value=Finding.severity,
        else_=5,
    )
    rows = (
        (
            await session.execute(
                stmt.order_by(order, Finding.last_seen_at.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )

    return PaginatedFindings(
        data=[FindingRead.model_validate(f) for f in rows],
        meta={"total": total, "limit": limit, "offset": offset},
    )


@router.get(
    "/findings/{finding_id}",
    response_model=FindingDetail,
    dependencies=[Depends(require(Permission.FINDING_READ))],
    summary="A finding with its evidence and remediation (FR-FIND-04)",
)
async def get_finding(
    finding_id: uuid.UUID, session: SessionDep, principal: PrincipalDep
) -> FindingDetail:
    finding = (
        await session.execute(select(Finding).where(Finding.id == finding_id))
    ).scalar_one_or_none()
    if finding is None:
        raise NotFoundError("Finding not found.")

    await InventoryService(session).get_device(finding.device_id, scope=principal.scope)

    definition = get_registry().get(finding.check_id) if finding.check_id else None
    return FindingDetail(
        **FindingRead.model_validate(finding).model_dump(),
        evidence=finding.evidence,
        remediation=finding.remediation,
        snapshot_id=finding.snapshot_id,
        rationale=definition.rationale if definition else None,
        references=definition.references.model_dump() if definition else {},
    )


@router.patch(
    "/findings/{finding_id}",
    response_model=FindingRead,
    dependencies=[Depends(require(Permission.FINDING_WRITE)), Depends(verify_csrf)],
    summary="Triage a finding: status, assignee, due date (FR-FIND-02)",
)
async def update_finding(
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    session: SessionDep,
    principal: PrincipalDep,
) -> FindingRead:
    finding = (
        await session.execute(select(Finding).where(Finding.id == finding_id))
    ).scalar_one_or_none()
    if finding is None:
        raise NotFoundError("Finding not found.")

    await InventoryService(session).get_device(finding.device_id, scope=principal.scope)
    before = finding.status

    if payload.status is not None:
        try:
            new_status = FindingStatus(payload.status)
        except ValueError as exc:
            raise ValidationProblem(
                f"{payload.status!r} is not a finding status. Valid values: "
                f"{', '.join(s.value for s in FindingStatus)}."
            ) from exc

        if new_status is FindingStatus.RESOLVED:
            raise ValidationProblem(
                "A finding is resolved by its check passing on a later assessment, not "
                "by hand. To close it now, mark it Risk Accepted or False Positive, or "
                "add an exception with a justification and an expiry date."
            )

        finding.status = new_status.value

    if payload.assignee_id is not None:
        finding.assignee_id = payload.assignee_id
    if payload.due_at is not None:
        finding.due_at = payload.due_at

    await session.flush()

    if payload.status is not None and payload.status != before:
        await AuditService(session).record(
            AuditAction.FINDING_STATUS_CHANGED,
            actor_id=principal.id,
            actor_username=principal.username,
            object_type="finding",
            object_id=finding.id,
            device_id=finding.device_id,
            details={"from": before, "to": finding.status, "check": finding.check_id},
            org_id=finding.org_id,
        )

    await session.commit()
    return FindingRead.model_validate(finding)


# ───────────────────────── results, risk, compliance ────────────────────────


@router.get(
    "/devices/{device_id}/checks",
    response_model=list[CheckResultRead],
    dependencies=[Depends(require(Permission.CHECK_READ))],
    summary="Every check result from a device's latest assessment (FR-CHK-03)",
)
async def device_check_results(
    device_id: uuid.UUID,
    session: SessionDep,
    principal: PrincipalDep,
    assessments: AssessmentDep,
) -> list[CheckResultRead]:
    device = await InventoryService(session).get_device(device_id, scope=principal.scope)

    latest = (
        await session.execute(
            select(CheckResult.snapshot_id)
            .where(CheckResult.device_id == device.id)
            .order_by(CheckResult.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    if latest is None:
        return []

    return [
        CheckResultRead.model_validate(r) for r in await assessments.results_for_snapshot(latest)
    ]


@router.get(
    "/devices/{device_id}/risk",
    response_model=RiskRead,
    dependencies=[Depends(require(Permission.FINDING_READ))],
    summary="A device's risk score and compliance position (FR-CHK-09)",
)
async def device_risk(
    device_id: uuid.UUID,
    session: SessionDep,
    principal: PrincipalDep,
    assessments: AssessmentDep,
) -> RiskRead:
    device = await InventoryService(session).get_device(device_id, scope=principal.scope)
    latest = await assessments.latest_risk(device)

    if latest is None:
        # Never assessed is not the same as scoring zero. Nulls make the UI say "not
        # assessed" rather than showing a clean score for a device nobody has looked at.
        return RiskRead(
            device_id=device.id,
            score=None,
            compliance_percent=None,
            coverage_percent=None,
            checks_evaluated=0,
            checks_passed=0,
            checks_failed=0,
            checks_not_evaluated=0,
            assessed_at=None,
        )

    components: dict[str, Any] = latest.components or {}
    return RiskRead(
        device_id=device.id,
        score=latest.score,
        compliance_percent=components.get("compliance_percent"),
        coverage_percent=components.get("coverage_percent"),
        checks_evaluated=latest.checks_evaluated,
        checks_passed=latest.checks_passed,
        checks_failed=latest.checks_failed,
        checks_not_evaluated=latest.checks_not_evaluated,
        components=components,
        assessed_at=latest.created_at,
    )


@router.get(
    "/compliance/{framework}",
    response_model=ComplianceRead,
    dependencies=[Depends(require(Permission.REPORT_READ))],
    summary="Results pivoted by compliance framework control (FR-CHK-05)",
)
async def compliance_by_framework(
    framework: str, session: SessionDep, principal: PrincipalDep
) -> ComplianceRead:
    registry = get_registry()
    mapped = registry.by_framework(framework)
    if not mapped:
        raise NotFoundError(
            f"No checks are mapped to {framework!r}. Known frameworks: "
            f"{', '.join(sorted(registry.frameworks()))}."
        )

    check_ids = [d.id for d in mapped]
    rows = (
        (
            await session.execute(
                select(
                    CheckResult.check_id,
                    CheckResult.outcome,
                    func.count().label("n"),
                    func.count(func.distinct(CheckResult.device_id)).label("devices"),
                )
                .where(CheckResult.check_id.in_(check_ids))
                .group_by(CheckResult.check_id, CheckResult.outcome)
            )
        )
        .tuples()
        .all()
    )

    tally: dict[str, dict[str, int]] = {}
    devices: set[Any] = set()
    for check_id, outcome, count, device_count in rows:
        tally.setdefault(check_id, {})[outcome] = count
        devices.add(device_count)

    controls: list[FrameworkControl] = []
    total_pass = total_decided = 0

    by_control: dict[str, list[str]] = {}
    for definition in mapped:
        for control in definition.references.frameworks().get(framework, []):
            by_control.setdefault(control, []).append(definition.id)

    for control, ids in sorted(by_control.items()):
        passed = sum(tally.get(i, {}).get(Outcome.PASS.value, 0) for i in ids)
        failed = sum(tally.get(i, {}).get(Outcome.FAIL.value, 0) for i in ids)
        skipped = sum(tally.get(i, {}).get(Outcome.NOT_EVALUATED.value, 0) for i in ids)
        controls.append(
            FrameworkControl(
                control=control,
                checks=sorted(ids),
                passed=passed,
                failed=failed,
                not_evaluated=skipped,
            )
        )
        total_pass += passed
        total_decided += passed + failed

    device_total = int(
        (
            await session.execute(
                select(func.count(func.distinct(CheckResult.device_id))).where(
                    CheckResult.check_id.in_(check_ids)
                )
            )
        ).scalar_one()
    )

    return ComplianceRead(
        framework=framework,
        device_count=device_total,
        compliance_percent=(round(100 * total_pass / total_decided) if total_decided else None),
        controls=controls,
    )


# ────────────────────────────── exceptions ──────────────────────────────────


@router.get(
    "/exceptions",
    response_model=list[ExceptionRead],
    dependencies=[Depends(require(Permission.POLICY_READ))],
    summary="Suppressions in force, with their expiry dates (FR-CHK-07)",
)
async def list_exceptions(
    policies: PolicyDep,
    active_only: bool = False,
) -> list[ExceptionRead]:
    rows = await policies.list_exceptions(active_only=active_only)
    return [ExceptionRead.model_validate(r) for r in rows]


@router.post(
    "/exceptions",
    response_model=ExceptionRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.EXCEPTION_WRITE)), Depends(verify_csrf)],
    summary="Suppress a finding, with a justification and an expiry (FR-CHK-07)",
)
async def create_exception(
    payload: ExceptionCreate, policies: PolicyDep, principal: PrincipalDep
) -> ExceptionRead:
    row = await policies.create_exception(
        check_id=payload.check_id,
        scope=ExceptionScope(payload.scope),
        device_id=payload.device_id,
        device_group_id=payload.device_group_id,
        justification=payload.justification,
        approver=payload.approver,
        expires_at=payload.expires_at,
        actor=principal,
    )
    await policies.session.commit()
    return ExceptionRead.model_validate(row)


@router.delete(
    "/exceptions/{exception_id}",
    response_model=ExceptionRead,
    dependencies=[Depends(require(Permission.EXCEPTION_WRITE)), Depends(verify_csrf)],
    summary="Revoke an exception, reopening what it suppressed",
)
async def revoke_exception(
    exception_id: uuid.UUID, policies: PolicyDep, principal: PrincipalDep
) -> ExceptionRead:
    row = await policies.revoke_exception(exception_id, actor=principal)
    await policies.session.commit()
    return ExceptionRead.model_validate(row)


__all__ = ["router"]
