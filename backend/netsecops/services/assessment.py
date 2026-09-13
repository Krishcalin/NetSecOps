"""Running a policy against a device (FR-CHK-03 … FR-CHK-09, FR-FIND-01).

This is where a check result becomes a stored fact: a `check_results` row for every
outcome, a `findings` row for the ones that are wrong, a risk score, and the lifecycle
transitions that connect this run to the last one.

Two decisions shape the whole module.

**Every outcome is stored, passes included.** Findings answer "what is wrong". Results
answer "what was examined", and without them a compliance percentage has no denominator
and a trend has no baseline. It is also the only way to show that a check which used to
fail now passes, rather than merely having disappeared.

**A finding is closed by evidence, not by absence.** When a check passes on a later run,
the finding it raised is resolved explicitly and stamped with the run that did it. A
finding that simply stopped being re-created would vanish with no record of why, and an
operator cannot tell "fixed" from "no longer checked".
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.checks.engine import CheckResult as EngineResult
from netsecops.checks.engine import DeviceContext, evaluate_all
from netsecops.checks.loader import CheckRegistry, get_registry
from netsecops.checks.schema import CheckDefinition, Outcome, Severity
from netsecops.core.errors import NotFoundError
from netsecops.core.logging import get_logger
from netsecops.db.models.collection import Finding, FindingKind, FindingStatus, Snapshot
from netsecops.db.models.inventory import Device, DeviceGroupMember
from netsecops.db.models.policy import (
    CheckResult,
    CustomCheck,
    ExceptionScope,
    FindingException,
    Policy,
    PolicyAssignment,
    RiskScore,
)
from netsecops.services.firewall_assessment import (
    FirewallAssessment,
    FirewallAssessmentService,
)
from netsecops.services.risk import RiskBreakdown, score_device

log = get_logger(__name__)


@dataclass(slots=True)
class AssessmentOutcome:
    """What one assessment of one device produced."""

    device_id: uuid.UUID
    snapshot_id: uuid.UUID | None
    policy_id: uuid.UUID | None
    results: list[EngineResult] = field(default_factory=list)
    findings_opened: int = 0
    findings_resolved: int = 0
    findings_suppressed: int = 0
    risk: RiskBreakdown | None = None
    #: Rulebase analysis, on devices that carry one (FR-FW). None where the platform has
    #: no firewall policy — which is not the same as a clean one.
    firewall: FirewallAssessment | None = None

    @property
    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self.results:
            counts[result.outcome.value] = counts.get(result.outcome.value, 0) + 1
        return counts


def finding_fingerprint(check_id: str) -> str:
    """The identity of a config finding on a device (FR-FIND-01).

    Just the check id. The device is already a column, and adding the observed value
    would make every change to a bad setting look like a new problem — a switch whose
    timeout went from 0 to 3600 would close one finding and open another, when in truth
    the same finding is still open.
    """
    return f"config:{check_id}"


class AssessmentService:
    def __init__(self, session: AsyncSession, *, registry: CheckRegistry | None = None) -> None:
        self.session = session
        self._registry = registry

    @property
    def registry(self) -> CheckRegistry:
        if self._registry is None:
            self._registry = get_registry()
        return self._registry

    # ──────────────────────────── policy choice ─────────────────────────

    async def policy_for_device(self, device: Device) -> Policy | None:
        """Which policy governs this device (FR-CHK-05).

        A policy assigned to one of the device's groups wins over the organisation
        default. Where several groups each carry a policy the most recently assigned
        one is used and the ambiguity is logged — silently picking one would leave an
        operator unable to explain why a check did not run.
        """
        group_ids = (
            (
                await self.session.execute(
                    select(DeviceGroupMember.group_id).where(
                        DeviceGroupMember.device_id == device.id
                    )
                )
            )
            .scalars()
            .all()
        )

        if group_ids:
            assigned = (
                (
                    await self.session.execute(
                        select(Policy)
                        .join(PolicyAssignment, PolicyAssignment.policy_id == Policy.id)
                        .where(
                            PolicyAssignment.device_group_id.in_(group_ids),
                            Policy.enabled.is_(True),
                        )
                        .order_by(PolicyAssignment.created_at.desc())
                    )
                )
                .scalars()
                .all()
            )
            if assigned:
                if len({p.id for p in assigned}) > 1:
                    log.info(
                        "assessment.multiple_policies",
                        device_id=str(device.id),
                        policies=[p.name for p in assigned],
                        chosen=assigned[0].name,
                    )
                return assigned[0]

        return (
            await self.session.execute(
                select(Policy).where(
                    Policy.is_default.is_(True),
                    Policy.enabled.is_(True),
                    Policy.org_id == device.org_id,
                )
            )
        ).scalar_one_or_none()

    async def checks_for_policy(
        self, policy: Policy | None, *, org_id: int = 1
    ) -> tuple[list[CheckDefinition], dict[str, Severity]]:
        """Resolve a policy to concrete check definitions and severity overrides.

        With no policy, every shipped check that is enabled by default runs. That is
        deliberate: a device nobody has written a policy for should still be assessed,
        and reporting nothing would look identical to reporting clean.
        """
        custom = await self._custom_definitions(org_id)
        available: dict[str, CheckDefinition] = {
            definition.id: definition for definition in self.registry.definitions()
        }
        available.update(custom)

        if policy is None:
            return (
                [d for d in available.values() if d.enabled_by_default],
                {},
            )

        selected: list[CheckDefinition] = []
        overrides: dict[str, Severity] = {}
        missing: list[str] = []

        for entry in policy.entries:
            if not entry.enabled:
                continue
            definition = available.get(entry.check_id)
            if definition is None:
                # A policy outliving a check it names is normal after a library
                # upgrade. Log it so the gap is visible rather than silent.
                missing.append(entry.check_id)
                continue
            selected.append(definition)
            if entry.severity_override:
                overrides[entry.check_id] = Severity(entry.severity_override)

        if missing:
            log.warning(
                "assessment.policy_references_unknown_checks",
                policy=policy.name,
                checks=missing,
            )

        return selected, overrides

    async def _custom_definitions(self, org_id: int) -> dict[str, CheckDefinition]:
        rows = (
            (
                await self.session.execute(
                    select(CustomCheck).where(
                        CustomCheck.org_id == org_id, CustomCheck.enabled.is_(True)
                    )
                )
            )
            .scalars()
            .all()
        )

        definitions: dict[str, CheckDefinition] = {}
        for row in rows:
            try:
                definitions[row.check_id] = CheckDefinition.model_validate(row.definition)
            except Exception as exc:
                # One malformed custom check must not cost the whole assessment.
                log.warning("assessment.custom_check_invalid", check=row.check_id, error=str(exc))
        return definitions

    # ───────────────────────────── exceptions ───────────────────────────

    async def active_exceptions(self, device: Device) -> dict[str, FindingException]:
        """Exceptions in force for this device, keyed by check id (FR-CHK-07).

        A device-scoped exception beats a group-scoped one, which beats a global one:
        the more specific decision was made with more knowledge.
        """
        group_ids = (
            (
                await self.session.execute(
                    select(DeviceGroupMember.group_id).where(
                        DeviceGroupMember.device_id == device.id
                    )
                )
            )
            .scalars()
            .all()
        )

        rows = (
            (
                await self.session.execute(
                    select(FindingException).where(FindingException.org_id == device.org_id)
                )
            )
            .scalars()
            .all()
        )

        precedence = {
            ExceptionScope.GLOBAL.value: 0,
            ExceptionScope.GROUP.value: 1,
            ExceptionScope.DEVICE.value: 2,
        }
        chosen: dict[str, FindingException] = {}

        for row in rows:
            if not row.is_active:
                continue
            if row.scope == ExceptionScope.DEVICE.value and row.device_id != device.id:
                continue
            if row.scope == ExceptionScope.GROUP.value and row.device_group_id not in group_ids:
                continue

            current = chosen.get(row.check_id)
            if current is None or precedence[row.scope] > precedence[current.scope]:
                chosen[row.check_id] = row

        return chosen

    async def expire_exceptions(self) -> int:
        """Mark exceptions whose date has passed, so findings reopen (FR-CHK-07).

        ``is_active`` already treats a past date as inactive, so this is housekeeping
        rather than the mechanism — it makes the state visible in the UI and in exports
        instead of leaving rows that claim to be active and are not.
        """
        from netsecops.db.models.policy import ExceptionStatus

        now = datetime.now(UTC)
        rows = (
            (
                await self.session.execute(
                    select(FindingException).where(
                        FindingException.status == ExceptionStatus.ACTIVE.value,
                        FindingException.expires_at <= now,
                    )
                )
            )
            .scalars()
            .all()
        )

        for row in rows:
            row.status = ExceptionStatus.EXPIRED.value

        if rows:
            await self.session.flush()
            log.info("exceptions.expired", count=len(rows))
        return len(rows)

    # ──────────────────────────── the assessment ────────────────────────

    async def assess(
        self,
        device: Device,
        snapshot: Snapshot,
        *,
        job_id: uuid.UUID | None = None,
        policy: Policy | None = None,
    ) -> AssessmentOutcome:
        """Evaluate the device's policy against a snapshot and store everything.

        There is deliberately no way to supply configuration text here. Regex checks
        read ``snapshot.config_redacted`` and nothing else, because their matched lines
        become evidence on a finding, and a finding travels into exports, emails and
        tickets. An earlier version accepted the raw collected output as an argument
        and the job runner duly passed it — which put unredacted configuration one
        parameter away from every finding the system produces (C-2).
        """
        resolved_policy = policy if policy is not None else await self.policy_for_device(device)
        definitions, overrides = await self.checks_for_policy(resolved_policy, org_id=device.org_id)

        context = DeviceContext.from_ncm(
            snapshot.ncm,
            device_class=device.device_class,
            platform=device.effective_platform or device.platform,
            hostname=device.hostname,
        )

        results = evaluate_all(
            definitions,
            snapshot.ncm,
            device=context,
            config_text=snapshot.config_redacted,
            severity_overrides=overrides,
        )

        exceptions = await self.active_exceptions(device)
        outcome = AssessmentOutcome(
            device_id=device.id,
            snapshot_id=snapshot.id,
            policy_id=resolved_policy.id if resolved_policy else None,
            results=results,
        )

        for result in results:
            suppression = exceptions.get(result.check_id) if result.is_finding else None
            await self._store_result(device, snapshot, result, job_id, resolved_policy, suppression)

            if result.is_finding and suppression is None:
                await self._open_finding(device, snapshot, result)
                outcome.findings_opened += 1
            elif result.is_finding:
                outcome.findings_suppressed += 1
            elif result.outcome is Outcome.PASS:
                if await self._resolve_finding(device, result.check_id):
                    outcome.findings_resolved += 1

        # Rulebase analysis, on devices that carry one. Deliberately after the checks and
        # in its own try: a rulebase is attacker-influenced data of unbounded size, and a
        # surprise in one must not cost the device its entire configuration assessment.
        try:
            outcome.firewall = await FirewallAssessmentService(self.session).assess(
                device, snapshot
            )
        except Exception as exc:
            log.exception(
                "assessment.firewall_analysis_failed",
                device_id=str(device.id),
                error=str(exc),
            )

        outcome.risk = await self._store_risk(device, results, job_id)
        await self.session.flush()

        log.info(
            "assessment.completed",
            device_id=str(device.id),
            policy=resolved_policy.name if resolved_policy else "all-checks",
            checks=len(results),
            **outcome.counts,
            risk=outcome.risk.score if outcome.risk else None,
            firewall_rules=outcome.firewall.rules_analysed if outcome.firewall else 0,
        )
        return outcome

    async def _store_result(
        self,
        device: Device,
        snapshot: Snapshot,
        result: EngineResult,
        job_id: uuid.UUID | None,
        policy: Policy | None,
        suppression: FindingException | None,
    ) -> CheckResult:
        row = CheckResult(
            org_id=device.org_id,
            device_id=device.id,
            snapshot_id=snapshot.id,
            job_id=job_id,
            policy_id=policy.id if policy else None,
            check_id=result.check_id,
            check_version=result.check_version,
            outcome=result.outcome.value,
            severity=result.severity.value,
            message=result.message,
            reason=result.reason,
            evidence=_evidence_payload(result),
            duration_ms=result.duration_ms,
            suppressed_by_id=suppression.id if suppression else None,
        )
        self.session.add(row)
        return row

    async def _open_finding(
        self, device: Device, snapshot: Snapshot, result: EngineResult
    ) -> Finding:
        """Create or refresh the finding for a failing check (FR-FIND-01)."""
        fingerprint = finding_fingerprint(result.check_id)
        now = datetime.now(UTC)
        definition = self.registry.get(result.check_id)

        existing = (
            await self.session.execute(
                select(Finding).where(
                    Finding.device_id == device.id, Finding.fingerprint == fingerprint
                )
            )
        ).scalar_one_or_none()

        evidence = _evidence_payload(result)

        if existing is not None:
            existing.severity = result.severity.value
            existing.description = result.message
            existing.evidence = evidence
            existing.snapshot_id = snapshot.id
            existing.last_seen_at = now
            existing.occurrences += 1
            if not FindingStatus(existing.status).is_active:
                # It came back. Reopened rather than New, so the history shows this is
                # a regression and not a first sighting.
                existing.status = FindingStatus.REOPENED.value
                existing.resolved_at = None
            await self.session.flush()
            return existing

        finding = Finding(
            org_id=device.org_id,
            device_id=device.id,
            kind=FindingKind.CONFIG.value,
            fingerprint=fingerprint,
            check_id=result.check_id,
            title=result.title or result.check_id,
            description=result.message,
            severity=result.severity.value,
            status=FindingStatus.NEW.value,
            evidence=evidence,
            remediation=definition.remediation if definition else None,
            snapshot_id=snapshot.id,
            first_seen_at=now,
            last_seen_at=now,
        )
        self.session.add(finding)
        await self.session.flush()
        return finding

    async def _resolve_finding(self, device: Device, check_id: str) -> bool:
        """Close a finding whose check now passes (FR-FIND-01)."""
        finding = (
            await self.session.execute(
                select(Finding).where(
                    Finding.device_id == device.id,
                    Finding.fingerprint == finding_fingerprint(check_id),
                )
            )
        ).scalar_one_or_none()

        if finding is None or not FindingStatus(finding.status).is_active:
            return False

        finding.status = FindingStatus.RESOLVED.value
        finding.resolved_at = datetime.now(UTC)
        await self.session.flush()
        return True

    async def _store_risk(
        self, device: Device, results: Sequence[EngineResult], job_id: uuid.UUID | None
    ) -> RiskBreakdown:
        breakdown = score_device(results, criticality=device.criticality)

        self.session.add(
            RiskScore(
                org_id=device.org_id,
                device_id=device.id,
                job_id=job_id,
                score=breakdown.score,
                components=breakdown.to_components(),
                checks_evaluated=breakdown.evaluated,
                checks_passed=breakdown.counts.get(Outcome.PASS.value, 0),
                checks_failed=breakdown.counts.get(Outcome.FAIL.value, 0),
                checks_not_evaluated=breakdown.counts.get(Outcome.NOT_EVALUATED.value, 0),
            )
        )
        return breakdown

    # ─────────────────────────────── reads ──────────────────────────────

    async def latest_risk(self, device: Device) -> RiskScore | None:
        return (
            await self.session.execute(
                select(RiskScore)
                .where(RiskScore.device_id == device.id)
                .order_by(RiskScore.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

    async def results_for_snapshot(self, snapshot_id: uuid.UUID) -> Sequence[CheckResult]:
        return (
            (
                await self.session.execute(
                    select(CheckResult)
                    .where(CheckResult.snapshot_id == snapshot_id)
                    .order_by(CheckResult.severity, CheckResult.check_id)
                )
            )
            .scalars()
            .all()
        )

    async def get_policy(self, policy_id: uuid.UUID) -> Policy:
        policy = (
            await self.session.execute(select(Policy).where(Policy.id == policy_id))
        ).scalar_one_or_none()
        if policy is None:
            raise NotFoundError("Policy not found.")
        return policy


def _evidence_payload(result: EngineResult) -> dict[str, Any]:
    """The evidence block stored on a result and copied onto a finding (FR-FIND-04).

    Excerpts are already redacted — provenance is redacted at capture in Phase 2 — but
    the observed value is stringified defensively, because it travels into JSONB and
    from there into exports and tickets.
    """
    return {
        "observed": _safe(result.observed),
        "expected": result.expected,
        "lines": [
            {
                "path": line.path,
                "line_start": line.line_start,
                "line_end": line.line_end,
                "excerpt": line.excerpt,
                "command": line.command,
            }
            for line in result.evidence
        ],
    }


def _safe(value: Any) -> Any:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, list | tuple):
        return [_safe(item) for item in value][:50]
    if isinstance(value, dict):
        return {str(k): _safe(v) for k, v in list(value.items())[:50]}
    return str(value)


__all__ = ["AssessmentOutcome", "AssessmentService", "finding_fingerprint"]
