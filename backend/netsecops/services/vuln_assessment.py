"""Turning advisories into findings (FR-VUL-03, FR-VUL-04, FR-VUL-05, FR-VUL-09).

The last link. Everything before this produced verdicts nobody could see: the matcher
answers one question about one advisory and returns a dataclass. This runs it across the
estate, writes the answers down, and gives them a lifecycle.

**Which advisories a device is weighed against.** All of them. Pre-filtering by product
before matching sounds obvious and is where a whole vendor's coverage disappears â€” the
filter needs the same product-identity logic the matcher already has, and two
implementations of that drift. The matcher is cheap; the estate is not large; correctness
is worth more than the query.

**The rule that governs resolution.** A vulnerability finding closes only when the
advisory stops matching â€” the device was upgraded. It does **not** close because the
device became unassessable. Those look identical in the data (no confirmed match this
run) and mean opposite things: one is patched, the other is a device whose version
stopped being readable. Resolving on `NOT_EVALUATED` would mean an estate that lost its
`show version` collection would report itself progressively cured.

**Findings and matches are different records.** A match exists for every advisory weighed
against every device, including the ones that did not apply â€” it is the audit trail of
what was considered. A finding exists only where something needs doing. Conflating them
gives you either a findings list nobody can read or a match table that cannot answer
"was this even checked?".
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import get_logger
from netsecops.db.models.collection import (
    Finding,
    FindingKind,
    FindingSeverity,
    FindingStatus,
    Snapshot,
)
from netsecops.db.models.inventory import Device, DeviceStatus
from netsecops.db.models.vulnerability import EolRecordRow, VulnAdvisory, VulnMatch
from netsecops.ncm.models import NormalisedConfig
from netsecops.vuln.advisory import (
    Advisory,
    AffectedProduct,
    ConstraintKind,
    FeatureCondition,
    Score,
    VersionConstraint,
)
from netsecops.vuln.eol import EolRecord, LifecycleStatus
from netsecops.vuln.eol import assess as assess_lifecycle
from netsecops.vuln.matcher import Confidence, Match, match

log = get_logger(__name__)

#: CVSS base score to finding severity. The bands are CVSS v3.1's own, so a finding's
#: severity and the score printed beside it never disagree on screen.
_SEVERITY_BANDS: tuple[tuple[float, FindingSeverity], ...] = (
    (9.0, FindingSeverity.CRITICAL),
    (7.0, FindingSeverity.HIGH),
    (4.0, FindingSeverity.MEDIUM),
    (0.1, FindingSeverity.LOW),
)


def vuln_fingerprint(source: str, advisory_id: str) -> str:
    """The identity of a vulnerability finding on a device (FR-FIND-01).

    Keyed on the advisory rather than the CVE: one advisory may carry several CVEs, and
    keying on the CVE would open three findings for one upgrade. Keyed on (source,
    advisory_id) rather than advisory_id alone, because a Cisco advisory and an NVD
    record about the same flaw are different statements with different affected ranges,
    and collapsing them would let one silently resolve the other.
    """
    return f"vuln:{source}:{advisory_id}"


def eol_fingerprint(cycle: str) -> str:
    return f"eol:{cycle}"


@dataclass(slots=True)
class DeviceAssessment:
    """What one device's vulnerability assessment produced."""

    device_id: uuid.UUID
    #: The snapshot the verdicts were reached against. None means there was nothing to
    #: match — which produces the same empty result as "nothing matched" and must not be
    #: reported as one.
    snapshot_id: uuid.UUID | None = None
    matches: list[Match] = field(default_factory=list)
    findings_opened: int = 0
    findings_resolved: int = 0
    lifecycle: LifecycleStatus | None = None
    #: How many advisories were weighed. Zero means the catalogue is empty, not that the
    #: device is clean — the distinction a job log has to preserve.
    advisories_considered: int = 0
    #: Devices the assessment could not rule on, and why. Surfaced rather than counted
    #: as clean â€” this is the coverage gap the estate does not know it has.
    not_evaluated: list[str] = field(default_factory=list)

    @property
    def confirmed(self) -> int:
        return sum(1 for m in self.matches if m.confidence is Confidence.CONFIRMED)

    @property
    def likely(self) -> int:
        return sum(1 for m in self.matches if m.confidence is Confidence.LIKELY)


class VulnAssessmentService:
    """Run the matcher across devices and record the results."""

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id

    async def assess_device(self, device: Device) -> DeviceAssessment:
        """Weigh every stored advisory against one device."""
        outcome = DeviceAssessment(device_id=device.id)

        snapshot = await self._latest_snapshot(device)
        if snapshot is None:
            outcome.not_evaluated.append(
                "Nothing has been collected from this device, so no advisory can be "
                "matched against it."
            )
            return outcome

        outcome.snapshot_id = snapshot.id
        ncm = NormalisedConfig.model_validate(snapshot.ncm or {})
        advisories = await self._advisories()
        outcome.advisories_considered = len(advisories)

        for row in advisories:
            advisory = _rebuild(row)
            result = match(ncm, advisory, platform=device.platform)
            outcome.matches.append(result)

            await self._store_match(device, snapshot, row, result)

            if result.confidence in (Confidence.CONFIRMED, Confidence.LIKELY):
                await self._open_finding(device, snapshot, row, result)
                outcome.findings_opened += 1
            elif result.confidence is Confidence.NOT_AFFECTED:
                # Only a positive statement of non-affectedness closes a finding.
                if await self._resolve_finding(
                    device, vuln_fingerprint(row.source, row.advisory_id)
                ):
                    outcome.findings_resolved += 1
            else:
                # NOT_EVALUATED. Any existing finding is deliberately left open: the
                # device did not become safe, it became unreadable.
                outcome.not_evaluated.append(
                    f"{row.advisory_id}: {result.reasoning[0] if result.reasoning else 'unknown'}"
                )

        await self._assess_lifecycle(device, ncm, snapshot, outcome)

        log.info(
            "vuln.device_assessed",
            device_id=str(device.id),
            advisories=len(advisories),
            confirmed=outcome.confirmed,
            likely=outcome.likely,
            not_evaluated=len(outcome.not_evaluated),
            opened=outcome.findings_opened,
            resolved=outcome.findings_resolved,
        )
        return outcome

    async def assess_all(self) -> list[DeviceAssessment]:
        """Every active device in the estate."""
        devices = (
            (
                await self.session.execute(
                    select(Device).where(
                        Device.org_id == self.org_id,
                        Device.status != DeviceStatus.ARCHIVED.value,
                    )
                )
            )
            .scalars()
            .all()
        )
        return [await self.assess_device(device) for device in devices]

    # â”€â”€ end of life (FR-VUL-05) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    async def _assess_lifecycle(
        self,
        device: Device,
        ncm: NormalisedConfig,
        snapshot: Snapshot,
        outcome: DeviceAssessment,
    ) -> None:
        records = await self._eol_records(device)
        assessment = assess_lifecycle(ncm.device.version, records, platform=device.platform)
        outcome.lifecycle = assessment.status

        if assessment.status is LifecycleStatus.UNKNOWN:
            outcome.not_evaluated.append(f"lifecycle: {assessment.reasoning}")
            return

        cycle = assessment.record.cycle if assessment.record else "unknown"
        fingerprint = eol_fingerprint(cycle)

        if assessment.status is LifecycleStatus.SUPPORTED:
            if await self._resolve_finding(device, fingerprint):
                outcome.findings_resolved += 1
            return

        severity = {
            LifecycleStatus.END_OF_LIFE: FindingSeverity.HIGH,
            LifecycleStatus.END_OF_SUPPORT: FindingSeverity.HIGH,
            LifecycleStatus.APPROACHING_END_OF_SUPPORT: FindingSeverity.MEDIUM,
        }[assessment.status]

        await self._upsert_finding(
            device,
            fingerprint=fingerprint,
            title=f"{device.platform or 'Software'} release {cycle} is {assessment.status.value.replace('_', ' ')}",
            description=assessment.reasoning,
            severity=severity,
            snapshot_id=snapshot.id,
            remediation=(
                f"Upgrade to a supported release. The latest in this cycle is {assessment.record.latest}."
                if assessment.record and assessment.record.latest
                else "Upgrade to a release the vendor still maintains."
            ),
            evidence={"lifecycle": assessment.status.value, "cycle": cycle},
        )
        outcome.findings_opened += 1

    # â”€â”€ persistence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    async def _store_match(
        self, device: Device, snapshot: Snapshot, row: VulnAdvisory, result: Match
    ) -> None:
        """Record the verdict, including the ones that did not apply.

        A match row for a NOT_AFFECTED advisory is not noise: it is the difference
        between "we checked and it does not apply" and "we never looked", and only one
        of those should let somebody sleep.
        """
        existing = (
            await self.session.execute(
                select(VulnMatch).where(
                    VulnMatch.device_id == device.id, VulnMatch.advisory_id == row.id
                )
            )
        ).scalar_one_or_none()

        match_row = existing or VulnMatch(
            org_id=self.org_id, device_id=device.id, advisory_id=row.id
        )
        match_row.snapshot_id = snapshot.id
        match_row.confidence = result.confidence.value
        match_row.cve_ids = list(result.cve_ids)
        match_row.reasoning = list(result.reasoning)
        match_row.fixed_versions = list(result.fixed_versions)

        if existing is None:
            self.session.add(match_row)
        await self.session.flush()

    async def _open_finding(
        self, device: Device, snapshot: Snapshot, row: VulnAdvisory, result: Match
    ) -> None:
        cves = ", ".join(result.cve_ids) or row.advisory_id
        qualifier = " (likely)" if result.confidence is Confidence.LIKELY else ""

        # Upgrade guidance, as text and only as text â€” the same rule the check library
        # follows for remediation (SRS Â§8). There is no field here that could be run.
        remediation = (
            f"Upgrade to {', '.join(result.fixed_versions)} or later."
            if result.fixed_versions
            else None
        ) or ("\n".join(row.remediations) if row.remediations else None)

        await self._upsert_finding(
            device,
            fingerprint=vuln_fingerprint(row.source, row.advisory_id),
            title=f"{cves}{qualifier}",
            description="\n".join(result.reasoning),
            severity=_severity_for(row),
            # One CVE goes in the column for querying; the full list stays in evidence,
            # because an advisory carrying several is common and the column holds one.
            cve_id=result.cve_ids[0] if result.cve_ids else None,
            snapshot_id=snapshot.id,
            remediation=remediation,
            evidence={
                "advisory_id": row.advisory_id,
                "source": row.source,
                "cve_ids": result.cve_ids,
                "confidence": result.confidence.value,
                "fixed_versions": result.fixed_versions,
                "references": row.references[:5],
            },
        )

    async def _upsert_finding(
        self,
        device: Device,
        *,
        fingerprint: str,
        title: str,
        description: str,
        severity: FindingSeverity,
        evidence: dict[str, object],
        cve_id: str | None = None,
        snapshot_id: uuid.UUID | None = None,
        remediation: str | None = None,
    ) -> Finding:
        now = datetime.now(UTC)
        existing = (
            await self.session.execute(
                select(Finding).where(
                    Finding.device_id == device.id, Finding.fingerprint == fingerprint
                )
            )
        ).scalar_one_or_none()

        if existing is not None:
            existing.last_seen_at = now
            existing.occurrences += 1
            existing.severity = severity.value
            existing.title = title
            existing.description = description
            existing.evidence = evidence
            existing.snapshot_id = snapshot_id
            if remediation:
                existing.remediation = remediation
            if not FindingStatus(existing.status).is_active:
                # It came back â€” the device was downgraded, or an exception lapsed.
                # Reopened rather than New, so the history shows a regression.
                existing.status = FindingStatus.REOPENED.value
                existing.resolved_at = None
            await self.session.flush()
            return existing

        finding = Finding(
            org_id=self.org_id,
            device_id=device.id,
            kind=FindingKind.VULN.value,
            fingerprint=fingerprint,
            title=title,
            description=description,
            severity=severity.value,
            status=FindingStatus.NEW.value,
            cve_id=cve_id,
            snapshot_id=snapshot_id,
            remediation=remediation,
            first_seen_at=now,
            last_seen_at=now,
            occurrences=1,
            evidence=evidence,
        )
        self.session.add(finding)
        await self.session.flush()
        return finding

    async def _resolve_finding(self, device: Device, fingerprint: str) -> bool:
        """Close a finding whose advisory no longer matches.

        Reached only from a positive NOT_AFFECTED. The caller must never route
        NOT_EVALUATED here â€” see the module docstring.
        """
        finding = (
            await self.session.execute(
                select(Finding).where(
                    Finding.device_id == device.id, Finding.fingerprint == fingerprint
                )
            )
        ).scalar_one_or_none()

        if finding is None or not FindingStatus(finding.status).is_active:
            return False

        finding.status = FindingStatus.RESOLVED.value
        finding.resolved_at = datetime.now(UTC)
        await self.session.flush()
        return True

    # â”€â”€ reads â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    async def _latest_snapshot(self, device: Device) -> Snapshot | None:
        return (
            await self.session.execute(
                select(Snapshot)
                .where(Snapshot.device_id == device.id)
                .order_by(Snapshot.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

    async def _advisories(self) -> Sequence[VulnAdvisory]:
        return (
            (
                await self.session.execute(
                    select(VulnAdvisory).where(VulnAdvisory.org_id == self.org_id)
                )
            )
            .scalars()
            .all()
        )

    async def _eol_records(self, device: Device) -> list[EolRecord]:
        rows = (
            (
                await self.session.execute(
                    select(EolRecordRow).where(
                        EolRecordRow.org_id == self.org_id,
                        EolRecordRow.vendor == (device.vendor or ""),
                    )
                )
            )
            .scalars()
            .all()
        )
        return [
            EolRecord(
                vendor=row.vendor,
                product=row.product,
                cycle=row.cycle,
                source=row.source,
                support_ends=row.support_ends,
                life_ends=row.life_ends,
                support_ended_undated=row.support_ended_undated,
                life_ended_undated=row.life_ended_undated,
                latest=row.latest,
            )
            for row in rows
        ]


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ rebuilding an advisory â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


def _rebuild(row: VulnAdvisory) -> Advisory:
    """Turn a stored row back into the model the matcher reasons over.

    Every field the matcher consults must survive this, including the ones that look
    like metadata: ``notes_unparsed`` is what stops a partly-understood advisory
    clearing a device, and an advisory rebuilt without it would start confidently
    ruling devices out.
    """
    return Advisory(
        source=row.source,
        advisory_id=row.advisory_id,
        title=row.title,
        description=row.description,
        cve_ids=list(row.cve_ids),
        cwe_ids=list(row.cwe_ids),
        scores=[
            Score(
                version=str(entry.get("version") or ""),
                base_score=entry.get("base_score"),
                vector=entry.get("vector"),
                severity=entry.get("severity"),
            )
            for entry in row.scores
        ],
        affected=[_rebuild_product(entry) for entry in row.affected],
        fixed=[_rebuild_product(entry) for entry in row.fixed],
        conditions=[
            FeatureCondition(
                path=str(entry["path"]),
                expected=entry["expected"],
                description=str(entry.get("description") or ""),
            )
            for entry in row.conditions
        ],
        remediations=list(row.remediations),
        references=list(row.references),
        published=row.published,
        modified=row.modified,
        notes_unparsed=list(row.notes_unparsed),
    )


def _rebuild_product(entry: dict[str, object]) -> AffectedProduct:
    constraint = entry.get("constraint") or {}
    if not isinstance(constraint, dict):
        constraint = {}
    return AffectedProduct(
        vendor=entry.get("vendor"),  # type: ignore[arg-type]
        product=entry.get("product"),  # type: ignore[arg-type]
        cpe=entry.get("cpe"),  # type: ignore[arg-type]
        product_id=entry.get("product_id"),  # type: ignore[arg-type]
        constraint=VersionConstraint(
            kind=ConstraintKind(str(constraint.get("kind") or "unparsed")),
            raw=str(constraint.get("raw") or ""),
            introduced=constraint.get("introduced"),
            fixed=constraint.get("fixed"),
            version=constraint.get("version"),
        ),
    )


def _severity_for(row: VulnAdvisory) -> FindingSeverity:
    """Severity from the highest CVSS the advisory published.

    An advisory with no score at all becomes MEDIUM rather than LOW: no score means
    nobody has assessed it yet, which is not the same as assessing it as minor, and
    filing it at the bottom of the list is how a zero-day with no CVSS goes unread.
    """
    best: float | None = None
    for entry in row.scores:
        value = entry.get("base_score")
        if isinstance(value, int | float) and (best is None or value > best):
            best = float(value)

    if best is None:
        return FindingSeverity.MEDIUM

    for threshold, severity in _SEVERITY_BANDS:
        if best >= threshold:
            return severity
    return FindingSeverity.INFO


__all__ = [
    "DeviceAssessment",
    "VulnAssessmentService",
    "eol_fingerprint",
    "vuln_fingerprint",
]
