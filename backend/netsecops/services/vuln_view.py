"""Reading the vulnerability position (FR-VUL-04, FR-VUL-07).

The matcher, the feed importer and the assessment service have been complete and tested
since Phase 6, and none of them was reachable: no route, no worker branch, no CLI
command. This assembles what they produced into the shapes the API returns.

A vulnerability finding's facts are spread across four tables by design — the finding
carries the lifecycle, the match carries the verdict and its reasoning, the advisory
carries the vendor's text, and the CVE row carries scoring that arrives on a different
schedule from all of it. Joining them is this module's whole job; doing it in each
route handler would mean four chances to forget the EPSS null.

**Nothing here defaults a null to a zero or a false.** `kev = None` means the KEV
catalogue was never imported and `kev = False` means it was and this CVE is not in it.
`epss = None` means unscored, not harmless. A device with no assessment on record is
counted separately from a device assessed and found clean. Each of those pairs looks
identical after one careless `or 0`, and each collapse tells an operator the estate is
safer than anybody has established.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import Select, any_, case, func, literal, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Scope
from netsecops.db.models.collection import Finding, FindingKind, FindingStatus
from netsecops.db.models.inventory import Device
from netsecops.db.models.vulnerability import VulnAdvisory, VulnCve, VulnMatch
from netsecops.schemas.vulnerability import (
    AffectedDeviceRead,
    CveDetailRead,
    CvssRead,
    VulnerabilityRead,
    VulnerabilitySummary,
)

#: Worst first. Severity is a string column, so ordering it alphabetically would open
#: the page with "critical" below "high" and "low" above both.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _kev_flag(flags: Sequence[bool | None]) -> bool | None:
    """Roll several CVEs' KEV flags into one, keeping all three states.

    True if any of them is known-exploited. False only when at least one was checked
    against the catalogue and none was listed. None when nothing was checked — which is
    the state that must not collapse into False, because "no known-exploited CVEs here"
    and "the KEV catalogue has never been imported" would then read identically on a
    dashboard whose whole purpose is to say which it is.
    """
    if any(flag is True for flag in flags):
        return True
    if any(flag is False for flag in flags):
        return False
    return None


def _cvss(payload: dict[str, Any] | None) -> CvssRead | None:
    if not payload:
        return None
    return CvssRead(
        version=payload.get("version"),
        base_score=payload.get("base_score") or payload.get("baseScore"),
        base_severity=payload.get("base_severity") or payload.get("baseSeverity"),
        vector=payload.get("vector") or payload.get("vectorString"),
    )


class VulnViewService:
    """Read-only assembly of the vulnerability views."""

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id

    # ── scope ────────────────────────────────────────────────────────────

    async def _visible(self, stmt: Select[Any], scope: Scope) -> Select[Any]:
        """Narrow a query to the devices this principal may see (FR-AUTH-05).

        Applied in the query rather than filtered afterwards, so a paged response
        cannot return a short page of visible rows out of a long page of invisible
        ones and report the wrong total.
        """
        if scope.unrestricted:
            return stmt
        from netsecops.services.inventory import InventoryService

        visible = await InventoryService(self.session).visible_device_ids(scope)
        return stmt.where(Finding.device_id.in_(visible))

    # ── list ─────────────────────────────────────────────────────────────

    async def list_vulnerabilities(
        self,
        *,
        scope: Scope,
        device_id: uuid.UUID | None = None,
        severity: str | None = None,
        status: str | None = None,
        confidence: str | None = None,
        cve_id: str | None = None,
        kev_only: bool = False,
        active_only: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[VulnerabilityRead], int]:
        stmt = (
            select(Finding, Device)
            .join(Device, Device.id == Finding.device_id)
            .where(Finding.kind == FindingKind.VULN.value)
        )

        if device_id is not None:
            stmt = stmt.where(Finding.device_id == device_id)
        stmt = await self._visible(stmt, scope)

        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if status:
            stmt = stmt.where(Finding.status == status)
        elif active_only:
            stmt = stmt.where(Finding.status.in_(FindingStatus.active_values()))
        if cve_id:
            stmt = stmt.where(Finding.evidence["cve_ids"].astext.ilike(f"%{cve_id}%"))
        if confidence:
            stmt = stmt.where(Finding.evidence["confidence"].astext == confidence)

        total = int(
            (
                await self.session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )

        order = case(SEVERITY_ORDER, value=Finding.severity, else_=5)
        rows = (
            await self.session.execute(
                stmt.order_by(order, Finding.last_seen_at.desc()).limit(limit).offset(offset)
            )
        ).all()

        enriched = await self._enrich([(finding, device) for finding, device in rows])
        if kev_only:
            # Filtered after enrichment because the KEV flag lives on the CVE row, not
            # on the finding. The total above therefore counts before this filter, and
            # the caller is told so in the response meta.
            enriched = [row for row in enriched if row.kev]
        return enriched, total

    async def _enrich(self, rows: Sequence[tuple[Finding, Device]]) -> list[VulnerabilityRead]:
        """Attach advisory text and CVE scoring to a page of findings.

        Two batched lookups rather than two per row: a device with three hundred open
        advisories is ordinary, and this page is the vulnerability view's landing query.
        """
        cve_ids: set[str] = set()
        advisory_keys: set[tuple[str, str]] = set()
        for finding, _ in rows:
            evidence = finding.evidence or {}
            cve_ids.update(evidence.get("cve_ids") or [])
            source, advisory_id = evidence.get("source"), evidence.get("advisory_id")
            if source and advisory_id:
                advisory_keys.add((source, advisory_id))

        cves = await self._cves(cve_ids)
        advisories = await self._advisories(advisory_keys)

        results: list[VulnerabilityRead] = []
        for finding, device in rows:
            evidence = finding.evidence or {}
            finding_cves = list(evidence.get("cve_ids") or [])
            advisory = advisories.get((evidence.get("source"), evidence.get("advisory_id")))

            # The worst-scored CVE on the advisory is the one that decides how the row
            # reads, since a single advisory routinely carries several.
            scored = [cves[c] for c in finding_cves if c in cves]
            headline = max(
                scored,
                key=lambda c: (_cvss(c.cvss31) or CvssRead()).base_score or 0.0,
                default=None,
            )

            results.append(
                VulnerabilityRead(
                    finding_id=finding.id,
                    device_id=device.id,
                    device_hostname=device.hostname,
                    title=finding.title,
                    severity=finding.severity,
                    status=finding.status,
                    advisory_id=evidence.get("advisory_id"),
                    advisory_source=evidence.get("source"),
                    cve_ids=finding_cves,
                    cwe_ids=list(advisory.cwe_ids) if advisory else [],
                    cvss=_cvss(headline.cvss31 if headline else None),
                    epss=headline.epss if headline else None,
                    kev=_kev_flag([cve.kev for cve in scored]),
                    kev_due_date=next(
                        (cve.kev_due_date for cve in scored if cve.kev and cve.kev_due_date),
                        None,
                    ),
                    confidence=evidence.get("confidence"),
                    reasoning=(finding.description or "").splitlines(),
                    installed_version=device.os_version,
                    fixed_versions=list(evidence.get("fixed_versions") or []),
                    remediations=[finding.remediation] if finding.remediation else [],
                    references=list(evidence.get("references") or []),
                    published=advisory.published if advisory else None,
                    modified=advisory.modified if advisory else None,
                    first_seen_at=finding.first_seen_at,
                    last_seen_at=finding.last_seen_at,
                )
            )
        return results

    async def _cves(self, cve_ids: set[str]) -> dict[str, VulnCve]:
        if not cve_ids:
            return {}
        rows = (
            (
                await self.session.execute(
                    select(VulnCve).where(
                        VulnCve.org_id == self.org_id, VulnCve.cve_id.in_(cve_ids)
                    )
                )
            )
            .scalars()
            .all()
        )
        return {row.cve_id: row for row in rows}

    async def _advisories(
        self, keys: set[tuple[str, str]]
    ) -> dict[tuple[str | None, str | None], VulnAdvisory]:
        if not keys:
            return {}
        sources = {source for source, _ in keys}
        ids = {advisory_id for _, advisory_id in keys}
        rows = (
            (
                await self.session.execute(
                    select(VulnAdvisory).where(
                        VulnAdvisory.org_id == self.org_id,
                        VulnAdvisory.source.in_(sources),
                        VulnAdvisory.advisory_id.in_(ids),
                    )
                )
            )
            .scalars()
            .all()
        )
        return {(row.source, row.advisory_id): row for row in rows}

    # ── one CVE across the estate ────────────────────────────────────────

    async def cve_detail(self, cve_id: str, *, scope: Scope) -> CveDetailRead | None:
        """Everything known about one CVE, and every device it reaches.

        Returns None only when no feed has ever mentioned the CVE *and* no match
        references it — "we have never heard of this" rather than "nothing is affected".
        """
        cve = (
            await self.session.execute(
                select(VulnCve).where(VulnCve.org_id == self.org_id, VulnCve.cve_id == cve_id)
            )
        ).scalar_one_or_none()

        advisories = (
            (
                await self.session.execute(
                    select(VulnAdvisory).where(
                        VulnAdvisory.org_id == self.org_id,
                        # `literal(x) == any_(col)` rather than `col.any(x)`: both emit
                        # `x = ANY (col)`, but the attribute form resolves to the
                        # relationship comparator in type-checking and fails strict mypy.
                        literal(cve_id) == any_(VulnAdvisory.cve_ids),
                    )
                )
            )
            .scalars()
            .all()
        )

        if cve is None and not advisories:
            return None

        rows = (
            await self.session.execute(
                select(VulnMatch, Device)
                .join(Device, Device.id == VulnMatch.device_id)
                .where(
                    VulnMatch.org_id == self.org_id,
                    literal(cve_id) == any_(VulnMatch.cve_ids),
                )
            )
        ).all()

        # Materialised as tuples rather than filtering the Row sequence in place: a Row
        # and a plain tuple are different types, and reassigning one to the other is what
        # the type checker objected to.
        matches: list[tuple[VulnMatch, Device]] = [(row[0], row[1]) for row in rows]

        if not scope.unrestricted:
            from netsecops.services.inventory import InventoryService

            visible = set(await InventoryService(self.session).visible_device_ids(scope))
            matches = [(m, d) for m, d in matches if d.id in visible]

        affected: list[AffectedDeviceRead] = []
        unevaluated: list[AffectedDeviceRead] = []
        for match, device in matches:
            entry = AffectedDeviceRead(
                device_id=device.id,
                hostname=device.hostname,
                mgmt_ip=str(device.mgmt_ip),
                platform=device.platform,
                installed_version=device.os_version,
                confidence=match.confidence,
                fixed_versions=list(match.fixed_versions or []),
            )
            # Not Affected devices are deliberately in neither list: they were checked
            # and ruled out, which is a real answer and not an exposure.
            if match.confidence in {"confirmed", "likely"}:
                affected.append(entry)
            elif match.confidence == "not_evaluated":
                unevaluated.append(entry)

        return CveDetailRead(
            cve_id=cve_id,
            description=cve.description if cve else None,
            cvss31=_cvss(cve.cvss31) if cve else None,
            cvss40=_cvss(cve.cvss40) if cve else None,
            cwe_ids=list(cve.cwe_ids) if cve else [],
            epss=cve.epss if cve else None,
            kev=cve.kev if cve else None,
            kev_due_date=cve.kev_due_date if cve else None,
            published=cve.published if cve else None,
            modified=cve.modified if cve else None,
            advisories=[
                {
                    "source": row.source,
                    "advisory_id": row.advisory_id,
                    "title": row.title,
                    # Derived, not stored: an advisory is fully understood only when no
                    # statement in it defeated the parser. It matters here because a
                    # partly-read advisory can raise a finding but can never clear a
                    # device, and a reader deciding whether to trust a "not affected"
                    # verdict needs to know which kind they are looking at.
                    "fully_interpreted": not row.notes_unparsed,
                    "unparsed_statements": list(row.notes_unparsed or []),
                    "references": list(row.references or [])[:5],
                }
                for row in advisories
            ],
            affected_devices=affected,
            unevaluated_devices=unevaluated,
        )

    # ── summary ──────────────────────────────────────────────────────────

    async def summary(self, *, scope: Scope) -> VulnerabilitySummary:
        stmt = (
            select(Finding, Device)
            .join(Device, Device.id == Finding.device_id)
            .where(
                Finding.kind == FindingKind.VULN.value,
                Finding.status.in_(FindingStatus.active_values()),
            )
        )
        stmt = await self._visible(stmt, scope)
        rows = (await self.session.execute(stmt)).all()
        enriched = await self._enrich([(f, d) for f, d in rows])

        by_severity: dict[str, int] = {}
        by_confidence: dict[str, int] = {}
        for row in enriched:
            by_severity[row.severity] = by_severity.get(row.severity, 0) + 1
            if row.confidence:
                by_confidence[row.confidence] = by_confidence.get(row.confidence, 0) + 1

        assessed = {
            device_id
            for (device_id,) in (
                await self.session.execute(
                    select(VulnMatch.device_id).where(VulnMatch.org_id == self.org_id).distinct()
                )
            ).all()
        }
        device_stmt = select(func.count()).select_from(Device)
        total_devices = int((await self.session.execute(device_stmt)).scalar_one())

        return VulnerabilitySummary(
            total=len(enriched),
            by_severity=by_severity,
            by_confidence=by_confidence,
            kev_count=sum(1 for row in enriched if row.kev),
            devices_affected=len({row.device_id for row in enriched}),
            devices_unassessed=max(0, total_devices - len(assessed)),
        )


__all__ = ["SEVERITY_ORDER", "VulnViewService"]
