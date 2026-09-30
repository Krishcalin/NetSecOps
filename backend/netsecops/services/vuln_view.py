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
from netsecops.db.models.inventory import Device, DeviceStatus
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


def _score(cve: VulnCve) -> float:
    """The best available base score for ranking, across every scored CVSS version.

    A CVE scored only under CVSS 4.0 — increasingly common for post-2024 CVEs, and both
    the NVD and CSAF importers ingest it — has a NULL cvss31. Ranking on v3.1 alone
    reads that as 0.0, sorting a genuinely critical finding to the bottom of the page.
    """
    return max(
        (_cvss(cve.cvss31) or CvssRead()).base_score or 0.0,
        (_cvss(cve.cvss40) or CvssRead()).base_score or 0.0,
    )


def _headline_cvss(cve: VulnCve | None) -> CvssRead | None:
    """The score to display for a row, preferring whichever version scores highest.

    Falls back to whichever version is present, so a v4-only CVE still shows its score
    rather than a blank cell for a real high/critical.
    """
    if cve is None:
        return None
    candidates = [c for c in (_cvss(cve.cvss31), _cvss(cve.cvss40)) if c is not None]
    if not candidates:
        return None
    return max(candidates, key=lambda c: c.base_score or 0.0)


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

        if kev_only:
            # In the query, not after it. Filtering an already-paged list left page two
            # of a KEV-only request empty whenever the first fifty findings by severity
            # happened not to be exploited — and reported a total counted before the
            # filter, so the pager promised rows that could not be reached. That is the
            # same mistake `_visible` above exists to avoid, and the KEV list is the one
            # an operator opens when something is being exploited right now.
            stmt = stmt.where(self._is_kev())

        total = int(
            (
                await self.session.execute(select(func.count()).select_from(stmt.subquery()))
            ).scalar_one()
        )

        rows = (
            await self.session.execute(stmt.order_by(*self._ranking()).limit(limit).offset(offset))
        ).all()

        return await self._enrich([(finding, device) for finding, device in rows]), total

    # ── ranking ──────────────────────────────────────────────────────────

    def _cve_ids_contain(self) -> Any:
        """Correlate a CVE row to the finding that names it.

        The finding stores its CVEs as a JSONB array on `evidence`, so the join is
        containment: `'["CVE-1","CVE-2"]'::jsonb @> '"CVE-1"'::jsonb`.
        """
        return Finding.evidence["cve_ids"].op("@>")(func.to_jsonb(VulnCve.cve_id))

    def _is_kev(self) -> Any:
        """Whether any CVE on this finding is in CISA's catalogue."""
        return (
            select(VulnCve.id)
            .where(
                VulnCve.org_id == self.org_id,
                VulnCve.kev.is_(True),
                self._cve_ids_contain(),
            )
            .correlate(Finding)
            .exists()
        )

    def _max_epss(self) -> Any:
        """The highest exploit-prediction score across this finding's CVEs.

        Max rather than average: one advisory covering three CVEs is as urgent as its
        most likely-to-be-exploited member, and averaging would let two quiet CVEs bury
        an active one.
        """
        return (
            select(func.max(VulnCve.epss))
            .where(VulnCve.org_id == self.org_id, self._cve_ids_contain())
            .correlate(Finding)
            .scalar_subquery()
        )

    def _ranking(self) -> tuple[Any, ...]:
        """The order the list is read in (FR-VUL-06).

        **Known-exploited outranks severity**, which is the whole argument for ingesting
        the KEV catalogue: a CVSS 9.8 nobody has ever attacked and a 7.5 in active
        ransomware use are not the same work item, and sorting by severity alone puts
        them the wrong way round. Severity breaks the tie within each group, then EPSS,
        then recency.

        EPSS sorts nulls last rather than as zero. An unscored CVE is one FIRST has not
        modelled, which for something published last week is precisely the opposite of
        "almost certainly not exploited".
        """
        return (
            self._is_kev().desc(),
            case(SEVERITY_ORDER, value=Finding.severity, else_=5),
            self._max_epss().desc().nullslast(),
            Finding.last_seen_at.desc(),
        )

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
            # reads, since a single advisory routinely carries several. Ranked across
            # every CVSS version so a v4-only CVE is not sorted to the bottom at 0.0.
            scored = [cves[c] for c in finding_cves if c in cves]
            headline = max(scored, key=_score, default=None)

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
                    cvss=_headline_cvss(headline),
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

        # Numerator and denominator must describe the same population, or the
        # "unassessed" count is fiction. `total` and `by_severity` above are narrowed to
        # this org and this principal's visible groups; the coverage count has to match.
        # `assess_all` also skips archived devices, so a device count that includes them
        # would report devices as unassessed that the assessor deliberately never touches.
        from netsecops.services.inventory import InventoryService

        inventory = InventoryService(self.session)

        assessed_stmt = (
            select(VulnMatch.device_id)
            .join(Device, Device.id == VulnMatch.device_id)
            .where(
                VulnMatch.org_id == self.org_id,
                Device.status != DeviceStatus.ARCHIVED.value,
            )
            .distinct()
        )
        assessed_stmt = await inventory.scoped(assessed_stmt, scope)
        assessed = {
            device_id for (device_id,) in (await self.session.execute(assessed_stmt)).all()
        }

        device_stmt = (
            select(func.count())
            .select_from(Device)
            .where(
                Device.org_id == self.org_id,
                Device.status != DeviceStatus.ARCHIVED.value,
            )
        )
        device_stmt = await inventory.scoped(device_stmt, scope)
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
