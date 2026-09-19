"""Vulnerability endpoints (SRS §4.2, FR-VUL-04, FR-VUL-07, FR-VUL-08).

Phase 6 built the matcher, the feed importer and the assessment service, and shipped
none of them to a user: there was no route, no worker branch and no CLI command, so the
one capability AlgoSec has no equivalent for — CVE exposure derived from a parsed
configuration rather than from a credentialed scanner — was unreachable. This is that
surface.

Read paths are scoped through the device, so a principal restricted to a device group
sees that group's exposure and the totals agree with the rows. There is exactly one
write: an offline bundle import for air-gapped deployments (FR-VUL-08, constraint C-7).
It does not touch a device; the whole subsystem is a read of data we already hold.

Network sync arrived later (FR-VUL-07) and is deliberately the *second* path: the offline
importer is the one air-gapped deployments depend on, so it stays primary and the online
route reuses its ingest wholesale rather than growing one of its own. `POST
/vulnerabilities/feeds/sync` queues a job; `feeds_offline_mode` makes it refuse.

Staleness is the risk either way, because a stale feed produces a confident-looking clean
answer rather than an obviously broken one — which is why the feed list reports each
source's own data date beside the import time, and why a sync that could not cover the
whole gap it was asked for comes back partial rather than succeeded.

State changes on a vulnerability finding — Risk Accepted, False Positive and the rest of
FR-VUL-09 — go through `PATCH /findings/{id}`, which already enforces the lifecycle and
writes the audit entry. Duplicating that here would give the same finding two doors with
one lock between them.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Query, UploadFile

from netsecops.api.deps import PrincipalDep, SessionDep, require, verify_csrf
from netsecops.core.errors import NotFoundError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.schemas.jobs import JobRead
from netsecops.schemas.vulnerability import (
    CveDetailRead,
    FeedImportRead,
    FeedStatusRead,
    PaginatedVulnerabilities,
    VulnerabilitySummary,
)
from netsecops.services.cpe_coverage import CpeCoverageService, as_dict
from netsecops.services.feeds import FeedImportService
from netsecops.services.jobs import JobService
from netsecops.services.upgrade_path import UpgradePathService
from netsecops.services.vuln_view import VulnViewService
from netsecops.vuln.fetch import DEFAULT_SOURCES

log = get_logger(__name__)
router = APIRouter(tags=["vulnerabilities"])

#: An offline bundle is an operator-supplied file. A cap here is not about disk: an
#: unbounded upload is parsed in memory before its digest can be checked.
MAX_BUNDLE_BYTES = 256 * 1024 * 1024


def vuln_view(session: SessionDep) -> VulnViewService:
    return VulnViewService(session)


def feed_service(session: SessionDep) -> FeedImportService:
    return FeedImportService(session)


ViewDep = Annotated[VulnViewService, Depends(vuln_view)]
FeedDep = Annotated[FeedImportService, Depends(feed_service)]


@router.get(
    "/vulnerabilities",
    response_model=PaginatedVulnerabilities,
    dependencies=[Depends(require(Permission.VULN_READ))],
    summary="Vulnerability findings across the estate (FR-VUL-04)",
)
async def list_vulnerabilities(
    views: ViewDep,
    principal: PrincipalDep,
    device_id: uuid.UUID | None = None,
    severity: str | None = None,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    confidence: str | None = None,
    cve_id: Annotated[str | None, Query(alias="cve")] = None,
    kev_only: bool = False,
    active_only: bool = True,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedVulnerabilities:
    rows, total = await views.list_vulnerabilities(
        scope=principal.scope,
        device_id=device_id,
        severity=severity,
        status=status_filter,
        confidence=confidence,
        cve_id=cve_id,
        kev_only=kev_only,
        active_only=active_only,
        limit=limit,
        offset=offset,
    )
    # `total` is exact, including under `kev_only`: the catalogue membership is applied
    # in the query rather than to the fetched page, so the pager cannot promise rows
    # that do not exist. It used to be applied afterwards and said so here.
    meta: dict[str, object] = {"total": total, "limit": limit, "offset": offset}
    return PaginatedVulnerabilities(data=rows, meta=meta)


@router.get(
    "/vulnerabilities/summary",
    response_model=VulnerabilitySummary,
    dependencies=[Depends(require(Permission.VULN_READ))],
    summary="Estate vulnerability counts, including what was never assessed",
)
async def vulnerability_summary(views: ViewDep, principal: PrincipalDep) -> VulnerabilitySummary:
    return await views.summary(scope=principal.scope)


@router.get(
    "/vulnerabilities/feeds",
    response_model=list[FeedStatusRead],
    dependencies=[Depends(require(Permission.VULN_READ))],
    summary="Feed synchronisation status and last-sync counts (FR-VUL-07)",
)
async def list_feeds(
    feeds: FeedDep, limit: Annotated[int, Query(ge=1, le=200)] = 50
) -> list[FeedStatusRead]:
    """Every sync attempt, newest first — including the ones that failed.

    A feed page that showed only successes would answer "when did this last work" with
    silence on the day it stopped working, which is the day the answer matters.
    """
    history = await feeds.history(limit=limit)
    return [FeedStatusRead.model_validate(row) for row in history]


@router.post(
    "/vulnerabilities/feeds/import",
    response_model=FeedImportRead,
    dependencies=[Depends(require(Permission.VULN_WRITE)), Depends(verify_csrf)],
    summary="Import an offline NVD/CSAF/EoL/KEV/EPSS bundle (FR-VUL-08)",
)
async def import_feed_bundle(
    feeds: FeedDep,
    principal: PrincipalDep,
    file: Annotated[UploadFile, File()],
    feed: Annotated[str, Query(min_length=1, max_length=64)] = "manual",
    expected_sha256: Annotated[str | None, Query(min_length=64, max_length=64)] = None,
    vendor: Annotated[str | None, Query(max_length=64)] = None,
    product: Annotated[str | None, Query(max_length=128)] = None,
) -> FeedImportRead:
    """Load a feed bundle from a file, for deployments with no route to the internet.

    The digest is verified before anything is written, and a mismatch imports nothing at
    all rather than a partial catalogue — a half-loaded advisory set produces devices
    that report zero vulnerabilities for a reason nobody can see.

    ``vendor`` and ``product`` are required for an end-of-life bundle and ignored for
    the others: an endoflife.date export carries release cycles and nothing that says
    whose they are, and filing Cisco's lifecycle dates under Fortinet would mark a
    supported estate as dead. The service refuses rather than guesses.
    """
    payload = await file.read()
    if not payload:
        raise ValidationProblem("The uploaded bundle is empty.")
    if len(payload) > MAX_BUNDLE_BYTES:
        raise ValidationProblem(
            f"The bundle is {len(payload)} bytes, over the {MAX_BUNDLE_BYTES}-byte limit."
        )

    result = await feeds.import_bundle(
        payload,
        feed=feed,
        actor=principal,
        expected_sha256=expected_sha256,
        vendor=vendor,
        product=product,
    )

    return FeedImportRead(
        feed=feed,
        kind=result.kind.value if result.kind else "unknown",
        status=result.status.value,
        digest=result.sync.bundle_sha256 or "",
        advisories_ingested=result.advisories,
        cves_ingested=result.cves,
        eol_records_ingested=result.eol_records,
        kev_entries_ingested=result.kev_entries,
        epss_scores_ingested=result.epss_scores,
        kev_cleared=result.kev_cleared,
        records_rejected=result.rejected,
        source_version=result.source_version,
        errors=[result.sync.error_message] if result.sync.error_message else [],
    )


@router.post(
    "/vulnerabilities/feeds/sync",
    response_model=JobRead,
    status_code=202,
    dependencies=[Depends(require(Permission.VULN_WRITE)), Depends(verify_csrf)],
    summary="Queue a feed sync from the publishers (FR-VUL-07)",
)
async def sync_feeds(
    session: SessionDep,
    principal: PrincipalDep,
    sources: Annotated[list[str] | None, Query()] = None,
) -> JobRead:
    """Fetch the configured feeds now, rather than waiting for the schedule.

    Returns a queued job rather than doing the work in the request. NVD's incremental
    window can run to tens of thousands of records and three publishers are contacted in
    sequence; holding an HTTP connection open for that would time out at whatever proxy
    sits in front, and the operator would have no way to tell a slow sync from a stuck
    one. As a job it has a status, a cancel, an audit record and a history.

    With no ``sources`` every configured feed is synced. Naming them is for the estate
    that mirrors one and fetches the rest.

    This is refused in offline mode (C-7) — by the fetcher rather than here, so that the
    refusal is recorded against the run and an operator can see that it was attempted.
    """
    known = sorted(DEFAULT_SOURCES)
    chosen = list(sources or known)
    unknown = [s for s in chosen if s not in DEFAULT_SOURCES]
    if unknown:
        raise ValidationProblem(
            f"Unknown feed source(s): {', '.join(unknown)}. Known sources: {', '.join(known)}."
        )

    job = await JobService(session).create_feed_sync(sources=chosen, actor=principal)
    return JobRead.model_validate(job)


@router.get(
    "/vulnerabilities/devices/{device_id}/upgrade-path",
    dependencies=[Depends(require(Permission.VULN_READ))],
    summary="What each candidate release would eliminate (FR-VUL-10)",
)
async def upgrade_path(device_id: uuid.UUID, session: SessionDep) -> dict[str, Any]:
    """Rank the releases this device could move to by what each one closes.

    Candidates come only from versions the device's own advisories name as fixed —
    nothing is synthesised, because recommending a release that may not exist costs an
    engineer a maintenance window they do not get back.

    Each CVE is reported as eliminated, remaining or **undetermined**, and the third is
    never folded into the others. Cisco IOS trains are why: `15.2(7)E3` and `15.2(4)M5`
    are parallel with independent fix schedules, and neither is later than the other.
    """
    report = await UpgradePathService(session).for_device(device_id)
    if report is None:
        raise NotFoundError(f"No device with id {device_id}.")
    return report.as_dict()


@router.get(
    "/vulnerabilities/cpe-coverage",
    dependencies=[Depends(require(Permission.VULN_READ))],
    summary="Whether the CPE product names are backed by imported advisories (FR-VUL-02)",
)
async def cpe_coverage(session: SessionDep) -> dict[str, Any]:
    """Check the platform-to-CPE table against the CPEs real advisories use.

    A wrong product name is the most dangerous defect the matcher can have, because it
    fails **silently**: it produces no error and no unparsed record, just a device that
    matches nothing — which is indistinguishable from a device with no vulnerabilities.

    Three outcomes, and the third is why this is worth reading carefully. *Corroborated*
    means an imported advisory uses this exact vendor and product. *Contradicted* means
    advisories for that vendor exist and none of them does — the name is probably wrong.
    *No evidence* means no advisory for that vendor has been imported at all, which says
    nothing either way and must not be chased as a fault.
    """
    return as_dict(await CpeCoverageService(session).build())


@router.get(
    "/vulnerabilities/{cve_id}",
    response_model=CveDetailRead,
    dependencies=[Depends(require(Permission.VULN_READ))],
    summary="One CVE, and every device it reaches (FR-VUL-04)",
)
async def get_cve(cve_id: str, views: ViewDep, principal: PrincipalDep) -> CveDetailRead:
    """Affected devices, and separately the ones whose verdict could not be reached.

    A device the matcher could not evaluate — no version collected, an unreadable
    version range, two incomparable release trains — is neither affected nor clear.
    Listing it with the clear ones would be the single most dangerous rounding error
    this endpoint could make, so it has its own list.
    """
    detail = await views.cve_detail(cve_id.upper(), scope=principal.scope)
    if detail is None:
        raise NotFoundError(f"No feed or match references {cve_id}.")
    return detail
