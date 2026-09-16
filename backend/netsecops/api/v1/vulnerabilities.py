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

There is no scheduled or network feed sync (FR-VUL-07). Imports are offline and by hand,
which matters because a stale feed produces a confident-looking clean answer rather than
an obviously broken one.

State changes on a vulnerability finding — Risk Accepted, False Positive and the rest of
FR-VUL-09 — go through `PATCH /findings/{id}`, which already enforces the lifecycle and
writes the audit entry. Duplicating that here would give the same finding two doors with
one lock between them.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, File, Query, UploadFile

from netsecops.api.deps import PrincipalDep, SessionDep, require
from netsecops.core.errors import NotFoundError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.schemas.vulnerability import (
    CveDetailRead,
    FeedImportRead,
    FeedStatusRead,
    PaginatedVulnerabilities,
    VulnerabilitySummary,
)
from netsecops.services.feeds import FeedImportService
from netsecops.services.vuln_view import VulnViewService

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
    meta: dict[str, object] = {"total": total, "limit": limit, "offset": offset}
    if kev_only:
        # The KEV flag lives on the CVE row rather than the finding, so it is applied
        # after the page is fetched. Saying so keeps `total` from reading as a lie.
        meta["filtered_after_count"] = True
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
    dependencies=[Depends(require(Permission.VULN_WRITE))],
    summary="Import an offline NVD/CSAF/EoL bundle (FR-VUL-08)",
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
        records_rejected=result.rejected,
        errors=[result.sync.error_message] if result.sync.error_message else [],
    )


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
