"""Discovery endpoints (SRS §4.2, FR-DISC-01, FR-DISC-04).

Phase 7 built the scope model, the probe allow-list, the fingerprinter and the review
queue, and registered no router, so none of it could be reached. This is that surface.

Runs can now be started, which they could not before. The reason they could not was never
this module: it was that an endpoint accepting "go" would have probed as fast as the event
loop allowed, and that is the port sweep SRS §1.2 forbids. What changed is FR-DISC-05 —
`discovery/pacing.py` meters host starts and `discovery/transport.py` holds the meter, so
there is no route from this handler to a socket that is not paced. The button is safe
because of what is underneath it, not because of what it validates.

Scheduling, the other half of FR-DISC-05, is still unbuilt: a run is started by a person.
The `schedules` table exists and has no service behind it, and that gap is shared with
FR-JOB-02 and FR-RPT-04 rather than being discovery's alone.

Creating a scope validates through `build_scope`, which subtracts exclusions from the
address space before counting and refuses a scope that resolves to more addresses than
the ceiling allows. The refusal names the likely cause, because an operator who reads
only "over the limit" raises the limit.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select

from netsecops.api.deps import PrincipalDep, SessionDep, require, verify_csrf
from netsecops.core.errors import NotFoundError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.db.models.discovery import DiscoveryRun, DiscoveryScope
from netsecops.db.models.inventory import DeviceClass
from netsecops.discovery.scopes import build_scope
from netsecops.schemas.discovery import (
    DiscoveredHostRead,
    DiscoveryRunRead,
    DiscoveryRunRequest,
    DiscoveryRunStart,
    DiscoveryScopeCreate,
    DiscoveryScopeRead,
    HostApproval,
    HostRejection,
    PaginatedHosts,
)
from netsecops.schemas.inventory import DeviceRead
from netsecops.services.discovery_review import DiscoveryReviewService

log = get_logger(__name__)
router = APIRouter(tags=["discovery"])


def review_service(session: SessionDep) -> DiscoveryReviewService:
    return DiscoveryReviewService(session)


ReviewDep = Annotated[DiscoveryReviewService, Depends(review_service)]


def _scope_read(row: DiscoveryScope) -> DiscoveryScopeRead:
    """Attach the resolved address count to a stored scope.

    Recomputed on every read rather than stored, because the subtraction of exclusions
    is the security-relevant step and the number an operator sanity-checks before
    running anything. Recomputing costs nothing next to the probing it gates.
    """
    read = DiscoveryScopeRead.model_validate(row)
    try:
        resolved = build_scope(
            row.name,
            row.targets,
            exclusions=row.exclusions,
            tcp_ports=row.tcp_ports or None,
            snmp_configured=row.snmp_configured,
            auto_onboard=row.auto_onboard,
        )
        read.address_count = resolved.size
    except Exception:
        # Ceilings and parsing rules can tighten between releases. A scope stored under
        # the old rules must still be readable, or it cannot be found and corrected.
        read.address_count = None
    return read


# ── scopes ───────────────────────────────────────────────────────────────────


@router.get(
    "/discovery/scopes",
    response_model=list[DiscoveryScopeRead],
    dependencies=[Depends(require(Permission.DISCOVERY_READ))],
    summary="Discovery scopes (FR-DISC-01)",
)
async def list_scopes(session: SessionDep) -> list[DiscoveryScopeRead]:
    rows = (
        (await session.execute(select(DiscoveryScope).order_by(DiscoveryScope.name)))
        .scalars()
        .all()
    )
    return [_scope_read(row) for row in rows]


@router.post(
    "/discovery/scopes",
    response_model=DiscoveryScopeRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.DISCOVERY_WRITE))],
    summary="Define what may be probed (FR-DISC-01)",
)
async def create_scope(
    payload: DiscoveryScopeCreate, session: SessionDep, principal: PrincipalDep
) -> DiscoveryScopeRead:
    """Validate and store a scope.

    `build_scope` is the validation, and it runs before anything is written: it parses
    every target, subtracts the exclusions, and counts the remainder without enumerating
    it. A mistyped prefix — `10.0.0.0/8` where `10.0.0.0/18` was meant — is refused here
    with the reason, rather than becoming sixteen million probes later.
    """
    resolved = build_scope(
        payload.name,
        payload.targets,
        exclusions=payload.exclusions,
        tcp_ports=payload.tcp_ports or None,
        snmp_configured=payload.snmp_configured,
        auto_onboard=payload.auto_onboard,
    )

    row = DiscoveryScope(
        org_id=1,
        name=payload.name,
        description=payload.description,
        targets=list(payload.targets),
        exclusions=list(payload.exclusions),
        tcp_ports=list(resolved.tcp_ports),
        rate_limit_per_second=payload.rate_limit_per_second,
        snmp_configured=payload.snmp_configured,
        auto_onboard=payload.auto_onboard,
        enabled=payload.enabled,
    )
    session.add(row)
    await session.flush()

    log.info(
        "discovery.scope_created",
        scope=row.name,
        addresses=resolved.size,
        auto_onboard=row.auto_onboard,
        actor=principal.username,
    )
    return _scope_read(row)


@router.delete(
    "/discovery/scopes/{scope_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.DISCOVERY_WRITE))],
    summary="Remove a discovery scope",
)
async def delete_scope(scope_id: uuid.UUID, session: SessionDep) -> None:
    row = (
        await session.execute(select(DiscoveryScope).where(DiscoveryScope.id == scope_id))
    ).scalar_one_or_none()
    if row is None:
        raise NotFoundError(f"No discovery scope {scope_id}.")
    await session.delete(row)
    await session.flush()


# ── runs ─────────────────────────────────────────────────────────────────────


@router.post(
    "/discovery/scopes/{scope_id}/runs",
    response_model=DiscoveryRunStart,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(require(Permission.DISCOVERY_WRITE)), Depends(verify_csrf)],
    summary="Probe every address in a scope (FR-DISC-05)",
)
async def start_run(
    scope_id: uuid.UUID,
    session: SessionDep,
    principal: PrincipalDep,
    payload: DiscoveryRunRequest | None = None,
) -> DiscoveryRunStart:
    """Queue a run of this scope.

    202 rather than 201, and a job id rather than a run: probing even a small scope
    outlives an HTTP request, so the work is handed to the queue and the caller polls.
    The ``discovery_runs`` row does not exist yet when this returns — the executor writes
    it as its first act — which is why what comes back is the job to watch.

    **This is the endpoint that was deliberately missing.** It could not be written
    before FR-DISC-05, because an endpoint that accepted "go" and probed as fast as the
    event loop allowed would be the port sweep SRS §1.2 forbids. What makes it writable
    now is not this handler but :class:`~netsecops.discovery.pacing.HostPacer` and the
    fact that :class:`~netsecops.discovery.transport.HostProber` holds one: there is no
    path from here to a socket that is not paced, so "go" cannot mean "as fast as
    possible" even if a future caller wants it to.

    The scope is re-validated on the way through. It was checked when it was created, but
    the ceiling and the parsing rules can tighten between releases, and a scope stored
    under the old rules must be refused *before* it is probed rather than after.
    """
    from netsecops.services.jobs import JobService
    from netsecops.workers.queue import get_queue

    scope_row = (
        await session.execute(select(DiscoveryScope).where(DiscoveryScope.id == scope_id))
    ).scalar_one_or_none()
    if scope_row is None:
        raise NotFoundError(f"No discovery scope {scope_id}.")

    if not scope_row.enabled:
        raise ValidationProblem(
            f"Discovery scope '{scope_row.name}' is disabled. Enable it before running "
            "it, so that the decision to send packets to these addresses is explicit."
        )

    # Raises with the reason if the stored scope no longer resolves — a mistyped prefix
    # must be refused here, not discovered 16 million probes into a run.
    resolved = build_scope(
        scope_row.name,
        scope_row.targets,
        exclusions=scope_row.exclusions,
        tcp_ports=scope_row.tcp_ports or None,
        snmp_configured=scope_row.snmp_configured,
        auto_onboard=scope_row.auto_onboard,
    )

    jobs = JobService(session)
    job = await jobs.create_discovery(
        discovery_scope_id=scope_row.id,
        actor=principal,
        idempotency_key=(payload.idempotency_key if payload else None),
    )

    # Committed before the worker can see it: enqueueing an id the worker could read
    # before the row is visible is the classic queue race.
    await session.commit()
    await get_queue().enqueue_job(job.id, correlation_id=job.correlation_id)

    log.info(
        "discovery.run_queued",
        scope=scope_row.name,
        job_id=str(job.id),
        addresses=resolved.size,
        rate_per_second=scope_row.rate_limit_per_second,
        actor=principal.username,
    )

    return DiscoveryRunStart(
        job_id=job.id,
        scope_id=scope_row.id,
        address_count=resolved.size,
        rate_limit_per_second=scope_row.rate_limit_per_second,
    )


@router.get(
    "/discovery/runs",
    response_model=list[DiscoveryRunRead],
    dependencies=[Depends(require(Permission.DISCOVERY_READ))],
    summary="Discovery run history",
)
async def list_runs(
    session: SessionDep,
    scope_id: uuid.UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[DiscoveryRunRead]:
    """Runs that have happened, newest first.

    A run carries ``notes`` as well as counters, and they are worth reading together:
    "0 hosts found" means one thing on its own and another beside "no echo request could
    be sent". The counters alone would make an undetectable estate look like a quiet one.
    """
    stmt = select(DiscoveryRun).order_by(DiscoveryRun.started_at.desc()).limit(limit)
    if scope_id is not None:
        stmt = stmt.where(DiscoveryRun.scope_id == scope_id)
    rows = (await session.execute(stmt)).scalars().all()
    return [DiscoveryRunRead.model_validate(row) for row in rows]


# ── the review queue ─────────────────────────────────────────────────────────


@router.get(
    "/discovery/pending",
    response_model=PaginatedHosts,
    dependencies=[Depends(require(Permission.DISCOVERY_READ))],
    summary="Hosts awaiting review, least understood first (FR-DISC-04)",
)
async def list_pending(
    reviews: ReviewDep, limit: Annotated[int, Query(ge=1, le=500)] = 200
) -> PaginatedHosts:
    """The queue, sorted by ascending confidence.

    Deliberately not by confidence descending: the entries that most need a human are
    the ones the fingerprinter was least sure about, and sorting the other way puts the
    easy ones on page one and the genuinely unknown devices where nobody looks.
    """
    rows = await reviews.pending(limit=limit)
    return PaginatedHosts(
        data=[DiscoveredHostRead.model_validate(row) for row in rows],
        meta={"count": len(rows), "limit": limit},
    )


@router.get(
    "/discovery/pending/{host_id}",
    response_model=DiscoveredHostRead,
    dependencies=[Depends(require(Permission.DISCOVERY_READ))],
    summary="One discovered host and the evidence behind its fingerprint",
)
async def get_host(host_id: uuid.UUID, reviews: ReviewDep) -> DiscoveredHostRead:
    return DiscoveredHostRead.model_validate(await reviews.get(host_id))


@router.post(
    "/discovery/pending/{host_id}/approve",
    response_model=DeviceRead,
    dependencies=[Depends(require(Permission.DISCOVERY_WRITE))],
    summary="Onboard a discovered host as a device (FR-DISC-04)",
)
async def approve_host(
    host_id: uuid.UUID,
    payload: HostApproval,
    reviews: ReviewDep,
    principal: PrincipalDep,
) -> DeviceRead:
    """Create the device. The only path by which a discovered host becomes one.

    The fingerprinter's vendor and platform are offered rather than imposed — a wrong
    platform selects the wrong collection profile and with it the wrong command
    allow-list, which is the one mistake here with a blast radius beyond the inventory.
    """
    host = await reviews.get(host_id)
    device = await reviews.approve(
        host,
        actor=principal,
        vendor=payload.vendor,
        platform=payload.platform,
        hostname=payload.hostname,
        device_class=DeviceClass(payload.device_class),
        note=payload.note,
    )
    return DeviceRead.model_validate(device)


@router.post(
    "/discovery/pending/{host_id}/reject",
    response_model=DiscoveredHostRead,
    dependencies=[Depends(require(Permission.DISCOVERY_WRITE))],
    summary="Mark a discovered host as deliberately not ours (FR-DISC-04)",
)
async def reject_host(
    host_id: uuid.UUID,
    payload: HostRejection,
    reviews: ReviewDep,
    principal: PrincipalDep,
) -> DiscoveredHostRead:
    host = await reviews.get(host_id)
    rejected = await reviews.reject(host, actor=principal, note=payload.note)
    return DiscoveredHostRead.model_validate(rejected)
