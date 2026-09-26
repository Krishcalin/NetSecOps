"""Segmentation policy and the matrix it is checked against (FR-TOPO-07).

The policy is *policy*, so writing it needs `POLICY_WRITE` — the same permission that
governs the check baseline, and for the same reason: it is a statement about what the
organisation intends, and changing it silently changes what every later report means.
Reading the matrix needs `POLICY_READ` plus `SNAPSHOT_READ`, because the answer is
assembled out of stored configurations and anyone reading it is reading those.

`GET /segmentation/matrix` recomputes on every call. Nothing is cached and no verdict
is stored: a saved "compliant" is a claim about an estate that has since changed, and
this is the one place where a stale pass is worse than no answer. Freezing one is what
the `path_analysis` report and the report archive are for.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status

from netsecops.api.deps import PrincipalDep, SessionDep, require, verify_csrf
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.db.models.audit import AuditAction
from netsecops.schemas.segmentation import (
    CellRead,
    MatrixRead,
    RuleCreate,
    RuleRead,
    ZoneCreate,
    ZoneRead,
)
from netsecops.services.audit import AuditService
from netsecops.services.segmentation import SegmentationService
from netsecops.services.topology import TopologyService

log = get_logger(__name__)
router = APIRouter(tags=["segmentation"])


@router.get(
    "/segmentation/zones",
    response_model=list[ZoneRead],
    dependencies=[Depends(require(Permission.POLICY_READ))],
    summary="The named address spaces the policy is written against (FR-TOPO-07)",
)
async def list_zones(session: SessionDep) -> list[ZoneRead]:
    zones = await SegmentationService(session).zones()
    return [ZoneRead.model_validate(zone) for zone in zones]


@router.post(
    "/segmentation/zones",
    response_model=ZoneRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.POLICY_WRITE)), Depends(verify_csrf)],
    summary="Declare a zone (FR-TOPO-07)",
)
async def create_zone(
    payload: ZoneCreate,
    session: SessionDep,
    principal: PrincipalDep,
) -> ZoneRead:
    """A zone is address space, not a firewall's zone name.

    `dmz` on one device and `DMZ` on another may be different things, and a router has
    no zone names at all. The addresses are what the path walk can evaluate, so they
    are what a zone is.
    """
    zone = await SegmentationService(session).create_zone(
        name=payload.name, prefixes=payload.prefixes, description=payload.description
    )

    await AuditService(session).record(
        AuditAction.SEGMENTATION_POLICY_CHANGED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="segmentation_zone",
        object_id=zone.id,
        details={"name": zone.name, "prefixes": list(zone.prefixes)},
    )
    return ZoneRead.model_validate(zone)


@router.get(
    "/segmentation/rules",
    response_model=list[RuleRead],
    dependencies=[Depends(require(Permission.POLICY_READ))],
    summary="The declared intent, one ordered zone pair at a time (FR-TOPO-07)",
)
async def list_rules(session: SessionDep) -> list[RuleRead]:
    rules = await SegmentationService(session).rules()
    return [RuleRead.model_validate(rule) for rule in rules]


@router.post(
    "/segmentation/rules",
    response_model=RuleRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.POLICY_WRITE)), Depends(verify_csrf)],
    summary="Declare what should happen between two zones (FR-TOPO-07)",
)
async def create_rule(
    payload: RuleCreate,
    session: SessionDep,
    principal: PrincipalDep,
) -> RuleRead:
    """Ordered, because "A may reach B" says nothing about the reverse.

    Most real segmentation is asymmetric — a web tier reaching a database tier is
    normal and the reverse is an incident — so a symmetric matrix would quietly assert
    the opposite of half of what was declared.
    """
    rule = await SegmentationService(session).create_rule(
        source_zone_id=payload.source_zone_id,
        destination_zone_id=payload.destination_zone_id,
        expectation=payload.expectation,
        protocol=payload.protocol,
        port=payload.port,
        justification=payload.justification,
    )

    await AuditService(session).record(
        AuditAction.SEGMENTATION_POLICY_CHANGED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="segmentation_rule",
        object_id=rule.id,
        details={
            "source_zone_id": str(rule.source_zone_id),
            "destination_zone_id": str(rule.destination_zone_id),
            "expectation": rule.expectation,
            "protocol": rule.protocol,
            "port": rule.port,
        },
    )
    return RuleRead.model_validate(rule)


@router.delete(
    "/segmentation/rules/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.POLICY_WRITE)), Depends(verify_csrf)],
    summary="Withdraw a declared expectation (FR-TOPO-07)",
)
async def delete_rule(
    rule_id: uuid.UUID,
    session: SessionDep,
    principal: PrincipalDep,
) -> None:
    await SegmentationService(session).delete_rule(rule_id)
    await AuditService(session).record(
        AuditAction.SEGMENTATION_POLICY_CHANGED,
        actor_id=principal.id,
        actor_username=principal.username,
        object_type="segmentation_rule",
        object_id=rule_id,
        details={"deleted": True},
    )


@router.get(
    "/segmentation/matrix",
    response_model=MatrixRead,
    dependencies=[
        Depends(require(Permission.POLICY_READ)),
        Depends(require(Permission.SNAPSHOT_READ)),
    ],
    summary="What the estate actually does, against what the policy says (FR-TOPO-07)",
)
async def matrix(session: SessionDep) -> MatrixRead:
    """Each cell is evaluated by walking a packet, not by searching the rulebases.

    A rule-centric check is wrong in both directions: a permissive rule on one firewall
    means nothing if a second denies the same traffic downstream, and a permit
    assembled from one rule on the edge and another on the core belongs to no single
    rule for a search to find.

    **`unverified` is never a pass.** A cell whose path could not be traced is reported
    as such and counted separately, because a matrix showing green for pairs nobody
    could test is a compliance artefact asserting isolation that was never checked.
    """
    graph = await TopologyService(session).graph()
    result = await SegmentationService(session).evaluate(graph)

    return MatrixRead(
        cells=[
            CellRead(
                rule_id=cell.rule_id,
                source_zone=cell.source_zone,
                destination_zone=cell.destination_zone,
                expectation=cell.expectation,
                protocol=cell.protocol,
                port=cell.port,
                status=cell.status.value,
                detail=cell.detail,
                justification=cell.justification,
                walked=list(cell.walked),
                limitations=list(cell.limitations),
            )
            for cell in result.cells
        ],
        upheld=result.upheld,
        violated=result.violated,
        unverified=result.unverified,
        limitations=list(result.limitations),
    )


__all__ = ["router"]
