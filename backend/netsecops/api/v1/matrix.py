"""Group-scoped connectivity discovery matrix (Slice B).

Reading it needs `SNAPSHOT_READ`, like every other path answer: the matrix is assembled
out of stored configurations, and anyone reading it is reading those. It recomputes on
every call and stores nothing — a saved "these zones are isolated" is a claim about an
estate that has since changed, and this is the one place where a stale answer is worse
than none. Freezing one is what the report archive is for.

The zones are the group's; the walk crosses the whole estate. That is stated on the
response (`scope_note`), not just here, because a cell that traversed a device outside
the group is still a true answer and a reader has to know it did.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query

from netsecops.api.deps import SessionDep, require
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.schemas.matrix import DerivedZoneRead, DiscoveryMatrixRead, MatrixCellRead
from netsecops.services.inventory import InventoryService
from netsecops.services.matrix import MatrixService
from netsecops.services.topology import TopologyService

log = get_logger(__name__)
router = APIRouter(tags=["matrix"])


@router.get(
    "/matrix/discover/{group_id}",
    response_model=DiscoveryMatrixRead,
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="What can reach what, for the zones of one device group",
)
async def discover_matrix(
    group_id: uuid.UUID,
    session: SessionDep,
    protocol: str = Query("tcp", description="Protocol to walk, e.g. tcp/udp/icmp"),
    port: int = Query(443, ge=0, le=65535, description="Destination port"),
) -> DiscoveryMatrixRead:
    """Each cell is a real walk across the estate, not a search of the rulebases.

    A permit assembled from one rule on the edge and another on the core belongs to no
    single rule for a search to find, and a permissive rule on one firewall means nothing
    if a second denies the same traffic downstream. So every cell is a packet, walked.
    """
    group = await InventoryService(session).get_group(group_id)
    graph = await TopologyService(session).graph()
    result = await MatrixService(session).discover(
        group, graph, protocol=protocol, port=port
    )

    return DiscoveryMatrixRead(
        group_id=result.group_id,
        group_name=result.group_name,
        protocol=result.protocol,
        port=result.port,
        zones=[
            DerivedZoneRead(
                cidr=zone.cidr, label=zone.label, device_hostnames=list(zone.device_hostnames)
            )
            for zone in result.zones
        ],
        cells=[
            MatrixCellRead(
                source=cell.source,
                destination=cell.destination,
                source_cidr=cell.source_cidr,
                destination_cidr=cell.destination_cidr,
                routing=cell.routing,
                policy=cell.policy,
                hops=list(cell.hops),
                notes=list(cell.notes),
            )
            for cell in result.cells
        ],
        scope_note=result.scope_note,
        limitations=list(result.limitations),
    )


__all__ = ["router"]
