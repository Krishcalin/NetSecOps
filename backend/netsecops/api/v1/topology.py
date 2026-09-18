"""Topology and path-analysis endpoints (SRS §4.2, FR-TOPO-03 … FR-TOPO-06).

Every route here is a read of stored snapshots. Nothing contacts a device, nothing
resolves a name, and no credential is touched — the service holds no vault, which is a
structural guarantee rather than a convention.

**The path query is a POST that changes nothing**, which is worth stating because it
looks like an exception. It takes a body because a packet is four correlated fields and a
query string of them is harder to read in an audit log than a JSON object; it is idempotent
and safe to retry. It sits behind `SNAPSHOT_READ` for the same reason the FR-FW-06 rule
query does: it is offline simulation over a stored rulebase, and anyone who may read the
rules may ask what they would do.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from netsecops.api.deps import SessionDep, require, verify_csrf
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.schemas.topology import (
    HopRead,
    MissingDeviceRead,
    PathRequest,
    PathResponse,
    TopologySummary,
)
from netsecops.services.topology import TopologyService

log = get_logger(__name__)
router = APIRouter(tags=["topology"])


def topology_service(session: SessionDep) -> TopologyService:
    return TopologyService(session)


ServiceDep = Annotated[TopologyService, Depends(topology_service)]


@router.post(
    "/topology/path",
    response_model=PathResponse,
    # A path query changes nothing, and still carries the CSRF check. The rule is easier
    # to keep absolute than with a "this POST is read-only" carve-out — which is exactly
    # the kind of exception that made discovery's four state-changing routes drift out of
    # coverage unnoticed. The SPA sends the header on every request, so it costs nothing.
    dependencies=[Depends(require(Permission.SNAPSHOT_READ)), Depends(verify_csrf)],
    summary="Can this host reach that one, and what decides (FR-TOPO-03)",
)
async def query_path(request: PathRequest, topology: ServiceDep) -> PathResponse:
    """Trace a packet across the estate, evaluating each firewall it crosses.

    The answer has two axes and they must be read together. `policy: allowed` appears
    only alongside `routing: routed`; anywhere the path could not be followed to the end,
    a permit reports as `partially-allowed` instead — because it speaks only for the
    devices that were actually consulted, and an untraced remainder may hold another
    firewall.

    `notes` is not decoration. It carries why the trace stopped, which devices could not
    contribute, and what App-ID or User-ID narrowing the simulation does not model.
    """
    result = await topology.path(
        source=request.source,
        destination=request.destination,
        protocol=request.protocol,
        port=request.port,
    )

    return PathResponse(
        source=result.source,
        destination=result.destination,
        protocol=result.protocol,
        port=result.port,
        routing=result.routing.value,
        policy=result.policy.value,
        hops=[
            HopRead(
                device_id=hop.device_id,
                hostname=hop.hostname,
                platform=hop.platform,
                matched_route=hop.matched_route,
                next_hop=hop.next_hop,
                egress_interface=hop.egress_interface,
                ingress_zone=hop.ingress_zone,
                egress_zone=hop.egress_zone,
                action=hop.action,
                rule_name=hop.rule_name,
                rule_order=hop.rule_order,
                limitations=list(hop.limitations),
            )
            for hop in result.hops
        ],
        stopped_at_prefix=result.stopped_at_prefix,
        stopped_at_next_hop=result.stopped_at_next_hop,
        stopped_at_device=result.stopped_at_device,
        notes=list(result.notes),
    )


@router.get(
    "/topology/missing-devices",
    response_model=list[MissingDeviceRead],
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="Unmanaged next hops, ranked by how much they obscure (FR-TOPO-06)",
)
async def list_missing_devices(
    topology: ServiceDep, limit: Annotated[int, Query(ge=1, le=500)] = 50
) -> list[MissingDeviceRead]:
    """Where onboarding one more device would buy the most reachability.

    Computed from the routes themselves rather than by running every path: the tables are
    better evidence than whichever queries somebody happened to ask, and the obvious
    construction is quadratic in the estate.

    These addresses are evidence, not a work queue. An unmanaged next hop may be an ISP's
    router, a customer handoff, or an HSRP virtual address that no single box owns — so
    the report says what was found and why it ranks where it does, and stops there.
    """
    found = await topology.missing(limit=limit)

    return [
        MissingDeviceRead(
            address=item.address,
            referenced_by=item.referenced_by,
            prefixes=item.prefixes,
            carries_default_route=item.carries_default_route,
            score=item.score,
            adjacent_to=item.adjacent_to,
            reason=item.reason,
        )
        for item in found
    ]


@router.get(
    "/topology/summary",
    response_model=TopologySummary,
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="What the graph is made of",
)
async def summary(topology: ServiceDep) -> TopologySummary:
    """Coverage, so a path answer can be read against what the graph actually knows.

    `devices_without_route_data` is the number that matters most: those devices are in
    the inventory, contribute no routes, and are the reason a path may stop somewhere
    that looks arbitrary.
    """
    stats = await topology.summary()
    return TopologySummary(
        devices=stats.devices,
        devices_with_routes=stats.devices_with_routes,
        devices_without_route_data=stats.devices_without_route_data,
        devices_with_rulebase=stats.devices_with_rulebase,
        routes=stats.routes,
        unmanaged_next_hops=stats.unmanaged_next_hops,
    )
