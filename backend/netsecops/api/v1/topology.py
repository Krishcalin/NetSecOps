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

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from netsecops.api.deps import PrincipalDep, SessionDep, require, verify_csrf
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Permission
from netsecops.schemas.topology import (
    DeviceNeighboursRead,
    EstateMapRead,
    HopRead,
    MapGroupRead,
    MapInterfaceRead,
    MapLinkRead,
    MapNodeRead,
    MissingDeviceRead,
    NeighbourRead,
    PathRequest,
    PathResponse,
    TopologySummary,
)
from netsecops.services.inventory import InventoryService
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
                undecidable=hop.undecidable,
                translation=hop.translation,
            )
            for hop in result.hops
        ],
        stopped_at_prefix=result.stopped_at_prefix,
        stopped_at_next_hop=result.stopped_at_next_hop,
        stopped_at_device=result.stopped_at_device,
        branched_at=list(result.branched_at),
        translated_at=list(result.translated_at),
        translation_unknown_at=list(result.translation_unknown_at),
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
    "/topology/map",
    response_model=EstateMapRead,
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="The whole layer-3 graph, drawable (FR-TOPO-02)",
)
async def estate_map(
    topology: ServiceDep, limit: Annotated[int, Query(ge=1, le=5000)] = 2000
) -> EstateMapRead:
    """Every device, every adjacency, and every point at which the estate ends.

    Same permission as the path query and for the same reason: this is a projection of
    stored configuration, and anyone who may read the configuration may see how it wires
    together. Nothing is sent to a device to produce it.

    Links are the same join a path walk makes — a route's next hop matched to an
    interface address — so a strand here is one a packet can actually take. Where that
    match fails, the next hop becomes a node of its own rather than being dropped: the
    boundary of the managed estate is the most useful thing on the picture.

    `limit` drops whole groups rather than individual devices, and `omitted_groups`
    names what was left out. A partial component would be a picture of a network that
    does not exist.
    """
    result = await topology.estate_map(limit=limit)

    return EstateMapRead(
        nodes=[
            MapNodeRead(
                id=node.id,
                kind=node.kind,
                label=node.label,
                group=node.group,
                tier=node.tier,
                platform=node.platform,
                vendor=node.vendor,
                device_class=node.device_class,
                criticality=node.criticality,
                status=node.status,
                site=node.site,
                has_rulebase=node.has_rulebase,
                inspects=node.inspects,
                routes=node.routes,
                routes_known=node.routes_known,
                interfaces=[
                    MapInterfaceRead(
                        name=interface.name,
                        addresses=list(interface.addresses),
                        zone=interface.zone,
                    )
                    for interface in node.interfaces
                ],
                interface_count=node.interface_count,
                findings=dict(node.findings),
                has_snapshot=node.has_snapshot,
                referenced_by=list(node.referenced_by),
                carries_default_route=node.carries_default_route,
            )
            for node in result.nodes
        ],
        links=[
            MapLinkRead(
                id=link.id,
                source=link.source,
                target=link.target,
                via=list(link.via),
                prefixes=link.prefixes,
                carries_default=link.carries_default,
                bidirectional=link.bidirectional,
                source_interface=link.source_interface,
                target_interface=link.target_interface,
                crosses_firewall=link.crosses_firewall,
            )
            for link in result.links
        ],
        groups=[
            MapGroupRead(
                id=group.id,
                label=group.label,
                label_source=group.label_source,
                devices=group.devices,
                firewalls=group.firewalls,
                unmanaged=group.unmanaged,
                links=group.links,
                tiers=group.tiers,
            )
            for group in result.groups
        ],
        devices=result.devices,
        unmanaged=result.unmanaged,
        devices_without_route_data=result.devices_without_route_data,
        isolated=result.isolated,
        omitted_groups=list(result.omitted_groups),
        omitted_devices=result.omitted_devices,
    )


@router.get(
    "/devices/{device_id}/neighbours",
    response_model=DeviceNeighboursRead,
    dependencies=[Depends(require(Permission.SNAPSHOT_READ))],
    summary="What this device can see on the wire, from CDP and LLDP (FR-TOPO-01)",
)
async def device_neighbours(
    device_id: uuid.UUID, session: SessionDep, principal: PrincipalDep
) -> DeviceNeighboursRead:
    """Stated physical adjacency, as opposed to the inferred kind everything else here
    reports.

    A route's next hop matched to an interface address concludes that two devices are
    connected. A neighbour entry is one of them saying so. They disagree more often than
    is comfortable — a layer-2 path crossing an unmanaged switch produces a routing
    adjacency with no cable behind it — and the disagreement is usually the finding.

    Both protocols appear in one list and are **not** merged. CDP and LLDP frequently
    report the same link differently, or only one of them reports it at all, and
    collapsing them would lose which one saw what.

    An empty list is not an answer on its own: read it with `cdp_enabled`,
    `lldp_enabled` and `snapshot_id`, which separate "the protocol is off" from "the
    protocol is on and nothing answered" from "nothing has been collected".
    """
    device = await InventoryService(session).get_device(device_id, scope=principal.scope)
    view = await TopologyService(session).neighbours_for(device)

    return DeviceNeighboursRead(
        device_id=device.id,
        snapshot_id=view.snapshot_id,
        cdp_enabled=view.cdp_enabled,
        lldp_enabled=view.lldp_enabled,
        neighbours=[
            NeighbourRead(
                protocol=entry.neighbour.protocol,
                local_interface=entry.neighbour.local_interface,
                remote_device=entry.neighbour.remote_device,
                remote_interface=entry.neighbour.remote_interface,
                remote_address=entry.neighbour.remote_address,
                platform=entry.neighbour.platform,
                capabilities=list(entry.neighbour.capabilities),
                device_id=entry.device_id,
                matched_by=entry.matched_by,
            )
            for entry in view.neighbours
        ],
        matched=view.matched,
        unmanaged=view.unmanaged,
    )


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
