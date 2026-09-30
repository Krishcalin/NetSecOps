"""Group-scoped connectivity discovery — the "what can reach what" matrix (Slice B).

`services/segmentation.py` answers **is what the estate does what we said it would do**:
it walks declared intent, one zone pair at a time. This answers the question you ask
*before* you have written any intent down — **what does the estate actually do** — for
the devices in one group. It is the discovery half of the same engine.

Two things it shares with segmentation, because they are the whole point of doing this
path-centrically rather than by reading a rulebase:

**The verdict is the path's, told honestly on both axes.** Each cell is a real walk
across the estate, so routing confidence and policy verdict are reported as they came
back — a pair whose path could not be traced is `unknown`/`not-routed`, never quietly
folded into "reachable". A discovery matrix that painted grey as green would be inventing
connectivity nobody established.

**The graph is the whole estate; only the *zones* are the group's.** This is the trap
this module is arranged around. A group's two edge firewalls may reach each other only
through a core device that is not in the group — truncating the graph to the group would
stop the walk at that core and report a real path as unreachable. So the zones are
derived from the group's devices and the walk crosses everything. The scope note on the
result says so, because a reader has to know the paths left the group to trust the answer.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import get_logger
from netsecops.db.models.inventory import DeviceGroup, DeviceGroupMember
from netsecops.topology.graph import TopologyGraph
from netsecops.topology.path import walk

log = get_logger(__name__)

#: The connectivity matrix is N zones × N zones of full path walks. A group with many
#: interfaces would be a lot of them, and past a point the matrix is unreadable anyway,
#: so the zone list is capped and the result says it was. Chosen so the worst case
#: (`MAX_ZONES * (MAX_ZONES - 1)` walks) stays comfortably under a second at estate size.
MAX_ZONES = 16

#: Interfaces this narrow are transit links and loopbacks, not zones anyone segments —
#: a /31 point-to-point, a /32 host route. Including them would fill the matrix with
#: rows nobody asked about and crowd out the subnets that matter.
_MIN_PREFIX_FOR_ZONE = 30


@dataclass(slots=True)
class DerivedZone:
    """One address space a group's devices are attached to, and how it is labelled."""

    cidr: str
    label: str
    device_hostnames: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MatrixCell:
    """One ordered pair's observed reachability, across the whole estate."""

    source: str
    destination: str
    source_cidr: str
    destination_cidr: str
    routing: str
    policy: str
    hops: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DiscoveryMatrix:
    group_id: uuid.UUID
    group_name: str
    protocol: str
    port: int
    zones: list[DerivedZone]
    cells: list[MatrixCell]
    scope_note: str
    limitations: list[str] = field(default_factory=list)


class MatrixService:
    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id

    async def discover(
        self,
        group: DeviceGroup,
        graph: TopologyGraph,
        *,
        protocol: str = "tcp",
        port: int = 443,
    ) -> DiscoveryMatrix:
        device_ids = await self._group_device_ids(group)
        zones, ipv6_present = self._derive_zones(graph, device_ids)

        limitations: list[str] = []
        if ipv6_present:
            # The walk parses forwarding tables for IPv4 only, so IPv6 subnets are dropped
            # from the zone set. Said plainly rather than omitted, or an IPv4-only view (or
            # an empty one, for an IPv6-only group) reads as the whole answer.
            limitations.append(
                "This group's devices carry IPv6 interfaces, which the connectivity matrix "
                "does not yet trace — only their IPv4 zones are shown. The IPv6 reachability "
                "of this group is not represented here."
            )
        if len(zones) < 2:
            # Zero or one zone yields no source/destination pair, so the cell list is empty.
            # An empty grid must not read as "nothing can reach anything" or "fully
            # isolated" — it is the absence of comparable zones, which the segmentation
            # service guards and this one now does too (invariant 2).
            limitations.append(
                f"Only {len(zones)} comparable zone(s) could be derived for this group, so "
                "there is no pair of zones to evaluate. This is the absence of comparable "
                "zones, not a finding that nothing here can reach anything — widen the group, "
                "or check that its devices carry routed IPv4 interfaces."
            )
        if len(zones) > MAX_ZONES:
            limitations.append(
                f"The group's devices are attached to {len(zones)} address spaces; the "
                f"matrix shows the first {MAX_ZONES}. Narrow the group or raise the cap."
            )
            zones = zones[:MAX_ZONES]

        cells: list[MatrixCell] = []
        for source in zones:
            for destination in zones:
                if source.cidr == destination.cidr:
                    continue
                result = walk(
                    graph,
                    source=source.cidr,
                    destination=destination.cidr,
                    protocol=protocol,
                    port=port,
                )
                cells.append(
                    MatrixCell(
                        source=source.label,
                        destination=destination.label,
                        source_cidr=source.cidr,
                        destination_cidr=destination.cidr,
                        routing=result.routing.value,
                        policy=result.policy.value,
                        hops=[hop.hostname for hop in result.hops],
                        notes=list(result.notes),
                    )
                )

        return DiscoveryMatrix(
            group_id=group.id,
            group_name=group.name,
            protocol=protocol,
            port=port,
            zones=zones,
            cells=cells,
            scope_note=(
                "Zones are the address spaces of this group's devices. Paths are walked "
                "across the whole estate, so a cell may traverse devices outside the "
                "group — truncating the graph to the group would report real paths as "
                "unreachable."
            ),
            limitations=limitations,
        )

    async def _group_device_ids(self, group: DeviceGroup) -> set[uuid.UUID]:
        """Devices in the group and every group beneath it (FR-INV-03 ltree subtree)."""
        descendants = select(DeviceGroup.id).where(DeviceGroup.path.op("<@")(group.path))
        rows = await self.session.execute(
            select(DeviceGroupMember.device_id).where(
                DeviceGroupMember.org_id == self.org_id,
                DeviceGroupMember.group_id.in_(descendants),
            )
        )
        return set(rows.scalars().all())

    def _derive_zones(
        self, graph: TopologyGraph, device_ids: set[uuid.UUID]
    ) -> tuple[list[DerivedZone], bool]:
        """The connected networks the group's devices sit on, one zone per distinct CIDR.

        A firewall's zone name is used as the label where the interface has one, because
        that is what an operator recognises; otherwise the interface name, and failing
        that the CIDR itself. The CIDR is always what the walk is asked about — a name is
        for the reader, an address is for the engine.

        Returns the zones and whether any IPv6 subnet was skipped, so the caller can state
        that the matrix is IPv4-only rather than presenting it as the whole answer.
        """
        by_cidr: dict[str, DerivedZone] = {}
        ipv6_present = False
        for device_id in device_ids:
            node = graph.nodes.get(device_id)
            if node is None:
                continue
            for interface, network in node.interface_networks:
                if not isinstance(network, ipaddress.IPv4Network):
                    # A real IPv6 subnet (not a /128 host route) is a zone this walk cannot
                    # yet trace. Flagged so its absence is stated, not silent.
                    if (
                        isinstance(network, ipaddress.IPv6Network)
                        and network.prefixlen < network.max_prefixlen
                    ):
                        ipv6_present = True
                    continue
                if network.prefixlen >= _MIN_PREFIX_FOR_ZONE:
                    continue
                cidr = str(network)
                zone = by_cidr.get(cidr)
                if zone is None:
                    zone = DerivedZone(
                        cidr=cidr,
                        label=node.zones.get(interface) or interface or cidr,
                    )
                    by_cidr[cidr] = zone
                if node.hostname not in zone.device_hostnames:
                    zone.device_hostnames.append(node.hostname)
        zones = sorted(by_cidr.values(), key=lambda zone: ipaddress.ip_network(zone.cidr))
        return zones, ipv6_present


__all__ = ["MatrixService", "DiscoveryMatrix", "DerivedZone", "MatrixCell", "MAX_ZONES"]
