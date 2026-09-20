"""The layer-3 graph (FR-TOPO-02).

Assembled from the forwarding tables FR-TOPO-01 put in the NCM, and from nothing else —
no probing, no traceroute, no CDP/LLDP walk, no agents. Every edge in here was read out
of a configuration that was already collected.

**The join between two devices is an interface address, not a guess.** A route's next hop
is an address; if that address is configured on an interface of some other device in the
inventory, the two are adjacent and the packet continues. If it is not, the path has
reached the edge of what NetSecOps manages — and that is a *result*, not a failure. It is
the single most useful thing this graph produces, because it names exactly which device
somebody would have to onboard to learn more (FR-TOPO-05, FR-TOPO-06).

Matching on subnet instead would be the tempting shortcut and would be wrong: two devices
on the same transit /30 both "contain" the next hop, and picking either one invents an
adjacency that may not exist. An exact address match is unambiguous.

**VRFs are separate forwarding domains.** A lookup in one VRF never sees another's
routes. Merging them would let a path cross between two networks a router exists to keep
apart, which is the one error a reachability answer must never make — so the VRF is part
of the lookup key rather than a label on the result.

**What the graph does not know, it says.** A device whose snapshot predates NCM 1.1 has no
routes because nothing ever parsed them, not because it has none; a device whose table was
truncated has a table that stops early. Both are recorded on the node, and both turn a
lookup that finds nothing into *unknown* rather than *unreachable*.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.ncm.models import Route

log = get_logger(__name__)

#: NCM versions that carry `routing.routes`. A snapshot older than this has an empty
#: route list because no parser ever filled one — which must read as "not known" rather
#: than "no routes", or every device collected before FR-TOPO-01 looks like a dead end.
ROUTES_SINCE = (1, 1)


def _version_tuple(version: str | None) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in (version or "0").split("."))
    except ValueError:
        return (0,)


@dataclass(frozen=True, slots=True)
class Adjacency:
    """One hop: a route, and the device its next hop belongs to."""

    route: Route
    #: None when the next hop is not an interface of any inventoried device — the path
    #: leaves the managed estate here.
    next_device_id: uuid.UUID | None


@dataclass(slots=True)
class DeviceNode:
    """One device's contribution to the graph."""

    device_id: uuid.UUID
    hostname: str
    platform: str | None = None
    vendor: str | None = None
    snapshot_id: uuid.UUID | None = None
    ncm_version: str | None = None

    routes: list[Route] = field(default_factory=list)
    #: Interface name → zone, for the zone-aware half of the rule query. Firewalls match
    #: on zones and a query that omits them can match a rule the device would not.
    zones: dict[str, str] = field(default_factory=dict)
    #: Every address configured on an interface, as an int. This is the join key.
    interface_addresses: set[int] = field(default_factory=set)
    #: Interface name → the networks it is attached to, for deriving an ingress zone.
    interface_networks: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = field(
        default_factory=list
    )

    routes_truncated: bool = False
    has_rulebase: bool = False
    #: The raw `firewall` section, handed to the rule query at walk time. Kept rather
    #: than resolved up front because most devices in a path are not firewalls and
    #: resolving every rulebase in the estate to answer one query is wasted work.
    firewall: dict[str, Any] = field(default_factory=dict)

    @property
    def routes_known(self) -> bool:
        """Whether this device's table was ever read.

        False for a snapshot predating route parsing. The distinction matters at every
        lookup: an unknown table cannot produce *unreachable*.
        """
        return _version_tuple(self.ncm_version) >= ROUTES_SINCE

    def zone_for(self, interface: str | None) -> str | None:
        return self.zones.get(interface) if interface else None

    def zone_containing(self, address: int) -> str | None:
        """The zone of the interface whose subnet holds this address.

        Used for the ingress zone: a packet arriving from somewhere reaches this device
        through whichever interface faces it, and that interface's zone is what the
        rulebase is written against.
        """
        best: tuple[int, str] | None = None
        for name, network in self.interface_networks:
            if _in_network(address, network):
                zone = self.zones.get(name)
                if zone and (best is None or network.prefixlen > best[0]):
                    best = (network.prefixlen, zone)
        return best[1] if best else None

    def interface_containing(self, address: int) -> str | None:
        """The interface whose subnet holds this address.

        `zone_containing` answers the same question for a platform that has zones, and
        returns None on one that does not — IOS and NX-OS have no zones at all. Choosing
        which access list governs a hop needs the interface name itself there, because
        that is what `ip access-group` is written under.

        Longest prefix wins, as in `zone_containing`: an address inside a /30 transit
        link and inside a summarised /16 arrived over the /30.

        Host entries are skipped. An interface with a /32 has no attached subnet, so
        nothing ever arrives *over* it — and the graph indexes each device's management
        address as a synthetic `management` /32 so that peers routing to it are joined
        correctly. Left in, that entry wins every longest-prefix comparison on exactly
        the hop where a neighbour routes to this device's address, which is most of them,
        and names an interface the packet did not arrive on. `zone_containing` never hit
        this because the synthetic entry carries no zone.
        """
        best: tuple[int, str] | None = None
        for name, network in self.interface_networks:
            if network.prefixlen == network.max_prefixlen:
                continue
            if _in_network(address, network) and (best is None or network.prefixlen > best[0]):
                best = (network.prefixlen, name)
        return best[1] if best else None

    def serves(self, address: int) -> bool:
        """Whether this device has a connected route covering the address.

        "The packet has arrived": the destination is on a subnet this device is directly
        attached to, so there is no further hop to take.
        """
        return any(
            route.protocol == "connected" and _covers(route.destination, address)
            for route in self.routes
        )

    def equal_cost_next_hops(self, address: int, vrf: str | None = None) -> list[str]:
        """Every next hop tying for best on this address, when there is more than one.

        `lookup` returns one route, which is what a router does per flow — but which one
        it picks depends on a hash of the flow, and the choice is not in any configuration
        this product reads. So a trace that follows the single best route is describing
        one of several real paths without saying so, and if the alternatives cross
        different firewalls the verdict is about an arbitrary one of them.

        Returns an empty list where there is no ambiguity, so the caller can stay silent
        in the ordinary case. Routes with no next hop are excluded: a connected or
        interface route is the end of the path rather than a branch in it.
        """
        best_key: tuple[int, int, int] | None = None
        hops: dict[tuple[int, int, int], list[str]] = {}

        for route in self.routes:
            if route.vrf != vrf or not route.next_hop:
                continue
            network = _network(route.destination)
            if network is None or not _in_network(address, network):
                continue

            key = (
                -network.prefixlen,
                route.distance if route.distance is not None else 1,
                route.metric if route.metric is not None else 0,
            )
            hops.setdefault(key, []).append(route.next_hop)
            if best_key is None or key < best_key:
                best_key = key

        if best_key is None:
            return []

        # Deduplicated: the same next hop learned twice is one path, not two.
        winners = sorted(set(hops[best_key]))
        return winners if len(winners) > 1 else []

    def routes_subdividing(self, low: int, high: int, vrf: str | None = None) -> list[str]:
        """Prefixes that cover part of this range and not the rest.

        A range query walks the path once, using one address to stand for the whole
        range. That is sound only while every address in it takes the same route — and a
        route whose prefix cuts across the range breaks exactly that. Half the subnet
        would go one way and half another, and a single traced path would describe one
        half while reporting on both.

        Returns the prefixes responsible, so the answer can name them rather than merely
        hedge.
        """
        found: list[str] = []
        for route in self.routes:
            if route.vrf != vrf:
                continue
            network = _network(route.destination)
            if network is None:
                continue
            net_low = int(network.network_address)
            net_high = int(network.broadcast_address)
            overlaps = net_low <= high and net_high >= low
            contains_all = net_low <= low and net_high >= high
            if overlaps and not contains_all:
                found.append(route.destination)
        return sorted(set(found))

    def other_vrfs_matching(self, address: int) -> list[str]:
        """VRFs *other than the global table* that hold a route to this address.

        A path walk looks in the global table, because nothing in the NCM says which VRF
        a packet entered on — interfaces are not bound to VRFs by any parser here. So a
        device whose relevant route lives in a named VRF would otherwise report
        "unreachable", turning a gap in what is modelled into a claim about the network.
        This is how the walk finds out to say "unknown" instead, and which VRF to name.
        """
        return sorted(
            {
                route.vrf
                for route in self.routes
                if route.vrf is not None and _covers(route.destination, address)
            }
        )

    def lookup(self, address: int, *, vrf: str | None = None) -> Route | None:
        """Longest-prefix match over this device's table, within one VRF.

        Longest prefix, then lowest administrative distance, then lowest metric — the
        order a router itself uses. Without the tie-breaks a device with two defaults
        would resolve differently between identical runs, and an answer that changes
        without the estate changing is worse than a wrong one, because nobody can tell
        which run to believe.
        """
        best: Route | None = None
        best_key: tuple[int, int, int] | None = None

        for route in self.routes:
            if route.vrf != vrf:
                continue
            network = _network(route.destination)
            if network is None or not _in_network(address, network):
                continue

            key = (
                -network.prefixlen,
                route.distance if route.distance is not None else 1,
                route.metric if route.metric is not None else 0,
            )
            if best_key is None or key < best_key:
                best, best_key = route, key

        return best


@dataclass(slots=True)
class TopologyGraph:
    """Every device's table, indexed so a path can be walked across them."""

    nodes: dict[uuid.UUID, DeviceNode] = field(default_factory=dict)
    #: Interface address → the device that owns it. The join between hops.
    _owners: dict[int, uuid.UUID] = field(default_factory=dict)

    def add(self, node: DeviceNode) -> None:
        self.nodes[node.device_id] = node
        for address in node.interface_addresses:
            # First writer wins, and a clash is worth saying out loud: two devices
            # claiming one address is a duplicate-IP misconfiguration or a stale
            # snapshot, and silently picking one would make paths depend on load order.
            if address in self._owners and self._owners[address] != node.device_id:
                log.warning(
                    "topology.duplicate_interface_address",
                    address=str(ipaddress.ip_address(address)),
                    held_by=str(self._owners[address]),
                    also_claimed_by=str(node.device_id),
                )
                continue
            self._owners[address] = node.device_id

    def device_at(self, address: str | int) -> DeviceNode | None:
        """The device with this exact address on an interface."""
        value = _to_int(address)
        if value is None:
            return None
        device_id = self._owners.get(value)
        return self.nodes.get(device_id) if device_id else None

    def device_serving(self, address: str | int) -> DeviceNode | None:
        """The device directly attached to the subnet holding this address.

        Where several qualify — a transit link with a router at each end — the most
        specific subnet wins, then the hostname, so the answer is stable across runs.
        """
        value = _to_int(address)
        if value is None:
            return None

        best: tuple[int, str, DeviceNode] | None = None
        for node in self.nodes.values():
            for route in node.routes:
                if route.protocol != "connected":
                    continue
                network = _network(route.destination)
                if network is None or not _in_network(value, network):
                    continue
                candidate = (-network.prefixlen, node.hostname, node)
                if best is None or candidate[:2] < best[:2]:
                    best = candidate
        return best[2] if best else None

    def adjacency(self, node: DeviceNode, route: Route) -> Adjacency:
        """Where a route leads, and whether that is somewhere we know about."""
        if route.next_hop is None:
            return Adjacency(route=route, next_device_id=None)
        neighbour = self.device_at(route.next_hop)
        return Adjacency(route=route, next_device_id=neighbour.device_id if neighbour else None)

    @property
    def unknown_route_tables(self) -> list[DeviceNode]:
        """Devices whose tables were never read, so cannot support a negative answer."""
        return [node for node in self.nodes.values() if not node.routes_known]


def build_graph(nodes: Iterable[DeviceNode]) -> TopologyGraph:
    graph = TopologyGraph()
    for node in nodes:
        graph.add(node)

    log.info(
        "topology.graph_built",
        devices=len(graph.nodes),
        routes=sum(len(node.routes) for node in graph.nodes.values()),
        interface_addresses=len(graph._owners),
        tables_unknown=len(graph.unknown_route_tables),
    )
    return graph


# ── address helpers ──────────────────────────────────────────────────────────


def _to_int(address: str | int) -> int | None:
    if isinstance(address, int):
        return address
    try:
        return int(ipaddress.ip_address(str(address).strip()))
    except ValueError:
        return None


def _network(prefix: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    try:
        return ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None


def _in_network(address: int, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """Whether an integer address falls inside a network.

    Compared as integers rather than by constructing an address object per test: a path
    walk does this for every route of every device it touches, and an estate's tables run
    to thousands of entries.
    """
    return int(network.network_address) <= address <= int(network.broadcast_address)


def _covers(prefix: str, address: int) -> bool:
    network = _network(prefix)
    return network is not None and _in_network(address, network)


__all__ = [
    "ROUTES_SINCE",
    "Adjacency",
    "DeviceNode",
    "TopologyGraph",
    "build_graph",
]
