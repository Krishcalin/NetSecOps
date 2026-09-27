"""The estate as a drawable graph (FR-TOPO-02).

Path analysis answers one question at a time. This is the other half of the same data:
the whole layer-3 graph, projected into nodes and links so an operator can *see* how the
estate is wired before they know which question to ask.

It invents no adjacency. Every link here is the same join the path walk makes — a route's
next hop is an address, and two devices are adjacent when that address is configured on
an interface of the other one. Drawing a link because two devices share a subnet would
be the tempting shortcut and would put strings on this picture that no packet follows.

**Where the estate ends is drawn, not omitted.** A next hop no inventoried device answers
for becomes a node of its own, so the map shows its own boundary rather than tapering off
into white space. That boundary is the most actionable thing on the picture: it names the
device somebody would have to onboard to learn more.

**The layout inputs are deterministic.** Tier comes from breadth-first distance off that
boundary, groups are the connected components of the graph, and every ordering falls back
to the hostname. A map that rearranges itself between two runs over an unchanged estate
cannot be compared with yesterday's, which is most of what a map is for.

**Groups are structural; their names are not.** A component is a fact about the routing
graph. The label put on it — a site, a shared hostname prefix — is a convenience for
reading the picture, and `group.label_source` says which it was so nobody mistakes
"london" for a site somebody configured.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.ncm.models import Route
from netsecops.topology.graph import DeviceNode, TopologyGraph

log = get_logger(__name__)

#: Prefixes that mean "everything". A link carrying one is the way out, and the picture
#: says so rather than making a reader count prefixes to work out which strand is the
#: default route.
DEFAULT_PREFIXES = frozenset({"0.0.0.0/0", "::/0"})

#: How many distinct next-hop addresses a single link reports. Two routers with a dozen
#: parallel transit links produce one strand on the picture, and the first few addresses
#: are enough to find it on the device; the full set is in the route table.
MAX_VIA_PER_LINK = 4

#: Hostname separators, for deriving a group label from a shared prefix.
_SEPARATORS = "-._"


@dataclass(frozen=True, slots=True)
class MapInterface:
    """One interface, as the picture needs it: a name, its addresses and its zone."""

    name: str
    addresses: tuple[str, ...] = ()
    zone: str | None = None


@dataclass(frozen=True, slots=True)
class DeviceMeta:
    """What the inventory knows about a device that the routing graph does not.

    Supplied by the service rather than read here, so this module stays a pure function
    of the graph and can be tested against hand-built nodes.
    """

    device_class: str | None = None
    criticality: str | None = None
    status: str | None = None
    site: str | None = None
    #: Addressed interfaces only, and capped. An access switch with forty-eight ports
    #: contributes one SVI to a layer-3 picture and forty-seven rows of noise to a
    #: payload; `interface_count` keeps the total honest.
    interfaces: tuple[MapInterface, ...] = ()
    interface_count: int = 0
    #: Severity → count, open findings only. Empty on a device that passed every check
    #: *and* on one nothing has ever checked. Those are different things and nothing
    #: available here separates them, so the map says so rather than colouring both
    #: green — see `has_snapshot`, which is the part that can be stated.
    findings: Mapping[str, int] = field(default_factory=dict)
    #: Whether a configuration was ever stored for this device. A device without one
    #: contributes no routes, no rules and no findings, and is on the picture only
    #: because it is in the inventory.
    has_snapshot: bool = False


@dataclass(slots=True)
class MapNode:
    """A box on the picture."""

    id: str
    #: `device` — in the inventory. `unmanaged` — an address routes point at that no
    #: inventoried device answers for. The two are never drawn alike: one is a thing
    #: NetSecOps has evidence about, the other is a hole in the evidence.
    kind: str
    label: str
    group: str
    tier: int

    platform: str | None = None
    vendor: str | None = None
    device_class: str | None = None
    criticality: str | None = None
    status: str | None = None
    site: str | None = None

    #: Carries security rules of any kind.
    has_rulebase: bool = False
    #: Carries rules that are *in force on traffic crossing it* — which is a narrower
    #: thing, and the one the picture is drawn from. An access switch whose only access
    #: list is a vty filter has a rulebase and inspects nothing, and badging it as a
    #: firewall would put a control on the map where the network has none.
    inspects: bool = False
    routes: int = 0
    #: False where the snapshot predates route parsing. Such a device is on the map, is
    #: connected to nothing, and has no routes *that anybody read* — which is a different
    #: statement from having none, and the picture has to make it.
    routes_known: bool = True
    interfaces: tuple[MapInterface, ...] = ()
    #: Every interface the device has, addressed or not. The list above is the subset
    #: that carries an address, so the two differ on a switch and the panel says so
    #: rather than implying a 48-port switch has one interface.
    interface_count: int = 0
    findings: Mapping[str, int] = field(default_factory=dict)
    has_snapshot: bool = False

    #: Unmanaged nodes only.
    referenced_by: tuple[str, ...] = ()
    carries_default_route: bool = False


@dataclass(slots=True)
class MapLink:
    """A strand between two boxes: one or more routes, and the interfaces at each end."""

    id: str
    source: str
    target: str
    #: The next-hop addresses that produced this link, capped at `MAX_VIA_PER_LINK`.
    via: tuple[str, ...] = ()
    #: How many prefixes are routed across it. A transit link carrying one prefix and a
    #: link carrying four hundred are different facts about the estate.
    prefixes: int = 0
    carries_default: bool = False
    #: True where each end routes to the other. A single direction is drawn as an arrow,
    #: because a route one way and nothing back is a real and common asymmetry.
    bidirectional: bool = False
    source_interface: str | None = None
    target_interface: str | None = None
    #: True where either end has a rulebase in force, so "which strands are inspected"
    #: is legible without opening each device.
    crosses_firewall: bool = False


@dataclass(slots=True)
class MapGroup:
    """One connected component of the graph."""

    id: str
    label: str
    #: `site` | `hostname` | `index`. What the label was derived from, so a reader knows
    #: whether it reflects something configured or something inferred from a name.
    label_source: str
    devices: int = 0
    firewalls: int = 0
    unmanaged: int = 0
    links: int = 0
    tiers: int = 1


@dataclass(slots=True)
class EstateMap:
    """Everything the picture is drawn from."""

    nodes: list[MapNode] = field(default_factory=list)
    links: list[MapLink] = field(default_factory=list)
    groups: list[MapGroup] = field(default_factory=list)

    devices: int = 0
    unmanaged: int = 0
    devices_without_route_data: int = 0
    isolated: int = 0

    #: Groups left out because the estate exceeded the cap, and how many devices they
    #: held. Whole groups are dropped rather than arbitrary devices: half a component is
    #: a picture of a network that does not exist.
    omitted_groups: tuple[str, ...] = ()
    omitted_devices: int = 0


def build_map(
    graph: TopologyGraph,
    *,
    meta: Mapping[uuid.UUID, DeviceMeta] | None = None,
    limit: int = 2000,
) -> EstateMap:
    """Project the routing graph into nodes, links and groups."""
    metadata = meta or {}
    links, endpoints = _links(graph)

    components = _components(graph.nodes, links)
    tiers = _tiers(links, components)

    nodes: list[MapNode] = []
    for device in sorted(graph.nodes.values(), key=lambda node: node.hostname):
        node_id = str(device.device_id)
        info = metadata.get(device.device_id, DeviceMeta())
        nodes.append(
            MapNode(
                id=node_id,
                kind="device",
                label=device.hostname,
                group=components[node_id],
                tier=tiers[node_id],
                platform=device.platform,
                vendor=device.vendor,
                device_class=info.device_class,
                criticality=info.criticality,
                status=info.status,
                site=info.site,
                has_rulebase=device.has_rulebase,
                inspects=_inspects(device.firewall),
                routes=len(device.routes),
                routes_known=device.routes_known,
                # The graph indexes addresses and subnets; it does not keep which
                # interface each address sat on. The inventory side does, so the
                # interface list arrives with the metadata rather than being recovered.
                interfaces=info.interfaces,
                interface_count=info.interface_count,
                findings=dict(info.findings),
                has_snapshot=info.has_snapshot,
            )
        )

    nodes.extend(_unmanaged_nodes(links, components, tiers))

    inspecting = {node.id for node in nodes if node.inspects}
    for link in links:
        link.crosses_firewall = link.source in inspecting or link.target in inspecting
        if pair := endpoints.get(link.id):
            link.source_interface = pair.get(link.source)
            link.target_interface = pair.get(link.target)

    groups = _groups(nodes, links)
    estate = EstateMap(
        nodes=nodes,
        links=links,
        groups=groups,
        devices=len(graph.nodes),
        unmanaged=sum(1 for node in nodes if node.kind == "unmanaged"),
        devices_without_route_data=len(graph.unknown_route_tables),
        isolated=_isolated(nodes, links),
    )

    if estate.devices > limit:
        _trim(estate, limit)

    log.info(
        "topology.map_built",
        devices=estate.devices,
        unmanaged=estate.unmanaged,
        links=len(estate.links),
        groups=len(estate.groups),
        omitted_devices=estate.omitted_devices,
    )
    return estate


# ── links ────────────────────────────────────────────────────────────────────


@dataclass(slots=True)
class _Pending:
    """A link under construction, before the two directions are merged."""

    via: dict[str, None] = field(default_factory=dict)
    prefixes: set[str] = field(default_factory=set)
    carries_default: bool = False
    directions: set[str] = field(default_factory=set)
    interfaces: dict[str, str] = field(default_factory=dict)


def _links(graph: TopologyGraph) -> tuple[list[MapLink], dict[str, dict[str, str]]]:
    """Every adjacency in the graph, with the two directions merged into one strand.

    A route both ways between the same pair is one wire, not two — but *which* it is
    matters, so the merged link remembers whether it saw one direction or both.
    """
    pending: dict[tuple[str, str], _Pending] = {}

    for device in graph.nodes.values():
        source_id = str(device.device_id)
        for route in device.routes:
            if not route.next_hop:
                continue
            neighbour = graph.device_at(route.next_hop)
            if neighbour is not None and neighbour.device_id == device.device_id:
                # A route pointing at this device's own address is not a hop to anywhere.
                continue

            target_id = str(neighbour.device_id) if neighbour else f"unmanaged:{route.next_hop}"
            key = (source_id, target_id) if source_id < target_id else (target_id, source_id)
            entry = pending.setdefault(key, _Pending())

            entry.via[route.next_hop] = None
            entry.prefixes.add(route.destination)
            entry.carries_default |= route.destination in DEFAULT_PREFIXES
            entry.directions.add(source_id)
            _record_interfaces(entry, device, neighbour, route)

    links: list[MapLink] = []
    endpoints: dict[str, dict[str, str]] = {}
    for (source_id, target_id), entry in sorted(pending.items()):
        link_id = f"{source_id}|{target_id}"
        links.append(
            MapLink(
                id=link_id,
                source=source_id,
                target=target_id,
                via=tuple(sorted(entry.via)[:MAX_VIA_PER_LINK]),
                prefixes=len(entry.prefixes),
                carries_default=entry.carries_default,
                bidirectional=len(entry.directions) > 1,
            )
        )
        endpoints[link_id] = dict(entry.interfaces)

    return links, endpoints


def _record_interfaces(
    entry: _Pending, device: DeviceNode, neighbour: DeviceNode | None, route: Route
) -> None:
    """Name the interface at each end of a strand.

    The near end is whatever the route itself says, falling back to the interface whose
    subnet faces the next hop. The far end is resolved the same way, by the subnet that
    holds the address rather than by an exact-address index — which is the same helper
    the path walk picks an access list with, and gives the same answer unless a device
    has two interfaces on overlapping subnets.

    First writer wins, so a link seen from both ends does not depend on iteration order.
    """
    near = route.interface or device.interface_containing(_address_int(route.next_hop))
    if near:
        entry.interfaces.setdefault(str(device.device_id), near)

    if neighbour is not None:
        far = neighbour.interface_containing(_address_int(route.next_hop))
        if far:
            entry.interfaces.setdefault(str(neighbour.device_id), far)


def _unmanaged_nodes(
    links: Iterable[MapLink], components: Mapping[str, str], tiers: Mapping[str, int]
) -> list[MapNode]:
    """A node per next hop nothing in the inventory answers for."""
    found: dict[str, MapNode] = {}

    for link in links:
        for node_id, other in ((link.source, link.target), (link.target, link.source)):
            if not node_id.startswith("unmanaged:"):
                continue
            node = found.get(node_id)
            if node is None:
                node = MapNode(
                    id=node_id,
                    kind="unmanaged",
                    label=node_id.removeprefix("unmanaged:"),
                    group=components.get(node_id, "g0"),
                    tier=tiers.get(node_id, 0),
                )
                found[node_id] = node
            node.referenced_by = (*node.referenced_by, other)
            node.carries_default_route |= link.carries_default

    return sorted(found.values(), key=lambda node: node.label)


# ── components, tiers and groups ─────────────────────────────────────────────


def _adjacency(links: Iterable[MapLink], *, devices_only: bool) -> dict[str, set[str]]:
    neighbours: dict[str, set[str]] = {}
    for link in links:
        if devices_only and (
            link.source.startswith("unmanaged:") or link.target.startswith("unmanaged:")
        ):
            continue
        neighbours.setdefault(link.source, set()).add(link.target)
        neighbours.setdefault(link.target, set()).add(link.source)
    return neighbours


def _components(devices: Mapping[uuid.UUID, DeviceNode], links: list[MapLink]) -> dict[str, str]:
    """Which component each node belongs to.

    Computed over device-to-device links only. Two devices whose default routes point at
    the same ISP address are *not* adjacent — the packet does not cross from one to the
    other — and letting an unmanaged node join components would merge every site that
    shares an upstream into one.
    """
    neighbours = _adjacency(links, devices_only=True)
    assigned: dict[str, str] = {}
    count = 0

    for device in sorted(devices.values(), key=lambda node: (node.hostname, str(node.device_id))):
        start = str(device.device_id)
        if start in assigned:
            continue
        group = f"g{count}"
        count += 1
        queue = deque([start])
        assigned[start] = group
        while queue:
            current = queue.popleft()
            for neighbour in sorted(neighbours.get(current, ())):
                if neighbour not in assigned:
                    assigned[neighbour] = group
                    queue.append(neighbour)

    # An unmanaged address belongs with whoever routes to it. Where several groups do,
    # the first by node id keeps the assignment stable rather than correct-looking — the
    # address is one thing and cannot sit in two places on a picture.
    for link in sorted(links, key=lambda item: item.id):
        for node_id, other in ((link.source, link.target), (link.target, link.source)):
            if node_id.startswith("unmanaged:") and node_id not in assigned:
                assigned[node_id] = assigned.get(other, "g0")

    return assigned


def _tiers(links: list[MapLink], components: Mapping[str, str]) -> dict[str, int]:
    """Breadth-first distance from the estate's boundary, per component.

    The boundary is where routes leave what NetSecOps manages, which in practice is the
    internet edge — so tier 0 is the edge, and depth increases inwards. A component with
    no boundary at all is rooted at its best-connected device, which is the closest thing
    to a core that the data supports.
    """
    neighbours = _adjacency(links, devices_only=True)
    boundary: set[str] = {
        link.source if link.target.startswith("unmanaged:") else link.target
        for link in links
        if link.source.startswith("unmanaged:") != link.target.startswith("unmanaged:")
    }

    members: dict[str, list[str]] = {}
    for node_id, group in components.items():
        if not node_id.startswith("unmanaged:"):
            members.setdefault(group, []).append(node_id)

    tiers: dict[str, int] = {}
    for ids in members.values():
        roots = sorted(node_id for node_id in ids if node_id in boundary)
        if not roots:
            roots = [
                max(
                    sorted(ids),
                    key=lambda node_id: len(neighbours.get(node_id, ())),
                )
            ]

        queue = deque[tuple[str, int]]((root, 0) for root in roots)
        for root in roots:
            tiers[root] = 0
        while queue:
            current, depth = queue.popleft()
            for neighbour in sorted(neighbours.get(current, ())):
                if neighbour not in tiers:
                    tiers[neighbour] = depth + 1
                    queue.append((neighbour, depth + 1))

        for node_id in ids:
            tiers.setdefault(node_id, 0)

    # Unmanaged addresses sit one tier outside whoever points at them: the picture reads
    # outward-to-inward, and the boundary is what the estate's edge faces.
    for link in links:
        for node_id, other in ((link.source, link.target), (link.target, link.source)):
            if node_id.startswith("unmanaged:"):
                outside = tiers.get(other, 0) - 1
                tiers[node_id] = min(tiers.get(node_id, outside), outside)

    return tiers


def _groups(nodes: list[MapNode], links: list[MapLink]) -> list[MapGroup]:
    by_group: dict[str, list[MapNode]] = {}
    for node in nodes:
        by_group.setdefault(node.group, []).append(node)

    group_of = {node.id: node.group for node in nodes}
    link_counts: dict[str, int] = {}
    for link in links:
        if group := group_of.get(link.source):
            link_counts[group] = link_counts.get(group, 0) + 1

    groups: list[MapGroup] = []
    for group_id, members in by_group.items():
        devices = [node for node in members if node.kind == "device"]
        label, source = _label_for(devices, group_id)
        groups.append(
            MapGroup(
                id=group_id,
                label=label,
                label_source=source,
                devices=len(devices),
                firewalls=sum(1 for node in devices if node.inspects),
                unmanaged=len(members) - len(devices),
                links=link_counts.get(group_id, 0),
                tiers=len({node.tier for node in members}) or 1,
            )
        )

    return sorted(groups, key=lambda group: (group.label.lower(), group.id))


def _label_for(devices: list[MapNode], group_id: str) -> tuple[str, str]:
    """A name for a component, and an honest statement of where the name came from."""
    if not devices:
        return group_id, "index"

    sites = {node.site for node in devices if node.site}
    if len(sites) == 1:
        return sites.pop() or group_id, "site"

    prefix = _common_prefix([node.label for node in devices])
    if len(prefix) >= 3:
        return prefix, "hostname"

    return f"Segment {group_id.removeprefix('g')}", "index"


def _common_prefix(names: list[str]) -> str:
    """The shared leading part of a set of hostnames, cut at a separator.

    Trimmed to a separator so a component of `london-core-01` and `london-dist-02`
    is called `london` rather than `london-`, and two unrelated names sharing a letter
    produce nothing rather than a one-character label.
    """
    if not names:
        return ""
    shortest = min(names, key=len)
    shared = ""
    for index, character in enumerate(shortest):
        if all(name[index] == character for name in names):
            shared += character
        else:
            break
    return shared.rstrip(_SEPARATORS)


def _isolated(nodes: list[MapNode], links: list[MapLink]) -> int:
    """Devices with no link at all.

    Worth counting on its own: a device in the inventory that joins nothing is either
    genuinely standalone — a Check Point management server forwards nothing — or a
    collection whose routes never parsed, and both look identical on the picture.
    """
    connected = {link.source for link in links} | {link.target for link in links}
    return sum(1 for node in nodes if node.kind == "device" and node.id not in connected)


def _trim(estate: EstateMap, limit: int) -> None:
    """Drop whole groups until the map fits, largest kept first."""
    ordered = sorted(estate.groups, key=lambda group: (-group.devices, group.label.lower()))
    keep: set[str] = set()
    budget = 0
    for group in ordered:
        if budget + group.devices > limit and keep:
            continue
        keep.add(group.id)
        budget += group.devices

    dropped = [group for group in estate.groups if group.id not in keep]
    if not dropped:
        return

    estate.omitted_groups = tuple(group.label for group in dropped)
    estate.omitted_devices = sum(group.devices for group in dropped)
    estate.nodes = [node for node in estate.nodes if node.group in keep]
    remaining = {node.id for node in estate.nodes}
    estate.links = [
        link for link in estate.links if link.source in remaining and link.target in remaining
    ]
    estate.groups = [group for group in estate.groups if group.id in keep]


# ── helpers ──────────────────────────────────────────────────────────────────


def _address_int(address: str | None) -> int:
    if not address:
        return -1
    try:
        return int(ipaddress.ip_address(address.strip()))
    except ValueError:
        return -1


def _inspects(firewall: Mapping[str, Any]) -> bool:
    """Whether this device's rules are in force on traffic crossing it.

    `SecurityRule.applied` is three-state on purpose. `None` means the question does not
    arise — a PAN-OS, FortiOS or Check Point rule is in force by existing. `True` and
    `False` appear on Cisco, where binding an access list to an interface is a separate
    act from writing it: a switch whose only access list is `access-class 99 in` on the
    vty lines filters *management* access and no transit traffic at all.

    So a rule counts unless it is explicitly bound to nothing. Reading it the other way
    round — counting only `applied is True` — would silently drop every PAN-OS and
    FortiOS firewall in the estate off the picture.
    """
    rules: Iterable[Mapping[str, Any]] = firewall.get("security_rules") or []
    return any(rule.get("applied") is not False for rule in rules)


__all__ = [
    "DEFAULT_PREFIXES",
    "DeviceMeta",
    "EstateMap",
    "MapGroup",
    "MapInterface",
    "MapLink",
    "MapNode",
    "build_map",
]
