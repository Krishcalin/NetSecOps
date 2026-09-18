"""Walking a path across the graph (FR-TOPO-03, FR-TOPO-04, FR-TOPO-05).

The question an operator actually asks is not "which rule matches on this firewall" —
that is FR-FW-06 and it has existed since Phase 4 — but "can this host reach that one,
and what decides". Answering it means finding the devices in between and asking each of
them, which is what this does.

**The result has two axes, and keeping them apart is the whole point.** Routing says how
far the path could be traced; policy says what the firewalls along it decided. They fail
independently, and a single verdict has to lie about one of them:

    Every firewall I found permits this, but I lost the path at 10.20.0.0/16
    because 10.20.0.1 belongs to no device in the inventory.

That sentence is honest and actionable — it says what to onboard. Collapsed to "allowed"
it becomes a claim the product cannot support, and somebody will open a firewall on the
strength of it. So a policy verdict of `allowed` is only ever produced alongside routing
`routed`: anything less becomes `partially-allowed`, which reads as the invitation to
look further that it is.

**A block is definitive; a permit is not.** If a device on the path denies the packet, it
dies there and nothing beyond matters — so `blocked` stands even when the rest of the
path is unknown. A permit only tells you about the devices actually consulted, and an
unknown remainder may hold another firewall. The asymmetry is deliberate and it is the
reason the two axes combine the way they do below.

**Nothing here sends a packet.** Every hop is a lookup in a stored table and every verdict
is `first_match` over a stored rulebase — the same offline simulation the rule query
already performs, run once per device on the path.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from enum import StrEnum

from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.firewall.analysis import first_match
from netsecops.firewall.model import PROTOCOL_NUMBERS, resolve_rulebase
from netsecops.ncm.models import Route
from netsecops.topology.graph import DeviceNode, TopologyGraph

log = get_logger(__name__)

#: A path longer than this is a routing loop rather than a long path. Real management
#: estates are a handful of hops deep; the cap exists so a mutual pair of default routes
#: terminates with a diagnosis instead of running until something else stops it.
MAX_HOPS = 32


class RoutingConfidence(StrEnum):
    """How far the path could be traced (FR-TOPO-04)."""

    #: A device on the path has a table we can read and no route to the destination.
    UNREACHABLE = "unreachable"
    #: Source and destination sit on the same attached subnet: nothing routes between
    #: them, so no firewall is in the way and no rulebase was consulted.
    SAME_ZONE = "same-zone"
    #: Traced end to end, every hop on a device in the inventory.
    ROUTED = "routed"
    #: Traced as far as the managed estate goes and then left it. The next hop is a real
    #: address that belongs to no device here.
    PARTIALLY_ROUTED = "partially-routed"
    #: Something in the way of an answer: a table never collected, a truncated table, a
    #: routing loop, or a source no device serves.
    UNKNOWN = "unknown"


class PolicyVerdict(StrEnum):
    """What the devices on the path decided (FR-TOPO-04)."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"
    #: Every firewall consulted permitted it, but the path was not traced all the way,
    #: so there may be another one. Never collapse this to `allowed`.
    PARTIALLY_ALLOWED = "partially-allowed"
    #: No path to evaluate policy over.
    NOT_ROUTED = "not-routed"


@dataclass(slots=True)
class Hop:
    """One device the packet passes through, and what it decided."""

    device_id: uuid.UUID
    hostname: str
    platform: str | None = None
    #: The route this device chose, as `destination via next-hop`.
    matched_route: str | None = None
    next_hop: str | None = None
    egress_interface: str | None = None
    ingress_zone: str | None = None
    egress_zone: str | None = None

    #: None where the device carries no rulebase — a router is a hop, not a decision.
    #: That is different from a firewall that permitted the packet, and the UI must not
    #: render them the same.
    action: str | None = None
    rule_name: str | None = None
    rule_order: int | None = None
    #: Caveats from the rule query, carried through rather than dropped: matching is over
    #: addresses, protocol and port only, so App-ID and User-ID narrowing is not simulated.
    limitations: tuple[str, ...] = ()


@dataclass(slots=True)
class PathResult:
    """The answer, on both axes."""

    source: str
    destination: str
    protocol: str
    port: int

    routing: RoutingConfidence
    policy: PolicyVerdict

    hops: list[Hop] = field(default_factory=list)
    #: Where the trace stopped, when it did not finish. Names the prefix and next hop so
    #: the answer is actionable rather than merely hedged (FR-TOPO-05).
    stopped_at_prefix: str | None = None
    stopped_at_next_hop: str | None = None
    stopped_at_device: str | None = None
    #: Plain-language reasons, shown beside the verdict. A caveat that lives only in a
    #: log is a caveat nobody reads.
    notes: list[str] = field(default_factory=list)

    @property
    def devices_traversed(self) -> int:
        return len(self.hops)

    @property
    def blocked_by(self) -> Hop | None:
        return next((hop for hop in self.hops if hop.action == "deny"), None)


def _address(value: str, label: str) -> int:
    try:
        return int(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ValidationProblem(
            f"'{value}' is not an IP address. A path query needs a literal {label} "
            "address — names are not resolved, so that what was analysed is what was asked."
        ) from None


def _protocol_number(protocol: str) -> int:
    text = (protocol or "").strip().lower()
    if text.isdigit():
        return int(text)
    number = PROTOCOL_NUMBERS.get(text)
    if number is None:
        raise ValidationProblem(
            f"'{protocol}' is not a protocol this can simulate. "
            f"Use one of: {', '.join(sorted(PROTOCOL_NUMBERS))}, or a protocol number."
        )
    return number


def _describe(route: Route) -> str:
    if route.next_hop:
        return f"{route.destination} via {route.next_hop}"
    if route.interface:
        return f"{route.destination} via {route.interface}"
    return route.destination


def _evaluate(
    node: DeviceNode,
    hop: Hop,
    *,
    source: int,
    destination: int,
    protocol: int,
    port: int,
) -> None:
    """Ask one device's rulebase about the packet, and record what it said.

    A device with no rulebase leaves `action` None rather than defaulting to permit. A
    router forwards without an opinion, and rendering that as "allowed" would count it as
    a control that was checked — the same mistake as reporting an unevaluated check as a
    pass.
    """
    if not node.has_rulebase:
        return

    try:
        rules, _ = resolve_rulebase(node.firewall)
    except Exception as exc:  # a malformed stored rulebase must not abort the path
        log.warning("topology.rulebase_unreadable", device=node.hostname, error=str(exc))
        hop.limitations = (
            f"{node.hostname} carries a rulebase this could not resolve, so its decision "
            "is unknown and is not counted as a permit.",
        )
        return

    if not rules:
        return

    result = first_match(
        rules,
        source=source,
        destination=destination,
        protocol=protocol,
        port=port,
        src_zone=hop.ingress_zone,
        dst_zone=hop.egress_zone,
    )

    if result.matched is None:
        # No rule matched. Every platform here ends its policy with an implicit deny, so
        # the packet is dropped — and saying so is more useful than "no rule matched",
        # which reads as though the question went unanswered.
        hop.action = "deny"
        hop.rule_name = "(implicit deny)"
        hop.limitations = result.limitations
        return

    hop.action = result.matched.action
    hop.rule_name = result.matched.name
    hop.rule_order = result.matched.order
    hop.limitations = result.limitations


def walk(
    graph: TopologyGraph,
    *,
    source: str,
    destination: str,
    protocol: str = "tcp",
    port: int = 443,
) -> PathResult:
    """Trace a packet across the estate and report both axes (FR-TOPO-03)."""
    src = _address(source, "source")
    dst = _address(destination, "destination")
    proto = _protocol_number(protocol)

    result = PathResult(
        source=source,
        destination=destination,
        protocol=protocol,
        port=port,
        routing=RoutingConfidence.UNKNOWN,
        policy=PolicyVerdict.NOT_ROUTED,
    )

    start = graph.device_serving(src)
    if start is None:
        result.notes.append(
            f"No device in the inventory is attached to a subnet containing {source}, so "
            "the path has no starting point. Onboard the device that serves that subnet, "
            "or start the query from an address inside the managed estate."
        )
        return _finalise(result)

    # Same attached subnet: the two hosts talk directly and nothing routes between them.
    # Reporting a firewall verdict here would be wrong in the dangerous direction — it
    # would imply a control sits in a path that has none.
    if start.serves(dst) and _same_connected_subnet(start, src, dst):
        result.routing = RoutingConfidence.SAME_ZONE
        result.policy = PolicyVerdict.NOT_ROUTED
        result.notes.append(
            f"{source} and {destination} are on the same subnet attached to "
            f"{start.hostname}, so traffic between them is not routed and no rulebase "
            "applies. A host firewall or a switch ACL could still block it; neither is "
            "visible from a configuration assessment."
        )
        return result

    current = start
    arrived_from = src
    visited: set[uuid.UUID] = set()

    for _ in range(MAX_HOPS):
        if current.device_id in visited:
            result.routing = RoutingConfidence.UNKNOWN
            result.stopped_at_device = current.hostname
            result.notes.append(
                f"The path returns to {current.hostname}, which is a routing loop rather "
                "than a route to the destination. The tables disagree with each other."
            )
            return _finalise(result)
        visited.add(current.device_id)

        hop = Hop(
            device_id=current.device_id,
            hostname=current.hostname,
            platform=current.platform,
            ingress_zone=current.zone_containing(arrived_from),
        )

        # Arrived: the destination is on a subnet this device is directly attached to.
        if current.serves(dst):
            hop.egress_zone = current.zone_containing(dst)
            hop.matched_route = "connected"
            _evaluate(current, hop, source=src, destination=dst, protocol=proto, port=port)
            result.hops.append(hop)
            result.routing = RoutingConfidence.ROUTED
            return _finalise(result)

        route = current.lookup(dst)
        if route is None:
            result.hops.append(hop)
            result.stopped_at_device = current.hostname
            other_vrfs = current.other_vrfs_matching(dst)
            if not current.routes_known:
                result.routing = RoutingConfidence.UNKNOWN
                result.notes.append(
                    f"{current.hostname} was collected before forwarding tables were "
                    "parsed, so its routes are unknown rather than absent. Re-collect it "
                    "to complete this path."
                )
            elif other_vrfs:
                # The global table has no route, but a VRF does. Which VRF a packet is in
                # is decided by the interface it arrives on, and no parser records that
                # binding — so this is a limit of what is modelled, not a property of the
                # network, and must not be reported as unreachable.
                result.routing = RoutingConfidence.UNKNOWN
                result.notes.append(
                    f"{current.hostname} has no route to {destination} in its global "
                    f"table, but VRF {', '.join(other_vrfs)} does. Which VRF carries this "
                    "traffic depends on the interface it arrives on, which is not "
                    "collected — so the path cannot be resolved rather than being absent."
                )
            elif current.routes_truncated:
                result.routing = RoutingConfidence.UNKNOWN
                result.notes.append(
                    f"{current.hostname}'s routing table was larger than is stored, so "
                    "the absence of a route here may be an artefact of truncation."
                )
            else:
                result.routing = RoutingConfidence.UNREACHABLE
                result.notes.append(
                    f"{current.hostname} has no route to {destination}. The packet is "
                    "dropped there, so no firewall beyond it is consulted."
                )
            return _finalise(result)

        hop.matched_route = _describe(route)
        hop.next_hop = route.next_hop
        hop.egress_interface = route.interface
        hop.egress_zone = current.zone_for(route.interface)
        _evaluate(current, hop, source=src, destination=dst, protocol=proto, port=port)
        result.hops.append(hop)

        # A rule that denies ends the path here, definitively. Continuing to trace would
        # produce hops the packet never reaches.
        if hop.action == "deny":
            result.routing = RoutingConfidence.ROUTED if route.next_hop else result.routing
            break

        adjacency = graph.adjacency(current, route)
        if adjacency.next_device_id is None:
            # The edge of the managed estate. This is the answer FR-TOPO-05 exists for,
            # and the input to the missing-device report.
            result.routing = RoutingConfidence.PARTIALLY_ROUTED
            result.stopped_at_prefix = route.destination
            result.stopped_at_next_hop = route.next_hop
            result.stopped_at_device = current.hostname
            result.notes.append(
                f"The path leaves the managed estate at {current.hostname}: it routes "
                f"{route.destination} via {route.next_hop or route.interface}, which "
                "belongs to no device in the inventory. Anything beyond that point — "
                "including further firewalls — is not visible here."
            )
            return _finalise(result)

        arrived_from = _address(route.next_hop, "next hop") if route.next_hop else arrived_from
        current = graph.nodes[adjacency.next_device_id]
    else:
        result.routing = RoutingConfidence.UNKNOWN
        result.notes.append(
            f"The path exceeded {MAX_HOPS} hops without reaching {destination}, which "
            "means the tables form a loop rather than a route."
        )

    return _finalise(result)


def _finalise(result: PathResult) -> PathResult:
    """Derive the policy axis from the hops and the routing axis (FR-TOPO-04).

    This is where the two axes are combined, and the combination is the product's honesty
    about its own coverage. The rule that matters: `allowed` requires `routed`. Anything
    less becomes `partially-allowed`, because a permit only speaks for the devices that
    were actually consulted and an untraced remainder may hold another firewall.
    """
    consulted = [hop for hop in result.hops if hop.action is not None]

    if any(hop.action == "deny" for hop in consulted):
        # Definitive: the packet dies at the first denial, so what lies beyond is moot.
        result.policy = PolicyVerdict.BLOCKED
        blocker = result.blocked_by
        if blocker:
            result.notes.append(
                f"{blocker.hostname} denies this traffic"
                + (f" at rule '{blocker.rule_name}'" if blocker.rule_name else "")
                + ". Devices beyond it were not evaluated, because the packet does not "
                "reach them."
            )
        return result

    if result.routing is RoutingConfidence.UNREACHABLE:
        result.policy = PolicyVerdict.NOT_ROUTED
        return result

    if not consulted:
        # Traced, and nothing on the way had a rulebase to consult.
        result.policy = (
            PolicyVerdict.PARTIALLY_ALLOWED
            if result.routing is not RoutingConfidence.ROUTED
            else PolicyVerdict.ALLOWED
        )
        if result.routing is RoutingConfidence.ROUTED:
            result.notes.append(
                "No device on this path carries a firewall rulebase, so nothing "
                "inspected the traffic. 'Allowed' here means unfiltered, not permitted."
            )
        return result

    if result.routing is RoutingConfidence.ROUTED:
        result.policy = PolicyVerdict.ALLOWED
        return result

    result.policy = PolicyVerdict.PARTIALLY_ALLOWED
    result.notes.append(
        f"{len(consulted)} device(s) on the traced part of this path permit the traffic, "
        "but the path was not followed to the destination — so this is not a statement "
        "that the traffic gets through."
    )
    return result


def _same_connected_subnet(node: DeviceNode, left: int, right: int) -> bool:
    """Whether both addresses fall in one of this device's attached subnets."""
    for route in node.routes:
        if route.protocol != "connected":
            continue
        try:
            network = ipaddress.ip_network(route.destination, strict=False)
        except ValueError:
            continue
        low, high = int(network.network_address), int(network.broadcast_address)
        if low <= left <= high and low <= right <= high:
            return True
    return False


__all__ = [
    "MAX_HOPS",
    "Hop",
    "PathResult",
    "PolicyVerdict",
    "RoutingConfidence",
    "walk",
]
