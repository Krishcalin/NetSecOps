"""Which unmanaged next hops obscure the most reachability (FR-TOPO-06).

Every path that stops early stops for the same reason: a route points at an address that
belongs to no device in the inventory. This ranks those addresses, so onboarding effort
goes where it buys the most answers instead of wherever the estate diagram happens to
start.

**It is computed from the graph, not from running every path.** The obvious construction
— walk every source-destination pair and tally where the walks died — is quadratic in the
estate and answers a slightly different question anyway: it measures the queries somebody
happened to ask rather than the reachability the gap conceals. The routes themselves are
the better evidence. A next hop referenced by nine devices, carrying four default routes,
is a hole in the map whoever queries it.

**A default route counts for more than a specific one, and that is not a fudge.** A
device routing 0.0.0.0/0 at an unknown next hop has delegated *everything it does not
otherwise know* to something invisible, so every query that does not resolve locally dies
there. A route for a single /24 obscures one subnet. Treating those as equal would rank a
lab's static route above the estate's edge firewall.

**What this does not claim.** An unmanaged next hop is not necessarily a device anyone
should onboard: it may be an ISP's router, a customer handoff, or an HSRP virtual address
that no single box owns. So the report names what was found and why it matters, and stops
short of telling anybody what to do about it — the addresses are evidence, not a work
queue.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from netsecops.core.logging import get_logger
from netsecops.topology.graph import TopologyGraph

log = get_logger(__name__)

#: What a default route counts for, against one specific route's 1.
#:
#: A device whose default route leaves the estate hides every destination it has no
#: specific route for, which on an edge device is the entire internet and on an internal
#: one is most of the estate. Ten is a judgement, not a measurement — it is large enough
#: that a single default outranks a handful of specific routes, and small enough that a
#: next hop referenced by a dozen devices still rises above one referenced by two.
DEFAULT_ROUTE_WEIGHT = 10


@dataclass(slots=True)
class MissingDevice:
    """An address that routes point at and no inventoried device answers for."""

    address: str
    #: Hostnames that route through it, so the finding can be verified against a real
    #: configuration rather than taken on trust.
    referenced_by: list[str] = field(default_factory=list)
    #: The prefixes routed through it, most general first.
    prefixes: list[str] = field(default_factory=list)
    carries_default_route: bool = False
    #: How much reachability this gap conceals. Comparable within one report only — it is
    #: a ranking, not a measurement of anything in the world.
    score: int = 0

    #: The subnet it sits on, where a device in the estate is attached to that subnet.
    #: A next hop on a subnet we already reach is usually a device sitting beside ones we
    #: manage — far more likely to be onboardable than an address on a transit link to
    #: somebody else's network.
    adjacent_to: str | None = None

    @property
    def reason(self) -> str:
        """Why this one is where it is in the ranking, in a sentence."""
        parts = [
            f"{len(self.referenced_by)} device(s) route through {self.address}",
            f"covering {len(self.prefixes)} prefix(es)",
        ]
        if self.carries_default_route:
            parts.append(
                "including a default route, so everything those devices cannot resolve "
                "locally leaves the estate here"
            )
        if self.adjacent_to:
            parts.append(f"on {self.adjacent_to}, a subnet the estate already reaches")
        return "; ".join(parts) + "."


def missing_devices(graph: TopologyGraph, *, limit: int = 50) -> list[MissingDevice]:
    """Rank the next hops that terminate path analysis (FR-TOPO-06)."""
    found: dict[str, MissingDevice] = {}

    for node in graph.nodes.values():
        for route in node.routes:
            if route.next_hop is None:
                # A connected or interface-routed entry leaves nowhere to go to.
                continue
            if graph.device_at(route.next_hop) is not None:
                continue

            entry = found.setdefault(route.next_hop, MissingDevice(address=route.next_hop))
            if node.hostname not in entry.referenced_by:
                entry.referenced_by.append(node.hostname)
            if route.destination not in entry.prefixes:
                entry.prefixes.append(route.destination)
            if route.destination == "0.0.0.0/0":
                entry.carries_default_route = True

    for entry in found.values():
        specific = sum(1 for prefix in entry.prefixes if prefix != "0.0.0.0/0")
        entry.score = len(entry.referenced_by) * (
            specific + (DEFAULT_ROUTE_WEIGHT if entry.carries_default_route else 0)
        )
        entry.prefixes.sort(key=_generality)
        entry.referenced_by.sort()
        entry.adjacent_to = _adjacent_subnet(graph, entry.address)

    ranked = sorted(found.values(), key=lambda item: (-item.score, item.address))

    log.info(
        "topology.missing_devices",
        found=len(ranked),
        with_default_route=sum(1 for item in ranked if item.carries_default_route),
    )
    return ranked[:limit]


def _generality(prefix: str) -> tuple[int, str]:
    """Sort key putting the broadest prefix first — that is the one that matters most."""
    try:
        return (ipaddress.ip_network(prefix, strict=False).prefixlen, prefix)
    except ValueError:
        return (128, prefix)


def _adjacent_subnet(graph: TopologyGraph, address: str) -> str | None:
    """The attached subnet this address sits on, if the estate reaches one.

    Distinguishes "a box sitting next to devices we manage" from "an address across a
    handoff", which is most of what decides whether a gap is worth closing.
    """
    try:
        value = int(ipaddress.ip_address(address))
    except ValueError:
        return None

    best: tuple[int, str] | None = None
    for node in graph.nodes.values():
        for route in node.routes:
            if route.protocol != "connected":
                continue
            try:
                network = ipaddress.ip_network(route.destination, strict=False)
            except ValueError:
                continue
            if int(network.network_address) <= value <= int(network.broadcast_address):
                if best is None or network.prefixlen > best[0]:
                    best = (network.prefixlen, route.destination)
    return best[1] if best else None


__all__ = ["DEFAULT_ROUTE_WEIGHT", "MissingDevice", "missing_devices"]
