"""Reading forwarding-table entries out of a configuration (FR-TOPO-01).

Shared by every vendor parser, because the hard part is identical across all of them and
getting it wrong fails silently in the same way each time.

**A prefix has to be normalised before it is stored.** The same network is written four
ways across this product's device set — `10.0.0.0 255.0.0.0` on IOS and ASA,
`10.0.0.0/8` on NX-OS and FortiOS, `10.0.0.0 255.0.0.0` again but with the mask in a
different argument position on Check Point, and as separate XML elements on PAN-OS. A
graph that compares those as text does not crash: it simply never matches a route to the
subnet it describes, so every path resolves to Unknown and the topology looks like an
estate of disconnected islands. That failure is invisible without a test that feeds it
two spellings of one network, which is why normalisation lives here rather than being
done four times.

**A route that cannot be parsed is dropped, not guessed.** An entry whose destination is
unreadable would otherwise become an edge pointing somewhere arbitrary, and a wrong edge
in a reachability graph is far worse than a missing one — a missing edge shows up as
Unknown and asks for a human, while a wrong one answers confidently.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from typing import Final

from netsecops.core.logging import get_logger
from netsecops.ncm.models import Interface, Route
from netsecops.parsers.base import ParseResult

log = get_logger(__name__)

#: The most routes stored per device.
#:
#: A distribution router carrying a full BGP table has upwards of a million entries, and
#: no configuration assessment needs them — the useful topology is connected, static and
#: interior-protocol routes. The cap bounds snapshot size; what matters is that crossing
#: it sets ``routes_truncated``, because a path that falls off the end of a truncated
#: table must answer Unknown rather than Unreachable.
MAX_ROUTES_PER_DEVICE: Final[int] = 5_000


def to_cidr(network: str, mask: str | int | None = None) -> str | None:
    """Normalise a destination to ``a.b.c.d/len``, or None if it is not one.

    Accepts every spelling the parsers encounter: an address with a dotted mask, an
    address with a prefix length as a separate argument, an address already in CIDR, and
    the various ways vendors spell a default route.
    """
    text = (network or "").strip()
    if not text:
        return None

    # `default`, `default-route` and `0.0.0.0/0` all mean the same thing, and a table
    # that stores them differently cannot match a default route to anything.
    #
    # Both literals below carry a B104 suppression: bandit reads any bare "0.0.0.0" as a
    # socket binding to every interface. These are a *routing destination* — the
    # spellings vendors use for a default route — and this module opens no socket at all.
    # The suppression is per-line rather than a B104 entry in pyproject's skip list, so a
    # real bind-all elsewhere in the codebase still fails the build.
    #
    # Keep the explanation here and the marker bare. Bandit treats every word after the
    # marker as another test id and logs a warning for each, and it scans *any* comment
    # containing the marker — including one merely describing it, which is how this
    # paragraph itself produced five warnings a run until it stopped spelling it out.
    default_spellings = {"default", "default-route", "0.0.0.0", "any"}  # nosec B104
    unset_masks = (None, "", "0.0.0.0", 0)  # nosec B104
    if text.lower() in default_spellings and mask in unset_masks:
        return "0.0.0.0/0"

    if "/" in text:
        try:
            return str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            log.debug("routes.unparseable_prefix", value=text)
            return None

    if mask is None or mask == "":
        # A bare address is a host route. `ip route 10.1.1.1 ...` without a mask is not
        # valid IOS, but it is valid on other platforms and means /32.
        try:
            return str(ipaddress.ip_network(f"{text}/32", strict=False))
        except ValueError:
            log.debug("routes.unparseable_prefix", value=text)
            return None

    try:
        return str(ipaddress.ip_network(f"{text}/{mask}", strict=False))
    except ValueError:
        log.debug("routes.unparseable_prefix", value=text, mask=str(mask))
        return None


def is_ip(value: str | None) -> bool:
    """Whether a token is a literal address.

    Used to tell a next hop from an egress interface: IOS accepts either in the same
    argument position, so `ip route 0.0.0.0 0.0.0.0 GigabitEthernet0/1` and
    `ip route 0.0.0.0 0.0.0.0 192.0.2.1` differ only in what the token looks like.
    """
    if not value:
        return False
    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


#: `ip route [vrf NAME] <dest> <mask> <next-hop-or-interface> [<interface>] [distance]`
#:
#: One expression for IOS, IOS-XE, NX-OS and ASA, because the grammar is the same and
#: keeping four near-identical regexes in four files is how they drift apart. The
#: trailing arguments are genuinely optional and genuinely ordered loosely, so they are
#: captured as a remainder and sorted out by type rather than by position.
IOS_STATIC_ROUTE: Final[re.Pattern[str]] = re.compile(
    r"^\s*ip\s+route\s+"
    r"(?:vrf\s+(?P<vrf>\S+)\s+)?"
    # The destination may already carry its prefix length: NX-OS writes `10.0.0.0/8`
    # where IOS writes `10.0.0.0 255.0.0.0`. Without the optional `/len` here the slash
    # is simply not matched, the mask group stays empty, and the route is stored as a
    # /32 — a host route to the network address, which matches nothing and silently
    # removes that network from the graph.
    r"(?P<dest>\d+\.\d+\.\d+\.\d+(?:/\d{1,2})?|default)"
    r"(?:\s+(?P<mask>\d+\.\d+\.\d+\.\d+|\d{1,2}))?"
    r"(?P<rest>.*)$",
    re.IGNORECASE,
)


def parse_ios_static_route(line: str) -> Route | None:
    """Read one IOS/NX-OS/ASA-style ``ip route`` line.

    The remainder after the prefix is where these differ in practice: a next hop, an
    egress interface, both, then an optional administrative distance and any of `name`,
    `tag`, `track` or `permanent`. Sorting the tokens by what they *are* rather than
    where they sit is what makes one function cover all three platforms — and what stops
    an interface-routed default being stored as a route to nowhere.
    """
    match = IOS_STATIC_ROUTE.match(line)
    if match is None:
        return None

    dest = match.group("dest") or ""
    mask = match.group("mask")
    rest = match.group("rest") or ""

    if "/" in dest and mask:
        # The destination already carried its prefix length, so the token the pattern
        # took for a mask is really the first argument after it — on NX-OS, the next hop.
        # `ip route 10.20.0.0/24 10.0.1.2` otherwise parsed the destination correctly and
        # dropped 10.0.1.2 on the floor, leaving a route that points nowhere: the path
        # walk stops at that device, reports the destination unreachable, and nothing
        # anywhere records that a route was read and then discarded.
        rest = f" {mask}{rest}"
        mask = None

    destination = to_cidr(dest, mask)
    if destination is None:
        return None

    next_hop: str | None = None
    interface: str | None = None
    distance: int | None = None

    tokens = rest.split()
    index = 0
    while index < len(tokens):
        token = tokens[index]
        lowered = token.lower()

        # Keyword arguments carry a value that must not be read as a positional token —
        # `name core-uplink` would otherwise leave `core-uplink` looking like an
        # interface.
        if lowered in {"name", "tag", "track"}:
            index += 2
            continue
        if lowered in {"permanent", "global"}:
            index += 1
            continue

        if is_ip(token):
            next_hop = token
        elif token.isdigit():
            distance = int(token)
        else:
            interface = token
        index += 1

    return Route(
        destination=destination,
        next_hop=next_hop,
        interface=interface,
        protocol="static",
        distance=distance,
        vrf=match.group("vrf"),
    )


#: `route <nameif> <dest> <mask> <gateway> [metric] [track N | tunneled]`
#:
#: ASA's own grammar, and the reason it cannot reuse the IOS reader: the *first*
#: argument is the interface name. Feeding `route outside 0.0.0.0 0.0.0.0 203.0.113.1`
#: to the IOS expression would read `outside` as the destination and drop the entry —
#: silently, since an unparseable route is dropped rather than guessed.
ASA_ROUTE: Final[re.Pattern[str]] = re.compile(
    r"^\s*route\s+(?P<interface>\S+)\s+"
    r"(?P<dest>\d+\.\d+\.\d+\.\d+)\s+(?P<mask>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<gateway>\d+\.\d+\.\d+\.\d+)"
    r"(?:\s+(?P<metric>\d+))?",
    re.IGNORECASE,
)


def parse_asa_route(line: str) -> Route | None:
    """Read one ASA ``route`` line.

    ASA calls the trailing number a metric where IOS calls it an administrative
    distance. Stored as `metric` to match what the device calls it, because an operator
    comparing the product against `show run route` should see their own vocabulary.
    """
    match = ASA_ROUTE.match(line)
    if match is None:
        return None

    destination = to_cidr(match.group("dest"), match.group("mask"))
    if destination is None:
        return None

    metric = match.group("metric")
    return Route(
        destination=destination,
        next_hop=match.group("gateway"),
        interface=match.group("interface"),
        protocol="static",
        metric=int(metric) if metric else None,
    )


def interface_network(address: str) -> str | None:
    """The subnet an interface address sits on, whichever way the vendor wrote it.

    Two spellings reach here and they are not interchangeable to ``ip_interface``:
    `10.1.1.1/24` and `10.1.1.1/255.255.255.0` from the Cisco parsers, and
    `10.1.1.1 255.255.255.0` — space-separated — from FortiOS, which stores what the
    device prints. Requiring a slash silently yields *zero* connected routes on every
    FortiGate in the estate, and a zero is indistinguishable from a device with no
    addressed interfaces, so nothing would look broken.
    """
    text = (address or "").strip()
    if not text:
        return None

    if " " in text:
        parts = text.split()
        if len(parts) != 2:
            return None
        text = f"{parts[0]}/{parts[1]}"

    if "/" not in text:
        # A bare address has no subnet to derive, only a host.
        return None

    try:
        return str(ipaddress.ip_interface(text).network)
    except ValueError:
        return None


def connected_routes(interfaces: Sequence[Interface]) -> list[Route]:
    """Derive the connected routes implied by interface addressing.

    Not parsed, derived — and derived here rather than left to the graph builder so that
    a snapshot carries the same facts however it is read. An interface with an address
    and a mask *is* a route to its own subnet, and those are the edges that attach a
    device to the networks it serves. Without them a graph knows every remote prefix a
    router can reach and nothing about the subnets hanging off it, which is most of what
    a path actually traverses.

    An interface that is administratively down contributes nothing: the subnet is not
    reachable through it, and including it would make a decommissioned link look live.
    """
    routes: list[Route] = []
    for interface in interfaces:
        name = interface.name
        if interface.admin_up is False:
            # `is False`, not falsy: None means the parser could not tell, and an
            # interface of unknown state still carries its subnet. Treating None as down
            # would drop every connected route on the platforms that do not report it.
            continue

        for address in interface.ip_addresses:
            network = interface_network(str(address))
            if network is None:
                log.debug(
                    "routes.unparseable_interface_address", interface=name, value=str(address)
                )
                continue

            routes.append(
                Route(
                    destination=network,
                    next_hop=None,
                    interface=name,
                    protocol="connected",
                )
            )
    return routes


def store(result: ParseResult, collected: Sequence[tuple[Route, int | None]]) -> None:
    """Append routes under the cap and record where each came from (FR-PARSE-04).

    Takes ``(route, line)`` pairs rather than plain routes because provenance is
    per-item throughout the NCM — a reader asking "why does this device claim a route to
    10.50/16" needs the configuration line, not a note that the list as a whole came from
    the file.

    A line of ``None`` means the route was *derived* rather than read: connected routes
    come from interface addressing, whose provenance is already recorded against the
    interface. Pointing them at a line they were not written on would be worse than
    leaving them unattributed.
    """
    routing = result.ncm.routing
    room = MAX_ROUTES_PER_DEVICE - len(routing.routes)

    if room <= 0:
        if collected:
            routing.routes_truncated = True
        return

    for route, line in collected[:room]:
        routing.routes.append(route)
        if line is not None:
            result.record(f"routing.routes.{len(routing.routes) - 1}", line=line)

    if len(collected) > room:
        routing.routes_truncated = True


__all__ = [
    "ASA_ROUTE",
    "IOS_STATIC_ROUTE",
    "MAX_ROUTES_PER_DEVICE",
    "connected_routes",
    "interface_network",
    "is_ip",
    "parse_asa_route",
    "parse_ios_static_route",
    "store",
    "to_cidr",
]
