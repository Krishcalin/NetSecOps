"""Reading a device's *operational* forwarding table (FR-TOPO-01).

`routes.py` reads the routes written in a configuration — statics, plus the connected
routes implied by interface addressing. This module reads what the device says its
forwarding table actually contains, which is the only place a protocol-learned route
exists: OSPF, BGP and EIGRP entries are in no configuration file anywhere.

**This required widening the read-only allow-list**, and that is the only reason it was
not built with the rest of Phase 8. `show ip route` is a show command and changes
nothing, but SRS §8.2 is a closed list precisely so that "it is only a show command"
cannot be used to grow it one entry at a time. The addition is recorded there with its
rationale rather than slipped in.

**The artefact wins over the configuration when both are present.** A device's own
forwarding table already contains its static routes, so parsing both and concatenating
would double every static entry — and two identical edges in a graph is not a cosmetic
problem, it is a route that appears to have two equal-cost paths where the device has
one. The fallback matters just as much: if the artefact is missing or unreadable, the
caller keeps the configuration-derived routes rather than reporting a device with no
routes at all, because an empty table would resolve every path to Unreachable when the
honest answer is Unknown.

**Three formats, not one.** IOS, IOS-XE, ASA and FortiOS all print a leading protocol
code and a prefix; NX-OS prints a prefix line followed by indented `*via` lines and
names the protocol in words. They are different enough that one regex covering both
would match neither reliably, and a route table that silently parses to nothing looks
exactly like a device with no routes.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Final

from netsecops.core.logging import get_logger
from netsecops.ncm.models import Route
from netsecops.parsers.routes import is_ip, store, to_cidr

if TYPE_CHECKING:
    from netsecops.parsers.base import ParseResult

log = get_logger(__name__)

#: Leading route codes, normalised to the protocol families the NCM records.
#:
#: Sub-types are deliberately collapsed: `O IA` (inter-area), `O E2` (external type 2)
#: and `O N1` (NSSA) are all OSPF, and a path walk cares which protocol installed a route,
#: not which LSA type carried it. The NCM's `Route.protocol` documents this closed set,
#: so widening it here without widening that is how the two drift apart.
PROTOCOL_BY_CODE: Final[dict[str, str]] = {
    "C": "connected",
    "L": "local",
    "S": "static",
    "R": "rip",
    "B": "bgp",
    "D": "eigrp",
    "EX": "eigrp",
    "O": "ospf",
    "IA": "ospf",
    "N1": "ospf",
    "N2": "ospf",
    "E1": "ospf",
    "E2": "ospf",
    "I": "isis",
    "i": "isis",
    "L1": "isis",
    "L2": "isis",
    "ia": "isis",
    "M": "mobile",
    "P": "static",
    "A": "other",
    "V": "other",
    "U": "static",
}

#: NX-OS names protocols in words, and suffixes the instance: `ospf-1`, `bgp-65000`.
PROTOCOL_BY_NAME: Final[dict[str, str]] = {
    "direct": "connected",
    "local": "local",
    "static": "static",
    "ospf": "ospf",
    "ospfv3": "ospf",
    "bgp": "bgp",
    "eigrp": "eigrp",
    "rip": "rip",
    "isis": "isis",
    "am": "other",
    "hmm": "other",
    "broadcast": "other",
}

#: `[administrative-distance/metric]`, which every one of these formats spells the same.
_AD_METRIC: Final[re.Pattern[str]] = re.compile(r"\[(\d+)/(\d+)\]")

_VIA_ADDRESS: Final[re.Pattern[str]] = re.compile(r"\bvia\s+(\d{1,3}(?:\.\d{1,3}){3})")

#: `10.0.0.0/8 is variably subnetted, 5 subnets, 3 masks` — a *context* line, not a route.
_SUBNETTED: Final[re.Pattern[str]] = re.compile(
    r"^\s+(?P<dest>\d{1,3}(?:\.\d{1,3}){3})/(?P<length>\d{1,2})\s+is\s+(?:variably\s+)?subnetted",
    re.IGNORECASE,
)

#: `IP Route Table for VRF "default"`
_NXOS_VRF: Final[re.Pattern[str]] = re.compile(
    r"^IP\s+Route\s+Table\s+for\s+VRF\s+\"(?P<vrf>[^\"]+)\"", re.IGNORECASE
)

#: `10.0.0.0/24, ubest/mbest: 1/0, attached`
_NXOS_PREFIX: Final[re.Pattern[str]] = re.compile(
    r"^(?P<dest>\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}),\s+ubest/mbest:", re.IGNORECASE
)

#: `    *via 10.0.0.2, Eth1/1, [0/0], 00:10:23, direct`
_NXOS_VIA: Final[re.Pattern[str]] = re.compile(r"^\s+\*{0,2}via\s+(?P<rest>.+)$", re.IGNORECASE)

#: How long a route table may be before it is clearly not a route table.
#:
#: Guards against a collection that captured a pager prompt, an error banner or an entire
#: `show tech-support` under the wrong key. Parsing megabytes of unrelated text is slow
#: and yields garbage routes, which are worse than none.
MAX_LINES: Final[int] = 200_000


def _is_age(token: str) -> bool:
    """Whether a token is an uptime rather than an interface name.

    Route tables print how long a route has been up in three shapes — `00:05:23`,
    `1w2d`, `never` — and all three sit in the same comma-separated position an interface
    name does. Reading one as an interface gives a route an egress interface of `1w2d`,
    which no device has and which quietly breaks joining the graph by interface.
    """
    if not token:
        return False
    lowered = token.lower()
    if lowered == "never":
        return True
    if re.fullmatch(r"\d+:\d{2}:\d{2}", lowered):
        return True
    return bool(re.fullmatch(r"(?:\d+[wdhmy])+", lowered))


def _is_netmask(token: str) -> bool:
    """Whether a token is a dotted subnet mask.

    ASA and older IOS print `10.0.0.0 255.0.0.0` where newer software prints
    `10.0.0.0/8`, so the token after the destination is sometimes a mask and sometimes
    the start of `[110/2] via ...`. Checked by asking whether it is a *valid contiguous*
    mask rather than merely four octets: `203.0.113.1` is four octets and is a next hop.
    """
    try:
        ipaddress.ip_address(token)
    except ValueError:
        return False
    try:
        # `ip_network` rejects non-contiguous values such as 255.0.255.0. The literal is
        # a zero *network* being masked, not a socket bound to every interface — this
        # module opens no socket — so B104 is suppressed. The suppression carries no
        # trailing prose: bandit parses anything after the id as further test names and
        # warns about each word.
        ipaddress.ip_network(f"0.0.0.0/{token}")  # nosec B104
    except ValueError:
        return False
    return True


def _looks_like_destination(token: str) -> bool:
    """Whether a token is the prefix a route line is about."""
    candidate = token.split("/")[0]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def _protocol_from_codes(codes: str) -> str | None:
    """Map a leading code field such as `S*`, `O IA` or `D EX` to a protocol family.

    Read left to right and stop at the first code that is known, because the first letter
    is the protocol and anything after it qualifies it. `D EX` is external EIGRP, still
    EIGRP; taking the last token instead would classify it by its qualifier.
    """
    for token in codes.replace("*", " ").split():
        if protocol := PROTOCOL_BY_CODE.get(token):
            return protocol
        # Codes are case-sensitive in Cisco's legend (`i` is IS-IS, `I` is IGRP), but a
        # capitalisation difference should degrade to the right family rather than to
        # nothing at all.
        if protocol := PROTOCOL_BY_CODE.get(token.upper()):
            return protocol
    return None


def _protocol_from_name(parts: list[str]) -> str | None:
    """Find NX-OS's protocol word among the comma-separated fields of a `via` line.

    Searched rather than taken by position: an OSPF entry appends its route type
    (`ospf-1, intra`) and a direct entry does not, so the protocol is the last field on
    some lines and the second-to-last on others.
    """
    for part in reversed(parts):
        base = part.strip().split("-")[0].lower()
        if protocol := PROTOCOL_BY_NAME.get(base):
            return protocol
    return None


def _interface_from(text: str) -> str | None:
    """The egress interface from the tail of a route line.

    Everything structural is removed first — the distance/metric bracket and the `via`
    address — and the last remaining comma-separated field is the interface, if it is not
    an uptime. Position cannot be used: IOS prints `via 10.0.0.1, 00:05:23, Gi0/0` and
    FortiOS prints `via 10.0.0.1, port1`, so the interface is the third field on one and
    the second on the other.
    """
    stripped = _AD_METRIC.sub("", _VIA_ADDRESS.sub("", text))
    for part in reversed([p.strip() for p in stripped.split(",")]):
        if not part:
            continue
        token = part.split()[-1]
        if _is_age(token) or is_ip(token):
            continue
        if token.lower() in {"connected", "attached", "permanent", "candidate"}:
            continue
        return token
    return None


def _build(
    *,
    destination: str,
    tail: str,
    protocol: str | None,
    vrf: str | None,
    interface: str | None,
    next_hop: str | None = None,
) -> Route:
    """Assemble a route from the parts each format has already identified.

    The interface is passed in rather than derived here, because the two formats put it
    in incompatible places: the code-prefixed formats end with it, NX-OS puts it second
    and ends with the protocol and route type. Deriving it centrally read `direct`,
    `intra` and a BGP tag as interface names — plausible-looking values that no device
    has, which then fail to join anything in the graph.
    """
    distance: int | None = None
    metric: int | None = None
    if match := _AD_METRIC.search(tail):
        distance, metric = int(match.group(1)), int(match.group(2))

    if next_hop is None and (match := _VIA_ADDRESS.search(tail)):
        next_hop = match.group(1)

    return Route(
        destination=destination,
        next_hop=next_hop,
        interface=interface,
        protocol=protocol,
        distance=distance,
        metric=metric,
        vrf=vrf,
    )


def parse_cisco_route_table(text: str, *, vrf: str | None = None) -> list[Route]:
    """Parse `show ip route` / `show route` output.

    Covers IOS, IOS-XE, ASA and FortiOS, which share a format: a leading protocol code, a
    destination, then a loosely ordered tail.

    Two shapes in this format are easy to miss and both lose routes silently:

    * **The `is subnetted` context line.** Classic IOS groups subnets under a parent and
      then prints the children *without* a prefix length — `O 172.16.1.0 [110/65] via …`
      under `172.16.0.0/24 is subnetted, 3 subnets`. Read literally that child is a /32,
      a host route to a network address, which matches no traffic and removes the subnet
      from the graph. The parent's length is carried down to any child that has none.
    * **Equal-cost continuation lines.** A second path to the same destination is printed
      as a bare `[110/2] via 10.0.0.5, …` with no code and no prefix. Dropped, the graph
      believes a redundant path is a single point of failure; misread as a new route, it
      invents a destination of whatever parsed first.
    """
    routes: list[Route] = []
    parent_length: int | None = None
    last_destination: str | None = None

    for raw in text.splitlines()[:MAX_LINES]:
        line = raw.rstrip()
        if not line.strip():
            continue

        if match := _SUBNETTED.match(line):
            parent_length = int(match.group("length"))
            continue

        stripped = line.strip()

        # A continuation line carries another next hop for the destination above it.
        if stripped.startswith("[") or (stripped.startswith("via ") and last_destination):
            if last_destination is None:
                continue
            previous = routes[-1] if routes else None
            routes.append(
                _build(
                    destination=last_destination,
                    tail=stripped,
                    protocol=previous.protocol if previous else None,
                    vrf=vrf,
                    interface=_interface_from(stripped),
                )
            )
            continue

        # A route line starts at column zero with its protocol code. Anything else
        # indented is a legend, a banner or a gateway-of-last-resort note.
        if line[0].isspace() or not line[0].isalpha():
            continue

        # Every token before the destination must be a route code, and the search for the
        # destination stops at the first token that is not one.
        #
        # Scanning ahead for "the first thing that looks like an address" instead is
        # subtly catastrophic: given `S 999.999.999.999/24 [1/0] via 10.0.0.1`, the
        # malformed destination fails to parse, the scan continues, and the *next hop*
        # becomes the destination — yielding a confident route to 10.0.0.1/32 that the
        # device does not have. That is the wrong-edge failure this module exists to
        # avoid, and it was found by the test asserting a bad prefix is dropped.
        tokens = stripped.split()
        codes: list[str] = []
        index: int | None = None
        for position, token in enumerate(tokens):
            if _looks_like_destination(token):
                index = position
                break
            cleaned = token.strip("*%+")
            if not cleaned or _protocol_from_codes(cleaned) is None:
                break
            codes.append(cleaned)

        if index is None or not codes:
            continue

        protocol = _protocol_from_codes(" ".join(codes))
        if protocol is None:
            continue

        destination_token = tokens[index]
        tail_tokens = tokens[index + 1 :]

        mask: str | int | None = None
        if "/" not in destination_token and tail_tokens and _is_netmask(tail_tokens[0]):
            mask = tail_tokens[0]
            tail_tokens = tail_tokens[1:]
        elif "/" not in destination_token and parent_length is not None:
            mask = parent_length

        destination = to_cidr(destination_token, mask)
        if destination is None:
            log.debug("route_tables.unparseable_destination", value=destination_token)
            continue

        last_destination = destination
        tail = " ".join(tail_tokens)
        routes.append(
            _build(
                destination=destination,
                tail=tail,
                protocol=protocol,
                vrf=vrf,
                interface=_interface_from(tail),
            )
        )

    return routes


def parse_nxos_route_table(text: str) -> list[Route]:
    """Parse NX-OS `show ip route`.

    NX-OS prints a prefix on its own line and each path beneath it, which means a
    destination with three next hops is four lines and a destination with none is one.
    The VRF comes from a header line rather than from each entry, so it is carried
    forward — and it must be, because two VRFs routinely hold the same prefix and merging
    them joins networks that by design cannot reach each other.

    `default` is normalised to None to match the rest of the NCM, where the global table
    is the absence of a VRF rather than one named "default". Storing the literal string
    would make a global route fail to match a global lookup.
    """
    routes: list[Route] = []
    vrf: str | None = None
    destination: str | None = None

    for raw in text.splitlines()[:MAX_LINES]:
        line = raw.rstrip()
        if not line.strip():
            continue

        if match := _NXOS_VRF.match(line.strip()):
            name = match.group("vrf")
            vrf = None if name.lower() == "default" else name
            destination = None
            continue

        if match := _NXOS_PREFIX.match(line.strip()):
            destination = to_cidr(match.group("dest"))
            continue

        if match := _NXOS_VIA.match(line):
            if destination is None:
                continue
            parts = [p.strip() for p in match.group("rest").split(",")]
            if not parts:
                continue

            head = parts[0]
            # The first field is the next hop, except on a route out an interface with no
            # gateway — `*via Null0, [1/0]` — where it is the interface itself.
            next_hop = head if is_ip(head) else None
            interface = None if is_ip(head) else head

            # The interface, when there is a gateway, is the field immediately after it —
            # and only there. Everything beyond is the distance/metric bracket, the
            # uptime, the protocol and its route type, all of which look like plausible
            # interface names to a search that works backwards from the end.
            if interface is None and len(parts) > 1:
                candidate = parts[1]
                token = candidate.split()[0] if candidate.split() else ""
                if token and not token.startswith("[") and not _is_age(token):
                    if PROTOCOL_BY_NAME.get(token.split("-")[0].lower()) is None:
                        interface = token

            routes.append(
                _build(
                    destination=destination,
                    tail=", ".join(parts[1:]),
                    protocol=_protocol_from_name(parts),
                    vrf=vrf,
                    interface=interface,
                    next_hop=next_hop,
                )
            )

    return routes


#: Gaia's legend, which reuses Cisco's letters for different things.
#:
#: Kept separate from :data:`PROTOCOL_BY_CODE` rather than merged into it, because four
#: of the letters collide outright: Gaia's `D` is a BGP default route where Cisco's is
#: EIGRP, `P` is Suppressed where Cisco's is a periodic static, `U` is Unreachable where
#: Cisco's is a per-user static, and `i` is Inactive where Cisco's is IS-IS. Reusing the
#: Cisco map would not fail — it would return a confident, wrong protocol for each, and
#: a graph edge labelled `eigrp` on a Check Point gateway is harder to disbelieve than
#: one labelled nothing at all.
GAIA_PROTOCOL_BY_CODE: Final[dict[str, str]] = {
    "C": "connected",
    "S": "static",
    "R": "rip",
    "B": "bgp",
    #: A BGP default route — a qualifier on `B`, not a protocol of its own.
    "D": "bgp",
    "O": "ospf",
    "IA": "ospf",
    "E": "ospf",
    "N": "ospf",
    #: Aggregate and kernel remnant. Real forwarding entries, but neither names a
    #: routing protocol, and `Route.protocol` documents a closed set.
    "A": "other",
    "K": "other",
    "U": "other",
}

#: Codes marking a route the device is *not* forwarding on: hidden, suppressed by a
#: route map, or inactive. Plain `show route` should not print these at all — they need
#: `show route all` — so this is a guard rather than an expectation, and they are
#: dropped because a graph edge for a route the device will not use is a path that does
#: not exist.
_GAIA_NOT_FORWARDING: Final[frozenset[str]] = frozenset({"H", "P", "i"})

#: `S   0.0.0.0/0   via 192.168.211.254, eth0, cost 0, age 16426`
#: `C   192.168.211.0/24   is directly connected, eth0`
_GAIA_ROUTE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<codes>[A-Za-z]{1,2}(?:\s+[A-Za-z]{1,2})*)\s+"
    r"(?P<destination>\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\s+"
    r"(?P<tail>.+)$"
)

#: Gaia prints `cost 0` where Cisco prints `[110/2]`, so `_AD_METRIC` finds nothing.
_GAIA_COST: Final[re.Pattern[str]] = re.compile(r"\bcost\s+(\d+)")


def parse_gaia_route_table(text: str) -> list[Route]:
    """Parse Check Point Gaia `show route` output.

    Gaia's forwarding table is not in `show configuration`, which carries the static
    routes somebody typed and nothing the gateway learned. A Check Point gateway in a
    routed core therefore appeared in the topology graph with its static routes only,
    and the graph had no way to say so.

    Two line shapes, both with a leading code:

        S    0.0.0.0/0          via 192.168.211.254, eth0, cost 0, age 16426
        C    192.168.211.0/24   is directly connected, eth0

    **The interface is taken by position, not by elimination.** `_interface_from` walks
    the comma-separated fields from the right and skips anything that looks like an
    uptime — which works where the tail ends with the interface, and fails here: Gaia
    ends with `cost 0, age 16426`, and `16426` is not a recognised uptime spelling, so
    that helper would hand back `16426` as the egress interface. That is the exact bug
    `_is_age` exists to prevent, arriving through a format it was not written against.
    In Gaia's grammar the interface always follows the next hop, so it is read there.
    """
    routes: list[Route] = []

    for raw in text.splitlines()[:MAX_LINES]:
        line = raw.strip()
        match = _GAIA_ROUTE.match(line)
        if match is None:
            continue

        tail = match.group("tail")
        # The legend lists the same letters followed by ` - Connected`, and a route
        # line always says where the traffic goes. Without this the legend parses as
        # a table of routes to nowhere.
        directly_connected = "is directly connected" in tail
        if "via" not in tail and not directly_connected:
            continue

        codes = match.group("codes").split()
        if _GAIA_NOT_FORWARDING.intersection(codes):
            continue

        destination = to_cidr(match.group("destination"))
        if destination is None:
            continue

        protocol: str | None = None
        for code in codes:
            if found := GAIA_PROTOCOL_BY_CODE.get(code):
                protocol = found
                break

        fields = [part.strip() for part in tail.split(",")]
        interface: str | None = None
        next_hop: str | None = None

        if directly_connected:
            # `is directly connected, eth0`
            interface = fields[1] if len(fields) > 1 else None
        else:
            # `via 10.0.0.1, eth0, cost 0, age 16426` — the interface follows the hop.
            if via := _VIA_ADDRESS.search(fields[0]):
                next_hop = via.group(1)
            interface = fields[1] if len(fields) > 1 else None

        metric: int | None = None
        if cost := _GAIA_COST.search(tail):
            metric = int(cost.group(1))

        routes.append(
            Route(
                destination=destination,
                next_hop=next_hop,
                interface=interface or None,
                protocol=protocol,
                metric=metric,
            )
        )

    return routes


def store_routes(
    result: ParseResult,
    *commands: str,
    parser: Callable[[str], list[Route]],
    from_config: Sequence[tuple[Route, int | None]],
) -> None:
    """Store the forwarding table, preferring the device's own over the configuration's.

    One place decides this for every platform, because the rule is subtle in both
    directions and four copies of it would not stay in step.

    **The operational table wins when it has anything in it.** It already contains the
    static routes the configuration declares, so storing both would duplicate every
    static entry — and a duplicated route is not cosmetic in a graph, it is a prefix that
    appears to have two equal-cost paths where the device has one.

    **An empty or unreadable table falls back rather than erasing.** A collection from
    before this command was added, an offline configuration upload, a device that refused
    the command — all yield nothing here, and storing that nothing would leave a device
    with no routes at all. Every path through it would then resolve to Unreachable, which
    is a confident wrong answer, where the configuration's own statics still support an
    honest partial one.

    Routes from the artefact carry no configuration line, so they are stored with a
    provenance of None: pointing them at a line of the running configuration they were
    never written on would be worse than leaving them unattributed.
    """
    text = result.context.artifact(*commands)
    operational = parser(text) if text else []

    if operational:
        store(result, [(route, None) for route in operational])
        return

    if text:
        log.debug("route_tables.artefact_unreadable", commands=list(commands))
    store(result, from_config)


__all__ = [
    "GAIA_PROTOCOL_BY_CODE",
    "MAX_LINES",
    "PROTOCOL_BY_CODE",
    "PROTOCOL_BY_NAME",
    "parse_cisco_route_table",
    "parse_gaia_route_table",
    "parse_nxos_route_table",
    "store_routes",
]
