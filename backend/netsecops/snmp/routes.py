"""Read a forwarding table over SNMP, into the NCM's own `Route` shape (FR-TOPO-01).

Why this exists, stated precisely, because the obvious reason is already solved: on IOS,
IOS-XE, NX-OS, ASA and FortiOS the collection profile issues `show ip route` or its
equivalent, so learned routes reach the graph over the CLI and this adds nothing there.

The gap is the platforms with **no route command at all** — `checkpoint_gaia`, and
`panos` — whose routing tables are therefore absent entirely, static and learned alike.
Those are firewalls, which is to say the devices a path most often crosses and the ones
whose absence from the graph costs the most: a path reaching a PAN-OS firewall today
finds a device that can answer what it *permits* and not where it would *send* anything.

SNMP is used rather than adding a route command to each of their allow-lists because one
read reaches every platform uniformly, including a device whose CLI profile does not
exist yet — and because widening two vendor allow-lists is a change to what the product
sends to devices, where this is a MIB read the SRS already contemplates (§8: "SNMP v2c/v3
GET only (discovery/fingerprint & optional inventory), never SET").

**The index is the data.** `ipCidrRouteEntry` is indexed by destination, mask, TOS and
next hop, so walking any one column returns the whole route in the OID and one attribute
in the value. Three column walks therefore yield everything needed, rather than the
fifteen a naive subtree walk would drag back.

**A reject route is not a route.** `ipCidrRouteType` distinguishes `remote` and `local`
from `reject`, which is a configured black hole. Treating one as forwarding would make
the path walker claim reachability that deliberately does not exist, so they are excluded
and counted — counted because "no route" and "a route that discards" are different
answers and an operator chasing a broken path needs to know which they have.

**An empty walk is not an empty table.** A device that does not implement this MIB, one
whose view excludes it, and one with genuinely no routes are three different situations.
:class:`RouteWalk` reports which, because this codebase has repeatedly found that the
expensive failure is a confident empty result rather than an error.
"""

from __future__ import annotations

import asyncio
import secrets
import socket
from dataclasses import dataclass
from typing import Final, Protocol

from netsecops.core.logging import get_logger
from netsecops.ncm.models import Route
from netsecops.snmp.codec import (
    MAX_RESPONSE,
    SNMP_PORT,
    SnmpError,
    VarBind,
    build_getbulk,
    build_getnext,
    parse_varbinds,
)

log = get_logger(__name__)

#: RFC 2096. `ipCidrRouteEntry`, the table every mainstream platform still populates.
IP_CIDR_ROUTE_TABLE: Final[str] = "1.3.6.1.2.1.4.24.4.1"

IP_CIDR_ROUTE_IF_INDEX: Final[str] = f"{IP_CIDR_ROUTE_TABLE}.5"
IP_CIDR_ROUTE_TYPE: Final[str] = f"{IP_CIDR_ROUTE_TABLE}.6"
IP_CIDR_ROUTE_PROTO: Final[str] = f"{IP_CIDR_ROUTE_TABLE}.7"

#: `ifDescr`, to turn an interface index into the name an operator recognises.
IF_DESCR: Final[str] = "1.3.6.1.2.1.2.2.1.2"

#: Ceilings. A walk is the only thing here that scales with the size of the device, so
#: both the rows and the datagrams are bounded, and hitting either is reported rather
#: than silently truncating a table the caller then treats as complete.
MAX_ROUTES: Final[int] = 10_000
MAX_PACKETS: Final[int] = 600

#: `ipCidrRouteType`: other(1), reject(2), local(3), remote(4).
_TYPE_REJECT: Final[int] = 2
_TYPE_LOCAL: Final[int] = 3

#: `ipCidrRouteProto` onto the NCM's vocabulary. Anything unlisted becomes `other`
#: rather than being guessed at — `ciscoIgrp` and `idpr` are real values with no NCM
#: equivalent, and inventing one would put a protocol in the graph that nothing else
#: in the product understands.
_PROTOCOL: Final[dict[int, str]] = {
    2: "connected",  # local
    3: "static",  # netmgmt — set by management, which is what a static route is
    8: "rip",
    9: "isis",
    13: "ospf",
    14: "bgp",
    16: "eigrp",  # ciscoEigrp
}


class SnmpChannel(Protocol):
    """One request, one reply. Implemented by UDP; substituted by a fake in tests."""

    async def exchange(self, request: bytes) -> bytes: ...


@dataclass(slots=True)
class UdpChannel:
    """A single unconnected UDP socket, reused across a walk.

    One socket for the whole walk rather than one per datagram: a walk is dozens of
    exchanges and re-binding for each would burn ephemeral ports for nothing.
    """

    address: str
    timeout: float = 3.0
    port: int = SNMP_PORT
    _sock: socket.socket | None = None

    def __enter__(self) -> UdpChannel:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setblocking(False)
        return self

    def __exit__(self, *_: object) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    async def exchange(self, request: bytes) -> bytes:
        if self._sock is None:
            raise SnmpError("The channel is not open.")
        loop = asyncio.get_running_loop()
        try:
            await loop.sock_sendto(self._sock, request, (self.address, self.port))
            return await asyncio.wait_for(
                loop.sock_recv(self._sock, MAX_RESPONSE), timeout=self.timeout
            )
        except (TimeoutError, OSError) as exc:
            raise SnmpError(f"No SNMP response from {self.address}: {exc}") from exc


@dataclass(frozen=True, slots=True)
class RouteWalk:
    """What one device's forwarding table yielded, and how complete it is."""

    routes: tuple[Route, ...] = ()
    #: Routes the device holds that discard traffic. Excluded from `routes`, reported
    #: because a black hole and a missing route look identical from a path trace.
    rejected: int = 0
    #: True when a ceiling stopped the walk. The routes gathered are real; the table is
    #: not fully represented, and a caller must not read a miss as "no such route".
    truncated: bool = False
    #: Set when the agent answered and the table is genuinely empty, as opposed to the
    #: walk never having been attempted. Distinguishing these is the whole point.
    table_present: bool = False
    #: A one-line reason when nothing could be read, for the collection's notes.
    note: str | None = None
    packets: int = 0

    @property
    def usable(self) -> bool:
        return bool(self.routes)


def parse_route_index(oid: str, *, column: str) -> tuple[str, str, str] | None:
    """Pull ``(destination, mask, next_hop)`` out of an ``ipCidrRouteEntry`` OID.

    The index is ``dest(4) . mask(4) . tos(1) . nextHop(4)`` — thirteen arcs after the
    column. Anything else is not a row of this table, and is skipped rather than
    part-parsed into a route with plausible-looking wrong values.
    """
    if not oid.startswith(f"{column}."):
        return None

    arcs = oid[len(column) + 1 :].split(".")
    if len(arcs) != 13 or not all(arc.isdigit() and int(arc) < 256 for arc in arcs):
        return None

    destination = ".".join(arcs[0:4])
    mask = ".".join(arcs[4:8])
    next_hop = ".".join(arcs[9:13])
    return destination, mask, next_hop


def _prefix_length(mask: str) -> int | None:
    """Dotted mask to a prefix length, refusing non-contiguous masks.

    A non-contiguous mask cannot be written in CIDR, and coercing one would produce a
    prefix that matches addresses the device does not route.
    """
    try:
        value = int.from_bytes(bytes(int(part) for part in mask.split(".")), "big")
    except ValueError:
        return None
    if value == 0:
        return 0
    inverted = value ^ 0xFFFFFFFF
    if inverted & (inverted + 1):
        return None
    return 32 - inverted.bit_length()


def _build_route(
    index: tuple[str, str, str],
    *,
    route_type: int | None,
    protocol: int | None,
    interface: str | None,
) -> Route | None:
    destination, mask, next_hop = index
    length = _prefix_length(mask)
    if length is None:
        return None

    # 0.0.0.0 as a next hop means "on the link" in this MIB, and `Route.next_hop` says
    # None for exactly that. Carrying the literal zero would make every connected route
    # look like it forwarded to a host that does not exist.
    gateway = None if next_hop == "0.0.0.0" or route_type == _TYPE_LOCAL else next_hop

    resolved = _PROTOCOL.get(protocol or 0, "other")
    if route_type == _TYPE_LOCAL and resolved == "other":
        resolved = "connected"

    return Route(
        destination=f"{destination}/{length}",
        next_hop=gateway,
        interface=interface,
        protocol=resolved,
    )


async def _walk_column(
    channel: SnmpChannel,
    community: str,
    base: str,
    *,
    budget: list[int],
    max_rows: int = MAX_ROUTES,
) -> tuple[dict[str, VarBind], bool]:
    """GETBULK-walk one column. Returns ``(bindings_by_oid, truncated)``.

    Falls back to GETNEXT once, and only on an agent error: some older agents answer
    GETBULK with `genErr` rather than implementing it, and losing the whole table to
    that would be a poor trade for one retry.
    """
    found: dict[str, VarBind] = {}
    cursor = base
    bulk = True

    while True:
        if budget[0] <= 0 or len(found) >= max_rows:
            return found, True

        request_id = secrets.randbelow(0x7FFFFFFF)
        request = (
            build_getbulk(community, (cursor,), request_id)
            if bulk
            else build_getnext(community, (cursor,), request_id)
        )

        budget[0] -= 1
        try:
            bindings = parse_varbinds(await channel.exchange(request))
        except SnmpError:
            if not bulk:
                raise
            # One downgrade, then let the next failure surface.
            bulk = False
            continue

        if not bindings:
            return found, False

        before = cursor
        for binding in bindings:
            if binding.is_end_of_mib or not binding.oid.startswith(f"{base}."):
                return found, False
            if binding.is_absent:
                continue
            found[binding.oid] = binding
            cursor = binding.oid
            if len(found) >= max_rows:
                return found, True

        # Progress means the *cursor* moved, not that bindings arrived. An agent that
        # answers every request with the same row satisfies the second and never the
        # first, and without this the walk would spend its whole packet budget and then
        # report a truncated table — claiming a partial answer where it had a broken
        # agent.
        if cursor == before:
            # The agent returned a page that moved nothing forward. Continuing would
            # loop until the packet budget ran out and report a truncated table; saying
            # so immediately is more useful and cannot spin.
            raise SnmpError("SNMP agent did not advance the walk.")


async def walk_routes(
    channel: SnmpChannel,
    community: str,
    *,
    max_routes: int = MAX_ROUTES,
    max_packets: int = MAX_PACKETS,
    with_interfaces: bool = True,
) -> RouteWalk:
    """Read `ipCidrRouteTable` from one device.

    Never raises for an ordinary failure: a device that does not answer, does not
    implement the MIB or refuses the community is a normal outcome of collecting from a
    mixed estate, and the caller needs a result it can record beside the snapshot rather
    than an exception that abandons the collection.
    """
    budget = [max_packets]

    try:
        protos, truncated = await _walk_column(
            channel, community, IP_CIDR_ROUTE_PROTO, budget=budget, max_rows=max_routes
        )
    except SnmpError as exc:
        return RouteWalk(note=str(exc), packets=max_packets - budget[0])

    if not protos:
        # The agent answered and the column is empty. That is a real answer — the device
        # implements the MIB and has nothing in it, or exposes no view of it — and it is
        # recorded as such rather than as a failure.
        return RouteWalk(table_present=True, packets=max_packets - budget[0])

    types: dict[str, VarBind] = {}
    if_indexes: dict[str, VarBind] = {}
    interfaces: dict[int, str] = {}

    try:
        types, types_truncated = await _walk_column(
            channel, community, IP_CIDR_ROUTE_TYPE, budget=budget, max_rows=max_routes
        )
        truncated = truncated or types_truncated

        if with_interfaces:
            if_indexes, index_truncated = await _walk_column(
                channel, community, IP_CIDR_ROUTE_IF_INDEX, budget=budget, max_rows=max_routes
            )
            truncated = truncated or index_truncated

            descrs, _ = await _walk_column(channel, community, IF_DESCR, budget=budget)
            interfaces = {
                int(oid.rsplit(".", 1)[-1]): str(binding.value)
                for oid, binding in descrs.items()
                if binding.value is not None
            }
    except SnmpError as exc:
        # The protocol column succeeded, so there are real routes. The supplementary
        # columns failing degrades them rather than voiding them — which is the same
        # judgement FR-COL-08 makes about a partial collection.
        log.info("snmp.routes.partial", reason=str(exc))

    routes: list[Route] = []
    rejected = 0

    for oid, proto in protos.items():
        index = parse_route_index(oid, column=IP_CIDR_ROUTE_PROTO)
        if index is None:
            continue

        suffix = oid[len(IP_CIDR_ROUTE_PROTO) :]
        type_binding = types.get(f"{IP_CIDR_ROUTE_TYPE}{suffix}")
        route_type = type_binding.value if type_binding else None

        if route_type == _TYPE_REJECT:
            rejected += 1
            continue

        index_binding = if_indexes.get(f"{IP_CIDR_ROUTE_IF_INDEX}{suffix}")
        interface = None
        if index_binding is not None and isinstance(index_binding.value, int):
            interface = interfaces.get(index_binding.value)

        route = _build_route(
            index,
            route_type=route_type if isinstance(route_type, int) else None,
            protocol=proto.value if isinstance(proto.value, int) else None,
            interface=interface,
        )
        if route is not None:
            routes.append(route)

    return RouteWalk(
        routes=tuple(routes),
        rejected=rejected,
        truncated=truncated,
        table_present=True,
        packets=max_packets - budget[0],
    )


__all__ = [
    "IF_DESCR",
    "IP_CIDR_ROUTE_PROTO",
    "IP_CIDR_ROUTE_TABLE",
    "MAX_PACKETS",
    "MAX_ROUTES",
    "RouteWalk",
    "SnmpChannel",
    "UdpChannel",
    "parse_route_index",
    "walk_routes",
]
