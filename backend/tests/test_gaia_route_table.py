"""Check Point Gaia's forwarding table (FR-TOPO-01).

`show configuration` carries the static routes somebody typed. It carries nothing the
gateway learned, so a Check Point in a routed core reached the topology graph with its
statics only — and the graph could not say that was all it had.

This replaces the SNMP route walk, which was built for this gap on a premise that turned
out to be false in both halves: Gaia's `show route` was already on the §8.2 allow-list
and merely missing from the collection profile, and `ipCidrRouteTable` is not implemented
on most of the platforms the walk targeted anyway.

Output shapes are taken from Check Point's published examples, not invented:

    S    0.0.0.0/0          via 192.168.211.254, eth0, cost 0, age 16426
    C    127.0.0.0/8        is directly connected, lo
"""

from __future__ import annotations

from pathlib import Path

from netsecops.ncm.models import Route
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser
from netsecops.parsers.route_tables import parse_gaia_route_table

#: Kept beside the other real captures rather than inline, so the format this parser
#: claims to read is reviewable on its own.
SHOW_ROUTE = (
    Path(__file__).parent / "fixtures/operational/checkpoint_gaia/show_route.txt"
).read_text(encoding="utf-8")


def routes_by_destination(text: str) -> dict[str, Route]:
    return {route.destination: route for route in parse_gaia_route_table(text)}


def test_the_legend_is_not_parsed_as_routes() -> None:
    """Every legend letter is also a route code, so the header is the obvious trap.

    `O - OSPF IntraArea (IA - InterArea...` leads with a valid code, and without the
    requirement that a route line say where traffic goes it parses as a route.
    """
    parsed = parse_gaia_route_table(SHOW_ROUTE)

    assert len(parsed) == 9


def test_a_via_route_reads_hop_interface_and_cost() -> None:
    route = routes_by_destination(SHOW_ROUTE)["0.0.0.0/0"]

    assert route.next_hop == "192.168.211.254"
    assert route.interface == "eth0"
    assert route.protocol == "static"
    assert route.metric == 0


def test_the_interface_is_not_the_age() -> None:
    """The defect this parser exists to avoid, asserted directly.

    `_interface_from` walks the fields from the right and skips what looks like an
    uptime. Gaia ends its lines `cost 20, age 904`, and `904` matches no uptime
    spelling, so that helper hands back `904` as the egress interface — a plausible
    value no device has, which then silently fails to join anything in the graph.
    """
    route = routes_by_destination(SHOW_ROUTE)["10.20.0.0/16"]

    assert route.interface == "eth1"
    assert route.metric == 20


def test_a_connected_route_has_no_next_hop() -> None:
    """None here is an answer, not missing data: the destination is on the link."""
    route = routes_by_destination(SHOW_ROUTE)["127.0.0.0/8"]

    assert route.protocol == "connected"
    assert route.interface == "lo"
    assert route.next_hop is None


def test_learned_protocols_are_distinguished() -> None:
    """A graph built from statics alone is partial, and can only say so per edge."""
    parsed = routes_by_destination(SHOW_ROUTE)

    assert parsed["10.20.0.0/16"].protocol == "bgp"
    assert parsed["10.30.4.0/24"].protocol == "ospf"


def test_gaia_codes_are_not_read_with_ciscos_meanings() -> None:
    """Four letters collide, and the wrong answer is confident rather than empty.

    Gaia's `D` is a BGP default route; Cisco's is EIGRP. Gaia's `U` is Unreachable;
    Cisco's is a per-user static. Sharing one map would label a Check Point gateway's
    edges `eigrp` and `static`, which is harder to disbelieve than an unlabelled edge.
    """
    text = (
        "D         0.0.0.0/0           via 10.1.1.1, eth0, cost 0, age 10\n"
        "U         10.99.0.0/16        via 10.1.1.1, eth0, cost 0, age 10\n"
    )

    parsed = routes_by_destination(text)

    assert parsed["0.0.0.0/0"].protocol == "bgp"
    assert parsed["10.99.0.0/16"].protocol == "other"


def test_routes_the_device_is_not_forwarding_on_are_dropped() -> None:
    """A hidden or inactive route is a path that does not exist.

    Plain `show route` should not print these — they need `show route all` — so this is
    a guard rather than an expectation.
    """
    text = (
        "i         10.77.0.0/16        via 10.1.1.1, eth0, cost 0, age 10\n"
        "H         10.78.0.0/16        via 10.1.1.1, eth0, cost 0, age 10\n"
        "S         10.79.0.0/16        via 10.1.1.1, eth0, cost 0, age 10\n"
    )

    assert list(routes_by_destination(text)) == ["10.79.0.0/16"]


def test_the_parser_uses_show_route_when_the_collection_captured_it() -> None:
    """End to end: the operational table reaches the NCM through the Gaia parser."""
    config = (
        "set hostname cp-gw\nset static-route 10.5.0.0/16 nexthop gateway address 10.1.1.9 on\n"
    )

    ncm = get_parser("checkpoint_gaia").parse(
        ParseContext(
            text=config,
            command="show configuration",
            supporting={"show route": SHOW_ROUTE},
        )
    )

    destinations = {route.destination for route in ncm.routing.routes}
    assert "10.20.0.0/16" in destinations, "learned BGP route never reached the NCM"
    assert "10.30.4.0/24" in destinations


def test_without_show_route_the_static_routes_survive() -> None:
    """Falling back rather than erasing.

    A collection where the command failed must not leave the device with no routes at
    all — that reads as a gateway that routes nothing, rather than one we asked badly.
    """
    config = (
        "set hostname cp-gw\nset static-route 10.5.0.0/16 nexthop gateway address 10.1.1.9 on\n"
    )

    ncm = get_parser("checkpoint_gaia").parse(
        ParseContext(text=config, command="show configuration")
    )

    assert "10.5.0.0/16" in {route.destination for route in ncm.routing.routes}
