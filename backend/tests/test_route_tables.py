"""Operational forwarding-table parsing (FR-TOPO-01).

The assertions here are written against what the fixture files actually contain, read by
hand. A route table that parses to *nothing* looks exactly like a device with no routes,
and a route parsed with the wrong prefix length looks exactly like a route — so almost
every failure in this module is silent, and the tests are shaped to catch the silent
ones rather than to exercise the happy path twice.
"""

from __future__ import annotations

import pathlib

import pytest

from netsecops.parsers.route_tables import (
    PROTOCOL_BY_CODE,
    parse_cisco_route_table,
    parse_nxos_route_table,
)

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "operational"


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


def find(routes, destination, next_hop=None):
    """The route to a destination, optionally disambiguated by next hop."""
    matches = [
        r
        for r in routes
        if r.destination == destination and (next_hop is None or r.next_hop == next_hop)
    ]
    assert matches, f"no route to {destination}" + (f" via {next_hop}" if next_hop else "")
    return matches[0]


# ────────────────────────────── Cisco IOS ───────────────────────────────


class TestCiscoIos:
    # Function-scoped deliberately: a class-scoped fixture defined as an instance method
    # is deprecated in pytest 8 and removed in 10, and these files are small enough that
    # re-parsing per test costs nothing.
    @pytest.fixture
    def routes(self):
        return parse_cisco_route_table(load("cisco_ios/show_ip_route.txt"))

    def test_reads_every_route_and_no_legend_lines(self, routes):
        # Ten entries: one default, two connected/local, two OSPF, two subnetted OSPF,
        # one BGP and two equal-cost EIGRP. The legend at the top of the file is eight
        # lines that all begin with a letter, which is what a naive reader treats as
        # routes.
        assert len(routes) == 10

    def test_default_route(self, routes):
        default = find(routes, "0.0.0.0/0")
        assert (default.next_hop, default.protocol, default.distance) == ("10.10.10.1", "static", 1)

    def test_connected_and_local_are_distinguished(self, routes):
        assert find(routes, "10.10.10.0/24").protocol == "connected"
        assert find(routes, "10.10.10.2/32").protocol == "local"

    def test_ospf_subtypes_collapse_to_the_family(self, routes):
        # `O` and `O IA` are both OSPF. Classifying by the qualifier instead of the
        # protocol letter would make inter-area routes their own protocol.
        assert find(routes, "10.10.0.0/24").protocol == "ospf"
        assert find(routes, "10.20.0.0/24").protocol == "ospf"

    def test_subnetted_children_inherit_the_parent_prefix_length(self, routes):
        # The fixture prints `172.16.1.0` with no length under
        # `172.16.0.0/24 is subnetted`. Read literally that is a /32 — a host route to a
        # network address, which matches no traffic and silently removes the subnet.
        assert find(routes, "172.16.1.0/24").protocol == "ospf"
        assert find(routes, "172.16.2.0/24").protocol == "ospf"
        assert not [r for r in routes if r.destination.startswith("172.16.1.0/32")]

    def test_equal_cost_paths_become_separate_routes(self, routes):
        eigrp = [r for r in routes if r.destination == "198.51.100.0/24"]
        assert len(eigrp) == 2
        assert {r.next_hop for r in eigrp} == {"10.10.10.1", "10.10.10.3"}
        # The continuation line carries no protocol code of its own, so it has to inherit
        # one. Left as None, half a redundant path is an edge of unknown origin.
        assert {r.protocol for r in eigrp} == {"eigrp"}

    def test_uptime_is_not_mistaken_for_an_interface(self, routes):
        # `B 192.0.2.0/24 [20/0] via 10.10.10.1, 01:22:41` ends with an uptime and names
        # no interface. Reading the last field blindly gives an interface of "01:22:41".
        bgp = find(routes, "192.0.2.0/24")
        assert (bgp.protocol, bgp.interface) == ("bgp", None)

    def test_interface_read_from_the_tail(self, routes):
        assert find(routes, "10.10.0.0/24").interface == "Vlan10"

    def test_distance_and_metric(self, routes):
        ospf = find(routes, "10.10.0.0/24")
        assert (ospf.distance, ospf.metric) == (110, 2)


# ───────────────────────────── Cisco ASA ────────────────────────────────


class TestCiscoAsa:
    # Function-scoped deliberately: a class-scoped fixture defined as an instance method
    # is deprecated in pytest 8 and removed in 10, and these files are small enough that
    # re-parsing per test costs nothing.
    @pytest.fixture
    def routes(self):
        return parse_cisco_route_table(load("cisco_asa/show_route.txt"))

    def test_dotted_masks_normalise_to_cidr(self, routes):
        # ASA prints `10.10.0.0 255.255.255.0`, not `10.10.0.0/24`. Stored as text the
        # graph never matches a route to its own subnet.
        assert find(routes, "10.10.0.0/24").protocol == "connected"
        assert find(routes, "203.0.113.0/29").interface == "outside"

    def test_default_route_with_a_zero_mask(self, routes):
        # `0.0.0.0 0.0.0.0` — the mask is a valid netmask and must not be read as a next
        # hop, and the destination must not become a /32.
        default = find(routes, "0.0.0.0/0")
        assert (default.next_hop, default.interface) == ("203.0.113.1", "outside")

    def test_a_next_hop_is_not_mistaken_for_a_mask(self, routes):
        # `S 10.30.0.0 255.255.0.0 [1/0] via 10.10.0.2, inside` has both. Only the
        # contiguous mask may be consumed as one.
        static = find(routes, "10.30.0.0/16")
        assert (static.next_hop, static.protocol) == ("10.10.0.2", "static")

    def test_nameif_is_the_interface(self, routes):
        assert find(routes, "10.20.0.0/24").interface == "dmz"


# ─────────────────────────────── FortiOS ────────────────────────────────


class TestFortiOs:
    # Function-scoped deliberately: a class-scoped fixture defined as an instance method
    # is deprecated in pytest 8 and removed in 10, and these files are small enough that
    # re-parsing per test costs nothing.
    @pytest.fixture
    def routes(self):
        return parse_cisco_route_table(load("fortios/get_router_info_routing_table_all.txt"))

    def test_interface_precedes_the_uptime(self, routes):
        # FortiOS prints `via 10.10.0.2, internal, 01:05:44` where IOS prints the
        # interface last. Position-based reading gets one of the two wrong.
        ospf = find(routes, "10.10.10.0/24")
        assert (ospf.interface, ospf.protocol) == ("internal", "ospf")

    def test_route_without_an_uptime(self, routes):
        static = find(routes, "10.30.0.0/16")
        assert (static.interface, static.next_hop) == ("internal", "10.10.0.2")

    def test_default_and_connected(self, routes):
        assert find(routes, "0.0.0.0/0").interface == "wan1"
        assert find(routes, "10.100.0.0/24").protocol == "connected"


# ──────────────────────────────── NX-OS ─────────────────────────────────


class TestNxos:
    # Function-scoped deliberately: a class-scoped fixture defined as an instance method
    # is deprecated in pytest 8 and removed in 10, and these files are small enough that
    # re-parsing per test costs nothing.
    @pytest.fixture
    def routes(self):
        return parse_nxos_route_table(load("cisco_nxos/show_ip_route.txt"))

    def test_vrfs_stay_separate(self, routes):
        # Two default routes exist in this fixture, one per VRF. Merged, a management
        # route would answer a global lookup and join networks that by design cannot
        # reach each other.
        defaults = [r for r in routes if r.destination == "0.0.0.0/0"]
        assert len(defaults) == 2
        assert {r.vrf for r in defaults} == {None, "management"}

    def test_default_vrf_is_stored_as_none(self, routes):
        # The global table is the absence of a VRF everywhere else in the NCM. Storing
        # the literal "default" would make a global route fail a global lookup.
        assert find(routes, "10.10.10.0/24").vrf is None

    def test_interface_is_the_field_after_the_gateway(self, routes):
        # NX-OS ends its lines with the protocol and route type, so a reader that works
        # backwards picks up `direct`, `intra` or a BGP tag as the interface name.
        assert find(routes, "10.10.0.0/24", "10.10.10.1").interface == "Vlan10"
        assert find(routes, "10.100.0.0/24").interface == "mgmt0"

    def test_bgp_tag_is_not_an_interface(self, routes):
        bgp = find(routes, "192.0.2.0/24")
        assert (bgp.protocol, bgp.interface) == ("bgp", None)

    def test_protocol_words_map_to_families(self, routes):
        # `direct` is NX-OS for connected, and `ospf-1` carries its instance number.
        assert find(routes, "10.10.10.0/24").protocol == "connected"
        assert find(routes, "10.10.10.2/32").protocol == "local"
        assert find(routes, "10.10.0.0/24", "10.10.10.1").protocol == "ospf"

    def test_null_route_has_an_interface_and_no_gateway(self, routes):
        # `*via Null0` — the first field is an interface, not an address. Stored as a
        # next hop it becomes an edge to a device that does not exist.
        discard = next(r for r in routes if r.destination == "0.0.0.0/0" and r.vrf is None)
        assert (discard.next_hop, discard.interface) == (None, "Null0")

    def test_equal_cost_paths(self, routes):
        paths = [r for r in routes if r.destination == "10.10.0.0/24"]
        assert {r.next_hop for r in paths} == {"10.10.10.1", "10.10.10.3"}


# ───────────────────────────── robustness ───────────────────────────────


class TestRobustness:
    def test_crlf_is_handled(self):
        # Device output arrives over SSH with CRLF, and the fixtures store it that way.
        # A stray carriage return on the end of every line turns each interface name into
        # one that matches nothing.
        routes = parse_cisco_route_table("S*    0.0.0.0/0 [1/0] via 10.0.0.1, Gi0/1\r\n")
        assert routes[0].interface == "Gi0/1"

    @pytest.mark.parametrize("age", ["00:05:23", "1w2d", "3d04h", "never"])
    def test_uptimes_are_never_read_as_interfaces(self, age):
        # Route tables print uptime in several shapes and all of them sit where an
        # interface name sits. `never` is the one a fixture is least likely to contain
        # and the one a device shows for a route that has not flapped since boot.
        routes = parse_cisco_route_table(f"O    10.0.0.0/8 [110/2] via 10.1.1.1, {age}\n")
        assert routes[0].interface is None

    def test_a_non_contiguous_mask_is_not_consumed(self):
        # `255.0.255.0` is four valid octets and not a subnet mask. Accepting it feeds an
        # impossible prefix to normalisation, which drops the route entirely — so the
        # check that survives here is the difference between one route and none.
        routes = parse_cisco_route_table("S    10.30.0.0 255.0.255.0 [1/0] via 10.1.1.1\n")
        assert len(routes) == 1

    @pytest.mark.parametrize("code", ["S*", "S%", "S+", "S*%"])
    def test_route_flags_are_stripped_from_the_code(self, code):
        # `*` marks a candidate default, `%` a next-hop override and `+` a replicated
        # route. They attach to the protocol letter, and a reader that does not strip
        # them drops precisely the default route that matters most to a path walk.
        routes = parse_cisco_route_table(f"{code}   0.0.0.0/0 [1/0] via 10.1.1.1\n")
        assert [r.protocol for r in routes] == ["static"]

    def test_empty_input_yields_no_routes(self):
        assert parse_cisco_route_table("") == []
        assert parse_nxos_route_table("") == []

    def test_legend_only_output_yields_no_routes(self):
        # Every line of a legend begins with a letter, like every route line.
        legend = "Codes: L - local, C - connected, S - static\n       D - EIGRP, O - OSPF\n"
        assert parse_cisco_route_table(legend) == []

    def test_unparseable_destination_is_dropped_not_guessed(self):
        # A wrong edge answers confidently; a missing one resolves to Unknown and asks a
        # human. The second is the safe failure.
        assert parse_cisco_route_table("S    999.999.999.999/24 [1/0] via 10.0.0.1\n") == []

    def test_gateway_of_last_resort_line_is_not_a_route(self):
        text = "Gateway of last resort is 10.0.0.1 to network 0.0.0.0\n"
        assert parse_cisco_route_table(text) == []

    def test_vrf_is_carried_onto_cisco_routes_when_given(self):
        routes = parse_cisco_route_table("S 10.0.0.0/8 [1/0] via 10.1.1.1\n", vrf="tenant-a")
        assert routes[0].vrf == "tenant-a"

    def test_continuation_before_any_route_is_ignored(self):
        # Truncated output can begin mid-entry. There is no destination to attach it to.
        assert parse_cisco_route_table("        [110/2] via 10.0.0.5, Gi0/1\n") == []

    def test_every_documented_code_maps_to_a_known_family(self):
        # Route.protocol documents a closed set. A code mapping to something outside it
        # would store a protocol no consumer handles.
        allowed = {
            "connected",
            "local",
            "static",
            "ospf",
            "bgp",
            "eigrp",
            "rip",
            "isis",
            "mobile",
            "other",
        }
        assert set(PROTOCOL_BY_CODE.values()) <= allowed
