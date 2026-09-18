"""Reading forwarding tables out of configurations (FR-TOPO-01).

A topology graph is built by matching a route's destination against the subnets other
devices serve. Every failure mode of that matching is silent: a prefix stored in the
wrong spelling does not raise, it simply never matches, and the result is an estate that
looks like a set of disconnected islands with every path answering Unknown. Nothing goes
red. So the normalisation is tested spelling by spelling, and each vendor's grammar is
tested through its real parser rather than against the regex alone.

The corpus cannot carry this on its own. Only the ASA fixture has static routes — the
others are switches, or firewalls whose fixtures predate anyone caring where a packet
goes — so the vendor cases below use inline configurations. They are small on purpose:
each one is the smallest input that distinguishes a correct reader from a plausible
wrong one.

Two mutations worth trying on anything here: make `to_cidr` return its input unchanged,
and delete the `admin_up is False` guard in `connected_routes`. Both leave a graph that
builds, looks populated, and is wrong.
"""

from __future__ import annotations

import pytest

from netsecops.ncm.models import NCM_VERSION, Interface, NormalisedConfig
from netsecops.parsers.base import ParseContext, ParseResult
from netsecops.parsers.registry import get_parser
from netsecops.parsers.routes import (
    MAX_ROUTES_PER_DEVICE,
    connected_routes,
    interface_network,
    is_ip,
    parse_asa_route,
    parse_ios_static_route,
    store,
    to_cidr,
)


def parse(platform: str, text: str):
    return get_parser(platform).parse(ParseContext(text=text))


def destinations(ncm, protocol: str | None = None) -> set[str]:
    return {
        route.destination
        for route in ncm.routing.routes
        if protocol is None or route.protocol == protocol
    }


def _iface(n: int) -> Interface:
    """A distinct addressed interface, for filling a route table to its cap."""
    return Interface(name=f"e{n}", ip_addresses=[f"10.{n // 256}.{n % 256}.1/24"])


def route_for(ncm, destination: str):
    for route in ncm.routing.routes:
        if route.destination == destination:
            return route
    raise AssertionError(f"no route to {destination} in {destinations(ncm)}")


class TestOlderSnapshotsStillLoad:
    """The NCM is a stored schema, so removing a field breaks persisted data.

    `vuln_assessment` re-validates stored snapshots through
    `NormalisedConfig.model_validate`, and every NCM model sets ``extra="forbid"`` so a
    parser typo fails loudly. The same setting turns a field deleted from the schema into
    a validation error on every snapshot written before the deletion — for years of
    retained evidence, in production, on a path no test exercises, because tests build
    their snapshots with the current model.
    """

    def test_a_snapshot_written_before_routes_existed_still_validates(self) -> None:
        """`static_routes` was NCM 1.0's route field. It is dead and it must still load."""
        stored = {
            "ncm_version": "1.0",
            "routing": {"protocols": [], "static_routes": 3, "ip_source_routing": False},
        }

        ncm = NormalisedConfig.model_validate(stored)

        assert ncm.routing.static_routes == 3
        assert ncm.routing.routes == []

    def test_a_parser_no_longer_writes_the_superseded_count(self) -> None:
        """One field, one source of truth. A count beside the list it summarises is an
        invitation for the two to disagree with no way to tell which is right."""
        ncm = parse(
            "cisco_ios",
            "hostname r1\nip route 10.0.0.0 255.0.0.0 192.0.2.1\n",
        )

        assert ncm.routing.static_routes is None
        assert len(ncm.routing.routes) == 1


# ═════════════════════ the normalisation everything rests on ═════════════════


class TestPrefixNormalisation:
    @pytest.mark.parametrize(
        ("network", "mask", "expected"),
        [
            # The same /8, as each of this product's five platforms writes it.
            ("10.0.0.0", "255.0.0.0", "10.0.0.0/8"),
            ("10.0.0.0", "8", "10.0.0.0/8"),
            ("10.0.0.0/8", None, "10.0.0.0/8"),
            ("10.0.0.0", 8, "10.0.0.0/8"),
            # Host routes.
            ("192.0.2.1", "255.255.255.255", "192.0.2.1/32"),
            ("192.0.2.1", None, "192.0.2.1/32"),
            # An address inside the subnet rather than the network address. Operators
            # write this constantly and mean the network.
            ("10.1.1.5", "255.255.255.0", "10.1.1.0/24"),
        ],
    )
    def test_every_spelling_of_one_network_normalises_the_same(
        self, network: str, mask: str | int | None, expected: str
    ) -> None:
        assert to_cidr(network, mask) == expected

    @pytest.mark.parametrize("spelling", ["default", "DEFAULT", "default-route", "0.0.0.0", "any"])
    def test_every_spelling_of_the_default_route_agrees(self, spelling: str) -> None:
        """The route that matters most to a path walk, and the one spelled most ways.

        A default stored as the literal `default` never matches anything, so a firewall
        with a default route looks like one with no way out — which reads as a dead end
        rather than as a gateway to somewhere unmanaged.
        """
        assert to_cidr(spelling) == "0.0.0.0/0"

    def test_an_unreadable_destination_is_dropped_rather_than_guessed(self) -> None:
        """A wrong edge answers confidently; a missing one asks for a human."""
        assert to_cidr("not-an-address", "255.0.0.0") is None
        assert to_cidr("10.0.0.0", "not-a-mask") is None
        assert to_cidr("") is None

    def test_a_token_is_only_a_next_hop_if_it_is_an_address(self) -> None:
        """IOS accepts a gateway or an interface in the same argument position."""
        assert is_ip("192.0.2.1") is True
        assert is_ip("GigabitEthernet0/1") is False
        assert is_ip(None) is False


class TestInterfaceAddressing:
    @pytest.mark.parametrize(
        ("address", "expected"),
        [
            ("10.1.1.1/24", "10.1.1.0/24"),
            ("10.1.1.1/255.255.255.0", "10.1.1.0/24"),
            # FortiOS stores what the device prints, which is space-separated. Requiring
            # a slash yields zero connected routes on every FortiGate — and zero is
            # indistinguishable from a device with no addressed interfaces.
            ("10.1.1.1 255.255.255.0", "10.1.1.0/24"),
        ],
    )
    def test_all_three_stored_forms_resolve(self, address: str, expected: str) -> None:
        assert interface_network(address) == expected

    def test_a_bare_address_has_no_subnet(self) -> None:
        assert interface_network("10.1.1.1") is None


# ══════════════════════════ connected routes ═════════════════════════════════


class TestConnectedRoutes:
    def test_an_addressed_interface_becomes_a_route_to_its_subnet(self) -> None:
        routes = connected_routes([Interface(name="Gi0/1", ip_addresses=["10.1.1.1/24"])])

        assert len(routes) == 1
        assert routes[0].destination == "10.1.1.0/24"
        assert routes[0].protocol == "connected"
        assert routes[0].next_hop is None
        assert routes[0].interface == "Gi0/1"

    def test_a_shut_interface_contributes_nothing(self) -> None:
        """A decommissioned link must not look live.

        The subnet is not reachable through an interface that is administratively down,
        and an edge drawn for it makes a path succeed through a link that forwards
        nothing.
        """
        routes = connected_routes(
            [Interface(name="Gi0/2", ip_addresses=["10.9.9.1/24"], admin_up=False)]
        )

        assert routes == []

    def test_an_interface_of_unknown_state_still_counts(self) -> None:
        """Absent is not false. `admin_up=None` means the parser could not tell."""
        routes = connected_routes(
            [Interface(name="Gi0/3", ip_addresses=["10.8.8.1/24"], admin_up=None)]
        )

        assert len(routes) == 1

    def test_a_secondary_address_is_its_own_route(self) -> None:
        routes = connected_routes(
            [Interface(name="Gi0/4", ip_addresses=["10.1.1.1/24", "10.2.2.1/24"])]
        )

        assert {route.destination for route in routes} == {"10.1.1.0/24", "10.2.2.0/24"}


class TestTheRouteCap:
    @staticmethod
    def _result() -> ParseResult:
        return ParseResult(ParseContext(text=""))

    def test_storing_within_the_cap_does_not_flag_truncation(self) -> None:
        result = self._result()

        store(result, [(route, None) for route in connected_routes([_iface(0)])])

        assert len(result.ncm.routing.routes) == 1
        assert result.ncm.routing.routes_truncated is None

    def test_crossing_the_cap_is_recorded_rather_than_silently_dropped(self) -> None:
        """A path falling off the end of a truncated table must answer Unknown.

        Truncating is fine — nobody assesses a million BGP routes. Truncating without
        saying so turns "we stopped looking" into "there is no route", which is the same
        class of error as reporting an unevaluated check as a pass.
        """
        result = self._result()
        interfaces = [_iface(n) for n in range(MAX_ROUTES_PER_DEVICE + 10)]

        store(result, [(route, None) for route in connected_routes(interfaces)])

        assert len(result.ncm.routing.routes) == MAX_ROUTES_PER_DEVICE
        assert result.ncm.routing.routes_truncated is True

    def test_a_route_read_from_a_line_carries_its_provenance(self) -> None:
        """FR-PARSE-04. "Why does this device claim a route to 10.50/16" is answered by
        the configuration line, not by a note that the list came from the file."""
        result = self._result()
        route = parse_ios_static_route("ip route 10.50.0.0 255.255.0.0 192.0.2.1")
        assert route is not None

        store(result, [(route, 42)])

        assert "routing.routes.0" in result.ncm.provenance.entries

    def test_a_derived_route_is_left_unattributed_rather_than_misattributed(self) -> None:
        """A connected route was not written on any line.

        Its provenance is the interface it came from, which is recorded separately.
        Pointing it at a line it does not appear on would be worse than leaving it blank.
        """
        result = self._result()

        store(result, [(route, None) for route in connected_routes([_iface(0)])])

        assert "routing.routes.0" not in result.ncm.provenance.entries


# ═════════════════════════ per-vendor grammars ═══════════════════════════════


class TestIosStaticRoutes:
    def test_a_plain_static_route(self) -> None:
        route = parse_ios_static_route("ip route 10.0.0.0 255.0.0.0 192.0.2.1")

        assert route is not None
        assert (route.destination, route.next_hop, route.protocol) == (
            "10.0.0.0/8",
            "192.0.2.1",
            "static",
        )

    def test_an_interface_routed_default_is_not_a_route_to_nowhere(self) -> None:
        """IOS accepts an egress interface where a gateway would go.

        Read positionally, `GigabitEthernet0/1` lands in the next-hop field and the route
        points at a host that does not exist. Sorting the trailing tokens by what they
        *are* is what keeps this right.
        """
        route = parse_ios_static_route("ip route 0.0.0.0 0.0.0.0 GigabitEthernet0/1")

        assert route is not None
        assert route.destination == "0.0.0.0/0"
        assert route.next_hop is None
        assert route.interface == "GigabitEthernet0/1"

    def test_an_interface_and_a_gateway_together(self) -> None:
        route = parse_ios_static_route("ip route 10.0.0.0 255.0.0.0 GigabitEthernet0/1 192.0.2.1")

        assert route is not None
        assert route.interface == "GigabitEthernet0/1"
        assert route.next_hop == "192.0.2.1"

    def test_a_trailing_distance_is_not_mistaken_for_an_interface(self) -> None:
        route = parse_ios_static_route("ip route 10.0.0.0 255.0.0.0 192.0.2.1 210")

        assert route is not None
        assert route.distance == 210
        assert route.interface is None

    def test_a_named_route_does_not_absorb_its_own_name(self) -> None:
        """`name core-uplink` would otherwise leave `core-uplink` looking like an
        interface, and the route would claim an egress port that does not exist."""
        route = parse_ios_static_route("ip route 10.0.0.0 255.0.0.0 192.0.2.1 name core-uplink")

        assert route is not None
        assert route.interface is None
        assert route.next_hop == "192.0.2.1"

    def test_a_vrf_route_keeps_its_vrf(self) -> None:
        """Two VRFs holding the same prefix do not compete, and must not be merged."""
        route = parse_ios_static_route("ip route vrf MGMT 10.0.0.0 255.0.0.0 192.0.2.1")

        assert route is not None
        assert route.vrf == "MGMT"

    def test_it_reaches_the_ncm_through_the_real_parser(self) -> None:
        ncm = parse(
            "cisco_ios",
            "hostname edge-rtr\n"
            "interface GigabitEthernet0/1\n"
            " ip address 192.0.2.2 255.255.255.248\n"
            "ip route 0.0.0.0 0.0.0.0 192.0.2.1\n"
            "ip route 10.50.0.0 255.255.0.0 192.0.2.1\n",
        )

        assert ncm.ncm_version == NCM_VERSION
        assert destinations(ncm, "static") == {"0.0.0.0/0", "10.50.0.0/16"}
        assert destinations(ncm, "connected") == {"192.0.2.0/29"}


class TestNxosStaticRoutes:
    def test_a_prefix_length_mask_normalises_like_a_dotted_one(self) -> None:
        """NX-OS writes `10.0.0.0/8` where IOS writes a dotted mask. One reader.

        This caught the reader storing `10.0.0.0/8` as a /32: the destination pattern
        matched only the dotted-quad, the slash went unmatched, and the mask group stayed
        empty. A host route to a network address matches nothing, so the /8 vanished from
        the graph with no error — and `0.0.0.0/0` still worked, because the default-route
        special case rescued it. One passing case hiding a broken one is why this asserts
        a non-default prefix.
        """
        ncm = parse(
            "cisco_nxos",
            "hostname dc-sw\nip route 10.0.0.0/8 192.0.2.1\nip route 0.0.0.0/0 192.0.2.254\n",
        )

        assert destinations(ncm, "static") == {"10.0.0.0/8", "0.0.0.0/0"}


class TestAsaRoutes:
    def test_the_first_argument_is_the_interface_not_the_destination(self) -> None:
        """The reason ASA cannot reuse the IOS reader.

        Fed to the IOS expression, `outside` reads as the destination and the entry is
        dropped — silently, because an unreadable route is dropped rather than guessed.
        """
        route = parse_asa_route("route outside 0.0.0.0 0.0.0.0 203.0.113.1 1")

        assert route is not None
        assert route.interface == "outside"
        assert route.destination == "0.0.0.0/0"
        assert route.next_hop == "203.0.113.1"
        assert route.metric == 1

    def test_the_fixture_firewall_has_its_default_route(self) -> None:
        """Through the corpus, since ASA is the one platform whose fixture has routes."""
        import pathlib

        fixture = next(pathlib.Path("tests/fixtures").rglob("edge_firewall.cfg"))
        ncm = parse("cisco_asa", fixture.read_text(encoding="utf-8"))

        default = route_for(ncm, "0.0.0.0/0")
        assert default.protocol == "static"
        assert default.interface == "outside"


class TestFortiosStaticRoutes:
    CONFIG = """config system interface
    edit "wan1"
        set ip 203.0.113.2 255.255.255.248
    next
end
config router static
    edit 1
        set gateway 203.0.113.1
        set device "wan1"
    next
    edit 2
        set dst 10.50.0.0 255.255.0.0
        set gateway 10.1.1.254
        set device "internal"
        set distance 15
    next
    edit 3
        set dst 172.16.0.0 255.240.0.0
        set gateway 10.1.1.253
        set status disable
    next
end
"""

    def test_an_absent_destination_means_the_default_route(self) -> None:
        """FortiOS omits `set dst` entirely for a default rather than writing 0.0.0.0.

        Skipping entries without a destination would drop precisely the route a path
        walk needs most.
        """
        ncm = parse("fortios", self.CONFIG)

        default = route_for(ncm, "0.0.0.0/0")
        assert default.next_hop == "203.0.113.1"
        assert default.interface == "wan1"

    def test_a_space_separated_destination_normalises(self) -> None:
        ncm = parse("fortios", self.CONFIG)

        route = route_for(ncm, "10.50.0.0/16")
        assert route.distance == 15
        assert route.interface == "internal"

    def test_a_disabled_route_is_not_in_the_forwarding_table(self) -> None:
        """It is configured and not installed. An edge for it is a path the device
        will not take."""
        ncm = parse("fortios", self.CONFIG)

        assert "172.16.0.0/12" not in destinations(ncm)


class TestGaiaStaticRoutes:
    CONFIG = """set interface eth0 ipv4-address 203.0.113.2 mask-length 29
set static-route default nexthop gateway address 203.0.113.1 on
set static-route 10.50.0.0/16 nexthop gateway address 10.1.1.254 on
set static-route 10.60.0.0/16 nexthop gateway logical eth2 on
set static-route 172.16.0.0/12 nexthop gateway address 10.1.1.253 off
"""

    def test_a_default_route_written_as_the_word_default(self) -> None:
        ncm = parse("checkpoint_gaia", self.CONFIG)

        assert route_for(ncm, "0.0.0.0/0").next_hop == "203.0.113.1"

    def test_a_logical_nexthop_is_an_interface_not_a_gateway(self) -> None:
        """Gaia puts an address or an egress interface in the same grammatical slot."""
        ncm = parse("checkpoint_gaia", self.CONFIG)

        route = route_for(ncm, "10.60.0.0/16")
        assert route.interface == "eth2"
        assert route.next_hop is None

    def test_a_route_switched_off_is_configured_and_not_installed(self) -> None:
        ncm = parse("checkpoint_gaia", self.CONFIG)

        assert "172.16.0.0/12" not in destinations(ncm)


class TestPanosStaticRoutes:
    CONFIG = """<config>
  <devices><entry name="localhost.localdomain"><network>
    <interface><ethernet>
      <entry name="ethernet1/1"><layer3><ip><entry name="203.0.113.2/29"/></ip></layer3></entry>
    </ethernet></interface>
    <virtual-router>
      <entry name="default">
        <routing-table><ip><static-route>
          <entry name="to-internet">
            <destination>0.0.0.0/0</destination>
            <nexthop><ip-address>203.0.113.1</ip-address></nexthop>
            <interface>ethernet1/1</interface>
            <metric>10</metric>
          </entry>
          <entry name="blackhole">
            <destination>10.99.0.0/16</destination>
            <nexthop><discard/></nexthop>
          </entry>
        </static-route></ip></routing-table>
      </entry>
      <entry name="mgmt-vr">
        <routing-table><ip><static-route>
          <entry name="mgmt-default">
            <destination>0.0.0.0/0</destination>
            <nexthop><ip-address>10.100.0.1</ip-address></nexthop>
          </entry>
        </static-route></ip></routing-table>
      </entry>
    </virtual-router>
  </network></entry></devices>
</config>
"""

    def test_a_static_route_is_read_with_its_metric(self) -> None:
        ncm = parse("panos", self.CONFIG)

        routes = [r for r in ncm.routing.routes if r.destination == "0.0.0.0/0"]
        internet = next(r for r in routes if r.vrf == "default")
        assert internet.next_hop == "203.0.113.1"
        assert internet.metric == 10

    def test_two_virtual_routers_keep_their_own_default_routes(self) -> None:
        """Separate virtual routers are separate forwarding tables by design.

        Merging them lets a path cross between two networks a firewall exists to keep
        apart, which is the one error a reachability answer must never make.
        """
        ncm = parse("panos", self.CONFIG)

        defaults = {r.vrf: r.next_hop for r in ncm.routing.routes if r.destination == "0.0.0.0/0"}
        assert defaults == {"default": "203.0.113.1", "mgmt-vr": "10.100.0.1"}

    def test_a_discard_route_is_not_an_edge_to_anywhere(self) -> None:
        """A black hole is a deliberate drop. Drawing it as a hop invents reachability."""
        ncm = parse("panos", self.CONFIG)

        blackhole = route_for(ncm, "10.99.0.0/16")
        assert blackhole.next_hop is None
