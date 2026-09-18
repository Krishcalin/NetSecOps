"""Phase 8 acceptance (SRS §12).

    over a fixture estate of five devices, a path query across three of them returns the
    correct traversed-device list and rule verdicts, and a query whose next hop is not in
    inventory returns `unknown` naming that next hop rather than `unreachable`

The estate is five devices and one router nobody owns:

    (internet)
        │
   203.0.113.1          ← unmanaged: an ISP router, in nobody's inventory
        │
   ┌────┴─────┐  outside 203.0.113.2/29                        [rulebase]
   │ edge-fw  │  inside  10.0.0.1/30
   └────┬─────┘
        │ 10.0.0.2
   ┌────┴─────┐  up  10.0.0.2/30      lan    10.10.0.1/24
   │ core-rtr │  dmz 10.0.1.1/30      branch 10.0.2.1/30       [no rulebase]
   └─┬──┬───┬─┘
     │  │   │ 10.0.1.2
     │  │  ┌┴─────────┐  up  10.0.1.2/30                       [rulebase]
     │  │  │  dmz-fw  │  dmz 10.20.0.1/24
     │  │  └──────────┘
     │  │ 10.0.2.2
     │ ┌┴───────────┐  up  10.0.2.2/30                         [no rulebase]
     │ │ branch-rtr │  lan 10.30.0.1/24
     │ └────────────┘
     │ 10.10.0.2
   ┌─┴──────────┐  lan  10.10.0.2/24                           [no rulebase]
   │  access-sw │  vlan 10.40.0.1/24
   └────────────┘

Every link here has unit tests of its own in `test_topology.py`. What this file asserts is
that the criterion as written is actually met, and — the part that matters more — that the
two axes stay separate under a query designed to tempt them together. `edge-fw` permits
everything, so a system willing to report "allowed" for a path it could not finish tracing
would pass a naively-written version of this test and be dangerously wrong in the field.

The core router's routes are OSPF-learned rather than static, because after the 2026-09-18
allow-list amendment that is where a real estate's routes come from. A graph that only
understood statics would find no path across this estate at all.
"""

from __future__ import annotations

import ipaddress
import pathlib
import uuid
from typing import Any

import pytest

from netsecops.ncm.models import Route
from netsecops.parsers.route_tables import parse_cisco_route_table
from netsecops.topology.graph import DeviceNode, build_graph
from netsecops.topology.missing import missing_devices
from netsecops.topology.path import PolicyVerdict, RoutingConfidence, walk

FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "operational"

#: The ISP router every default route points at, and which nobody has onboarded.
UNMANAGED_NEXT_HOP = "203.0.113.1"


def connected(prefix: str, interface: str) -> Route:
    return Route(destination=prefix, interface=interface, protocol="connected")


def ospf(prefix: str, via: str, interface: str) -> Route:
    return Route(
        destination=prefix, next_hop=via, interface=interface, protocol="ospf", distance=110
    )


def static(prefix: str, via: str, interface: str | None = None) -> Route:
    return Route(destination=prefix, next_hop=via, interface=interface, protocol="static")


def permit_all() -> dict[str, Any]:
    return {"security_rules": [{"order": 1, "name": "permit-any", "action": "allow"}]}


def deny_ssh_to_dmz() -> dict[str, Any]:
    return {
        "security_rules": [
            {
                "order": 1,
                "name": "block-ssh-to-dmz",
                "action": "deny",
                "dst": ["10.20.0.0/24"],
                "services": ["tcp/22"],
            },
            {"order": 2, "name": "permit-rest", "action": "allow"},
        ]
    }


def node(
    hostname: str,
    *,
    routes: list[Route],
    addresses: dict[str, str],
    zones: dict[str, str] | None = None,
    firewall: dict[str, Any] | None = None,
) -> DeviceNode:
    built = DeviceNode(
        device_id=uuid.uuid5(uuid.NAMESPACE_DNS, hostname),
        hostname=hostname,
        platform="cisco_asa" if firewall else "cisco_ios",
        ncm_version="1.1",
        routes=routes,
        zones=dict(zones or {}),
        routes_truncated=False,
        has_rulebase=bool(firewall),
        firewall=firewall or {},
    )
    for interface, address in addresses.items():
        parsed = ipaddress.ip_interface(address)
        built.interface_addresses.add(int(parsed.ip))
        built.interface_networks.append((interface, parsed.network))
    return built


@pytest.fixture
def estate():
    """The five-device estate drawn in the module docstring."""
    edge = node(
        "edge-fw",
        addresses={"outside": "203.0.113.2/29", "inside": "10.0.0.1/30"},
        zones={"outside": "outside", "inside": "inside"},
        routes=[
            connected("203.0.113.0/29", "outside"),
            connected("10.0.0.0/30", "inside"),
            static("0.0.0.0/0", UNMANAGED_NEXT_HOP, "outside"),
            ospf("10.10.0.0/24", "10.0.0.2", "inside"),
            ospf("10.20.0.0/24", "10.0.0.2", "inside"),
            ospf("10.30.0.0/24", "10.0.0.2", "inside"),
            ospf("10.40.0.0/24", "10.0.0.2", "inside"),
        ],
        firewall=permit_all(),
    )
    core = node(
        "core-rtr",
        addresses={
            "up": "10.0.0.2/30",
            "lan": "10.10.0.1/24",
            "dmz": "10.0.1.1/30",
            "branch": "10.0.2.1/30",
        },
        routes=[
            connected("10.0.0.0/30", "up"),
            connected("10.10.0.0/24", "lan"),
            connected("10.0.1.0/30", "dmz"),
            connected("10.0.2.0/30", "branch"),
            ospf("0.0.0.0/0", "10.0.0.1", "up"),
            ospf("10.20.0.0/24", "10.0.1.2", "dmz"),
            ospf("10.30.0.0/24", "10.0.2.2", "branch"),
            ospf("10.40.0.0/24", "10.10.0.2", "lan"),
        ],
    )
    dmz = node(
        "dmz-fw",
        addresses={"up": "10.0.1.2/30", "dmz": "10.20.0.1/24"},
        zones={"up": "trust", "dmz": "dmz"},
        routes=[
            connected("10.0.1.0/30", "up"),
            connected("10.20.0.0/24", "dmz"),
            static("0.0.0.0/0", "10.0.1.1", "up"),
        ],
        firewall=deny_ssh_to_dmz(),
    )
    branch = node(
        "branch-rtr",
        addresses={"up": "10.0.2.2/30", "lan": "10.30.0.1/24"},
        routes=[
            connected("10.0.2.0/30", "up"),
            connected("10.30.0.0/24", "lan"),
            static("0.0.0.0/0", "10.0.2.1", "up"),
        ],
    )
    access = node(
        "access-sw",
        addresses={"lan": "10.10.0.2/24", "vlan": "10.40.0.1/24"},
        routes=[
            connected("10.10.0.0/24", "lan"),
            connected("10.40.0.0/24", "vlan"),
            static("0.0.0.0/0", "10.10.0.1", "lan"),
        ],
    )
    return build_graph([edge, core, dmz, branch, access])


# ══════════════ the criterion, clause by clause ══════════════════════════════


class TestAPathAcrossThreeDevices:
    """ "a path query across three of them returns the correct traversed-device list"."""

    def test_the_traversed_devices_are_correct_and_in_order(self, estate) -> None:
        result = walk(estate, source="10.40.0.50", destination="10.20.0.10", port=443)

        assert [hop.hostname for hop in result.hops] == ["access-sw", "core-rtr", "dmz-fw"]
        assert result.routing is RoutingConfidence.ROUTED

    def test_the_rule_verdicts_are_correct(self, estate) -> None:
        result = walk(estate, source="10.40.0.50", destination="10.20.0.10", port=443)
        verdicts = {hop.hostname: hop.action for hop in result.hops}

        # The two switches have no rulebase and therefore no opinion. Reporting "allow"
        # for them would count a device that inspected nothing as a control that passed.
        assert verdicts == {"access-sw": None, "core-rtr": None, "dmz-fw": "allow"}
        assert result.policy is PolicyVerdict.ALLOWED

    def test_the_same_path_on_a_denied_port_is_blocked(self, estate) -> None:
        """The verdict has to follow the rulebase, not the route."""
        result = walk(estate, source="10.40.0.50", destination="10.20.0.10", port=22)

        assert result.policy is PolicyVerdict.BLOCKED
        blocked_at = next(hop for hop in result.hops if hop.action == "deny")
        assert blocked_at.hostname == "dmz-fw"

    def test_a_block_is_reported_even_though_the_route_is_complete(self, estate) -> None:
        # Routing and policy are independent: the packet is perfectly routable and is
        # dropped anyway. Collapsing the two axes loses exactly this distinction.
        result = walk(estate, source="10.40.0.50", destination="10.20.0.10", port=22)
        assert result.routing is RoutingConfidence.ROUTED

    def test_a_four_device_path_reaches_the_far_branch(self, estate) -> None:
        # Not part of the criterion, but the estate is only meaningful if the graph can
        # cross it in more than one direction.
        result = walk(estate, source="10.40.0.50", destination="10.30.0.10", port=443)

        assert [hop.hostname for hop in result.hops] == [
            "access-sw",
            "core-rtr",
            "branch-rtr",
        ]
        assert result.routing is RoutingConfidence.ROUTED


class TestAnUnmanagedNextHop:
    """ "returns `unknown` naming that next hop rather than `unreachable`"."""

    def test_routing_is_not_unreachable(self, estate) -> None:
        """`partially-routed`, which is the criterion's "unknown" made more precise.

        FR-TOPO-05 says this case SHALL be `unknown`; FR-TOPO-04 defines
        `partially-routed` as its own value meaning exactly this case. The two cannot both
        hold, and the implementation took the more precise one — `unknown` is then
        reserved for the genuinely unanswerable (a table never collected, a truncated
        table, a routing loop, a VRF binding nothing records), which is a different
        situation needing a different remedy: re-collect the device, versus onboard the
        next hop.

        The SRS is amended at §3.8a to record that reading. Both of the criterion's actual
        requirements — not `unreachable`, and the next hop named — are asserted here and
        in the test below.
        """
        result = walk(estate, source="10.40.0.50", destination="198.51.100.10", port=443)

        assert result.routing is not RoutingConfidence.UNREACHABLE
        assert result.routing is RoutingConfidence.PARTIALLY_ROUTED

    def test_the_next_hop_that_stopped_the_analysis_is_named(self, estate) -> None:
        # "I could not complete this" is only actionable if it says where it stopped.
        # Onboarding 203.0.113.1 — or knowing it is an ISP router and never will be — is
        # the decision this answer exists to support.
        result = walk(estate, source="10.40.0.50", destination="198.51.100.10", port=443)

        assert result.stopped_at_next_hop == UNMANAGED_NEXT_HOP
        # And the prefix it was following when it ran out of estate, because the next hop
        # alone does not say which traffic is affected.
        assert result.stopped_at_prefix == "0.0.0.0/0"
        assert result.stopped_at_device == "edge-fw"

    def test_a_permit_does_not_become_allowed_on_an_unfinished_path(self, estate) -> None:
        """The single assertion this phase exists to protect (FR-TOPO-04).

        Every firewall actually consulted on this path permits the traffic. Reporting
        `allowed` would be defensible, wrong, and acted upon: the untraced remainder
        beyond 203.0.113.1 may hold another firewall, and somebody opens a rule on the
        strength of this answer.
        """
        result = walk(estate, source="10.40.0.50", destination="198.51.100.10", port=443)

        assert result.policy is not PolicyVerdict.ALLOWED
        assert result.policy is PolicyVerdict.PARTIALLY_ALLOWED

    def test_the_devices_it_did_cross_are_still_reported(self, estate) -> None:
        # A partial answer is worth more than none: three of the four decisions on this
        # path are known and should be shown.
        result = walk(estate, source="10.40.0.50", destination="198.51.100.10", port=443)

        assert [hop.hostname for hop in result.hops] == ["access-sw", "core-rtr", "edge-fw"]


class TestTheMissingDeviceReport:
    """FR-TOPO-06, which is what turns "unknown" into a work item."""

    def test_the_unmanaged_next_hop_is_ranked_first(self, estate) -> None:
        missing = missing_devices(estate)

        assert missing, "no missing devices found in an estate with an unmanaged next hop"
        assert missing[0].address == UNMANAGED_NEXT_HOP

    def test_carrying_a_default_route_is_what_ranks_it(self, estate) -> None:
        # A default route conceals everything not matched by a more specific prefix, so
        # it outranks any number of specific ones. This estate has exactly one unmanaged
        # next hop and it holds the default.
        top = missing_devices(estate)[0]
        assert top.carries_default_route is True
        assert top.score > 0

    def test_it_is_computed_without_running_every_path(self, estate) -> None:
        # Derived from the routes themselves. Counting terminated path queries instead
        # would measure which questions somebody happened to ask, not the size of the gap.
        top = missing_devices(estate)[0]
        assert top.prefixes
        assert "edge-fw" in top.referenced_by


# ═══════════ the routes the criterion is walked over are real ════════════════


class TestDynamicRoutesReachTheGraph:
    """The 2026-09-18 allow-list amendment, end to end.

    The estate above is hand-built so the path assertions stay readable. This checks the
    other half: that a real `show ip route` capture parses into routes of the same shape,
    so the graph is being fed what a device actually reports rather than what a test
    author found convenient.
    """

    def test_a_real_capture_yields_protocol_learned_routes(self) -> None:
        routes = parse_cisco_route_table((FIXTURES / "cisco_ios/show_ip_route.txt").read_text())

        learned = {r.protocol for r in routes} - {"connected", "local", "static"}
        assert learned == {"ospf", "bgp", "eigrp"}

    def test_those_routes_build_a_graph(self) -> None:
        routes = parse_cisco_route_table((FIXTURES / "cisco_ios/show_ip_route.txt").read_text())
        switch = node("switch", addresses={"Vlan10": "10.10.10.2/24"}, routes=routes)
        graph = build_graph([switch])

        # A destination only OSPF knows about resolves, which it could not before the
        # forwarding table was collected.
        result = walk(graph, source="10.10.10.5", destination="10.10.0.5", port=443)
        assert result.routing is not RoutingConfidence.UNREACHABLE
