"""The layer-3 graph and the path walk (FR-TOPO-02 … FR-TOPO-06).

Built around one small estate, described once below, because the properties worth testing
are about how devices relate and a single-device fixture cannot express any of them.

    (internet)
        │
    203.0.113.1        ← unmanaged: an ISP router, in nobody's inventory
        │
   ┌────┴─────┐  outside 203.0.113.2/29   zone: outside
   │ edge-fw  │  inside  10.0.0.1/30      zone: inside        [has a rulebase]
   └────┬─────┘
        │ 10.0.0.2
   ┌────┴─────┐  up  10.0.0.2/30
   │ core-rtr │  lan 10.10.0.1/24                             [no rulebase]
   └────┬─────┘  dmz 10.0.1.1/30
        │ 10.0.1.2
   ┌────┴─────┐  up  10.0.1.2/30          zone: trust
   │  dmz-fw  │  dmz 10.20.0.1/24         zone: dmz           [has a rulebase]
   └──────────┘

The single most important assertion in this file is that a permit never reports as
`allowed` when the path was not traced to the end. Everything else is mechanism; that one
is the product's honesty about its own coverage, and it is the one a well-meaning
simplification would remove.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from netsecops.core.errors import ValidationProblem
from netsecops.ncm.models import Route
from netsecops.topology.graph import DeviceNode, build_graph
from netsecops.topology.missing import missing_devices
from netsecops.topology.path import PolicyVerdict, RoutingConfidence, walk


def address(text: str) -> int:
    """An IP as the walker holds it: an integer, not a string."""
    import ipaddress

    return int(ipaddress.ip_address(text))


def connected(prefix: str, interface: str) -> Route:
    return Route(destination=prefix, interface=interface, protocol="connected")


def static(prefix: str, via: str, interface: str | None = None) -> Route:
    return Route(destination=prefix, next_hop=via, interface=interface, protocol="static")


def permit_all(name: str = "permit-any") -> dict[str, Any]:
    return {"security_rules": [{"order": 1, "name": name, "action": "allow"}]}


def deny_to(prefix: str, name: str = "block-dmz") -> dict[str, Any]:
    """A rulebase that denies traffic to one prefix and permits the rest."""
    return {
        "security_rules": [
            {"order": 1, "name": name, "action": "deny", "dst": [prefix]},
            {"order": 2, "name": "permit-rest", "action": "allow"},
        ]
    }


def acl(name: str, *, applied: bool, action: str = "deny") -> list[dict[str, Any]]:
    """One named access list's worth of rules, marked bound or unbound."""
    return [
        {
            "order": 1,
            "name": f"{name}-1",
            "rulebase": name,
            "applied": applied,
            "action": action,
        }
    ]


def node(
    hostname: str,
    *,
    routes: list[Route],
    addresses: dict[str, str],
    zones: dict[str, str] | None = None,
    firewall: dict[str, Any] | None = None,
    ncm_version: str = "1.1",
    truncated: bool = False,
) -> DeviceNode:
    """A device node built the way the service builds one, without a database."""
    import ipaddress

    built = DeviceNode(
        device_id=uuid.uuid5(uuid.NAMESPACE_DNS, hostname),
        hostname=hostname,
        platform="cisco_asa" if firewall else "cisco_ios",
        ncm_version=ncm_version,
        routes=routes,
        zones=dict(zones or {}),
        routes_truncated=truncated,
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
    """The three-device estate drawn in the module docstring."""
    edge = node(
        "edge-fw",
        addresses={"outside": "203.0.113.2/29", "inside": "10.0.0.1/30"},
        zones={"outside": "outside", "inside": "inside"},
        routes=[
            connected("203.0.113.0/29", "outside"),
            connected("10.0.0.0/30", "inside"),
            static("0.0.0.0/0", "203.0.113.1", "outside"),
            static("10.10.0.0/24", "10.0.0.2", "inside"),
            static("10.20.0.0/24", "10.0.0.2", "inside"),
        ],
        firewall=permit_all(),
    )
    core = node(
        "core-rtr",
        addresses={"up": "10.0.0.2/30", "lan": "10.10.0.1/24", "dmz": "10.0.1.1/30"},
        routes=[
            connected("10.0.0.0/30", "up"),
            connected("10.10.0.0/24", "lan"),
            connected("10.0.1.0/30", "dmz"),
            static("0.0.0.0/0", "10.0.0.1", "up"),
            static("10.20.0.0/24", "10.0.1.2", "dmz"),
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
        firewall=permit_all(),
    )
    return build_graph([edge, core, dmz])


@pytest.fixture
def equal_cost_estate():
    """The same shape, but the core reaches the DMZ two ways.

    Two firewalls in parallel, which is how anybody builds a resilient DMZ edge, and the
    two do not agree: one permits the traffic and the other denies it. A router picks
    between equal-cost paths by hashing the flow, so the packet may take either — and a
    trace that follows one of them and reports "allowed" has described the lucky half.
    """
    core = node(
        "core-rtr",
        addresses={"lan": "10.10.0.1/24", "a": "10.0.1.1/30", "b": "10.0.2.1/30"},
        routes=[
            connected("10.10.0.0/24", "lan"),
            connected("10.0.1.0/30", "a"),
            connected("10.0.2.0/30", "b"),
            static("10.20.0.0/24", "10.0.1.2", "a"),
            static("10.20.0.0/24", "10.0.2.2", "b"),
        ],
    )
    permissive = node(
        "dmz-fw-a",
        addresses={"up": "10.0.1.2/30", "dmz": "10.20.0.1/24"},
        routes=[connected("10.0.1.0/30", "up"), connected("10.20.0.0/24", "dmz")],
        firewall=permit_all(),
    )
    strict = node(
        "dmz-fw-b",
        addresses={"up": "10.0.2.2/30", "dmz": "10.20.0.2/24"},
        routes=[connected("10.0.2.0/30", "up"), connected("10.20.0.0/24", "dmz")],
        firewall=deny_to("10.20.0.0/24", name="block-dmz-b"),
    )
    return build_graph([core, permissive, strict])


class TestTranslationIsDeclaredNotModelled:
    """A path that continues past a device which may rewrite the packet (FR-TOPO-04).

    Translation is not modelled, and the reason is data rather than effort: `original`
    holds the *source* members on PAN-OS whatever the rule translates, a VIP's *external*
    address on FortiOS, several joined originals on Check Point, and nothing at all on
    Cisco ASA, which records only the raw line and an interface pair. `direction` collides
    the same way. A matcher built on that is wrong differently on each platform, and a
    wrong path verdict is somebody opening a firewall.

    So the engine reports that translation *could* apply and declines to say whether it
    does — which still beats the alternative, because the alternative was reporting a
    clean end-to-end permit across a boundary that may have rewritten the packet.
    """

    @staticmethod
    def _estate(nat_on_middle: bool):
        edge = node(
            "edge-fw",
            addresses={"lan": "10.10.0.1/24", "up": "10.0.1.1/30"},
            routes=[
                connected("10.10.0.0/24", "lan"),
                connected("10.0.1.0/30", "up"),
                static("10.20.0.0/24", "10.0.1.2", "up"),
            ],
            firewall=permit_all(),
        )
        middle = node(
            "mid-fw",
            addresses={"down": "10.0.1.2/30", "up": "10.0.2.1/30"},
            routes=[
                connected("10.0.1.0/30", "down"),
                connected("10.0.2.0/30", "up"),
                static("10.20.0.0/24", "10.0.2.2", "up"),
            ],
            firewall={
                **permit_all(),
                **(
                    {"nat_rules": [{"order": 1, "name": "hide-behind-outside"}]}
                    if nat_on_middle
                    else {}
                ),
            },
        )
        far = node(
            "dmz-fw",
            addresses={"down": "10.0.2.2/30", "dmz": "10.20.0.1/24"},
            routes=[connected("10.0.2.0/30", "down"), connected("10.20.0.0/24", "dmz")],
            firewall=permit_all(),
        )
        return build_graph([edge, middle, far])

    def test_a_permit_past_a_translating_device_is_not_reported_as_allowed(self) -> None:
        """The regression. Every hop permits and the path reaches the destination.

        The devices after `mid-fw` were asked about the addresses in the query, and if
        `mid-fw` rewrites them, they answered about a packet that does not exist.
        """
        result = walk(
            self._estate(nat_on_middle=True),
            source="10.10.0.5",
            destination="10.20.0.5",
            port=443,
        )

        assert result.routing is RoutingConfidence.ROUTED
        assert result.policy is PolicyVerdict.PARTIALLY_ALLOWED
        assert result.translated_at
        assert "mid-fw" in result.translated_at[0]

    def test_the_same_estate_without_nat_is_plainly_allowed(self) -> None:
        """The caveat must attach to translation, not to having three hops."""
        result = walk(
            self._estate(nat_on_middle=False),
            source="10.10.0.5",
            destination="10.20.0.5",
            port=443,
        )

        assert result.policy is PolicyVerdict.ALLOWED
        assert result.translated_at == []

    def test_nat_on_the_final_device_does_not_degrade_the_verdict(self) -> None:
        """A translating firewall at the end invalidates nothing.

        The trace is over, and the addresses it reasoned about are the ones asked for.
        Degrading here would hedge nearly every path through an internet edge, and a
        caveat on every answer is one nobody reads.
        """
        core = node(
            "core-rtr",
            addresses={"lan": "10.10.0.1/24", "dmz": "10.0.1.1/30"},
            routes=[
                connected("10.10.0.0/24", "lan"),
                connected("10.0.1.0/30", "dmz"),
                static("10.20.0.0/24", "10.0.1.2", "dmz"),
            ],
        )
        edge = node(
            "dmz-fw",
            addresses={"up": "10.0.1.2/30", "dmz": "10.20.0.1/24"},
            routes=[connected("10.0.1.0/30", "up"), connected("10.20.0.0/24", "dmz")],
            firewall={**permit_all(), "nat_rules": [{"order": 1, "name": "vip"}]},
        )

        result = walk(
            build_graph([core, edge]), source="10.10.0.5", destination="10.20.0.5", port=443
        )

        assert result.policy is PolicyVerdict.ALLOWED
        assert result.translated_at == []

    def test_a_denial_still_stands_over_a_translating_device(self) -> None:
        """Blocked stays definitive. The packet died before the uncertainty mattered."""
        edge = node(
            "edge-fw",
            addresses={"lan": "10.10.0.1/24", "up": "10.0.1.1/30"},
            routes=[
                connected("10.10.0.0/24", "lan"),
                connected("10.0.1.0/30", "up"),
                static("10.20.0.0/24", "10.0.1.2", "up"),
            ],
            firewall={
                **deny_to("10.20.0.0/24", name="no-dmz"),
                "nat_rules": [{"order": 1, "name": "hide"}],
            },
        )

        result = walk(build_graph([edge]), source="10.10.0.5", destination="10.20.0.5", port=443)

        assert result.policy is PolicyVerdict.BLOCKED

    def test_a_path_that_branches_and_translates_reports_both(self) -> None:
        """Two caveats on one path, and the reader needs both.

        They degrade the verdict to the same thing, so whichever is checked first can
        return and the other is silently dropped — leaving a `partially-allowed` whose
        note explains only half of why. An operator reading "one of two equal-cost
        paths" would reasonably conclude that narrowing the route settles it, and it
        does not.
        """
        core = node(
            "core-rtr",
            addresses={"lan": "10.10.0.1/24", "a": "10.0.1.1/30", "b": "10.0.2.1/30"},
            routes=[
                connected("10.10.0.0/24", "lan"),
                connected("10.0.1.0/30", "a"),
                connected("10.0.2.0/30", "b"),
                static("10.20.0.0/24", "10.0.1.2", "a"),
                static("10.20.0.0/24", "10.0.2.2", "b"),
            ],
            firewall={**permit_all(), "nat_rules": [{"order": 1, "name": "hide-behind-core"}]},
        )
        left = node(
            "dmz-fw-a",
            addresses={"up": "10.0.1.2/30", "dmz": "10.20.0.1/24"},
            routes=[connected("10.0.1.0/30", "up"), connected("10.20.0.0/24", "dmz")],
            firewall=permit_all(),
        )
        right = node(
            "dmz-fw-b",
            addresses={"up": "10.0.2.2/30", "dmz": "10.20.0.2/24"},
            routes=[connected("10.0.2.0/30", "up"), connected("10.20.0.0/24", "dmz")],
            firewall=permit_all(),
        )

        result = walk(
            build_graph([core, left, right]),
            source="10.10.0.5",
            destination="10.20.0.5",
            port=443,
        )
        notes = " ".join(result.notes)

        assert result.policy is PolicyVerdict.PARTIALLY_ALLOWED
        assert result.branched_at and result.translated_at
        assert "equal-cost" in notes
        assert "translate addresses" in notes


class TestWhichRulebaseGoverns:
    """A Cisco device's policy is a set of ACLs, not one ordered list (FR-TOPO-04).

    `SecurityRule.rulebase` records the enforcement context and the hygiene analysis
    honours it — two entries in different ACLs are never compared, because they never
    see the same packet. The path walk was evaluating all of them as one list in file
    order, which on any device with more than one ACL means the first ACL in the file
    decides every path. Since each ends in `deny any`, every path came back blocked by a
    rule governing traffic in a different direction.

    A false `blocked` is the dangerous direction: it says a control is already in place,
    and somebody stops looking.
    """

    @staticmethod
    def _estate(firewall: dict[str, Any]):
        core = node(
            "core-rtr",
            addresses={"lan": "10.10.0.1/24", "up": "10.0.1.1/30"},
            routes=[
                connected("10.10.0.0/24", "lan"),
                connected("10.0.1.0/30", "up"),
                static("10.20.0.0/24", "10.0.1.2", "up"),
            ],
        )
        edge = node(
            "edge-fw",
            addresses={"up": "10.0.1.2/30", "dmz": "10.20.0.1/24"},
            routes=[connected("10.0.1.0/30", "up"), connected("10.20.0.0/24", "dmz")],
            firewall=firewall,
        )
        return build_graph([core, edge])

    def test_two_bound_access_lists_produce_no_verdict_rather_than_a_wrong_one(self) -> None:
        """The regression.

        `OUTSIDE-IN` denies everything inbound from the internet and `INSIDE-IN` permits
        the user network outbound. Flattened, the outbound query is decided by the
        inbound list and reported blocked. Which one governs depends on the interface
        the packet arrives on, and that binding is not yet recorded in a form this can
        read — so the honest answer is that the decision is unknown.
        """
        firewall = {
            "security_rules": [
                *acl("OUTSIDE-IN", applied=True, action="deny"),
                *acl("INSIDE-IN", applied=True, action="allow"),
            ]
        }

        result = walk(self._estate(firewall), source="10.10.0.5", destination="10.20.0.5", port=443)
        hop = next(h for h in result.hops if h.hostname == "edge-fw")

        assert hop.action is None, "a device with two bound ACLs must not pick one arbitrarily"
        assert result.policy is not PolicyVerdict.BLOCKED
        assert hop.limitations and "access lists bound to different interfaces" in " ".join(
            hop.limitations
        )

    def test_one_access_list_still_decides(self) -> None:
        """The hedge must not spread to the ordinary case: a device with a single
        rulebase has no ambiguity to report."""
        firewall = {"security_rules": [*acl("INSIDE-IN", applied=True, action="deny")]}

        result = walk(self._estate(firewall), source="10.10.0.5", destination="10.20.0.5", port=443)
        hop = next(h for h in result.hops if h.hostname == "edge-fw")

        assert hop.action == "deny"
        assert result.policy is PolicyVerdict.BLOCKED

    def test_a_platform_with_one_policy_is_unaffected(self) -> None:
        """PAN-OS, FortiOS and Check Point rules carry no rulebase and are all in force.
        Grouping by a field that is None everywhere must leave one context, not many."""
        result = walk(
            self._estate(deny_to("10.20.0.0/24")),
            source="10.10.0.5",
            destination="10.20.0.5",
            port=443,
        )

        assert result.policy is PolicyVerdict.BLOCKED


class TestAnUnappliedAccessListFiltersNothing:
    """An ACL bound to no interface is a vty filter, an SNMP filter, or a leftover.

    It ends in `deny any` like every other, and evaluating it reported traffic blocked
    at a switch that forwards it without looking. The parsers mark the rules, because
    `ncm.acls` records the binding and the path walk never sees it.
    """

    @staticmethod
    def _estate(firewall: dict[str, Any]):
        access = node(
            "access-sw",
            addresses={"vlan10": "10.10.0.2/24"},
            routes=[connected("10.10.0.0/24", "vlan10"), static("0.0.0.0/0", "10.10.0.1")],
            firewall=firewall,
        )
        core = node(
            "core-rtr",
            addresses={"lan": "10.10.0.1/24", "dmz": "10.20.0.1/24"},
            routes=[connected("10.10.0.0/24", "lan"), connected("10.20.0.0/24", "dmz")],
        )
        return build_graph([access, core])

    def test_it_does_not_block_the_path(self) -> None:
        firewall = {"security_rules": [*acl("99", applied=False, action="deny")]}

        result = walk(self._estate(firewall), source="10.10.0.5", destination="10.20.0.5", port=443)
        hop = next(h for h in result.hops if h.hostname == "access-sw")

        assert hop.action is None
        assert result.policy is not PolicyVerdict.BLOCKED

    def test_the_device_says_it_carries_an_unapplied_policy(self) -> None:
        """Silence would be wrong in the other direction: somebody wrote a policy here
        and did not apply it, and that is worth seeing."""
        firewall = {"security_rules": [*acl("99", applied=False, action="deny")]}

        result = walk(self._estate(firewall), source="10.10.0.5", destination="10.20.0.5", port=443)
        hop = next(h for h in result.hops if h.hostname == "access-sw")

        assert hop.limitations and "bound to no interface" in " ".join(hop.limitations)

    def test_a_bound_access_list_on_the_same_device_still_decides(self) -> None:
        """The filter must remove the unapplied rules and then get out of the way —
        not leave one bound ACL looking like an ambiguous pair."""
        firewall = {
            "security_rules": [
                *acl("99", applied=False, action="allow"),
                *acl("TRANSIT-IN", applied=True, action="deny"),
            ]
        }

        result = walk(self._estate(firewall), source="10.10.0.5", destination="10.20.0.5", port=443)
        hop = next(h for h in result.hops if h.hostname == "access-sw")

        assert hop.action == "deny"
        assert hop.rule_name == "TRANSIT-IN-1"


class TestSegmentationQueries:
    """Asking about subnets rather than hosts (FR-TOPO-03, extended).

    "Can anything in the user VLAN reach anything in the DMZ on 443" is the question a
    segmentation review runs on, and until now it could only be asked one host pair at a
    time — 65,536 queries for a pair of /24s, answering whether one arbitrary pair gets
    through rather than whether the boundary holds.

    The interesting answer is the non-uniform one. A boundary that is open except for one
    address is the finding; a host-by-host query lands on that address once in 256 tries.
    """

    def test_a_subnet_pair_is_traced_like_a_host_pair(self, estate) -> None:
        result = walk(estate, source="10.10.0.0/24", destination="10.20.0.0/24", port=443)

        assert result.routing is RoutingConfidence.ROUTED
        assert [hop.hostname for hop in result.hops] == ["core-rtr", "dmz-fw"]
        assert result.policy is PolicyVerdict.ALLOWED

    def test_a_host_query_still_answers_the_same_way(self, estate) -> None:
        """Ranges must not change the answer to the question that already worked."""
        ranged = walk(estate, source="10.10.0.0/24", destination="10.20.0.0/24", port=443)
        single = walk(estate, source="10.10.0.5", destination="10.20.0.5", port=443)

        assert single.policy is ranged.policy
        assert [h.hostname for h in single.hops] == [h.hostname for h in ranged.hops]

    def test_a_single_denied_host_makes_the_range_verdict_not_allowed(self) -> None:
        """The finding the whole feature exists for.

        The DMZ firewall permits the subnet except one server. Asked host by host, 255
        of 256 queries say "allowed" and the boundary looks uniformly open.
        """
        core = node(
            "core-rtr",
            addresses={"lan": "10.10.0.1/24", "dmz": "10.0.1.1/30"},
            routes=[
                connected("10.10.0.0/24", "lan"),
                connected("10.0.1.0/30", "dmz"),
                static("10.20.0.0/24", "10.0.1.2", "dmz"),
            ],
        )
        dmz = node(
            "dmz-fw",
            addresses={"up": "10.0.1.2/30", "dmz": "10.20.0.1/24"},
            routes=[connected("10.0.1.0/30", "up"), connected("10.20.0.0/24", "dmz")],
            firewall={
                "security_rules": [
                    {"order": 1, "name": "protect-db", "action": "deny", "dst": ["10.20.0.5"]},
                    {"order": 2, "name": "permit-rest", "action": "allow"},
                ]
            },
        )
        graph = build_graph([core, dmz])

        result = walk(graph, source="10.10.0.0/24", destination="10.20.0.0/24", port=443)

        assert result.policy is not PolicyVerdict.ALLOWED
        assert result.policy is PolicyVerdict.PARTIALLY_ALLOWED
        assert "protect-db" in " ".join(result.notes)

    def test_the_note_says_how_to_get_a_definite_answer(self) -> None:
        """A hedge that does not say what to do next is barely better than a wrong answer."""
        core = node(
            "core-rtr",
            addresses={"lan": "10.10.0.1/24", "dmz": "10.0.1.1/30"},
            routes=[
                connected("10.10.0.0/24", "lan"),
                connected("10.0.1.0/30", "dmz"),
                static("10.20.0.0/24", "10.0.1.2", "dmz"),
            ],
        )
        dmz = node(
            "dmz-fw",
            addresses={"up": "10.0.1.2/30", "dmz": "10.20.0.1/24"},
            routes=[connected("10.0.1.0/30", "up"), connected("10.20.0.0/24", "dmz")],
            firewall={
                "security_rules": [
                    {"order": 1, "name": "protect-db", "action": "deny", "dst": ["10.20.0.5"]},
                    {"order": 2, "name": "permit-rest", "action": "allow"},
                ]
            },
        )
        result = walk(
            build_graph([core, dmz]), source="10.10.0.0/24", destination="10.20.0.0/24", port=443
        )

        assert "Narrow the range" in " ".join(result.notes)

    def test_a_range_split_across_two_routes_is_not_traced_as_one(self) -> None:
        """Half the range goes one way and half another, so one trace describes neither.

        The routing axis catches this before the policy axis is reached: a single walk
        cannot stand for a range the tables subdivide.
        """
        core = node(
            "core-rtr",
            addresses={"lan": "10.10.0.1/24", "a": "10.0.1.1/30", "b": "10.0.2.1/30"},
            routes=[
                connected("10.10.0.0/24", "lan"),
                connected("10.0.1.0/30", "a"),
                connected("10.0.2.0/30", "b"),
                static("10.20.0.0/25", "10.0.1.2", "a"),
                static("10.20.0.128/25", "10.0.2.2", "b"),
            ],
        )
        result = walk(
            build_graph([core]), source="10.10.0.0/24", destination="10.20.0.0/24", port=443
        )

        assert result.routing is RoutingConfidence.UNKNOWN
        notes = " ".join(result.notes)
        assert "more than one prefix" in notes
        assert "10.20.0.0/25" in notes

    def test_an_ipv6_range_is_refused_rather_than_guessed(self) -> None:
        """Forwarding tables are parsed for IPv4 only, so v6 has nothing to walk."""
        with pytest.raises(ValidationProblem, match="IPv6"):
            walk(build_graph([]), source="2001:db8::/32", destination="2001:db8:1::/48")

    def test_a_name_is_still_refused(self) -> None:
        """Names are not resolved, so that what was analysed is what was asked."""
        with pytest.raises(ValidationProblem, match="not an IP address or CIDR"):
            walk(build_graph([]), source="webserver", destination="10.20.0.5")


class TestEqualCostPaths:
    """A packet with more than one way to go (FR-TOPO-04).

    `lookup` returns the single best route, which is what a router does per flow — but
    which one it picks depends on a hash of the header that appears in no configuration.
    So following the first silently turns "one of the paths permits this" into "this is
    permitted", and the difference matters most in exactly the topology people build for
    resilience: two firewalls in parallel that have drifted apart.
    """

    def test_the_alternatives_are_reported(self, equal_cost_estate) -> None:
        result = walk(equal_cost_estate, source="10.10.0.5", destination="10.20.0.5", port=443)

        assert result.branched_at, "a packet with two equal-cost routes was traced as if it had one"
        assert "10.0.1.2" in result.branched_at[0]
        assert "10.0.2.2" in result.branched_at[0]

    def test_a_permit_down_one_path_is_not_reported_as_allowed(self, equal_cost_estate) -> None:
        """The regression this exists for.

        The traced path goes through the permissive firewall and reaches the destination,
        so every check the old code made says `routed` and `allowed`. The other path is
        denied, and the packet may take it.
        """
        result = walk(equal_cost_estate, source="10.10.0.5", destination="10.20.0.5", port=443)

        assert result.routing is RoutingConfidence.ROUTED
        assert result.policy is PolicyVerdict.PARTIALLY_ALLOWED
        assert result.policy is not PolicyVerdict.ALLOWED

    def test_the_note_says_what_was_not_examined(self, equal_cost_estate) -> None:
        """A hedge nobody can act on is barely better than the overclaim."""
        result = walk(equal_cost_estate, source="10.10.0.5", destination="10.20.0.5", port=443)
        notes = " ".join(result.notes)

        assert "equal-cost" in notes
        assert "could still deny" in notes

    def test_an_unambiguous_path_is_still_plainly_allowed(self, estate) -> None:
        """The caveat must not attach itself to every path.

        One route to the destination is one path, and hedging it would make the verdict
        meaningless everywhere.
        """
        result = walk(estate, source="10.10.0.5", destination="10.20.0.5", port=443)

        assert result.branched_at == []
        assert result.policy is PolicyVerdict.ALLOWED

    def test_a_denial_on_the_followed_path_still_stands(self, equal_cost_estate) -> None:
        """Blocked is asymmetric and stays so.

        A packet denied on the path it took is denied, whatever the alternatives offered
        — the existing rule that a block is definitive is not weakened by this.
        """
        result = walk(equal_cost_estate, source="10.10.0.5", destination="10.20.0.9", port=443)

        assert result.policy in (PolicyVerdict.BLOCKED, PolicyVerdict.PARTIALLY_ALLOWED)

    def test_duplicate_next_hops_are_not_a_branch(self) -> None:
        """The same next hop learned twice is one path.

        A device can hold the same route from two sources — a static and a redistributed
        copy — and reporting that as a choice would hedge a path that has none.
        """
        device = node(
            "rtr",
            addresses={"lan": "10.10.0.1/24", "up": "10.0.1.1/30"},
            routes=[
                connected("10.10.0.0/24", "lan"),
                connected("10.0.1.0/30", "up"),
                static("10.20.0.0/24", "10.0.1.2", "up"),
                static("10.20.0.0/24", "10.0.1.2", "up"),
            ],
        )

        assert device.equal_cost_next_hops(address("10.20.0.5")) == []

    def test_a_worse_route_is_not_an_alternative(self) -> None:
        """Equal cost means equal. A backup route is not a path the packet may take."""
        device = node(
            "rtr",
            addresses={"lan": "10.10.0.1/24"},
            routes=[
                connected("10.10.0.0/24", "lan"),
                Route(
                    destination="10.20.0.0/24",
                    next_hop="10.0.1.2",
                    protocol="static",
                    distance=1,
                ),
                Route(
                    destination="10.20.0.0/24",
                    next_hop="10.0.2.2",
                    protocol="static",
                    distance=200,
                ),
            ],
        )

        assert device.equal_cost_next_hops(address("10.20.0.5")) == []


# ═════════════════════════ tracing across devices ════════════════════════════


class TestAPathIsTraced:
    def test_it_crosses_the_devices_between_two_subnets(self, estate) -> None:
        """The question FR-FW-06 could not answer: which firewall is even in the way."""
        result = walk(estate, source="10.10.0.5", destination="10.20.0.5", port=443)

        assert result.routing is RoutingConfidence.ROUTED
        assert [hop.hostname for hop in result.hops] == ["core-rtr", "dmz-fw"]

    def test_it_reports_the_route_each_device_chose(self, estate) -> None:
        result = walk(estate, source="10.10.0.5", destination="10.20.0.5")

        assert result.hops[0].matched_route == "10.20.0.0/24 via 10.0.1.2"
        assert result.hops[0].next_hop == "10.0.1.2"
        assert result.hops[1].matched_route == "connected"

    def test_a_router_on_the_path_has_no_opinion(self, estate) -> None:
        """A device with no rulebase is a hop, not a decision.

        Defaulting it to "allow" would count a router as a control that was checked,
        which is the same misreport as an unevaluated check shown as a pass.
        """
        result = walk(estate, source="10.10.0.5", destination="10.20.0.5")

        core = next(hop for hop in result.hops if hop.hostname == "core-rtr")
        assert core.action is None

    def test_a_firewall_on_the_path_is_asked(self, estate) -> None:
        result = walk(estate, source="10.10.0.5", destination="10.20.0.5")

        dmz = next(hop for hop in result.hops if hop.hostname == "dmz-fw")
        assert dmz.action == "allow"
        assert dmz.rule_name == "permit-any"

    def test_zones_are_derived_from_the_interfaces_the_packet_uses(self, estate) -> None:
        """Firewalls match on zones; a query without them can match a rule the device
        would not."""
        result = walk(estate, source="10.10.0.5", destination="10.20.0.5")

        dmz = next(hop for hop in result.hops if hop.hostname == "dmz-fw")
        assert dmz.ingress_zone == "trust"
        assert dmz.egress_zone == "dmz"

    def test_the_longest_prefix_wins(self, estate) -> None:
        """core-rtr has both a default and a /24 for the DMZ. The /24 decides."""
        result = walk(estate, source="10.10.0.5", destination="10.20.0.5")

        assert result.hops[0].next_hop == "10.0.1.2"


class TestTwoHostsOnOneSubnet:
    def test_nothing_is_routed_and_no_rulebase_applies(self, estate) -> None:
        """Reporting a firewall verdict here would be wrong in the dangerous direction:
        it implies a control sits in a path that has none."""
        result = walk(estate, source="10.10.0.5", destination="10.10.0.6")

        assert result.routing is RoutingConfidence.SAME_ZONE
        assert result.policy is PolicyVerdict.NOT_ROUTED
        assert result.hops == []

    def test_it_says_what_it_cannot_see(self, estate) -> None:
        result = walk(estate, source="10.10.0.5", destination="10.10.0.6")

        assert any("host firewall" in note for note in result.notes)


# ══════════════ leaving the estate — the answer that matters most ════════════


class TestLeavingTheManagedEstate:
    def test_it_stops_and_names_where(self, estate) -> None:
        """FR-TOPO-05. The path reaches the edge firewall, which routes the default at an
        ISP address nobody has onboarded."""
        result = walk(estate, source="10.10.0.5", destination="8.8.8.8")

        assert result.routing is RoutingConfidence.PARTIALLY_ROUTED
        assert result.stopped_at_prefix == "0.0.0.0/0"
        assert result.stopped_at_next_hop == "203.0.113.1"
        assert result.stopped_at_device == "edge-fw"

    def test_a_permit_on_the_traced_part_is_not_reported_as_allowed(self, estate) -> None:
        """**The assertion this whole file exists for.**

        Every firewall found permits the traffic, and the path was lost before the
        destination. "Allowed" would be a claim the product cannot support, and somebody
        will open a firewall on the strength of it. It has to read as partial.
        """
        result = walk(estate, source="10.10.0.5", destination="8.8.8.8")

        assert all(hop.action in (None, "allow") for hop in result.hops)
        assert result.policy is PolicyVerdict.PARTIALLY_ALLOWED
        assert result.policy is not PolicyVerdict.ALLOWED

    def test_the_note_says_what_to_do_about_it(self, estate) -> None:
        """A hedge that does not say what would resolve it is just a hedge."""
        result = walk(estate, source="10.10.0.5", destination="8.8.8.8")

        note = " ".join(result.notes)
        assert "203.0.113.1" in note
        assert "no device in the inventory" in note


# ═══════════════════════════ blocked and unreachable ═════════════════════════


class TestABlockIsDefinitive:
    def test_a_denying_rule_stops_the_path(self, estate) -> None:
        blocker = node(
            "dmz-fw",
            addresses={"up": "10.0.1.2/30", "dmz": "10.20.0.1/24"},
            zones={"up": "trust", "dmz": "dmz"},
            routes=[
                connected("10.0.1.0/30", "up"),
                connected("10.20.0.0/24", "dmz"),
            ],
            firewall=deny_to("10.20.0.0/24"),
        )
        graph = build_graph(
            blocker if existing.hostname == "dmz-fw" else existing
            for existing in estate.nodes.values()
        )

        result = walk(graph, source="10.10.0.5", destination="10.20.0.5")

        assert result.policy is PolicyVerdict.BLOCKED
        assert result.blocked_by is not None
        assert result.blocked_by.hostname == "dmz-fw"

    def test_it_stands_even_when_the_rest_of_the_path_is_unknown(self) -> None:
        """A block is definitive where a permit is not: the packet dies at the denial, so
        what lies beyond it cannot change the answer."""
        wall = node(
            "wall",
            addresses={"in": "10.10.0.1/24", "out": "10.0.0.1/30"},
            routes=[
                connected("10.10.0.0/24", "in"),
                connected("10.0.0.0/30", "out"),
                static("0.0.0.0/0", "10.0.0.99", "out"),
            ],
            firewall=deny_to("8.8.8.8/32"),
        )

        result = walk(build_graph([wall]), source="10.10.0.5", destination="8.8.8.8")

        assert result.policy is PolicyVerdict.BLOCKED


class TestUnreachable:
    def test_a_device_with_no_route_drops_the_packet(self) -> None:
        island = node(
            "island",
            addresses={"lan": "10.10.0.1/24"},
            routes=[connected("10.10.0.0/24", "lan")],
        )

        result = walk(build_graph([island]), source="10.10.0.5", destination="8.8.8.8")

        assert result.routing is RoutingConfidence.UNREACHABLE
        assert result.policy is PolicyVerdict.NOT_ROUTED

    def test_no_firewall_beyond_it_is_claimed_to_have_been_consulted(self) -> None:
        island = node(
            "island",
            addresses={"lan": "10.10.0.1/24"},
            routes=[connected("10.10.0.0/24", "lan")],
            firewall=permit_all(),
        )

        result = walk(build_graph([island]), source="10.10.0.5", destination="8.8.8.8")

        assert result.policy is PolicyVerdict.NOT_ROUTED


# ═══════════════════ what the graph does not know, it says ═══════════════════


class TestUnknownRatherThanNegative:
    def test_an_old_snapshot_cannot_produce_unreachable(self) -> None:
        """A device collected before FR-TOPO-01 has no routes because nothing parsed
        them, not because it has none. Reporting Unreachable would turn a collection gap
        into a statement about the network."""
        old = node(
            "legacy",
            addresses={"lan": "10.10.0.1/24"},
            routes=[connected("10.10.0.0/24", "lan")],
            ncm_version="1.0",
        )

        result = walk(build_graph([old]), source="10.10.0.5", destination="8.8.8.8")

        assert result.routing is RoutingConfidence.UNKNOWN
        assert any("before forwarding tables were parsed" in n for n in result.notes)

    def test_a_truncated_table_cannot_produce_unreachable(self) -> None:
        big = node(
            "core",
            addresses={"lan": "10.10.0.1/24"},
            routes=[connected("10.10.0.0/24", "lan")],
            truncated=True,
        )

        result = walk(build_graph([big]), source="10.10.0.5", destination="8.8.8.8")

        assert result.routing is RoutingConfidence.UNKNOWN
        assert any("truncation" in note for note in result.notes)

    def test_a_source_no_device_serves_has_no_starting_point(self, estate) -> None:
        result = walk(estate, source="192.0.2.50", destination="10.20.0.5")

        assert result.routing is RoutingConfidence.UNKNOWN
        assert result.hops == []
        assert any("no starting point" in note for note in result.notes)

    def test_a_routing_loop_is_diagnosed_rather_than_run(self) -> None:
        """Two devices defaulting at each other. Without loop detection this runs until
        something else stops it and reports whatever it happens to end on."""
        left = node(
            "left",
            addresses={"lan": "10.10.0.1/24", "link": "10.0.0.1/30"},
            routes=[
                connected("10.10.0.0/24", "lan"),
                connected("10.0.0.0/30", "link"),
                static("0.0.0.0/0", "10.0.0.2", "link"),
            ],
        )
        right = node(
            "right",
            addresses={"link": "10.0.0.2/30"},
            routes=[
                connected("10.0.0.0/30", "link"),
                static("0.0.0.0/0", "10.0.0.1", "link"),
            ],
        )

        result = walk(build_graph([left, right]), source="10.10.0.5", destination="8.8.8.8")

        assert result.routing is RoutingConfidence.UNKNOWN
        assert any("loop" in note for note in result.notes)
        # Asserted specifically, because the hop cap also ends a loop and produces a
        # message containing the same word — so a test that only greps for "loop" passes
        # with the revisit check deleted. Naming the device is what distinguishes
        # "detected the loop" from "ran out of hops", and only the former can say where.
        assert result.stopped_at_device == "left"
        assert len(result.hops) < 5

    def test_a_route_in_another_vrf_is_unknown_rather_than_unreachable(self) -> None:
        """VRFs are separate forwarding domains, and which one a packet is in depends on
        the interface it arrived on — which no parser records.

        So a device whose only matching route lives in a VRF cannot be said to have no
        route. Reporting Unreachable there would turn a limit of what is modelled into a
        claim about the network, and it is the more dangerous direction: it says traffic
        stops where it may well flow.
        """
        router = node(
            "vrf-rtr",
            addresses={"lan": "10.10.0.1/24"},
            routes=[
                connected("10.10.0.0/24", "lan"),
                Route(
                    destination="8.8.8.0/24",
                    next_hop="10.99.0.1",
                    protocol="static",
                    vrf="INTERNET",
                ),
            ],
        )

        result = walk(build_graph([router]), source="10.10.0.5", destination="8.8.8.8")

        assert result.routing is RoutingConfidence.UNKNOWN
        assert any("VRF INTERNET" in note for note in result.notes)

    def test_a_vrf_route_is_not_used_as_if_it_were_global(self) -> None:
        """The other half of the same rule: the VRF route must not be *followed*.

        Merging the tables would let a packet cross between two networks a router exists
        to keep apart, which is the one error a reachability answer must never make.
        """
        router = node(
            "vrf-rtr",
            addresses={"lan": "10.10.0.1/24"},
            routes=[
                connected("10.10.0.0/24", "lan"),
                Route(
                    destination="8.8.8.0/24",
                    next_hop="10.99.0.1",
                    protocol="static",
                    vrf="INTERNET",
                ),
            ],
        )

        result = walk(build_graph([router]), source="10.10.0.5", destination="8.8.8.8")

        # The device is reached — it is on the path — but it takes no hop: no route was
        # chosen and the VRF's next hop never appears in the answer.
        assert [hop.hostname for hop in result.hops] == ["vrf-rtr"]
        assert result.hops[0].matched_route is None
        assert result.hops[0].next_hop is None
        assert "10.99.0.1" not in str(result.hops)


class TestInputIsValidated:
    def test_a_hostname_is_refused(self, estate) -> None:
        """Names are not resolved, so that what was analysed is what was asked."""
        with pytest.raises(ValidationProblem):
            walk(estate, source="server01.example.net", destination="10.20.0.5")

    def test_an_unknown_protocol_is_refused(self, estate) -> None:
        with pytest.raises(ValidationProblem):
            walk(estate, source="10.10.0.5", destination="10.20.0.5", protocol="carrier-pigeon")


# ══════════════════ the ranked missing-device report ═════════════════════════


class TestMissingDevices:
    def test_the_isp_router_is_found(self, estate) -> None:
        found = missing_devices(estate)

        assert [item.address for item in found] == ["203.0.113.1"]

    def test_it_names_who_routes_through_it(self, estate) -> None:
        """Evidence, so the finding can be checked against a real configuration rather
        than taken on trust."""
        found = missing_devices(estate)

        assert found[0].referenced_by == ["edge-fw"]
        assert "0.0.0.0/0" in found[0].prefixes

    def test_a_managed_next_hop_is_not_reported(self, estate) -> None:
        """10.0.0.2 and 10.0.1.2 are routed through and both belong to devices here."""
        addresses = {item.address for item in missing_devices(estate)}

        assert "10.0.0.2" not in addresses
        assert "10.0.1.2" not in addresses

    def test_a_default_route_outranks_a_handful_of_specific_ones(self) -> None:
        """A device defaulting at an unknown next hop hides everything it cannot resolve
        locally. A route for one /24 hides one subnet. Ranking them equally would put a
        lab's static route above the estate's edge."""
        edge = node(
            "edge",
            addresses={"out": "203.0.113.2/29", "in": "10.0.0.1/30"},
            routes=[
                connected("203.0.113.0/29", "out"),
                connected("10.0.0.0/30", "in"),
                static("0.0.0.0/0", "203.0.113.1", "out"),
            ],
        )
        lab = node(
            "lab",
            addresses={"lan": "10.9.0.1/24"},
            routes=[
                connected("10.9.0.0/24", "lan"),
                static("10.90.0.0/24", "10.9.0.99", "lan"),
                static("10.91.0.0/24", "10.9.0.99", "lan"),
                static("10.92.0.0/24", "10.9.0.99", "lan"),
            ],
        )

        ranked = missing_devices(build_graph([edge, lab]))

        assert [item.address for item in ranked] == ["203.0.113.1", "10.9.0.99"]

    def test_a_next_hop_many_devices_share_ranks_above_a_lone_one(self) -> None:
        shared = [
            node(
                f"branch-{n}",
                addresses={"lan": f"10.{n}.0.1/24", "wan": f"10.200.0.{n}/24"},
                routes=[
                    connected(f"10.{n}.0.0/24", "lan"),
                    connected("10.200.0.0/24", "wan"),
                    static("10.100.0.0/16", "10.200.0.254", "wan"),
                ],
            )
            for n in range(1, 5)
        ]
        lonely = node(
            "one-off",
            addresses={"lan": "10.50.0.1/24"},
            routes=[
                connected("10.50.0.0/24", "lan"),
                static("10.51.0.0/24", "10.50.0.9", "lan"),
            ],
        )

        ranked = missing_devices(build_graph([*shared, lonely]))

        assert ranked[0].address == "10.200.0.254"
        assert len(ranked[0].referenced_by) == 4

    def test_it_says_whether_the_gap_sits_beside_devices_we_manage(self, estate) -> None:
        """An address on a subnet the estate already reaches is far more likely to be
        onboardable than one across a handoff, and that is most of what decides whether
        a gap is worth closing."""
        found = missing_devices(estate)

        assert found[0].adjacent_to == "203.0.113.0/29"
        assert "203.0.113.0/29" in found[0].reason
