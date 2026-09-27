"""Projecting the graph into a drawable map (FR-TOPO-02).

The same three-device estate `test_topology.py` walks paths across, asked a different
question: what does it look like. The properties worth pinning here are the ones a
well-meaning simplification would remove —

* a strand exists only where a next hop is genuinely configured on the other device,
* the boundary is drawn rather than dropped,
* two devices that merely share an upstream are not in one group,
* and the whole thing is the same on the second run as on the first.
"""

from __future__ import annotations

import pytest

from netsecops.topology.estate_map import DeviceMeta, MapInterface, build_map
from netsecops.topology.graph import build_graph
from tests.test_topology import build_estate, connected, node, permit_all, static


@pytest.fixture
def estate():
    """The same three devices the path walk is tested against.

    Shared rather than restated, so a picture of the estate and a path answer about it
    cannot end up describing two different networks.
    """
    return build_estate()


def ids(map_result, kind: str | None = None) -> set[str]:
    return {n.label for n in map_result.nodes if kind is None or n.kind == kind}


class TestWhatIsDrawn:
    def test_every_device_becomes_a_box(self, estate) -> None:
        drawn = build_map(estate)
        assert ids(drawn, "device") == {"edge-fw", "core-rtr", "dmz-fw"}

    def test_the_boundary_is_a_box_too(self, estate) -> None:
        """The ISP router is the point of the picture, not an omission.

        It is what tells somebody which device to onboard next, and a map that simply
        stops at the edge firewall with nothing beyond it asserts the estate ends there.
        """
        drawn = build_map(estate)
        assert ids(drawn, "unmanaged") == {"203.0.113.1"}

        boundary = next(n for n in drawn.nodes if n.kind == "unmanaged")
        assert boundary.carries_default_route is True
        assert boundary.referenced_by  # named, so the picture can say who points here

    def test_adjacency_comes_from_a_configured_address_not_a_shared_subnet(self) -> None:
        """The mutation this guards: matching a next hop by subnet instead of exactly.

        Both of these devices sit on 10.0.0.0/30 and neither routes to the other's
        address, so there is no hop between them. A subnet match would draw one.
        """
        left = node("left", addresses={"a": "10.0.0.1/30"}, routes=[connected("10.0.0.0/30", "a")])
        right = node(
            "right", addresses={"a": "10.0.0.2/30"}, routes=[connected("10.0.0.0/30", "a")]
        )

        drawn = build_map(build_graph([left, right]))
        assert drawn.links == []
        assert drawn.isolated == 2

    def test_a_route_to_an_address_nobody_owns_reaches_the_boundary_not_a_device(self) -> None:
        only = node(
            "only",
            addresses={"a": "10.0.0.1/30"},
            routes=[connected("10.0.0.0/30", "a"), static("0.0.0.0/0", "10.0.0.9")],
        )
        drawn = build_map(build_graph([only]))

        assert [n.kind for n in drawn.nodes] == ["device", "unmanaged"]
        assert drawn.links[0].target == "unmanaged:10.0.0.9"


class TestStrands:
    def test_both_directions_are_one_strand(self, estate) -> None:
        """edge-fw routes to core-rtr and core-rtr routes back. One wire, not two."""
        drawn = build_map(estate)
        between = [
            link
            for link in drawn.links
            if {_label(drawn, link.source), _label(drawn, link.target)} == {"edge-fw", "core-rtr"}
        ]
        assert len(between) == 1
        assert between[0].bidirectional is True

    def test_a_one_way_route_is_not_straightened_into_a_plain_link(self) -> None:
        """A route out with nothing coming back is a real asymmetry and is marked."""
        speaker = node(
            "speaker",
            addresses={"a": "10.0.0.1/30"},
            routes=[connected("10.0.0.0/30", "a"), static("10.9.0.0/24", "10.0.0.2")],
        )
        silent = node(
            "silent", addresses={"a": "10.0.0.2/30"}, routes=[connected("10.0.0.0/30", "a")]
        )

        drawn = build_map(build_graph([speaker, silent]))
        assert len(drawn.links) == 1
        assert drawn.links[0].bidirectional is False

    def test_each_end_of_a_strand_names_its_interface(self, estate) -> None:
        """The whole reason to draw a firewall is to see which of its legs faces what."""
        drawn = build_map(estate)
        link = next(
            link
            for link in drawn.links
            if {_label(drawn, link.source), _label(drawn, link.target)} == {"edge-fw", "core-rtr"}
        )
        assert {link.source_interface, link.target_interface} == {"inside", "up"}

    def test_many_prefixes_over_one_wire_are_counted_not_multiplied(self, estate) -> None:
        """edge-fw routes two prefixes at core-rtr. One strand, carrying two."""
        drawn = build_map(estate)
        link = next(
            link
            for link in drawn.links
            if {_label(drawn, link.source), _label(drawn, link.target)} == {"edge-fw", "core-rtr"}
        )
        assert link.prefixes >= 2

    def test_a_strand_with_a_firewall_at_either_end_says_so(self, estate) -> None:
        drawn = build_map(estate)
        assert all(link.crosses_firewall for link in drawn.links if link.via)


class TestWhatCountsAsAFirewall:
    """`applied` is three-state, and reading it as a boolean is wrong in both directions.

    An access list bound to no interface filters no traffic crossing the device — it is
    usually a vty or SNMP filter — so a switch carrying one is not a control. But
    PAN-OS, FortiOS and Check Point rules record `applied: null`, because on those
    platforms a rule is in force by existing, and treating null as "not applied" would
    take every one of those firewalls off the picture.
    """

    def test_an_access_list_bound_to_nothing_is_not_a_firewall(self) -> None:
        switch = node(
            "acc-sw-01",
            addresses={"vlan10": "10.0.10.2/24"},
            routes=[connected("10.0.10.0/24", "vlan10")],
            firewall={
                "security_rules": [
                    # `access-class 99 in` on the vty lines: management access, and no
                    # transit traffic at all.
                    {"order": 1, "name": "99", "action": "allow", "applied": False},
                    {"order": 2, "name": "99", "action": "deny", "applied": False},
                ]
            },
        )

        box = build_map(build_graph([switch])).nodes[0]
        assert box.has_rulebase is True, "it does have rules"
        assert box.inspects is False, "and none of them are in force on traffic"

    def test_a_platform_that_does_not_bind_rules_still_counts(self) -> None:
        """PAN-OS records `applied: null`. Its rulebase is in force regardless."""
        gateway = node(
            "pa-01",
            addresses={"eth1": "10.0.0.1/30"},
            routes=[connected("10.0.0.0/30", "eth1")],
            firewall={"security_rules": [{"order": 1, "name": "allow-web", "action": "allow"}]},
        )

        assert build_map(build_graph([gateway])).nodes[0].inspects is True

    def test_a_bound_access_list_counts(self) -> None:
        router = node(
            "rtr-01",
            addresses={"gi0": "10.0.0.1/30"},
            routes=[connected("10.0.0.0/30", "gi0")],
            firewall={
                "security_rules": [
                    {"order": 1, "name": "OUTSIDE-IN", "action": "deny", "applied": False},
                    {"order": 1, "name": "INSIDE-OUT", "action": "allow", "applied": True},
                ]
            },
        )

        assert build_map(build_graph([router])).nodes[0].inspects is True


class TestGroups:
    def test_one_connected_estate_is_one_group(self, estate) -> None:
        drawn = build_map(estate)
        assert len(drawn.groups) == 1
        assert drawn.groups[0].devices == 3
        assert drawn.groups[0].firewalls == 2

    def test_two_sites_sharing_an_upstream_are_not_one_group(self) -> None:
        """The mutation this guards: letting an unmanaged address join components.

        Two edge firewalls in different cities both default to the same ISP address. No
        packet crosses from one to the other, and merging them would draw a link between
        two networks that have never met.
        """
        north = node(
            "north-edge",
            addresses={"out": "198.51.100.2/29"},
            routes=[connected("198.51.100.0/29", "out"), static("0.0.0.0/0", "198.51.100.1")],
        )
        south = node(
            "south-edge",
            addresses={"out": "198.51.100.3/29"},
            routes=[connected("198.51.100.0/29", "out"), static("0.0.0.0/0", "198.51.100.1")],
        )

        drawn = build_map(build_graph([north, south]))
        groups = {n.label: n.group for n in drawn.nodes if n.kind == "device"}
        assert groups["north-edge"] != groups["south-edge"]

    def test_a_group_is_named_after_its_site_when_it_has_one(self, estate) -> None:
        meta = {
            device_id: DeviceMeta(site="Docklands")
            for device_id in estate.nodes  # every device in the one group
        }
        drawn = build_map(estate, meta=meta)
        assert (drawn.groups[0].label, drawn.groups[0].label_source) == ("Docklands", "site")

    def test_otherwise_it_is_named_after_the_hostnames_and_says_so(self) -> None:
        """An inferred name must never be mistaken for something somebody configured."""
        left = node(
            "paris-core",
            addresses={"a": "10.0.0.1/30"},
            routes=[connected("10.0.0.0/30", "a"), static("10.9.0.0/24", "10.0.0.2")],
        )
        right = node(
            "paris-dist",
            addresses={"a": "10.0.0.2/30"},
            routes=[connected("10.0.0.0/30", "a"), static("0.0.0.0/0", "10.0.0.1")],
        )

        drawn = build_map(build_graph([left, right]))
        assert (drawn.groups[0].label, drawn.groups[0].label_source) == ("paris", "hostname")

    def test_unrelated_hostnames_fall_back_to_an_index(self) -> None:
        left = node(
            "alpha",
            addresses={"a": "10.0.0.1/30"},
            routes=[connected("10.0.0.0/30", "a"), static("10.9.0.0/24", "10.0.0.2")],
        )
        right = node(
            "bravo",
            addresses={"a": "10.0.0.2/30"},
            routes=[connected("10.0.0.0/30", "a"), static("0.0.0.0/0", "10.0.0.1")],
        )

        drawn = build_map(build_graph([left, right]))
        assert drawn.groups[0].label_source == "index"


class TestTiers:
    def test_the_edge_is_tier_zero_and_depth_increases_inwards(self, estate) -> None:
        drawn = build_map(estate)
        tier = {n.label: n.tier for n in drawn.nodes}

        assert tier["edge-fw"] == 0
        assert tier["core-rtr"] == 1
        assert tier["dmz-fw"] == 2

    def test_the_boundary_sits_outside_the_edge(self, estate) -> None:
        drawn = build_map(estate)
        tier = {n.label: n.tier for n in drawn.nodes}
        assert tier["203.0.113.1"] < tier["edge-fw"]

    def test_a_component_with_no_boundary_is_still_laid_out(self) -> None:
        """An estate with no route leaving it has no edge to start from.

        It must not collapse into every device at tier zero on top of each other, so the
        best-connected device is rooted instead.
        """
        hub = node(
            "hub",
            addresses={"a": "10.0.0.1/24"},
            routes=[connected("10.0.0.0/24", "a"), static("10.9.0.0/24", "10.0.0.2")],
        )
        spoke = node(
            "spoke",
            addresses={"a": "10.0.0.2/24"},
            routes=[connected("10.0.0.0/24", "a"), static("10.8.0.0/24", "10.0.0.1")],
        )

        drawn = build_map(build_graph([hub, spoke]))
        assert sorted(n.tier for n in drawn.nodes) == [0, 1]


class TestHonesty:
    def test_a_device_with_no_snapshot_is_on_the_map_and_says_it_has_none(self) -> None:
        orphan = node("never-collected", addresses={}, routes=[], ncm_version="")
        drawn = build_map(build_graph([orphan]), meta={orphan.device_id: DeviceMeta()})

        drawn_node = drawn.nodes[0]
        assert drawn_node.label == "never-collected"
        assert drawn_node.has_snapshot is False
        assert drawn.isolated == 1
        assert drawn.devices_without_route_data == 1

    def test_interfaces_reach_the_map_with_their_zones(self, estate) -> None:
        edge = next(n for n in estate.nodes.values() if n.hostname == "edge-fw")
        meta = {
            edge.device_id: DeviceMeta(
                interfaces=(
                    MapInterface(name="outside", addresses=("203.0.113.2/29",), zone="outside"),
                ),
                interface_count=6,
            )
        }
        drawn = build_map(estate, meta=meta)
        box = next(n for n in drawn.nodes if n.label == "edge-fw")

        assert box.interfaces[0].zone == "outside"
        # The count of all of them, not just the addressed ones that were carried.
        assert box.interface_count == 6

    def test_trimming_drops_whole_groups_and_names_them(self) -> None:
        """Half a component is a picture of a network that does not exist."""
        big = [
            node(
                f"big-{index}",
                addresses={"a": f"10.1.0.{index + 1}/24"},
                routes=[
                    connected("10.1.0.0/24", "a"),
                    static(f"10.9.{index}.0/24", "10.1.0.1"),
                ],
            )
            for index in range(3)
        ]
        lone = node(
            "lone-01", addresses={"a": "10.2.0.1/24"}, routes=[connected("10.2.0.0/24", "a")]
        )

        drawn = build_map(build_graph([*big, lone]), limit=3)

        assert drawn.omitted_devices == 1
        assert drawn.omitted_groups == ("lone-01",)
        assert "lone-01" not in ids(drawn)
        # Everything still on the map is still whole.
        assert len(ids(drawn, "device")) == 3

    def test_it_would_rather_draw_fewer_devices_than_half_a_group(self) -> None:
        """The case that separates "whole groups" from "the first N devices".

        Two groups of two, with room for three. Trimming by device would keep one and a
        half groups — a picture with a router wired to something that is not on it. The
        third slot goes unused instead, and the reader is told which group is missing.
        """
        pair = [
            node(
                f"{site}-{role}",
                addresses={"a": f"10.{index}.0.{1 if role == 'core' else 2}/24"},
                routes=[
                    connected(f"10.{index}.0.0/24", "a"),
                    static(
                        "10.9.0.0/24" if role == "core" else "0.0.0.0/0",
                        f"10.{index}.0.{2 if role == 'core' else 1}",
                    ),
                ],
            )
            for index, site in enumerate(("alpha", "bravo"))
            for role in ("core", "dist")
        ]

        drawn = build_map(build_graph(pair), limit=3)

        assert len(ids(drawn, "device")) == 2, "a group was split to fill the limit"
        assert drawn.omitted_devices == 2
        assert len(drawn.omitted_groups) == 1
        # And nothing left on the map points at something that is not.
        drawn_ids = {n.id for n in drawn.nodes}
        assert all(link.source in drawn_ids and link.target in drawn_ids for link in drawn.links)


class TestDeterminism:
    def test_the_same_estate_produces_the_same_picture(self, estate) -> None:
        """Position is derived, never simulated.

        Two runs that disagree cannot be compared, and comparing this week's map with
        last week's is most of what anybody wants one for.
        """
        first = build_map(estate)
        second = build_map(estate)

        assert [(n.id, n.tier, n.group) for n in first.nodes] == [
            (n.id, n.tier, n.group) for n in second.nodes
        ]
        assert [link.id for link in first.links] == [link.id for link in second.links]

    def test_it_does_not_depend_on_the_order_devices_arrive_in(self) -> None:
        """Insertion order is a database detail and must not move a box."""
        devices = [
            node(
                "a-edge",
                addresses={"out": "198.51.100.2/29", "in": "10.0.0.1/30"},
                routes=[
                    connected("198.51.100.0/29", "out"),
                    connected("10.0.0.0/30", "in"),
                    static("0.0.0.0/0", "198.51.100.1"),
                    static("10.10.0.0/24", "10.0.0.2"),
                ],
                firewall=permit_all(),
            ),
            node(
                "b-core",
                addresses={"up": "10.0.0.2/30", "lan": "10.10.0.1/24"},
                routes=[
                    connected("10.0.0.0/30", "up"),
                    connected("10.10.0.0/24", "lan"),
                    static("0.0.0.0/0", "10.0.0.1"),
                ],
            ),
        ]

        forwards = build_map(build_graph(devices))
        backwards = build_map(build_graph(list(reversed(devices))))

        assert {(n.label, n.tier, n.kind) for n in forwards.nodes} == {
            (n.label, n.tier, n.kind) for n in backwards.nodes
        }
        assert [link.id for link in forwards.links] == [link.id for link in backwards.links]


def _label(drawn, node_id: str) -> str:
    return next(n.label for n in drawn.nodes if n.id == node_id)
