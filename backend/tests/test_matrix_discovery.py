"""Group-scoped connectivity discovery (Slice B).

The trap this feature is arranged around, and therefore the test that matters most, is
`test_the_walk_crosses_a_device_outside_the_group`: the zones are the group's, but the
paths are walked across the whole estate. A group's two edges may reach each other only
through a core that is not in the group, and truncating the graph to the group would
report that real path as unreachable. The other theme is honesty — an unrouted pair is
`not-routed`, never quietly reachable.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import User
from netsecops.db.models.inventory import DeviceGroupMember
from netsecops.services.matrix import MatrixService
from netsecops.services.topology import TopologyService
from netsecops.topology.cache import GRAPH_CACHE
from tests.conftest import make_group, make_user
from tests.test_topology_api import add_device, connected, ncm, static


@pytest.fixture(autouse=True)
def clean_cache():
    GRAPH_CACHE.clear()
    yield
    GRAPH_CACHE.clear()


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user: User = await make_user(session, username="matrix_actor", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


def permit_all() -> dict[str, Any]:
    return {"security_rules": [{"order": 1, "name": "permit-any", "action": "allow"}]}


async def in_group(session: AsyncSession, group, *devices) -> None:
    for device in devices:
        session.add(DeviceGroupMember(device_id=device.id, group_id=group.id))
    await session.flush()


async def routed_estate(session: AsyncSession, actor: Principal):
    """prod 10.10.0.0/24 ── edge-a ── core ── edge-b ── cde 10.20.0.0/24.

    `core` is the device that must be in the graph but is not in the group.
    """
    edge_a = await add_device(
        session,
        actor,
        hostname="edge-a",
        mgmt_ip="10.10.0.1",
        ncm_body=ncm(
            interfaces=[
                {"name": "prod", "ip_addresses": ["10.10.0.1/24"]},
                {"name": "up", "ip_addresses": ["10.0.0.1/30"]},
            ],
            routes=[
                connected("10.10.0.0/24", "prod"),
                connected("10.0.0.0/30", "up"),
                static("10.20.0.0/24", "10.0.0.2", "up"),
            ],
            firewall=permit_all(),
        ),
    )
    core = await add_device(
        session,
        actor,
        hostname="core",
        mgmt_ip="10.0.0.2",
        ncm_body=ncm(
            interfaces=[
                {"name": "a", "ip_addresses": ["10.0.0.2/30"]},
                {"name": "b", "ip_addresses": ["10.0.1.1/30"]},
            ],
            routes=[
                connected("10.0.0.0/30", "a"),
                connected("10.0.1.0/30", "b"),
                static("10.10.0.0/24", "10.0.0.1", "a"),
                static("10.20.0.0/24", "10.0.1.2", "b"),
            ],
        ),
    )
    edge_b = await add_device(
        session,
        actor,
        hostname="edge-b",
        mgmt_ip="10.20.0.1",
        ncm_body=ncm(
            interfaces=[
                {"name": "cde", "ip_addresses": ["10.20.0.1/24"]},
                {"name": "up", "ip_addresses": ["10.0.1.2/30"]},
            ],
            routes=[
                connected("10.20.0.0/24", "cde"),
                connected("10.0.1.0/30", "up"),
                static("10.10.0.0/24", "10.0.1.1", "up"),
            ],
            firewall=permit_all(),
        ),
    )
    return edge_a, core, edge_b


def cell(matrix, source_cidr: str, destination_cidr: str):
    return next(
        c
        for c in matrix.cells
        if c.source_cidr == source_cidr and c.destination_cidr == destination_cidr
    )


class TestZoneDerivation:
    async def test_zones_come_only_from_the_groups_devices(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        edge_a, _core, edge_b = await routed_estate(session, actor)
        group = await make_group(session, name="edges")
        await in_group(session, group, edge_a, edge_b)

        graph = await TopologyService(session).graph()
        matrix = await MatrixService(session).discover(group, graph)

        # The two edges' access subnets, and not the /30 transit links or the core.
        assert {z.cidr for z in matrix.zones} == {"10.10.0.0/24", "10.20.0.0/24"}

    async def test_transit_and_loopback_prefixes_are_not_zones(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        device = await add_device(
            session,
            actor,
            hostname="only",
            mgmt_ip="192.0.2.1",
            ncm_body=ncm(
                interfaces=[
                    {"name": "lan", "ip_addresses": ["192.0.2.1/24"]},
                    {"name": "transit", "ip_addresses": ["10.0.0.1/30"]},
                    {"name": "lo", "ip_addresses": ["10.1.1.1/32"]},
                ],
                routes=[connected("192.0.2.0/24", "lan")],
            ),
        )
        group = await make_group(session, name="one")
        await in_group(session, group, device)

        graph = await TopologyService(session).graph()
        matrix = await MatrixService(session).discover(group, graph)

        assert {z.cidr for z in matrix.zones} == {"192.0.2.0/24"}

    async def test_a_single_zone_group_says_there_is_nothing_to_compare(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """One zone yields no source/destination pair, so the cell list is empty. That must
        read as 'no comparable zones', not as a clean 'nothing can reach anything' answer."""
        device = await add_device(
            session,
            actor,
            hostname="solo",
            mgmt_ip="192.0.2.1",
            ncm_body=ncm(
                interfaces=[{"name": "lan", "ip_addresses": ["192.0.2.1/24"]}],
                routes=[connected("192.0.2.0/24", "lan")],
            ),
        )
        group = await make_group(session, name="solo-group")
        await in_group(session, group, device)

        graph = await TopologyService(session).graph()
        matrix = await MatrixService(session).discover(group, graph)

        assert len(matrix.zones) == 1
        assert matrix.cells == []
        assert any("comparable zone" in lim for lim in matrix.limitations), (
            "an empty matrix must be labelled, not presented as a complete answer"
        )

    async def test_ipv6_interfaces_are_flagged_not_silently_dropped(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The walk is IPv4-only. A group's IPv6 subnets must be reported as unrepresented,
        not omitted so an IPv4-only (or, for an IPv6-only group, empty) matrix looks whole."""
        device = await add_device(
            session,
            actor,
            hostname="dual",
            mgmt_ip="192.0.2.1",
            ncm_body=ncm(
                interfaces=[
                    {"name": "lan", "ip_addresses": ["192.0.2.1/24"]},
                    {"name": "lan6", "ip_addresses": ["2001:db8::1/64"]},
                ],
                routes=[connected("192.0.2.0/24", "lan")],
            ),
        )
        group = await make_group(session, name="dual-stack")
        await in_group(session, group, device)

        graph = await TopologyService(session).graph()
        matrix = await MatrixService(session).discover(group, graph)

        assert "192.0.2.0/24" in {z.cidr for z in matrix.zones}
        assert any("IPv6" in lim for lim in matrix.limitations), (
            "dropped IPv6 zones must be stated, not silent"
        )


class TestTheMatrixIsWalkedNotTruncated:
    async def test_the_walk_crosses_a_device_outside_the_group(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        edge_a, _core, edge_b = await routed_estate(session, actor)
        group = await make_group(session, name="edges")
        await in_group(session, group, edge_a, edge_b)

        graph = await TopologyService(session).graph()
        matrix = await MatrixService(session).discover(group, graph)

        crossing = cell(matrix, "10.10.0.0/24", "10.20.0.0/24")
        # The path from one edge to the other goes through `core`, which is NOT in the
        # group. That it appears in the hops is the proof the graph was not truncated.
        assert "core" in crossing.hops
        assert crossing.policy != "blocked"
        assert crossing.policy != "not-routed"

    async def test_an_unrouted_pair_is_reported_honestly(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        # Two devices in the group with no route between their subnets.
        a = await add_device(
            session,
            actor,
            hostname="island-a",
            mgmt_ip="172.16.0.1",
            ncm_body=ncm(
                interfaces=[{"name": "lan", "ip_addresses": ["172.16.0.1/24"]}],
                routes=[connected("172.16.0.0/24", "lan")],
            ),
        )
        b = await add_device(
            session,
            actor,
            hostname="island-b",
            mgmt_ip="172.17.0.1",
            ncm_body=ncm(
                interfaces=[{"name": "lan", "ip_addresses": ["172.17.0.1/24"]}],
                routes=[connected("172.17.0.0/24", "lan")],
            ),
        )
        group = await make_group(session, name="islands")
        await in_group(session, group, a, b)

        graph = await TopologyService(session).graph()
        matrix = await MatrixService(session).discover(group, graph)

        isolated = cell(matrix, "172.16.0.0/24", "172.17.0.0/24")
        assert isolated.policy in {"not-routed", "blocked"}
        assert isolated.policy != "allowed"


class TestTheApi:
    async def test_discover_returns_the_matrix(
        self, client: AsyncClient, session: AsyncSession, actor: Principal, analyst: User, authenticate
    ) -> None:
        edge_a, _core, edge_b = await routed_estate(session, actor)
        group = await make_group(session, name="edges")
        await in_group(session, group, edge_a, edge_b)
        authenticate(analyst)

        response = await client.get(f"/api/v1/matrix/discover/{group.id}")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["group_name"] == "edges"
        assert {z["cidr"] for z in body["zones"]} == {"10.10.0.0/24", "10.20.0.0/24"}
        assert "whole estate" in body["scope_note"]

    async def test_an_unknown_group_is_404(
        self, client: AsyncClient, session: AsyncSession, analyst: User, authenticate
    ) -> None:
        authenticate(analyst)
        response = await client.get(f"/api/v1/matrix/discover/{uuid.uuid4()}")
        assert response.status_code == 404
