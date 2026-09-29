"""Collapsing a DR set into one logical node in the topology graph (Slice A, PR2).

The one way this can be catastrophically wrong is the reason it is done carefully: the
standby's interface addresses are the graph's join key, so dropping the standby node
*without* carrying its addresses onto the primary would turn a real path — a next hop
pointing at the standby, or at a VIP the pair floats — into a false `unreachable` at the
very device the collapse removed. `test_a_next_hop_at_the_standby_resolves_to_the_primary`
is that assertion.

The second theme mirrors test_topology_cache: a DR set changes the graph without touching
a device or snapshot row, so declaring one must invalidate the cached graph or the estate
is served its pre-collapse shape.
"""

from __future__ import annotations

import ipaddress
import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import User
from netsecops.db.models.dr import DrRole
from netsecops.schemas.dr import DrMemberInput
from netsecops.services.dr import DrService
from netsecops.services.topology import TopologyService
from netsecops.topology.cache import GRAPH_CACHE
from netsecops.topology.graph import DeviceNode
from tests.conftest import make_user
from tests.test_topology_api import add_device, connected, ncm


@pytest.fixture(autouse=True)
def clean_cache():
    GRAPH_CACHE.clear()
    yield
    GRAPH_CACHE.clear()


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user: User = await make_user(session, username="dr_topo", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


def _addr(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


async def _pair(session: AsyncSession, actor: Principal):
    """A primary and a standby, each a real device with a one-interface snapshot."""
    primary = await add_device(
        session,
        actor,
        hostname="fw-primary",
        mgmt_ip="10.0.0.1",
        ncm_body=ncm(
            interfaces=[{"name": "g0", "ip_addresses": ["10.0.0.1/24"]}],
            routes=[connected("10.0.0.0/24", "g0")],
        ),
    )
    standby = await add_device(
        session,
        actor,
        hostname="fw-standby",
        mgmt_ip="10.0.0.2",
        ncm_body=ncm(
            interfaces=[{"name": "g0", "ip_addresses": ["10.0.0.2/24"]}],
            routes=[connected("10.0.0.0/24", "g0")],
        ),
    )
    return primary, standby


async def _declare(session: AsyncSession, primary, standby, name: str = "edge") -> None:
    await DrService(session).create_set(
        name=name,
        members=[
            DrMemberInput(device_id=primary.id, role=DrRole.PRIMARY),
            DrMemberInput(device_id=standby.id, role=DrRole.STANDBY),
        ],
    )


class TestTheCollapseInTheGraph:
    async def test_a_declared_set_collapses_the_standby_out_of_the_graph(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        primary, standby = await _pair(session, actor)

        before = await TopologyService(session).graph()
        assert {primary.id, standby.id} <= set(before.nodes)

        await _declare(session, primary, standby)

        after = await TopologyService(session).graph()
        assert primary.id in after.nodes
        assert standby.id not in after.nodes

    async def test_a_next_hop_at_the_standby_resolves_to_the_primary(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        primary, standby = await _pair(session, actor)
        await _declare(session, primary, standby)

        graph = await TopologyService(session).graph()
        owner = graph.device_at("10.0.0.2")

        assert owner is not None
        assert owner.device_id == primary.id

    async def test_without_a_set_both_devices_remain_nodes(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        primary, standby = await _pair(session, actor)

        graph = await TopologyService(session).graph()

        assert {primary.id, standby.id} <= set(graph.nodes)
        assert graph.device_at("10.0.0.2").device_id == standby.id


class TestTheCacheNoticesADeclaration:
    async def test_declaring_a_set_changes_the_fingerprint(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        primary, standby = await _pair(session, actor)

        before = await TopologyService(session)._fingerprint()
        await _declare(session, primary, standby)
        after = await TopologyService(session)._fingerprint()

        assert before != after
        assert after.dr_members == 2

    async def test_a_cached_graph_is_not_served_after_a_set_is_declared(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        primary, standby = await _pair(session, actor)

        # Build once so the pre-collapse graph is in the process cache.
        first = await TopologyService(session).graph()
        assert standby.id in first.nodes

        await _declare(session, primary, standby)

        # A fresh service must rebuild rather than serve the cached, pre-collapse graph.
        second = await TopologyService(session).graph()
        assert standby.id not in second.nodes


class TestTheCollapseMergesAddresses:
    """Unit-level: the merge itself, without the database round trip."""

    def test_it_unions_standby_addresses_and_prunes_its_metadata(
        self, session: AsyncSession
    ) -> None:
        primary_id, standby_id = uuid.uuid4(), uuid.uuid4()
        primary = DeviceNode(
            device_id=primary_id,
            hostname="p",
            interface_addresses={_addr("10.0.0.1")},
            interface_networks=[("g0", ipaddress.ip_network("10.0.0.0/24"))],
            zones={"g0": "trust"},
        )
        standby = DeviceNode(
            device_id=standby_id,
            hostname="s",
            # Its own address, plus a VIP the pair floats.
            interface_addresses={_addr("10.0.0.2"), _addr("10.0.0.9")},
            interface_networks=[("g0", ipaddress.ip_network("10.0.0.0/24"))],
            zones={"g1": "dmz"},
        )

        service = TopologyService(session)
        service._meta = {primary_id: object(), standby_id: object()}
        service._site_ids = {primary_id: None, standby_id: None}

        result = service._collapse_dr_sets([primary, standby], {primary_id: [standby_id]})

        assert [n.device_id for n in result] == [primary_id]
        assert primary.interface_addresses == {
            _addr("10.0.0.1"),
            _addr("10.0.0.2"),
            _addr("10.0.0.9"),
        }
        assert primary.zones == {"g0": "trust", "g1": "dmz"}
        # The standby is gone from the metadata too, so the estate is one device here
        # everywhere.
        assert standby_id not in service._meta
        assert standby_id not in service._site_ids

    def test_a_missing_primary_leaves_the_standbys_alone(self, session: AsyncSession) -> None:
        # The primary is archived or otherwise not an active node: there is nothing to
        # collapse onto, and the standby must not vanish with its addresses.
        standby_id = uuid.uuid4()
        standby = DeviceNode(device_id=standby_id, hostname="s")

        service = TopologyService(session)
        result = service._collapse_dr_sets([standby], {uuid.uuid4(): [standby_id]})

        assert [n.device_id for n in result] == [standby_id]
