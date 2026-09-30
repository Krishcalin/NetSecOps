"""Holding the graph between requests without holding a stale one (NFR-PERF-01).

`services/topology.py` refused to cache the graph and gave a good reason: an answer
that silently reflects yesterday's estate is the kind of wrong that looks right. The
cache exists because the graph costs ~580ms at 650 devices and one dashboard load
built two of them — but it is only worth having if that reason still holds.

So almost every test here is an *invalidation* test. A cache that never serves a hit
is merely slow; one that serves a hit it should not have is the failure the original
rule was protecting against, and it is invisible: the answer looks exactly like a
correct one.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import User
from netsecops.db.models.inventory import DeviceStatus
from netsecops.services.topology import TopologyService
from netsecops.topology.cache import GRAPH_CACHE
from tests.conftest import make_user
from tests.test_topology_api import add_device, connected, ncm, static


@pytest.fixture(autouse=True)
def clean_cache():
    """A process-wide cache is shared by every test in the run.

    Cleared on both sides: a leftover entry would make the next test's first build a
    hit, and this test's entry would outlive its transaction's rollback.
    """
    GRAPH_CACHE.clear()
    yield
    GRAPH_CACHE.clear()


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user: User = await make_user(session, username="cache_actor", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def seed(session: AsyncSession, actor: Principal, hostname: str, ip: str):
    return await add_device(
        session,
        actor,
        hostname=hostname,
        mgmt_ip=ip,
        ncm_body=ncm(
            interfaces=[{"name": "a", "ip_addresses": [f"{ip}/24"]}],
            routes=[connected(f"{ip.rsplit('.', 1)[0]}.0/24", "a")],
        ),
    )


class TestItServesAHit:
    async def test_a_second_service_reuses_the_graph(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The whole point: two requests, one build.

        A dashboard load asks for the topology summary and the segmentation matrix,
        which are separate requests and each built their own graph.
        """
        await seed(session, actor, "cache-a", "10.60.0.1")
        await session.commit()

        first = await TopologyService(session).graph()
        second = await TopologyService(session).graph()

        assert second is first, "the second service rebuilt a graph it could have reused"

    async def test_the_metadata_comes_back_with_it(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The map needs device class and interfaces, which are gathered during the
        build. A cache that returned only the graph would make every map request a
        rebuild, which is most of what this was for."""
        await seed(session, actor, "cache-meta", "10.60.1.1")
        await session.commit()
        await TopologyService(session).graph()

        drawn = await TopologyService(session).estate_map()

        assert [node.label for node in drawn.nodes if node.kind == "device"] == ["cache-meta"]
        assert drawn.nodes[0].device_class is not None


class TestItInvalidates:
    """Each of these is a change that alters the graph. Missing any one of them means
    serving an answer about an estate that has moved."""

    async def test_a_new_snapshot_invalidates_it(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The case the original rule was written for: a collection ran, so the
        configuration this graph was built from is no longer the current one."""
        device = await seed(session, actor, "cache-snap", "10.60.2.1")
        await session.commit()
        before = await TopologyService(session).graph()
        assert before.nodes[device.id].routes  # one connected route

        from netsecops.db.models.collection import Snapshot

        session.add(
            Snapshot(
                org_id=1,
                device_id=device.id,
                ncm=ncm(
                    interfaces=[{"name": "a", "ip_addresses": ["10.60.2.1/24"]}],
                    routes=[
                        connected("10.60.2.0/24", "a"),
                        static("0.0.0.0/0", "10.60.2.254", "a"),
                    ],
                ),
                ncm_version="1.1",
                config_hash="s" * 64,
                normalized_hash="s" * 64,
                config_redacted="! newer",
            )
        )
        await session.commit()

        after = await TopologyService(session).graph()

        assert after is not before
        assert len(after.nodes[device.id].routes) == 2, "the newer snapshot was not picked up"

    async def test_an_in_place_snapshot_refresh_invalidates_it(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """A re-collection whose config_hash matches updates the existing snapshot row in
        place — new NCM and version, same created_at (only updated_at moves). Keying the
        fingerprint on created_at served the pre-refresh graph (2026-09-30 audit); it must
        key on updated_at, which the in-place refresh moves."""
        from netsecops.db.models.collection import Snapshot

        device = await seed(session, actor, "cache-refresh", "10.60.9.1")
        await session.commit()
        before = await TopologyService(session).graph()
        assert len(before.nodes[device.id].routes) == 1

        snapshot = (
            await session.execute(select(Snapshot).where(Snapshot.device_id == device.id))
        ).scalars().one()
        # Same row, refreshed in place — this is what the dedup branch does; it moves
        # updated_at (onupdate) but not created_at, and inserts no new row.
        snapshot.ncm = ncm(
            interfaces=[{"name": "a", "ip_addresses": ["10.60.9.1/24"]}],
            routes=[connected("10.60.9.0/24", "a"), static("0.0.0.0/0", "10.60.9.254", "a")],
        )
        snapshot.ncm_version = "1.1"
        await session.commit()

        after = await TopologyService(session).graph()

        assert after is not before
        assert len(after.nodes[device.id].routes) == 2, "the in-place refresh was not picked up"

    async def test_a_new_device_invalidates_it(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        await seed(session, actor, "cache-one", "10.60.3.1")
        await session.commit()
        before = await TopologyService(session).graph()

        await seed(session, actor, "cache-two", "10.60.3.2")
        await session.commit()
        after = await TopologyService(session).graph()

        assert after is not before
        assert len(after.nodes) == len(before.nodes) + 1

    async def test_archiving_a_device_invalidates_it(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """Archived devices are excluded from the graph, so archiving one changes it.

        The count alone would catch this; `updated_at` is in the fingerprint as well
        because archiving one while onboarding another leaves the count unmoved.
        """
        device = await seed(session, actor, "cache-archive", "10.60.4.1")
        await seed(session, actor, "cache-stays", "10.60.4.2")
        await session.commit()
        before = await TopologyService(session).graph()

        device.status = DeviceStatus.ARCHIVED.value
        await session.commit()
        after = await TopologyService(session).graph()

        assert after is not before
        assert device.id not in after.nodes

    async def test_renaming_a_device_invalidates_it(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """A hostname is on every node and in every path answer, and renaming moves no
        count at all. This is the change `updated_at` is in the fingerprint for."""
        device = await seed(session, actor, "cache-before", "10.60.5.1")
        await session.commit()
        before = await TopologyService(session).graph()
        assert before.nodes[device.id].hostname == "cache-before"

        device.hostname = "cache-after"
        await session.commit()
        after = await TopologyService(session).graph()

        assert after.nodes[device.id].hostname == "cache-after"

    async def test_changing_a_management_address_invalidates_it(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The management address is indexed as an interface address and is how peers
        routing to it are joined, so moving one re-wires the graph."""
        device = await seed(session, actor, "cache-mgmt", "10.60.6.1")
        await session.commit()
        await TopologyService(session).graph()

        device.mgmt_ip = "10.60.6.9"
        await session.commit()
        after = await TopologyService(session).graph()

        # The new address is indexed. The old one still is too, because the snapshot's
        # interface `a` carries 10.60.6.1/24 — moving the management address does not
        # retract what the device's configuration says about itself.
        assert after.device_at("10.60.6.9") is not None
        assert after.nodes[device.id].hostname == "cache-mgmt"

    async def test_deleting_a_device_invalidates_it(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The change only the *device count* catches.

        Three things have to line up for that to be true, and each is deliberate
        here. The deleted device carries **no snapshot**, so the snapshot count and
        timestamp do not move — cascading a snapshot away is what masked this the
        first time it was written. It is **not** the most recently touched device, so
        `max(updated_at)` over what remains is unchanged. And the row is **hard
        deleted** rather than archived, so its own timestamp leaves with it.

        Take the device count out of the fingerprint and this graph goes on naming a
        device that no longer exists.
        """
        from netsecops.services.inventory import InventoryService

        keep = await seed(session, actor, "cache-keep", "10.60.10.1")
        doomed = await add_device(
            session,
            actor,
            hostname="cache-doomed",
            mgmt_ip="10.60.10.2",
            ncm_body=None,
        )
        await session.commit()
        # Touched last, so it — not the device being deleted — owns `max(updated_at)`.
        keep.notes = "most recently updated"
        await session.commit()

        before = await TopologyService(session).graph()
        assert len(before.nodes) == 2

        await InventoryService(session).delete_device(doomed, actor=actor)
        await session.commit()

        after = await TopologyService(session).graph()

        assert len(after.nodes) == 1, "a deleted device was still in the cached graph"
        assert doomed.id not in after.nodes


class TestItIsScopedToTheOrganisation:
    async def test_one_org_never_serves_another_its_graph(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """Each organisation keeps its own entry rather than evicting the other's.

        What `org_id` earns its place for is the cache *key*, not the equality check.
        Every timestamp in this schema comes from `clock_timestamp()` rather than
        `now()` — see `db/base.py`, which chose that deliberately — so two
        organisations' fingerprints differ by microseconds anyway and a shared slot
        would be a correctness problem only in the empty-estate case. It would still
        be a cache that holds one graph for the whole deployment and rebuilds on
        every alternating request, which is most of the benefit gone.

        So this asserts the eviction, not the disclosure: build one, build the other,
        and the first must still be a hit.
        """
        await seed(session, actor, "cache-org1", "10.60.7.1")
        await add_device(
            session,
            actor,
            hostname="cache-org2",
            mgmt_ip="10.60.7.2",
            ncm_body=ncm(
                interfaces=[{"name": "a", "ip_addresses": ["10.60.7.2/24"]}],
                routes=[connected("10.60.7.0/24", "a")],
            ),
            org_id=2,
        )
        await session.commit()

        first = await TopologyService(session, org_id=1).graph()
        other = await TopologyService(session, org_id=2).graph()
        again = await TopologyService(session, org_id=1).graph()

        assert other is not first
        assert [n.hostname for n in first.nodes.values()] == ["cache-org1"]
        assert [n.hostname for n in other.nodes.values()] == ["cache-org2"]
        # The one that matters: org 2's build did not evict org 1's.
        assert again is first, "the second organisation evicted the first one's graph"
        assert GRAPH_CACHE.size == 2


class TestTheSwitch:
    async def test_it_can_be_turned_off(self, session: AsyncSession, actor: Principal) -> None:
        """A product this careful about stale answers should let an operator refuse
        the trade without patching the source."""
        import netsecops.services.topology as topology_module

        await seed(session, actor, "cache-off", "10.60.8.1")
        await session.commit()

        original = topology_module.settings_cache_enabled
        topology_module.settings_cache_enabled = lambda: False
        try:
            first = await TopologyService(session).graph()
            second = await TopologyService(session).graph()
        finally:
            topology_module.settings_cache_enabled = original

        assert second is not first, "the cache was consulted although it is switched off"
        assert GRAPH_CACHE.size == 0


class TestItCostsOneQuery:
    async def test_a_hit_does_not_read_the_snapshots(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """A cache that still fetched every snapshot to decide it had one would save
        the parsing and none of the I/O — which is most of the 580ms."""
        from tests.test_topology_query_cost import counted

        await seed(session, actor, "cache-cost", "10.60.9.1")
        await session.commit()
        await TopologyService(session).graph()

        with counted(session) as statements:
            await TopologyService(session).graph()

        assert len(statements) == 1, (
            "a cache hit should cost exactly the fingerprint query, not "
            f"{len(statements)}:\n" + "\n".join(s.splitlines()[0][:90] for s in statements)
        )
        # The fingerprint *names* the snapshots table — it counts the rows and takes
        # the newest timestamp. What it must not do is read them: `ncm` is the whole
        # normalised configuration, and fetching 650 of those is most of the 580ms
        # this exists to avoid.
        assert "ncm" not in statements[0].lower()
        assert "count" in statements[0].lower()
