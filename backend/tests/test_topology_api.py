"""Path analysis over stored snapshots, through the API (FR-TOPO-03 … FR-TOPO-06).

`test_topology.py` proves the graph and the walk against hand-built nodes. This proves
the layer between them and the database: that a snapshot's JSON becomes a node with the
right routes, addresses and zones, that archived devices stay out of the estate, and that
a device with no snapshot is still visible to the missing-device report.

The estate here is the same three devices as the unit tests, built as real rows so the
NCM-to-node mapping is exercised rather than assumed — that mapping is where a field
renamed in the parser would silently stop reaching the graph.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.collection import Snapshot
from netsecops.db.models.inventory import DeviceClass, DeviceStatus, Vendor
from netsecops.services.inventory import InventoryService
from netsecops.services.topology import TopologyService
from tests.conftest import make_user

PATH = "/api/v1/topology/path"
MISSING = "/api/v1/topology/missing-devices"
SUMMARY = "/api/v1/topology/summary"


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="topology_analyst", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
async def signed_in(session: AsyncSession, authenticate):
    user = await make_user(session, username="topology_api", roles={Role.SECURITY_ANALYST})
    await session.commit()
    authenticate(user)
    return user


def ncm(
    *,
    interfaces: list[dict[str, Any]],
    routes: list[dict[str, Any]],
    firewall: dict[str, Any] | None = None,
    version: str = "1.1",
) -> dict[str, Any]:
    return {
        "ncm_version": version,
        "interfaces": interfaces,
        "routing": {"routes": routes, "protocols": []},
        "firewall": firewall or {},
    }


def connected(prefix: str, interface: str) -> dict[str, Any]:
    return {"destination": prefix, "interface": interface, "protocol": "connected"}


def static(prefix: str, via: str, interface: str | None = None) -> dict[str, Any]:
    return {
        "destination": prefix,
        "next_hop": via,
        "interface": interface,
        "protocol": "static",
    }


async def add_device(
    session: AsyncSession,
    actor: Principal,
    *,
    hostname: str,
    mgmt_ip: str,
    ncm_body: dict[str, Any] | None,
    status: str = DeviceStatus.ACTIVE.value,
):
    device = await InventoryService(session).create_device(
        mgmt_ip=mgmt_ip,
        actor=actor,
        hostname=hostname,
        vendor=Vendor.CISCO,
        platform="cisco_asa",
        device_class=DeviceClass.FIREWALL,
        status=status,
    )
    if ncm_body is not None:
        digest = uuid.uuid4().hex
        session.add(
            Snapshot(
                org_id=1,
                device_id=device.id,
                ncm=ncm_body,
                ncm_version=ncm_body.get("ncm_version", "1.1"),
                config_hash=digest,
                normalized_hash=digest,
                config_redacted=f"! {hostname}",
            )
        )
        await session.flush()
    return device


@pytest.fixture
async def estate(session: AsyncSession, actor: Principal):
    """edge-fw ─ core-rtr ─ dmz-fw, with an unmanaged ISP beyond the edge."""
    await add_device(
        session,
        actor,
        hostname="edge-fw",
        mgmt_ip="10.0.0.1",
        ncm_body=ncm(
            interfaces=[
                {"name": "outside", "ip_addresses": ["203.0.113.2/29"], "zone": "outside"},
                {"name": "inside", "ip_addresses": ["10.0.0.1/30"], "zone": "inside"},
            ],
            routes=[
                connected("203.0.113.0/29", "outside"),
                connected("10.0.0.0/30", "inside"),
                static("0.0.0.0/0", "203.0.113.1", "outside"),
                static("10.10.0.0/24", "10.0.0.2", "inside"),
            ],
            firewall={"security_rules": [{"order": 1, "name": "permit-any", "action": "allow"}]},
        ),
    )
    await add_device(
        session,
        actor,
        hostname="core-rtr",
        mgmt_ip="10.0.0.2",
        ncm_body=ncm(
            interfaces=[
                {"name": "up", "ip_addresses": ["10.0.0.2/30"]},
                {"name": "lan", "ip_addresses": ["10.10.0.1/24"]},
                {"name": "dmz", "ip_addresses": ["10.0.1.1/30"]},
            ],
            routes=[
                connected("10.0.0.0/30", "up"),
                connected("10.10.0.0/24", "lan"),
                connected("10.0.1.0/30", "dmz"),
                static("0.0.0.0/0", "10.0.0.1", "up"),
                static("10.20.0.0/24", "10.0.1.2", "dmz"),
            ],
        ),
    )
    await add_device(
        session,
        actor,
        hostname="dmz-fw",
        mgmt_ip="10.0.1.2",
        ncm_body=ncm(
            interfaces=[
                {"name": "up", "ip_addresses": ["10.0.1.2/30"], "zone": "trust"},
                {"name": "dmz", "ip_addresses": ["10.20.0.1/24"], "zone": "dmz"},
            ],
            routes=[
                connected("10.0.1.0/30", "up"),
                connected("10.20.0.0/24", "dmz"),
                static("0.0.0.0/0", "10.0.1.1", "up"),
            ],
            firewall={
                "security_rules": [
                    {"order": 1, "name": "no-telnet", "action": "deny", "services": ["tcp/23"]},
                    {"order": 2, "name": "permit-web", "action": "allow", "services": ["tcp/443"]},
                ]
            },
        ),
    )
    await session.flush()


# ════════════════════ the NCM-to-graph mapping ═══════════════════════════════


class TestTheGraphIsBuiltFromSnapshots:
    async def test_a_path_crosses_the_stored_estate(self, session: AsyncSession, estate) -> None:
        result = await TopologyService(session).path(
            source="10.10.0.5", destination="10.20.0.5", port=443
        )

        assert result.routing.value == "routed"
        assert [hop.hostname for hop in result.hops] == ["core-rtr", "dmz-fw"]

    async def test_zones_survive_the_round_trip(self, session: AsyncSession, estate) -> None:
        """The mapping from `interfaces[].zone` into the node is where a renamed field
        would silently stop reaching the rule query, taking zone matching with it."""
        result = await TopologyService(session).path(source="10.10.0.5", destination="10.20.0.5")

        dmz = next(hop for hop in result.hops if hop.hostname == "dmz-fw")
        assert (dmz.ingress_zone, dmz.egress_zone) == ("trust", "dmz")

    async def test_the_rulebase_decides_per_port(self, session: AsyncSession, estate) -> None:
        allowed = await TopologyService(session).path(
            source="10.10.0.5", destination="10.20.0.5", port=443
        )
        blocked = await TopologyService(session).path(
            source="10.10.0.5", destination="10.20.0.5", port=23
        )

        assert allowed.policy.value == "allowed"
        assert blocked.policy.value == "blocked"
        assert blocked.blocked_by is not None
        assert blocked.blocked_by.rule_name == "no-telnet"

    async def test_an_archived_device_is_not_in_the_estate(
        self, session: AsyncSession, actor: Principal, estate
    ) -> None:
        """Routing a path through decommissioned hardware would be worse than not
        finding one, because it answers confidently with a device that is gone."""
        await add_device(
            session,
            actor,
            hostname="old-fw",
            mgmt_ip="10.0.1.9",
            status=DeviceStatus.ARCHIVED.value,
            ncm_body=ncm(
                interfaces=[{"name": "x", "ip_addresses": ["203.0.113.1/29"]}],
                routes=[connected("203.0.113.0/29", "x")],
            ),
        )
        await session.flush()

        graph = await TopologyService(session).graph()

        assert "old-fw" not in {node.hostname for node in graph.nodes.values()}
        # And because it is absent, the ISP address it would have claimed is still a gap.
        assert graph.device_at("203.0.113.1") is None


class TestLeavingTheEstate:
    async def test_a_permit_beyond_the_edge_is_only_partially_allowed(
        self, session: AsyncSession, estate
    ) -> None:
        """The honesty rule, end to end from the database."""
        result = await TopologyService(session).path(
            source="10.10.0.5", destination="8.8.8.8", port=443
        )

        assert result.routing.value == "partially-routed"
        assert result.policy.value == "partially-allowed"
        assert result.stopped_at_next_hop == "203.0.113.1"


class TestCoverageIsReported:
    async def test_a_device_collected_before_routes_existed_is_named(
        self, session: AsyncSession, actor: Principal, estate
    ) -> None:
        """It is in the inventory, contributes nothing, and is the reason a path may stop
        somewhere that looks arbitrary. Leaving that to be inferred is how a coverage gap
        reads as a network fact."""
        await add_device(
            session,
            actor,
            hostname="legacy-sw",
            mgmt_ip="10.30.0.1",
            ncm_body=ncm(interfaces=[], routes=[], version="1.0"),
        )
        await session.flush()

        result = await TopologyService(session).path(source="10.10.0.5", destination="10.20.0.5")

        assert any("legacy-sw" in note for note in result.notes)

    async def test_the_summary_counts_what_the_graph_is_made_of(
        self, session: AsyncSession, estate
    ) -> None:
        stats = await TopologyService(session).summary()

        assert stats.devices == 3
        assert stats.devices_with_routes == 3
        assert stats.devices_with_rulebase == 2
        assert stats.unmanaged_next_hops == 1


class TestMissingDevicesFromStoredState:
    async def test_the_isp_router_is_ranked(self, session: AsyncSession, estate) -> None:
        found = await TopologyService(session).missing()

        assert [item.address for item in found] == ["203.0.113.1"]
        assert found[0].carries_default_route is True
        assert found[0].referenced_by == ["edge-fw"]

    async def test_a_device_with_no_snapshot_still_closes_a_gap(
        self, session: AsyncSession, actor: Principal, estate
    ) -> None:
        """A device in the inventory but never collected has no routes — yet its
        management address is known, and that address is enough to join two hops.

        Leaving such a device out of the graph entirely would keep it invisible to the
        very report that should be pointing at it.
        """
        before = await TopologyService(session).missing()
        assert "203.0.113.1" in {item.address for item in before}

        await add_device(session, actor, hostname="isp-edge", mgmt_ip="203.0.113.1", ncm_body=None)
        await session.flush()

        after = await TopologyService(session).missing()

        assert "203.0.113.1" not in {item.address for item in after}


# ═════════════════════════════ the HTTP surface ══════════════════════════════


class TestTheEndpoints:
    async def test_a_path_query_returns_both_axes(
        self, client: AsyncClient, signed_in, session: AsyncSession, actor: Principal
    ) -> None:
        await add_device(
            session,
            actor,
            hostname="solo-fw",
            mgmt_ip="10.10.0.1",
            ncm_body=ncm(
                interfaces=[
                    {"name": "lan", "ip_addresses": ["10.10.0.1/24"], "zone": "inside"},
                    {"name": "dmz", "ip_addresses": ["10.20.0.1/24"], "zone": "dmz"},
                ],
                routes=[connected("10.10.0.0/24", "lan"), connected("10.20.0.0/24", "dmz")],
                firewall={"security_rules": [{"order": 1, "name": "permit", "action": "allow"}]},
            ),
        )
        await session.commit()

        response = await client.post(
            PATH,
            json={
                "source": "10.10.0.5",
                "destination": "10.20.0.5",
                "protocol": "tcp",
                "port": 443,
            },
        )

        assert response.status_code == 200, response.text
        body = response.json()
        # Two fields, never one. A client wanting a single summary has to decide for
        # itself what "permitted, and I lost the path" means.
        assert body["routing"] == "routed"
        assert body["policy"] == "allowed"
        assert body["hops"][0]["hostname"] == "solo-fw"

    async def test_a_hostname_is_refused_rather_than_resolved(
        self, client: AsyncClient, signed_in
    ) -> None:
        response = await client.post(
            PATH, json={"source": "server01.example.net", "destination": "10.20.0.5"}
        )

        assert response.status_code == 422

    async def test_the_missing_report_reads_empty_rather_than_erroring(
        self, client: AsyncClient, signed_in
    ) -> None:
        response = await client.get(MISSING)

        assert response.status_code == 200
        assert response.json() == []

    async def test_the_summary_is_readable_on_an_empty_estate(
        self, client: AsyncClient, signed_in
    ) -> None:
        response = await client.get(SUMMARY)

        assert response.status_code == 200
        assert response.json()["devices"] == 0
