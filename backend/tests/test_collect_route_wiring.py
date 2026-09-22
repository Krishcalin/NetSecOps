"""A collection reads the forwarding table, and it reaches the snapshot (FR-TOPO-01).

The topology graph is built from `routing.routes` in the NCM, which the Cisco platforms
and FortiOS fill from `show ip route` and its equivalents. Check Point and PAN-OS have no
route command in their profiles, so their routing tables were absent entirely — and an
absent table looks, from the graph's side, exactly like a device with no routes. They are
firewalls, so they are the devices a path most often crosses.

These drive the real collection path rather than calling the walk directly, because the
walk has its own tests against a real BER-speaking agent (`test_snmp_routes.py`) and what
is unproven here is the *wiring*: that a collection asks at all, that the credential gate
holds, and that what comes back survives into the stored NCM. That is the failure this
codebase has now found twice — a built, tested engine reachable from nothing.

The channel is substituted; the merge, the credential resolution, the storage and the
parse are all real.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.adapters.policies import CISCO_IOS
from netsecops.adapters.readonly import ReadOnlyGuard
from netsecops.adapters.session import DeviceSession, NullRecorder
from netsecops.adapters.transport import SSHCredentials, SSHTransport
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, User
from netsecops.db.models.collection import Collection, Snapshot
from netsecops.db.models.inventory import CredentialType, DeviceClass, Vendor
from netsecops.db.models.jobs import Job, JobType
from netsecops.ncm.models import Route
from netsecops.services.credentials import CredentialService
from netsecops.services.inventory import InventoryService
from netsecops.services.snapshots import merge_learned_routes
from netsecops.snmp.routes import RouteWalk
from netsecops.workers import runner as runner_module
from netsecops.workers.runner import _collect_profile
from tests.conftest import make_user
from tests.fake_device import fake_device

DEVICE_USER = "netsecops"
DEVICE_PASSWORD = "device-pass"

LEARNED = (
    Route(destination="10.20.0.0/16", next_hop="10.0.0.9", protocol="ospf"),
    Route(destination="0.0.0.0/0", next_hop="10.0.0.1", protocol="bgp"),
)


@pytest.fixture
async def server():
    async for running in fake_device(username=DEVICE_USER, password=DEVICE_PASSWORD):
        yield running


@pytest.fixture
async def principal(session: AsyncSession) -> Principal:
    user: User = await make_user(session, username="collect_routes", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def make_device(session: AsyncSession, principal: Principal, *, ip: str) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=principal,
        hostname="rtr-collect-routes",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.ROUTER,
    )


async def make_job(session: AsyncSession, device: Device) -> Job:
    job = Job(
        org_id=device.org_id,
        job_type=JobType.COLLECT.value,
        status="running",
        started_at=datetime.now(UTC),
    )
    session.add(job)
    await session.flush()
    return job


async def give_community(
    session: AsyncSession, device: Device, principal: Principal, *, vault, name: str
) -> None:
    credentials = CredentialService(session, vault=vault)
    credential = await credentials.create(
        name=name,
        credential_type=CredentialType.SNMP_V2C,
        secret_data={"community": "s3cr3t-community"},
        actor=principal,
    )
    await credentials.assign(credential, device_id=device.id, actor=principal)


def session_for(running) -> DeviceSession:
    return DeviceSession(
        SSHTransport(
            running.host,
            SSHCredentials(username=DEVICE_USER, password=DEVICE_PASSWORD),
            port=running.port,
        ),
        ReadOnlyGuard(CISCO_IOS),
        recorder=NullRecorder(),
        device_id=uuid.uuid4(),
    )


async def stored_snapshot(session: AsyncSession, device: Device) -> Snapshot:
    rows = await session.execute(select(Snapshot).where(Snapshot.device_id == device.id))
    return list(rows.scalars().all())[-1]


def routes_in(snapshot: Snapshot) -> list[dict]:
    return list(snapshot.ncm.get("routing", {}).get("routes", []))


# ════════════════════════════ the merge ═══════════════════════════════════


class TestTheMerge:
    def test_learned_routes_are_added_to_the_parsed_ones(self) -> None:
        parsed = [Route(destination="192.168.1.0/24", next_hop=None, protocol="connected")]

        merged = merge_learned_routes(parsed, LEARNED)

        assert [route.destination for route in merged] == [
            "192.168.1.0/24",
            "10.20.0.0/16",
            "0.0.0.0/0",
        ]

    def test_the_parsed_route_wins_when_both_have_it(self) -> None:
        """A configuration is authored intent, and survives the device being unreachable."""
        parsed = [Route(destination="0.0.0.0/0", next_hop="10.0.0.1", protocol="static")]

        merged = merge_learned_routes(parsed, LEARNED)

        default = [route for route in merged if route.destination == "0.0.0.0/0"]
        assert len(default) == 1
        assert default[0].protocol == "static"

    def test_equal_cost_paths_to_one_prefix_are_both_kept(self) -> None:
        """Collapsing them would make a resilient design look single-homed."""
        parsed = [Route(destination="10.20.0.0/16", next_hop="10.0.0.9", protocol="static")]
        second = (Route(destination="10.20.0.0/16", next_hop="10.0.0.10", protocol="ospf"),)

        merged = merge_learned_routes(parsed, second)

        assert {route.next_hop for route in merged} == {"10.0.0.9", "10.0.0.10"}


# ════════════════════════════ the wiring ══════════════════════════════════


class TestACollectionReadsTheForwardingTable:
    async def test_learned_routes_reach_the_stored_snapshot(
        self, session: AsyncSession, principal: Principal, server, vault, monkeypatch
    ) -> None:
        """The regression this exists for: before the wiring, `routes` held statics only."""
        device = await make_device(session, principal, ip="10.92.0.1")
        await give_community(session, device, principal, vault=vault, name="snmp-routes-1")
        job = await make_job(session, device)

        monkeypatch.setattr(
            runner_module,
            "walk_routes",
            lambda *_args, **_kwargs: _walk(RouteWalk(routes=LEARNED, table_present=True)),
        )

        async with session_for(server) as device_session:
            outcome = await _collect_profile(
                session, job, device, device_session, "cisco_ios", vault=vault
            )

        assert outcome.succeeded is True
        destinations = {
            route["destination"] for route in routes_in(await stored_snapshot(session, device))
        }
        assert {"10.20.0.0/16", "0.0.0.0/0"} <= destinations

    async def test_a_device_without_a_community_is_not_walked(
        self, session: AsyncSession, principal: Principal, server, vault, monkeypatch
    ) -> None:
        """No credential means no probe — the same rule discovery applies to `public`."""
        device = await make_device(session, principal, ip="10.92.0.2")
        job = await make_job(session, device)

        called = False

        def _spy(*_args, **_kwargs):
            nonlocal called
            called = True
            return _walk(RouteWalk())

        monkeypatch.setattr(runner_module, "walk_routes", _spy)

        async with session_for(server) as device_session:
            outcome = await _collect_profile(
                session, job, device, device_session, "cisco_ios", vault=vault
            )

        assert outcome.succeeded is True
        assert called is False

    async def test_a_failed_walk_records_a_note_and_still_stores_the_snapshot(
        self, session: AsyncSession, principal: Principal, server, vault, monkeypatch
    ) -> None:
        """Supplementary data, in the FR-COL-08 sense: its absence must not cost a snapshot.

        And the reason has to be recorded, because "no learned routes" and "never asked"
        are the two answers this must never conflate.
        """
        device = await make_device(session, principal, ip="10.92.0.3")
        await give_community(session, device, principal, vault=vault, name="snmp-routes-3")
        job = await make_job(session, device)

        monkeypatch.setattr(
            runner_module,
            "walk_routes",
            lambda *_a, **_k: _walk(RouteWalk(note="No SNMP response from 10.92.0.3")),
        )

        async with session_for(server) as device_session:
            outcome = await _collect_profile(
                session, job, device, device_session, "cisco_ios", vault=vault
            )

        assert outcome.succeeded is True
        assert await stored_snapshot(session, device) is not None

        collection = (
            await session.execute(select(Collection).where(Collection.id == outcome.collection_id))
        ).scalar_one()
        assert "Route table" in (collection.error_message or "")

    async def test_a_truncated_walk_marks_the_table_truncated(
        self, session: AsyncSession, principal: Principal, server, vault, monkeypatch
    ) -> None:
        """A path falling off the end of a truncated table must resolve Unknown, not Unreachable."""
        device = await make_device(session, principal, ip="10.92.0.4")
        await give_community(session, device, principal, vault=vault, name="snmp-routes-4")
        job = await make_job(session, device)

        monkeypatch.setattr(
            runner_module,
            "walk_routes",
            lambda *_a, **_k: _walk(RouteWalk(routes=LEARNED, truncated=True, table_present=True)),
        )

        async with session_for(server) as device_session:
            await _collect_profile(session, job, device, device_session, "cisco_ios", vault=vault)

        snapshot = await stored_snapshot(session, device)
        assert snapshot.ncm["routing"]["routes_truncated"] is True


async def _walk(result: RouteWalk) -> RouteWalk:
    """`walk_routes` is awaited; a lambda returning a value would not be."""
    return result
