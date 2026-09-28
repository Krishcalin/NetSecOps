"""Collecting from a controller records its access points (SRS §1.3.1, FR-INV-04).

The companion to `test_collect_vuln_wiring.py`, and it exists for the same reason that
file does: **the bug is never in the service, it is in the wiring.** Every other test
of the access-point inventory calls `sync_access_points` directly, so all of them pass
with a runner that never calls it — which is exactly the defect this product keeps
finding in itself, most recently three times in one day.

A mutation that deleted the call from `_collect_profile` survived the entire
access-point suite. This is what kills it.

So this drives the real collection path against the fake SSH device: a Catalyst 9800
answering `show ap summary`, collected, parsed and stored, with the access points
appearing in the inventory at the other end.
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
from netsecops.db.models.inventory import DeviceClass, DeviceStatus, Vendor
from netsecops.db.models.jobs import Job, JobType
from netsecops.services.inventory import InventoryService
from netsecops.workers.runner import _collect_profile
from tests.conftest import make_user
from tests.fake_device import fake_device

DEVICE_USER = "netsecops"
DEVICE_PASSWORD = "device-pass"

#: Cisco's documented `show ap summary` shape, trimmed to two radios.
AP_SUMMARY = """\
Number of APs: 2

AP Name    Slots  AP Model  Ethernet MAC    Radio MAC       CC  RD  IP Address    State
----------------------------------------------------------------------------------------
AP-Floor1  2      9130AXI   aabb.ccdd.ee01  aabb.ccdd.ee10  IN  -D  10.92.0.11   Registered
AP-Floor2  2      9120AXI   aabb.ccdd.ee02  aabb.ccdd.ee20  IN  -D  10.92.0.12   Registered
"""


@pytest.fixture
async def server():
    async for running in fake_device(username=DEVICE_USER, password=DEVICE_PASSWORD):
        running.set_response("show ap summary", AP_SUMMARY)
        yield running


@pytest.fixture
async def principal(session: AsyncSession) -> Principal:
    user: User = await make_user(session, username="collect_ap", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def make_controller(session: AsyncSession, principal: Principal, *, ip: str) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=principal,
        hostname="wlc-collect-01",
        vendor=Vendor.CISCO,
        platform="cisco_c9800",
        device_class=DeviceClass.WIRELESS_CONTROLLER,
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


def session_for(running) -> DeviceSession:
    return DeviceSession(
        SSHTransport(
            running.host,
            SSHCredentials(username=DEVICE_USER, password=DEVICE_PASSWORD),
            port=running.port,
        ),
        # The 9800 shares the IOS allow-list, which is the point of the alias — the
        # six wireless commands were already on it.
        ReadOnlyGuard(CISCO_IOS),
        recorder=NullRecorder(),
        device_id=uuid.uuid4(),
    )


async def joined_aps(session: AsyncSession, controller: Device) -> list[Device]:
    rows = await session.execute(
        select(Device).where(Device.parent_device_id == controller.id).order_by(Device.hostname)
    )
    return list(rows.scalars())


class TestACollectionRecordsTheAccessPoints:
    async def test_they_appear_in_the_inventory_after_a_collect(
        self, session: AsyncSession, principal: Principal, server, vault
    ) -> None:
        """The regression. With the call removed from `_collect_profile` this is empty
        and nothing else in the suite notices."""
        controller = await make_controller(session, principal, ip="10.92.0.1")
        job = await make_job(session, controller)

        async with session_for(server) as device_session:
            outcome = await _collect_profile(
                session, job, controller, device_session, "cisco_c9800", vault=vault
            )

        assert outcome.succeeded is True
        assert [d.hostname for d in await joined_aps(session, controller)] == [
            "AP-Floor1",
            "AP-Floor2",
        ]

    async def test_they_arrive_as_assets_rather_than_as_targets(
        self, session: AsyncSession, principal: Principal, server, vault
    ) -> None:
        controller = await make_controller(session, principal, ip="10.92.0.2")
        job = await make_job(session, controller)

        async with session_for(server) as device_session:
            await _collect_profile(
                session, job, controller, device_session, "cisco_c9800", vault=vault
            )

        recorded = await joined_aps(session, controller)
        assert {d.status for d in recorded} == {DeviceStatus.INVENTORY_ONLY.value}
        assert {d.device_class for d in recorded} == {DeviceClass.WIRELESS_AP.value}

    async def test_a_second_collection_does_not_duplicate_them(
        self, session: AsyncSession, principal: Principal, server, vault
    ) -> None:
        # Collections are scheduled. Duplicating on each run would grow the estate's
        # device count without bound, which is the failure a reader would blame on
        # discovery rather than on this.
        controller = await make_controller(session, principal, ip="10.92.0.3")
        job = await make_job(session, controller)

        for _ in range(2):
            async with session_for(server) as device_session:
                await _collect_profile(
                    session, job, controller, device_session, "cisco_c9800", vault=vault
                )

        assert len(await joined_aps(session, controller)) == 2

    async def test_collecting_from_a_switch_records_nothing(
        self, session: AsyncSession, principal: Principal, server, vault
    ) -> None:
        """Most of the estate is not a wireless controller.

        A switch is collected with the plain IOS profile, never asks for an AP
        summary, and must produce no access points — not an empty controller with
        radios attached to it.
        """
        switch = await InventoryService(session).create_device(
            mgmt_ip="10.92.0.9",
            actor=principal,
            hostname="sw-collect-ap",
            vendor=Vendor.CISCO,
            platform="cisco_ios",
            device_class=DeviceClass.SWITCH,
        )
        job = await make_job(session, switch)

        async with session_for(server) as device_session:
            await _collect_profile(session, job, switch, device_session, "cisco_ios", vault=vault)

        assert await joined_aps(session, switch) == []
