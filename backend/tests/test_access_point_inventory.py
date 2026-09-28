"""Access points recorded as assets, never as targets (SRS §1.3.1, FR-INV-04).

A CAPWAP access point holds no configuration of its own — its controller does — so
NetSecOps never contacts one. It is still an asset, and an estate's AP count is a thing
people ask an inventory for. This is what lets it be both.

**The failure to avoid is not "no APs in the inventory". It is a wireless estate that
reads as uncollected.** An access point that can never be collected from, filed as an
ordinary device, is permanently unassessed: three hundred of them would drag the grade
distribution, the estate roll-up and every coverage figure towards "nobody has looked",
and the figures would be describing radios rather than the network. `inventory_only` is
what keeps them out of all of it, and most of this file is about that boundary holding.

The second failure is subtler and worse: **archiving an estate's access points because
one command came back empty.** An AP list that did not parse and a controller with no
APs joined are the same `[]`, so the sync refuses to act on either rather than guessing
which it is looking at.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Scope
from netsecops.db.models.inventory import Criticality, Device, DeviceClass, DeviceStatus, Vendor
from netsecops.services.access_points import sync_access_points
from netsecops.services.grading import GradingService
from netsecops.services.jobs import JobScope, JobService


def ncm(*aps: dict[str, Any], declared: int | None = None) -> dict[str, Any]:
    return {
        "wireless": {
            "aps": list(aps),
            "aps_declared": len(aps) if declared is None else declared,
        }
    }


#: One address per name, assigned on first use and stable afterwards. `devices` is
#: unique on `(org_id, mgmt_ip)` and the column is not nullable, so an address is not
#: decoration here — it is what makes the row storable. Keyed by name rather than
#: handed out in sequence so that building the same access point twice, which several
#: tests below do, produces the same one.
_ADDRESSES: dict[str, str] = {}


def ap(name: str, **fields: Any) -> dict[str, Any]:
    address = _ADDRESSES.setdefault(name, f"10.1.1.{len(_ADDRESSES) + 11}")
    return {"name": name, "model": None, "ip": address, "serial": None, **fields}


async def make_controller(
    session: AsyncSession, *, ip: str = "10.0.0.1", hostname: str = "wlc-01"
) -> Device:
    device = Device(
        org_id=1,
        hostname=hostname,
        mgmt_ip=ip,
        vendor=Vendor.CISCO.value,
        platform="cisco_c9800",
        device_class=DeviceClass.WIRELESS_CONTROLLER.value,
        criticality=Criticality.HIGH.value,
        status=DeviceStatus.ACTIVE.value,
    )
    session.add(device)
    await session.flush()
    return device


async def access_points(session: AsyncSession, controller: Device) -> list[Device]:
    rows = await session.execute(
        select(Device).where(Device.parent_device_id == controller.id).order_by(Device.hostname)
    )
    return list(rows.scalars())


class TestTheyAreAssetsNotTargets:
    @pytest.mark.anyio
    async def test_each_reported_access_point_becomes_an_inventory_row(self, session) -> None:
        controller = await make_controller(session)

        result = await sync_access_points(
            session,
            controller,
            ncm(ap("AP-Floor1", model="9130AXI", ip="10.1.1.11"), ap("AP-Floor2")),
        )

        assert result.added == 2
        assert [d.hostname for d in await access_points(session, controller)] == [
            "AP-Floor1",
            "AP-Floor2",
        ]

    @pytest.mark.anyio
    async def test_they_are_inventory_only_and_never_active(self, session) -> None:
        """The whole point. `active` would make them assessable devices that can never
        be assessed, and a wireless estate would then read as uncollected."""
        controller = await make_controller(session)

        await sync_access_points(session, controller, ncm(ap("AP-1")))

        assert [d.status for d in await access_points(session, controller)] == [
            DeviceStatus.INVENTORY_ONLY.value
        ]

    @pytest.mark.anyio
    async def test_they_are_outside_the_grade_distribution(self, session) -> None:
        """The consequence that matters, asserted through the thing that would suffer.

        `GradingService.grades` counts active devices. An access point counted there is
        a permanent ungraded row, and three hundred of them would describe an estate
        nobody had assessed.
        """
        controller = await make_controller(session)
        await sync_access_points(session, controller, ncm(ap("AP-1"), ap("AP-2"), ap("AP-3")))

        report = await GradingService(session).grades(scope=Scope.all())

        assert [d.hostname for d in report.devices] == ["wlc-01"]
        assert report.total_devices == 1
        assert report.ungraded == 1

    @pytest.mark.anyio
    async def test_they_carry_no_platform(self, session) -> None:
        # There is nothing to collect, so there is nothing to choose a profile or a
        # parser with. Naming one would imply a device that could be read.
        controller = await make_controller(session)

        await sync_access_points(session, controller, ncm(ap("AP-1")))

        assert [d.platform for d in await access_points(session, controller)] == [None]

    @pytest.mark.anyio
    async def test_they_inherit_the_controllers_criticality(self, session) -> None:
        # An access point in a plant room is as critical as the controller serving it.
        # Leaving it at the column default would quietly reclassify a whole estate.
        controller = await make_controller(session)

        await sync_access_points(session, controller, ncm(ap("AP-1")))

        assert [d.criticality for d in await access_points(session, controller)] == [
            Criticality.HIGH.value
        ]

    @pytest.mark.anyio
    async def test_one_with_no_address_is_skipped_rather_than_given_a_made_up_one(
        self, session
    ) -> None:
        """`devices` is unique on `(org_id, mgmt_ip)` and the column is not nullable.

        The first version of this borrowed the controller's address, which collided
        with the controller on the first access point and with itself on the second —
        every test in this class failed on the constraint, which is the only reason it
        was caught before a real controller hit it.

        `show ap summary` carries an address for every joined access point, so a
        missing one is a radio still joining or a row read incompletely. Skipped and
        counted. A placeholder address in an inventory is worse than an absent row,
        because somebody eventually tries to reach it.
        """
        controller = await make_controller(session, ip="10.0.0.9")

        result = await sync_access_points(
            session, controller, ncm(ap("AP-Joined"), {"name": "AP-Joining", "ip": None})
        )

        assert result.added == 1
        assert result.skipped == 1
        assert [d.hostname for d in await access_points(session, controller)] == ["AP-Joined"]


class TestItDoesNotActOnEvidenceItDoesNotHave:
    @pytest.mark.anyio
    async def test_a_device_with_no_wireless_section_is_left_alone(self, session) -> None:
        controller = await make_controller(session)

        result = await sync_access_points(session, controller, {"device": {"hostname": "sw-01"}})

        assert result.added == 0
        assert await access_points(session, controller) == []

    @pytest.mark.anyio
    async def test_an_empty_list_with_no_count_changes_nothing(self, session) -> None:
        """The dangerous case, and the reason for the guard.

        A controller whose `show ap summary` did not come back parses to `aps: []` —
        exactly what a controller with no APs joined parses to. Archiving on that would
        retire an estate's whole wireless inventory because one command failed.
        """
        controller = await make_controller(session)
        await sync_access_points(session, controller, ncm(ap("AP-1"), ap("AP-2")))

        result = await sync_access_points(session, controller, {"wireless": {"aps": []}})

        assert result.archived == 0
        assert [d.status for d in await access_points(session, controller)] == [
            DeviceStatus.INVENTORY_ONLY.value,
            DeviceStatus.INVENTORY_ONLY.value,
        ]

    @pytest.mark.anyio
    async def test_a_short_list_is_refused_rather_than_half_applied(self, session) -> None:
        """The parser's shortfall signal, acted on.

        The controller says four and two parsed. Applying that would archive the two
        that did not parse — turning a parsing problem into an inventory one, which is
        much harder to notice and much harder to undo.
        """
        controller = await make_controller(session)
        await sync_access_points(session, controller, ncm(ap("AP-1"), ap("AP-2"), ap("AP-3")))

        result = await sync_access_points(
            session, controller, ncm(ap("AP-1"), ap("AP-2"), declared=4)
        )

        assert result == type(result)()
        assert len(await access_points(session, controller)) == 3


class TestItTracksWhatTheControllerReports:
    @pytest.mark.anyio
    async def test_running_twice_does_not_duplicate(self, session) -> None:
        controller = await make_controller(session)
        payload = ncm(ap("AP-1", model="9130AXI"))

        await sync_access_points(session, controller, payload)
        second = await sync_access_points(session, controller, payload)

        assert second.added == 0
        assert len(await access_points(session, controller)) == 1

    @pytest.mark.anyio
    async def test_a_refreshed_model_or_address_is_recorded(self, session) -> None:
        controller = await make_controller(session)
        await sync_access_points(session, controller, ncm(ap("AP-1", ip="10.1.1.1")))

        await sync_access_points(
            session, controller, ncm(ap("AP-1", ip="10.1.1.99", model="9136AXI"))
        )

        [device] = await access_points(session, controller)
        assert str(device.mgmt_ip) == "10.1.1.99"
        assert device.model == "9136AXI"

    @pytest.mark.anyio
    async def test_one_that_stops_joining_is_archived_not_deleted(self, session) -> None:
        """ "This access point used to be here" is the question somebody asks after one
        goes missing, and a deleted row cannot answer it."""
        controller = await make_controller(session)
        await sync_access_points(session, controller, ncm(ap("AP-1"), ap("AP-Gone")))

        result = await sync_access_points(session, controller, ncm(ap("AP-1")))

        assert result.archived == 1
        statuses = {d.hostname: d.status for d in await access_points(session, controller)}
        assert statuses == {
            "AP-1": DeviceStatus.INVENTORY_ONLY.value,
            "AP-Gone": DeviceStatus.ARCHIVED.value,
        }

    @pytest.mark.anyio
    async def test_one_that_comes_back_is_restored_but_still_not_assessable(self, session) -> None:
        # Rejoining a controller does not make an access point readable, so it returns
        # to `inventory_only` rather than to `active`.
        controller = await make_controller(session)
        await sync_access_points(session, controller, ncm(ap("AP-1"), ap("AP-Flappy")))
        await sync_access_points(session, controller, ncm(ap("AP-1")))

        await sync_access_points(session, controller, ncm(ap("AP-1"), ap("AP-Flappy")))

        statuses = {d.hostname: d.status for d in await access_points(session, controller)}
        assert statuses["AP-Flappy"] == DeviceStatus.INVENTORY_ONLY.value

    @pytest.mark.anyio
    async def test_an_access_point_that_roams_to_another_controller_moves(self, session) -> None:
        """One radio, one row — and the lookup has to span the estate to know that.

        The first version scoped the search to the current controller, so a roamed
        access point was never found and the insert collided on `(org_id, mgmt_ip)`,
        aborting the whole collection with an integrity error. It also left the
        roam branch in `_apply` unreachable.
        """
        first = await make_controller(session, ip="10.0.0.1")
        second = await make_controller(session, ip="10.0.0.2", hostname="wlc-02")

        await sync_access_points(session, first, ncm(ap("AP-Roamer")))
        result = await sync_access_points(session, second, ncm(ap("AP-Roamer")))

        assert result.added == 0, "the roamed access point was recorded a second time"
        assert await access_points(session, first) == []
        assert [d.hostname for d in await access_points(session, second)] == ["AP-Roamer"]

    @pytest.mark.anyio
    async def test_one_controller_does_not_archive_anothers_access_points(self, session) -> None:
        """The hazard the roam fix introduced, and the reason archiving stayed scoped.

        The lookup spans the estate so a roam is recognised. Archiving on that same
        set would mean every controller retired every *other* controller's access
        points each time it was collected from — so each controller archives only what
        it is the parent of.
        """
        first = await make_controller(session, ip="10.0.0.1")
        second = await make_controller(session, ip="10.0.0.2", hostname="wlc-02")

        await sync_access_points(session, first, ncm(ap("AP-Site-A")))
        result = await sync_access_points(session, second, ncm(ap("AP-Site-B")))

        assert result.archived == 0
        assert [d.hostname for d in await access_points(session, first)] == ["AP-Site-A"]
        assert [d.status for d in await access_points(session, first)] == [
            DeviceStatus.INVENTORY_ONLY.value
        ]

    @pytest.mark.anyio
    async def test_a_device_somebody_entered_by_hand_is_never_adopted(self, session) -> None:
        """The lookup spans the estate so a roam is recognised, and is restricted to
        rows this service created so that breadth cannot reach anything else.

        **The name collides deliberately.** An autonomous Aironet onboarded by hand —
        with a credential, a platform and a real collection — can easily be called the
        same thing a nearby controller calls one of its radios. Without the
        `parent_device_id` restriction it would be adopted: re-parented, stripped to
        `inventory_only`, and silently dropped out of every assessment it was onboarded
        for. A version of this test using a *different* name passed with the
        restriction removed, which is the shape of a test that checks nothing.
        """
        controller = await make_controller(session)
        manual = Device(
            org_id=1,
            hostname="AP-Shared-Name",
            mgmt_ip="10.9.9.9",
            vendor=Vendor.CISCO.value,
            platform="cisco_ios",
            device_class=DeviceClass.WIRELESS_AP.value,
            status=DeviceStatus.ACTIVE.value,
        )
        session.add(manual)
        await session.flush()

        await sync_access_points(session, controller, ncm(ap("AP-Shared-Name")))
        await session.refresh(manual)

        assert manual.status == DeviceStatus.ACTIVE.value
        assert manual.parent_device_id is None
        assert manual.platform == "cisco_ios"
        assert str(manual.mgmt_ip) == "10.9.9.9"


class TestAnInventoryOnlyDeviceIsNotATarget:
    """The status is only worth having if the job engine honours it.

    A CAPWAP access point has no credential and nothing to collect, so a job that
    reached one would resolve nothing, connect to nothing and fail for ever — three
    hundred permanent failures per run on a wireless estate.
    """

    @pytest.mark.anyio
    async def test_a_job_naming_one_outright_still_skips_it(self, session) -> None:
        """Unlike `pending_review`, there is no approval that changes this.

        Naming an access point in a job is not a decision to assess it — it is a
        request the product cannot honour, because there is no credential and nothing
        to read. So it is dropped rather than attempted, the same way an archived
        device is dropped even when named.
        """
        controller = await make_controller(session)
        await sync_access_points(session, controller, ncm(ap("AP-Named")))
        [access_point] = await access_points(session, controller)

        targets = await JobService(session).resolve_scope(
            JobScope(device_ids=(access_point.id, controller.id)),
            Scope.all(),
        )

        assert [d.hostname for d in targets] == ["wlc-01"]

    @pytest.mark.anyio
    async def test_a_job_of_nothing_but_access_points_resolves_to_nothing(self, session) -> None:
        # Not "a job that quietly collects from three radios". Empty, so the caller
        # finds out rather than watching three permanent failures per run.
        controller = await make_controller(session)
        await sync_access_points(session, controller, ncm(ap("AP-A"), ap("AP-B")))
        ids = tuple(d.id for d in await access_points(session, controller))

        targets = await JobService(session).resolve_scope(JobScope(device_ids=ids), Scope.all())

        assert list(targets) == []
