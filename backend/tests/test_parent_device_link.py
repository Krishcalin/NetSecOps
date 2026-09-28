"""A derived device names the thing it was derived from (FR-INV-04, SRS §1.3.1).

`parent_device_id` has been on `DeviceRead` since Phase 1 and **no page has ever
rendered it**, for the obvious reason: a UUID tells an operator nothing. So a firewall
imported from a Panorama and an access point derived from a wireless controller both
appeared in the inventory as rows with an unexplained origin — and the access points
made it acute, because a controller can contribute three hundred of them at once.

The relationship has to work in both directions to be worth anything:

* **From the child**, `parent_hostname` says where the row came from. Without it the
  only honest thing the console could show was nothing.
* **From the parent**, `child_count` and the `parent_id` filter make those children
  reachable. A count with no way to open it is a number; a filter with no count is a
  page nobody knows to ask for.

The count is a grouped query per page rather than a `children` relationship on the
model. The relationship would be tidier and would load every row — a controller with
three hundred access points fetching three hundred devices to render the number 300, on
every page that happens to include it.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, User
from netsecops.db.models.inventory import DeviceClass, DeviceStatus, Vendor
from netsecops.schemas.inventory import DeviceRead
from netsecops.services.access_points import sync_access_points
from netsecops.services.inventory import InventoryService
from tests.conftest import make_user


@pytest.fixture
async def engineer(session: AsyncSession) -> User:
    return await make_user(session, username="parent_link", roles={Role.NETWORK_ENGINEER})


@pytest.fixture
async def principal(engineer: User) -> Principal:
    return Principal(
        id=engineer.id,
        username=engineer.username,
        roles=engineer.role_set,
        scope=Scope.all(),
    )


async def make_controller(session: AsyncSession, principal: Principal, *, ip: str) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=principal,
        hostname="wlc-parent-01",
        vendor=Vendor.CISCO,
        platform="cisco_c9800",
        device_class=DeviceClass.WIRELESS_CONTROLLER,
    )


def ncm(*names: str) -> dict:
    aps = [
        {"name": name, "model": "9130AXI", "ip": f"10.5.5.{index + 10}", "serial": None}
        for index, name in enumerate(names)
    ]
    return {"wireless": {"aps": aps, "aps_declared": len(aps)}}


class TestAChildNamesItsParent:
    @pytest.mark.anyio
    async def test_an_access_point_says_which_controller_it_came_from(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        controller = await make_controller(session, principal, ip="10.5.0.1")
        await sync_access_points(session, controller, ncm("AP-1"))

        rows, _ = await InventoryService(session).list_devices(
            scope=Scope.all(), device_class=DeviceClass.WIRELESS_AP
        )
        [access_point] = [DeviceRead.model_validate(row) for row in rows]

        assert access_point.parent_hostname == "wlc-parent-01"
        assert access_point.parent_device_id == controller.id

    @pytest.mark.anyio
    async def test_it_also_says_what_kind_of_parent(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """ "Via its controller" and "managed by" are not the same sentence.

        A wireless controller, a Panorama and a FortiManager are all parents, and only
        the class tells the console which relationship it is describing.
        """
        controller = await make_controller(session, principal, ip="10.5.0.2")
        await sync_access_points(session, controller, ncm("AP-2"))

        rows, _ = await InventoryService(session).list_devices(
            scope=Scope.all(), device_class=DeviceClass.WIRELESS_AP
        )
        [access_point] = [DeviceRead.model_validate(row) for row in rows]

        assert access_point.parent_device_class == DeviceClass.WIRELESS_CONTROLLER.value

    @pytest.mark.anyio
    async def test_a_device_with_no_parent_says_nothing_rather_than_guessing(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        # Most of the estate. `None`, not the device's own name, and not an empty
        # string that a template would render as an origin with no text.
        controller = await make_controller(session, principal, ip="10.5.0.3")

        view = DeviceRead.model_validate(controller)

        assert view.parent_hostname is None
        assert view.parent_device_class is None
        assert view.parent_device_id is None


class TestAParentReachesItsChildren:
    @pytest.mark.anyio
    async def test_a_controller_counts_its_access_points(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        inventory = InventoryService(session)
        controller = await make_controller(session, principal, ip="10.5.0.4")
        await sync_access_points(session, controller, ncm("AP-A", "AP-B", "AP-C"))

        counts = await inventory.child_counts([controller])

        assert counts == {controller.id: 3}

    @pytest.mark.anyio
    async def test_a_device_with_no_children_is_absent_rather_than_nought(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        # The caller defaults to nought. A dictionary of mostly zeroes is a page of
        # noise for the one row that has any.
        inventory = InventoryService(session)
        controller = await make_controller(session, principal, ip="10.5.0.5")

        assert await inventory.child_counts([controller]) == {}

    @pytest.mark.anyio
    async def test_counting_an_empty_page_asks_the_database_nothing(
        self, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Asserted by watching for the query, not by checking the answer.

        An empty page returns `{}` whether or not the guard is there — SQLAlchemy
        renders an empty `IN` as a false predicate rather than failing — so a test that
        only looked at the result passed with the early return deleted, and said in its
        own name that it had checked something it had not.
        """
        inventory = InventoryService(session)
        calls = 0
        original = session.execute

        async def counting(*args: object, **kwargs: object):
            nonlocal calls
            calls += 1
            return await original(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(session, "execute", counting)

        assert await inventory.child_counts([]) == {}
        assert calls == 0

    @pytest.mark.anyio
    async def test_the_children_can_be_listed_from_the_parent(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """The half that makes the count worth showing.

        A number with no way to open it tells somebody there are three access points
        and leaves them filtering by hand.
        """
        inventory = InventoryService(session)
        controller = await make_controller(session, principal, ip="10.5.0.6")
        await sync_access_points(session, controller, ncm("AP-X", "AP-Y"))

        rows, total = await inventory.list_devices(scope=Scope.all(), parent_id=controller.id)

        assert total == 2
        assert sorted(d.hostname for d in rows) == ["AP-X", "AP-Y"]

    @pytest.mark.anyio
    async def test_filtering_by_a_parent_with_no_children_returns_nothing(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        # Not "everything", which is what a filter that silently no-ops would give.
        inventory = InventoryService(session)
        controller = await make_controller(session, principal, ip="10.5.0.7")
        await sync_access_points(session, controller, ncm("AP-Q"))
        other = await InventoryService(session).create_device(
            mgmt_ip="10.5.0.8",
            actor=principal,
            hostname="wlc-empty",
            vendor=Vendor.CISCO,
            platform="cisco_c9800",
            device_class=DeviceClass.WIRELESS_CONTROLLER,
        )

        rows, total = await inventory.list_devices(scope=Scope.all(), parent_id=other.id)

        assert total == 0
        assert list(rows) == []


class TestTheEndpointCarriesIt:
    """The wiring, which the service tests above cannot reach.

    `child_count` is not a model attribute — it is a grouped query merged into the
    response by the route — so every test that goes through `InventoryService` passes
    with the route returning nought for every device. A mutation that did exactly that
    survived the whole service suite, and the console mocks the API, so nothing else
    would have caught it either.
    """

    async def test_the_device_list_reports_a_controller_s_children(
        self,
        client: AsyncClient,
        session: AsyncSession,
        principal: Principal,
        engineer,
        authenticate,
    ) -> None:
        controller = await make_controller(session, principal, ip="10.5.1.1")
        await sync_access_points(session, controller, ncm("AP-1", "AP-2"))
        authenticate(engineer)

        response = await client.get("/api/v1/devices")

        assert response.status_code == 200
        rows = {row["hostname"]: row for row in response.json()["data"]}
        assert rows["wlc-parent-01"]["child_count"] == 2

    async def test_the_device_list_names_a_parent(
        self,
        client: AsyncClient,
        session: AsyncSession,
        principal: Principal,
        engineer,
        authenticate,
    ) -> None:
        controller = await make_controller(session, principal, ip="10.5.1.2")
        await sync_access_points(session, controller, ncm("AP-Named"))
        authenticate(engineer)

        response = await client.get("/api/v1/devices")

        rows = {row["hostname"]: row for row in response.json()["data"]}
        assert rows["AP-Named"]["parent_hostname"] == "wlc-parent-01"
        assert rows["AP-Named"]["parent_device_class"] == "wireless_controller"

    async def test_an_ordinary_device_reports_no_children(
        self,
        client: AsyncClient,
        session: AsyncSession,
        principal: Principal,
        engineer,
        authenticate,
    ) -> None:
        # Nought, not absent: the field is not optional, and a console reading
        # `device.child_count > 0` against `undefined` would silently show nothing.
        await make_controller(session, principal, ip="10.5.1.3")
        authenticate(engineer)

        response = await client.get("/api/v1/devices")

        rows = {row["hostname"]: row for row in response.json()["data"]}
        assert rows["wlc-parent-01"]["child_count"] == 0
        assert rows["wlc-parent-01"]["parent_hostname"] is None

    async def test_the_filter_reaches_the_endpoint(
        self,
        client: AsyncClient,
        session: AsyncSession,
        principal: Principal,
        engineer,
        authenticate,
    ) -> None:
        controller = await make_controller(session, principal, ip="10.5.1.4")
        await sync_access_points(session, controller, ncm("AP-A", "AP-B"))
        authenticate(engineer)

        response = await client.get(f"/api/v1/devices?parent_id={controller.id}")

        body = response.json()
        assert body["meta"]["total"] == 2
        assert sorted(row["hostname"] for row in body["data"]) == ["AP-A", "AP-B"]


class TestItDoesNotWidenWhatSomebodyCanSee:
    @pytest.mark.anyio
    async def test_the_parent_filter_is_still_scoped(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        """A filter is not an authorisation.

        Naming a controller's id must not reach its access points when the caller
        cannot see the group they are in — scope is applied after the filter, and this
        is what proves the order.
        """
        inventory = InventoryService(session)
        controller = await make_controller(session, principal, ip="10.5.0.9")
        await sync_access_points(session, controller, ncm("AP-Hidden"))

        rows, total = await inventory.list_devices(
            scope=Scope(device_group_ids=frozenset()), parent_id=controller.id
        )

        assert total == 0
        assert list(rows) == []

    @pytest.mark.anyio
    async def test_an_access_point_still_reports_its_status(
        self, session: AsyncSession, principal: Principal
    ) -> None:
        # The parent link is additive. It must not cost the field the console uses to
        # say this device is an asset rather than a target.
        controller = await make_controller(session, principal, ip="10.5.0.10")
        await sync_access_points(session, controller, ncm("AP-Status"))

        rows, _ = await InventoryService(session).list_devices(
            scope=Scope.all(), device_class=DeviceClass.WIRELESS_AP
        )
        [view] = [DeviceRead.model_validate(row) for row in rows]

        assert view.status == DeviceStatus.INVENTORY_ONLY.value
