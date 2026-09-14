"""Manager enumeration endpoints (FR-INV-04, FR-DISC-06).

The split between the routes is the requirement, not an API-design preference: FR-INV-04
permits a manager to populate the inventory *with user approval*, so previewing writes
nothing, importing acts only on named identities, and approving is a separate decision
that is the only thing which admits a device to assessment.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, User
from netsecops.db.models.inventory import DeviceClass, DeviceStatus, Vendor
from netsecops.services.inventory import InventoryService
from tests.conftest import make_user

FIXTURES = Path(__file__).parent / "fixtures/managers"
PANORAMA = (FIXTURES / "panorama_devices.xml").read_text(encoding="utf-8")


@pytest.fixture
async def analyst_user(session: AsyncSession) -> User:
    return await make_user(session, username="mgr_api_analyst", roles={Role.SECURITY_ANALYST})


@pytest.fixture
async def manager(session: AsyncSession, analyst_user: User, authenticate) -> Device:
    principal = Principal(
        id=analyst_user.id,
        username=analyst_user.username,
        roles=analyst_user.role_set,
        scope=Scope.all(),
    )
    device = await InventoryService(session).create_device(
        mgmt_ip="10.100.0.20",
        actor=principal,
        hostname="panorama-api",
        vendor=Vendor.PALOALTO,
        platform="panos",
        device_class=DeviceClass.MANAGER,
    )
    authenticate(analyst_user)
    return device


class TestRouting:
    async def test_the_literal_route_is_not_shadowed_by_the_uuid_one(
        self, client: AsyncClient, manager: Device
    ) -> None:
        """`/devices/pending-review` is a literal sibling of `/devices/{device_id}`.

        Routes match in registration order and FastAPI does not fall through on a failed
        path-parameter validation, so with the devices router first this returns 422 with
        `pending-review` reported as a malformed UUID — an endpoint that looks broken for
        a reason nothing in its own module explains. The router registers managers first;
        this fails the build if that is ever undone.
        """
        response = await client.get("/api/v1/devices/pending-review")

        assert response.status_code == 200, (
            "the literal route is being parsed as a device id — check the router "
            "registration order in api/router.py"
        )
        assert isinstance(response.json(), list)


class TestPreview:
    async def test_it_reports_what_the_manager_manages(
        self, client: AsyncClient, manager: Device
    ) -> None:
        response = await client.post(
            f"/api/v1/devices/{manager.id}/children/preview", json={"payload": PANORAMA}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["counts"]["reported"] == 4
        assert body["counts"]["new"] == 3
        assert body["counts"]["unimportable"] == 1

    async def test_it_creates_nothing(self, client: AsyncClient, manager: Device) -> None:
        """The whole point of the split."""
        await client.post(
            f"/api/v1/devices/{manager.id}/children/preview", json={"payload": PANORAMA}
        )
        pending = await client.get("/api/v1/devices/pending-review")

        assert pending.json() == []

    async def test_each_proposal_carries_the_identity_to_approve(
        self, client: AsyncClient, manager: Device
    ) -> None:
        body = (
            await client.post(
                f"/api/v1/devices/{manager.id}/children/preview", json={"payload": PANORAMA}
            )
        ).json()

        new = [p for p in body["proposals"] if p["disposition"] == "new"]
        assert {p["identity"] for p in new} == {
            "001901234501",
            "001901234502",
            "001901234503",
        }

    async def test_a_non_manager_is_refused_with_an_explanation(
        self, client: AsyncClient, session: AsyncSession, analyst_user: User, authenticate
    ) -> None:
        principal = Principal(
            id=analyst_user.id,
            username=analyst_user.username,
            roles=analyst_user.role_set,
            scope=Scope.all(),
        )
        firewall = await InventoryService(session).create_device(
            mgmt_ip="10.100.0.21",
            actor=principal,
            hostname="not-a-manager",
            vendor=Vendor.PALOALTO,
            platform="panos",
            device_class=DeviceClass.FIREWALL,
        )
        authenticate(analyst_user)

        response = await client.post(
            f"/api/v1/devices/{firewall.id}/children/preview", json={"payload": PANORAMA}
        )

        assert response.status_code == 422
        assert "not recorded as a manager" in response.json()["detail"]


class TestImportAndApproval:
    async def test_only_named_devices_are_imported(
        self, client: AsyncClient, manager: Device
    ) -> None:
        response = await client.post(
            f"/api/v1/devices/{manager.id}/children/import",
            json={"payload": PANORAMA, "identities": ["001901234501"]},
        )

        assert response.status_code == 200
        assert response.json()["counts"]["created"] == 1

        pending = (await client.get("/api/v1/devices/pending-review")).json()
        assert [d["hostname"] for d in pending] == ["fw-branch-london"]

    async def test_imported_devices_await_approval(
        self, client: AsyncClient, manager: Device
    ) -> None:
        await client.post(
            f"/api/v1/devices/{manager.id}/children/import",
            json={"payload": PANORAMA, "identities": ["001901234501"]},
        )

        pending = (await client.get("/api/v1/devices/pending-review")).json()
        assert pending[0]["parent_device_id"] == str(manager.id)
        assert pending[0]["platform"] == "panos"
        assert pending[0]["serial_number"] == "001901234501"

    async def test_pending_can_be_filtered_to_one_manager(
        self, client: AsyncClient, manager: Device
    ) -> None:
        await client.post(
            f"/api/v1/devices/{manager.id}/children/import",
            json={"payload": PANORAMA, "identities": ["001901234501"]},
        )

        response = await client.get(
            "/api/v1/devices/pending-review", params={"manager_id": str(manager.id)}
        )
        assert len(response.json()) == 1

    async def test_approving_admits_the_device(
        self, client: AsyncClient, session: AsyncSession, manager: Device
    ) -> None:
        await client.post(
            f"/api/v1/devices/{manager.id}/children/import",
            json={"payload": PANORAMA, "identities": ["001901234501"]},
        )
        pending = (await client.get("/api/v1/devices/pending-review")).json()

        response = await client.post(f"/api/v1/devices/{pending[0]['id']}/approve")

        assert response.status_code == 200
        assert (await client.get("/api/v1/devices/pending-review")).json() == []

        device = await InventoryService(session).get_device(pending[0]["id"])
        assert device.status == DeviceStatus.ACTIVE.value

    async def test_approving_something_already_active_is_refused(
        self, client: AsyncClient, manager: Device
    ) -> None:
        response = await client.post(f"/api/v1/devices/{manager.id}/approve")

        assert response.status_code == 422
        assert "not awaiting review" in response.json()["detail"]

    async def test_an_identity_the_manager_no_longer_reports_is_an_error(
        self, client: AsyncClient, manager: Device
    ) -> None:
        """The list the human approved is not the list being acted on, and they should
        see that rather than have it silently resolved."""
        response = await client.post(
            f"/api/v1/devices/{manager.id}/children/import",
            json={"payload": PANORAMA, "identities": ["001901239999"]},
        )

        assert response.status_code == 422
        assert "not in the enumeration" in response.json()["detail"]

    async def test_an_unknown_criticality_lists_the_valid_ones(
        self, client: AsyncClient, manager: Device
    ) -> None:
        response = await client.post(
            f"/api/v1/devices/{manager.id}/children/import",
            json={
                "payload": PANORAMA,
                "identities": ["001901234501"],
                "criticality": "extremely",
            },
        )

        assert response.status_code == 422
        assert "critical" in response.json()["detail"]

    async def test_an_empty_approval_list_is_rejected(
        self, client: AsyncClient, manager: Device
    ) -> None:
        """Importing nothing is not a meaningful request, and accepting it would make an
        accidental empty approval look like a successful one."""
        response = await client.post(
            f"/api/v1/devices/{manager.id}/children/import",
            json={"payload": PANORAMA, "identities": []},
        )
        assert response.status_code == 422
