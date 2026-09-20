"""Sites, Device Groups and tags over HTTP (FR-INV-03, FR-AUTH-05).

Reference data, and the thing everything else is expressed in: a user's scope, a policy
assignment and a schedule's coverage all name Device Groups. These endpoints had no
functional test and no console page, which is how a site's `location` came to be accepted,
returned, and never stored.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from netsecops.core.rbac import Role
from tests.conftest import make_group, make_user

pytestmark = pytest.mark.asyncio


class TestSites:
    async def test_a_location_survives_the_round_trip(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """The regression.

        `SiteCreate` accepted `location`, `SiteRead` returned it, `sites.location` existed
        in the database, and the service between them never carried it — so a location
        submitted was discarded in silence and every site read back with `location: null`.
        Nothing failed, which is why it survived: a field that is always null looks like a
        field nobody has filled in.
        """
        authenticate(super_admin)

        created = await client.post("/api/v1/sites", json={"name": "HQ", "location": "London, EC2"})
        assert created.status_code == 201, created.text
        assert created.json()["location"] == "London, EC2"

        listed = await client.get("/api/v1/sites")
        assert next(s for s in listed.json() if s["name"] == "HQ")["location"] == "London, EC2"

    async def test_a_site_without_a_location_is_still_valid(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """It is optional, and threading it through must not have made it required."""
        authenticate(super_admin)

        created = await client.post("/api/v1/sites", json={"name": "Unlocated"})

        assert created.status_code == 201
        assert created.json()["location"] is None

    async def test_two_sites_cannot_share_a_name(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        authenticate(super_admin)
        await client.post("/api/v1/sites", json={"name": "Duplicate"})

        again = await client.post("/api/v1/sites", json={"name": "Duplicate"})

        assert again.status_code == 409


class TestDeviceGroups:
    async def test_a_child_carries_its_parent_in_its_path(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """The path is what scope checks resolve through, so it is the thing to assert."""
        authenticate(super_admin)
        parent = await client.post("/api/v1/device-groups", json={"name": "europe"})
        parent_path = parent.json()["path"]

        child = await client.post(
            "/api/v1/device-groups", json={"name": "london", "parent_id": parent.json()["id"]}
        )

        assert child.status_code == 201
        assert child.json()["path"].startswith(f"{parent_path}.")

    async def test_moving_a_group_rewrites_its_descendants(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """A move is not a single-row update.

        Every descendant's path embeds its ancestors, so a move that changed only the
        moved row would leave scope checks resolving through paths that no longer exist —
        and the failure would be a user quietly seeing the wrong devices, with nothing in
        any log to explain it.
        """
        old_parent = await make_group(session, name="old-parent")
        moved = await make_group(session, name="moved", parent=old_parent)
        leaf = await make_group(session, name="leaf", parent=moved)
        new_parent = await make_group(session, name="new-parent")
        authenticate(super_admin)

        response = await client.put(
            f"/api/v1/device-groups/{moved.id}/parent", json={"parent_id": str(new_parent.id)}
        )
        assert response.status_code == 200
        assert response.json()["path"].startswith(f"{new_parent.path}.")

        listed = (await client.get("/api/v1/device-groups")).json()
        leaf_now = next(g for g in listed if g["id"] == str(leaf.id))
        assert leaf_now["path"].startswith(f"{response.json()['path']}.")

    async def test_a_group_cannot_be_moved_beneath_itself(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """The console does not offer it, and the server refuses it anyway — a cycle here
        makes every path containment query wrong at once."""
        parent = await make_group(session, name="cycle-parent")
        child = await make_group(session, name="cycle-child", parent=parent)
        authenticate(super_admin)

        response = await client.put(
            f"/api/v1/device-groups/{parent.id}/parent", json={"parent_id": str(child.id)}
        )

        assert response.status_code == 422

    async def test_a_group_can_be_moved_to_the_top_level(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """`parent_id: null` is a real move, not a no-op the console should hide."""
        parent = await make_group(session, name="detach-parent")
        child = await make_group(session, name="detach-child", parent=parent)
        authenticate(super_admin)

        response = await client.put(
            f"/api/v1/device-groups/{child.id}/parent", json={"parent_id": None}
        )

        assert response.status_code == 200
        assert response.json()["parent_id"] is None
        assert "." not in response.json()["path"]


class TestReadersMayRead:
    async def test_an_auditor_can_see_the_structure_without_changing_it(
        self, client: AsyncClient, session, authenticate
    ) -> None:
        """The console shows this page to any device reader: the group filter on the
        inventory is useless until groups exist, and seeing what they are is a read."""
        auditor = await make_user(session, username="ref_auditor", roles={Role.AUDITOR})
        await make_group(session, name="visible-to-auditor")
        authenticate(auditor)

        assert (await client.get("/api/v1/device-groups")).status_code == 200
        assert (await client.get("/api/v1/sites")).status_code == 200
        assert (await client.get("/api/v1/tags")).status_code == 200
        assert (await client.post("/api/v1/sites", json={"name": "nope"})).status_code == 403
