"""The user and API-token endpoints over HTTP (FR-AUTH-05, FR-AUTH-07).

`test_users_service.py` covers the service. These cover the wire, because the console is
about to be built on it and the two are not the same surface: a field the service holds
but no response carries is invisible to a UI, and that is exactly what `device_group_ids`
was until this file was written.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient

from netsecops.core.rbac import Permission, Role
from tests.conftest import make_group, make_user

pytestmark = pytest.mark.asyncio

#: Deliberately not `conftest.TEST_PASSWORD`. A reset to the password already in force is
#: rejected as a policy violation, so reusing it here would make these tests fail for a
#: reason that has nothing to do with what they check.
STRONG_PASSWORD = "Staple-Mountain-Ledger-4!"


class TestUserAdministration:
    async def test_a_user_can_be_created_and_listed(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        authenticate(super_admin)

        created = await client.post(
            "/api/v1/users",
            json={
                "username": "new.operator",
                "email": "new.operator@example.com",
                "password": STRONG_PASSWORD,
                "full_name": "New Operator",
                "roles": [Role.AUDITOR.value],
            },
        )
        assert created.status_code == 201, created.text
        assert created.json()["roles"] == [Role.AUDITOR.value]

        listed = await client.get("/api/v1/users?search=new.operator")
        assert listed.status_code == 200
        assert [u["username"] for u in listed.json()["data"]] == ["new.operator"]

    async def test_deactivating_a_user_does_not_clear_their_roles(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """Deactivation is reversible, so what it costs to undo matters.

        The console offers deactivate beside delete precisely because it is the
        recoverable one, and it is only recoverable if reactivating restores the account
        rather than leaving a roleless husk.
        """
        target = await make_user(session, username="leaver", roles={Role.NETWORK_ENGINEER})
        authenticate(super_admin)

        response = await client.patch(f"/api/v1/users/{target.id}", json={"is_active": False})

        assert response.status_code == 200
        assert response.json()["is_active"] is False
        assert response.json()["roles"] == [Role.NETWORK_ENGINEER.value]

    async def test_a_password_reset_forces_a_change_at_next_sign_in(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """An administrator knows the password they just set. The flag is what stops it
        staying that way."""
        target = await make_user(session, username="forgot", roles={Role.AUDITOR})
        authenticate(super_admin)

        reset = await client.post(
            f"/api/v1/users/{target.id}/password",
            json={"new_password": STRONG_PASSWORD, "must_change_password": True},
        )
        assert reset.status_code == 204

        fetched = await client.get(f"/api/v1/users/{target.id}")
        assert fetched.json()["must_change_password"] is True

    async def test_roles_are_replaced_wholesale(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """PUT, not PATCH — the console sends the whole set, and sending one role must
        not leave the others in place."""
        target = await make_user(
            session, username="promoted", roles={Role.AUDITOR, Role.NETWORK_ENGINEER}
        )
        authenticate(super_admin)

        response = await client.put(
            f"/api/v1/users/{target.id}/roles", json={"roles": [Role.SECURITY_ANALYST.value]}
        )

        assert response.status_code == 200
        assert response.json()["roles"] == [Role.SECURITY_ANALYST.value]


class TestScopeCanBeReadBack:
    """FR-AUTH-05 — `PUT /users/{id}/scope` used to write something nothing returned.

    An administrator could set a user's Device Group scope and then had no way to ask
    what it was. That makes the setting write-only in practice: the next administrator
    either re-sends the whole set blind, or reads the audit log. A console cannot show a
    checkbox whose current state it is unable to fetch.
    """

    async def test_the_assignment_comes_back_on_the_user(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        target = await make_user(session, username="scoped", roles={Role.NETWORK_ENGINEER})
        north = await make_group(session, name="north")
        south = await make_group(session, name="south")
        authenticate(super_admin)

        written = await client.put(
            f"/api/v1/users/{target.id}/scope",
            json={"device_group_ids": [str(north.id), str(south.id)]},
        )
        assert written.status_code == 200
        assert set(written.json()["device_group_ids"]) == {str(north.id), str(south.id)}

        # The round trip is the point: a fresh read, not the echo of the write.
        fetched = await client.get(f"/api/v1/users/{target.id}")
        assert set(fetched.json()["device_group_ids"]) == {str(north.id), str(south.id)}

    async def test_it_is_visible_in_the_list_as_well_as_the_detail(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """The console shows scope on the row. A field only the detail endpoint carries
        would make it a click away from the list it belongs on."""
        target = await make_user(session, username="listed_scope", roles={Role.NETWORK_ENGINEER})
        group = await make_group(session, name="east")
        authenticate(super_admin)

        await client.put(
            f"/api/v1/users/{target.id}/scope", json={"device_group_ids": [str(group.id)]}
        )

        listed = await client.get("/api/v1/users?search=listed_scope")
        row = listed.json()["data"][0]
        assert row["device_group_ids"] == [str(group.id)]

    async def test_clearing_the_scope_empties_it(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """Empty means "sees nothing", not "unset" — the scope filter fails closed. So an
        emptied scope has to report as empty rather than quietly keeping the old set."""
        target = await make_user(session, username="unscoped", roles={Role.NETWORK_ENGINEER})
        group = await make_group(session, name="west")
        authenticate(super_admin)

        await client.put(
            f"/api/v1/users/{target.id}/scope", json={"device_group_ids": [str(group.id)]}
        )
        cleared = await client.put(
            f"/api/v1/users/{target.id}/scope", json={"device_group_ids": []}
        )

        assert cleared.json()["device_group_ids"] == []

    async def test_auth_me_still_reports_the_scope_in_force(
        self, client: AsyncClient, session, authenticate
    ) -> None:
        """The one endpoint where the field means something else, and deliberately.

        `/auth/me` answers "what can I see", so for an unrestricted role it reports no
        groups with `unrestricted_scope` set — which is the opposite of the empty list
        that means "nothing" on a group-scoped one. Moving the field onto the shared
        schema must not have quietly changed that.
        """
        admin = await make_user(session, username="me_admin", roles={Role.SUPER_ADMIN})
        group = await make_group(session, name="ignored-by-role")
        authenticate(admin)
        await client.put(
            f"/api/v1/users/{admin.id}/scope", json={"device_group_ids": [str(group.id)]}
        )

        me = await client.get("/api/v1/auth/me")

        assert me.json()["unrestricted_scope"] is True
        assert me.json()["device_group_ids"] == []


class TestRoleCatalogue:
    async def test_it_lists_every_role_with_its_permissions(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """The console builds its role picker and its token-scope picker from this.

        Hard-coding either in the browser would mean a second copy of the permission
        model that drifts from `rbac.py` the first time a permission is added.
        """
        authenticate(super_admin)

        response = await client.get("/api/v1/auth/roles")

        assert response.status_code == 200
        catalogue = response.json()
        assert {row["role"] for row in catalogue} == {role.value for role in Role}
        assert all(row["description"] for row in catalogue)
        assert Permission.USER_WRITE.value in next(
            row["permissions"] for row in catalogue if row["role"] == Role.SUPER_ADMIN.value
        )


class TestApiTokens:
    async def test_the_plaintext_is_returned_once_and_never_again(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """FR-AUTH-07. The console has to show it at creation because there is no second
        chance, and it must not pretend otherwise by showing a placeholder later."""
        authenticate(super_admin)

        created = await client.post(
            "/api/v1/api-tokens",
            json={"name": "ci-runner", "scopes": [Permission.DEVICE_READ.value]},
        )
        assert created.status_code == 201, created.text
        assert created.json()["token"]

        listed = await client.get("/api/v1/api-tokens")
        row = next(t for t in listed.json() if t["name"] == "ci-runner")
        assert "token" not in row
        assert row["prefix"]

    async def test_an_expiry_survives_the_round_trip(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """A token with no expiry is a permanent credential, so the console offers one —
        and an expiry it cannot read back is one nobody can check."""
        authenticate(super_admin)
        expires = (datetime.now(UTC) + timedelta(days=30)).replace(microsecond=0)

        created = await client.post(
            "/api/v1/api-tokens",
            json={
                "name": "expiring",
                "scopes": [Permission.DEVICE_READ.value],
                "expires_at": expires.isoformat(),
            },
        )

        assert created.status_code == 201
        assert datetime.fromisoformat(created.json()["expires_at"]) == expires

    async def test_revoking_marks_it_rather_than_hiding_it(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """A revoked token that vanishes from the list looks like one that never existed.

        The console greys the row instead, so "this token was withdrawn on Tuesday" is
        answerable without the audit log.
        """
        authenticate(super_admin)
        created = await client.post(
            "/api/v1/api-tokens",
            json={"name": "doomed", "scopes": [Permission.DEVICE_READ.value]},
        )
        token_id = created.json()["id"]

        revoked = await client.delete(f"/api/v1/api-tokens/{token_id}")
        assert revoked.status_code == 204

        listed = await client.get("/api/v1/api-tokens")
        row = next((t for t in listed.json() if t["id"] == token_id), None)
        assert row is not None, "a revoked token disappeared instead of being marked"
        assert row["revoked_at"] is not None

    async def test_listing_defaults_to_your_own(
        self, client: AsyncClient, session, authenticate, super_admin
    ) -> None:
        """`mine_only` defaults true, so the self-service page needs no parameter and a
        non-admin cannot accidentally be shown somebody else's."""
        other = await make_user(session, username="token_owner", roles={Role.SECURITY_ANALYST})
        authenticate(other)
        await client.post(
            "/api/v1/api-tokens",
            json={"name": "theirs", "scopes": [Permission.DEVICE_READ.value]},
        )

        authenticate(super_admin)
        mine = await client.get("/api/v1/api-tokens")

        assert [t["name"] for t in mine.json()] == []
