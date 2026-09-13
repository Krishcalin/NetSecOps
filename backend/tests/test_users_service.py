"""User, role and API-token service tests (FR-AUTH-05, FR-AUTH-07, FR-AUTH-08)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ConflictError, NotFoundError, PermissionDeniedError
from netsecops.core.rbac import Permission, Principal, Role, Scope
from netsecops.core.security import API_TOKEN_PREFIX, hash_token, verify_password
from netsecops.db.models import ApiToken, AuditLog, User
from netsecops.services.users import UserService
from tests.conftest import TEST_PASSWORD, make_group, make_user


def principal(user: User) -> Principal:
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
def service(session: AsyncSession) -> UserService:
    return UserService(session)


async def actions_for(session: AsyncSession, object_id: uuid.UUID) -> list[str]:
    rows = await session.execute(
        select(AuditLog.action).where(AuditLog.object_id == str(object_id))
    )
    return list(rows.scalars().all())


class TestCreate:
    async def test_creates_with_roles(self, service: UserService, super_admin: User) -> None:
        user = await service.create(
            username="newbie",
            email="newbie@example.com",
            password="Valid-P4ssword!",
            roles={Role.SECURITY_ANALYST},
            actor=principal(super_admin),
        )

        assert user.username == "newbie"
        assert user.role_set == {Role.SECURITY_ANALYST}
        assert verify_password("Valid-P4ssword!", user.password_hash)

    async def test_password_is_hashed_not_stored(
        self, service: UserService, super_admin: User
    ) -> None:
        user = await service.create(
            username="hashed",
            email="hashed@example.com",
            password="Valid-P4ssword!",
            actor=principal(super_admin),
        )
        assert "Valid-P4ssword!" not in user.password_hash
        assert user.password_hash.startswith("$argon2id$")

    async def test_duplicate_username_rejected(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        await make_user(session, username="taken")
        with pytest.raises(ConflictError, match="already exists"):
            await service.create(
                username="taken",
                email="other@example.com",
                password="Valid-P4ssword!",
                actor=principal(super_admin),
            )

    async def test_duplicate_email_rejected(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        existing = await make_user(session, username="emailowner")
        with pytest.raises(ConflictError, match="already exists"):
            await service.create(
                username="different",
                email=existing.email,
                password="Valid-P4ssword!",
                actor=principal(super_admin),
            )

    async def test_weak_password_rejected(self, service: UserService, super_admin: User) -> None:
        from netsecops.core.errors import PasswordPolicyError

        with pytest.raises(PasswordPolicyError):
            await service.create(
                username="weak",
                email="weak@example.com",
                password="short",
                actor=principal(super_admin),
            )

    async def test_creation_is_audited(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        user = await service.create(
            username="audited",
            email="audited@example.com",
            password="Valid-P4ssword!",
            actor=principal(super_admin),
        )
        await session.flush()
        assert "user.created" in await actions_for(session, user.id)


class TestListAndGet:
    async def test_get_missing_raises(self, service: UserService) -> None:
        with pytest.raises(NotFoundError):
            await service.get(uuid.uuid4())

    async def test_search_by_username(self, service: UserService, session: AsyncSession) -> None:
        await make_user(session, username="findme_alpha")
        await make_user(session, username="other_beta")

        rows, total = await service.list(search="findme")
        assert total == 1 and rows[0].username == "findme_alpha"

    async def test_filter_by_role(self, service: UserService, session: AsyncSession) -> None:
        await make_user(session, username="an_auditor", roles={Role.AUDITOR})
        await make_user(session, username="an_analyst", roles={Role.SECURITY_ANALYST})

        rows, total = await service.list(role=Role.AUDITOR)
        assert total == 1 and rows[0].username == "an_auditor"

    async def test_filter_by_active(self, service: UserService, session: AsyncSession) -> None:
        await make_user(session, username="active_one", is_active=True)
        await make_user(session, username="inactive_one", is_active=False)

        _, active = await service.list(is_active=True)
        _, inactive = await service.list(is_active=False)
        assert active == 1 and inactive == 1

    async def test_pagination(self, service: UserService, session: AsyncSession) -> None:
        for i in range(5):
            await make_user(session, username=f"page_{i}")

        rows, total = await service.list(limit=2, offset=1)
        assert total == 5 and len(rows) == 2


class TestUpdate:
    async def test_updates_fields(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        user = await make_user(session, username="editme")
        updated = await service.update(
            user, actor=principal(super_admin), full_name="New Name", email="new@example.com"
        )
        assert updated.full_name == "New Name"
        assert updated.email == "new@example.com"

    async def test_cannot_deactivate_self(self, service: UserService, super_admin: User) -> None:
        with pytest.raises(ConflictError, match="your own account"):
            await service.update(super_admin, actor=principal(super_admin), is_active=False)

    async def test_cannot_deactivate_last_super_admin(
        self, service: UserService, session: AsyncSession
    ) -> None:
        """The guard fires only when no *other* active Super Admin would remain."""
        lone = await make_user(session, username="lone_admin", roles={Role.SUPER_ADMIN})
        actor = principal(await make_user(session, username="an_operator"))

        with pytest.raises(ConflictError, match="Super Admin must remain"):
            await service.update(lone, actor=actor, is_active=False)

    async def test_may_deactivate_when_another_super_admin_remains(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        second = await make_user(session, username="second_admin", roles={Role.SUPER_ADMIN})
        updated = await service.update(second, actor=principal(super_admin), is_active=False)
        assert updated.is_active is False

    async def test_email_collision_rejected(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        a = await make_user(session, username="user_a")
        b = await make_user(session, username="user_b")
        with pytest.raises(ConflictError):
            await service.update(b, actor=principal(super_admin), email=a.email)

    async def test_no_change_writes_no_audit(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        user = await make_user(session, username="unchanged")
        await service.update(user, actor=principal(super_admin), full_name=user.full_name)
        await session.flush()
        assert "user.updated" not in await actions_for(session, user.id)


class TestDelete:
    async def test_deletes(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        user = await make_user(session, username="deleteme")
        user_id = user.id
        await service.delete(user, actor=principal(super_admin))

        assert (
            await session.execute(select(User).where(User.id == user_id))
        ).scalar_one_or_none() is None

    async def test_cannot_delete_self(self, service: UserService, super_admin: User) -> None:
        with pytest.raises(ConflictError, match="your own account"):
            await service.delete(super_admin, actor=principal(super_admin))

    async def test_cannot_delete_last_super_admin(
        self, service: UserService, session: AsyncSession
    ) -> None:
        lone = await make_user(session, username="lone_admin_del", roles={Role.SUPER_ADMIN})
        actor = principal(await make_user(session, username="deleting_operator"))

        with pytest.raises(ConflictError, match="Super Admin must remain"):
            await service.delete(lone, actor=actor)

    async def test_may_delete_when_another_super_admin_remains(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        second = await make_user(session, username="spare_admin", roles={Role.SUPER_ADMIN})
        await service.delete(second, actor=principal(super_admin))

        assert (
            await session.execute(select(User).where(User.id == second.id))
        ).scalar_one_or_none() is None


class TestRoles:
    async def test_grants_and_revokes(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        user = await make_user(session, username="rolechange", roles={Role.AUDITOR})

        updated = await service.set_roles(
            user, {Role.SECURITY_ANALYST, Role.NETWORK_ENGINEER}, actor=principal(super_admin)
        )
        assert updated.role_set == {Role.SECURITY_ANALYST, Role.NETWORK_ENGINEER}

    async def test_grant_and_revoke_are_audited_separately(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        user = await make_user(session, username="auditroles", roles={Role.AUDITOR})
        await service.set_roles(user, {Role.SECURITY_ANALYST}, actor=principal(super_admin))
        await session.flush()

        actions = await actions_for(session, user.id)
        assert "role.granted" in actions
        assert "role.revoked" in actions

    async def test_cannot_revoke_last_super_admin_role(
        self, service: UserService, session: AsyncSession
    ) -> None:
        lone = await make_user(session, username="lone_admin_role", roles={Role.SUPER_ADMIN})
        actor = principal(await make_user(session, username="role_operator"))

        with pytest.raises(ConflictError, match="Super Admin must remain"):
            await service.set_roles(lone, {Role.AUDITOR}, actor=actor)

    async def test_clearing_roles_removes_all_permissions(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        user = await make_user(session, username="stripped", roles={Role.SECURITY_ANALYST})
        updated = await service.set_roles(user, set(), actor=principal(super_admin))
        assert updated.role_set == frozenset()


class TestGroupScopes:
    async def test_assigns_scopes(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        user = await make_user(session, username="scoped", roles={Role.NETWORK_ENGINEER})
        groups = {
            (await make_group(session)).id,
            (await make_group(session)).id,
        }

        updated = await service.set_group_scopes(user, groups, actor=principal(super_admin))
        assert {s.device_group_id for s in updated.group_scopes} == groups

    async def test_scope_must_reference_a_real_group(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        """A scope pointing at a group that does not exist grants nothing meaningful."""
        from sqlalchemy.exc import IntegrityError

        user = await make_user(session, username="bogus_scope", roles={Role.AUDITOR})

        with pytest.raises(IntegrityError):
            await service.set_group_scopes(user, {uuid.uuid4()}, actor=principal(super_admin))

    async def test_replaces_rather_than_appends(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        user = await make_user(session, username="rescoped", roles={Role.AUDITOR})
        first = (await make_group(session)).id
        second = (await make_group(session)).id

        await service.set_group_scopes(user, {first}, actor=principal(super_admin))
        updated = await service.set_group_scopes(user, {second}, actor=principal(super_admin))

        assert {s.device_group_id for s in updated.group_scopes} == {second}

    async def test_scope_change_is_audited(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        user = await make_user(session, username="auditscope", roles={Role.AUDITOR})
        group = await make_group(session)

        await service.set_group_scopes(user, {group.id}, actor=principal(super_admin))
        await session.flush()
        assert "scope.changed" in await actions_for(session, user.id)


class TestApiTokens:
    async def test_creates_token_and_returns_plaintext_once(
        self, service: UserService, super_admin: User
    ) -> None:
        issued = await service.create_api_token(
            name="siem-feed",
            owner=super_admin,
            scopes={Permission.FINDING_READ},
            expires_at=None,
            actor=principal(super_admin),
        )

        assert issued.plaintext.startswith(API_TOKEN_PREFIX)
        assert issued.token.token_hash == hash_token(issued.plaintext)
        assert issued.token.scopes == ["finding:read"]

    async def test_plaintext_is_not_persisted(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        """FR-CRED-03's principle: only the hash is stored."""
        issued = await service.create_api_token(
            name="nostore",
            owner=super_admin,
            scopes={Permission.DEVICE_READ},
            expires_at=None,
            actor=principal(super_admin),
        )
        await session.flush()

        stored = (
            await session.execute(select(ApiToken).where(ApiToken.id == issued.token.id))
        ).scalar_one()
        assert issued.plaintext not in stored.token_hash
        assert stored.prefix == issued.plaintext[: len(stored.prefix)]

    async def test_scopes_cannot_exceed_owner_permissions(
        self, service: UserService, session: AsyncSession
    ) -> None:
        """A token must never become a privilege-escalation path around RBAC."""
        auditor = await make_user(session, username="tokenauditor", roles={Role.AUDITOR})

        with pytest.raises(PermissionDeniedError, match="exceed the owner"):
            await service.create_api_token(
                name="escalate",
                owner=auditor,
                scopes={Permission.USER_WRITE},
                expires_at=None,
                actor=principal(auditor),
            )

    async def test_expiry_is_honoured(self, service: UserService, super_admin: User) -> None:
        expired = await service.create_api_token(
            name="expired",
            owner=super_admin,
            scopes={Permission.DEVICE_READ},
            expires_at=datetime.now(UTC) - timedelta(days=1),
            actor=principal(super_admin),
        )
        assert expired.token.is_active is False

        live = await service.create_api_token(
            name="live",
            owner=super_admin,
            scopes={Permission.DEVICE_READ},
            expires_at=datetime.now(UTC) + timedelta(days=1),
            actor=principal(super_admin),
        )
        assert live.token.is_active is True

    async def test_revoke(self, service: UserService, super_admin: User) -> None:
        issued = await service.create_api_token(
            name="revokeme",
            owner=super_admin,
            scopes={Permission.DEVICE_READ},
            expires_at=None,
            actor=principal(super_admin),
        )
        revoked = await service.revoke_api_token(issued.token.id, actor=principal(super_admin))

        assert revoked.revoked_at is not None
        assert revoked.is_active is False

    async def test_revoke_missing_raises(self, service: UserService, super_admin: User) -> None:
        with pytest.raises(NotFoundError):
            await service.revoke_api_token(uuid.uuid4(), actor=principal(super_admin))

    async def test_cannot_revoke_another_users_token(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        analyst = await make_user(session, username="tokenowner", roles={Role.SECURITY_ANALYST})
        issued = await service.create_api_token(
            name="theirs",
            owner=analyst,
            scopes={Permission.DEVICE_READ},
            expires_at=None,
            actor=principal(analyst),
        )
        other = await make_user(session, username="nosy", roles={Role.SECURITY_ANALYST})

        with pytest.raises(PermissionDeniedError, match="your own API tokens"):
            await service.revoke_api_token(issued.token.id, actor=principal(other))

    async def test_super_admin_may_revoke_any_token(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        analyst = await make_user(session, username="analyst_tok", roles={Role.SECURITY_ANALYST})
        issued = await service.create_api_token(
            name="theirs",
            owner=analyst,
            scopes={Permission.DEVICE_READ},
            expires_at=None,
            actor=principal(analyst),
        )
        revoked = await service.revoke_api_token(issued.token.id, actor=principal(super_admin))
        assert revoked.revoked_at is not None

    async def test_list_filters_by_owner(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        analyst = await make_user(session, username="listowner", roles={Role.SECURITY_ANALYST})
        await service.create_api_token(
            name="mine",
            owner=super_admin,
            scopes={Permission.DEVICE_READ},
            expires_at=None,
            actor=principal(super_admin),
        )
        await service.create_api_token(
            name="theirs",
            owner=analyst,
            scopes={Permission.DEVICE_READ},
            expires_at=None,
            actor=principal(analyst),
        )

        assert len(await service.list_api_tokens(owner_id=analyst.id)) == 1
        assert len(await service.list_api_tokens()) == 2

    async def test_creation_is_audited(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        issued = await service.create_api_token(
            name="audited-token",
            owner=super_admin,
            scopes={Permission.DEVICE_READ},
            expires_at=None,
            actor=principal(super_admin),
        )
        await session.flush()
        assert "api_token.created" in await actions_for(session, issued.token.id)


class TestApiTokenAuthentication:
    """FR-AUTH-07 — resolving a token to a principal."""

    async def test_valid_token_resolves(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        from netsecops.services.auth import AuthService

        issued = await service.create_api_token(
            name="resolve",
            owner=super_admin,
            scopes={Permission.DEVICE_READ, Permission.FINDING_READ},
            expires_at=None,
            actor=principal(super_admin),
        )
        await session.flush()

        resolved = await AuthService(session).principal_for_api_token(issued.plaintext)

        assert resolved.is_service_account is True
        assert resolved.permissions == {Permission.DEVICE_READ, Permission.FINDING_READ}

    async def test_revoked_token_is_rejected(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        from netsecops.core.errors import AuthenticationError
        from netsecops.services.auth import AuthService

        issued = await service.create_api_token(
            name="revoked",
            owner=super_admin,
            scopes={Permission.DEVICE_READ},
            expires_at=None,
            actor=principal(super_admin),
        )
        await service.revoke_api_token(issued.token.id, actor=principal(super_admin))
        await session.flush()

        with pytest.raises(AuthenticationError, match="invalid or revoked"):
            await AuthService(session).principal_for_api_token(issued.plaintext)

    async def test_unknown_token_is_rejected(self, session: AsyncSession) -> None:
        from netsecops.core.errors import AuthenticationError
        from netsecops.services.auth import AuthService

        with pytest.raises(AuthenticationError):
            await AuthService(session).principal_for_api_token(f"{API_TOKEN_PREFIX}nonsense")

    async def test_inactive_owner_blocks_the_token(
        self, service: UserService, super_admin: User, session: AsyncSession
    ) -> None:
        from netsecops.core.errors import AuthenticationError
        from netsecops.services.auth import AuthService

        owner = await make_user(session, username="soon_disabled", roles={Role.SECURITY_ANALYST})
        issued = await service.create_api_token(
            name="orphan",
            owner=owner,
            scopes={Permission.DEVICE_READ},
            expires_at=None,
            actor=principal(owner),
        )
        owner.is_active = False
        await session.flush()

        with pytest.raises(AuthenticationError, match="not active"):
            await AuthService(session).principal_for_api_token(issued.plaintext)


class TestScopeResolution:
    """FR-AUTH-05 — group-scoped roles see only their groups."""

    async def test_unrestricted_role_sees_everything(
        self, session: AsyncSession, super_admin: User
    ) -> None:
        from netsecops.services.auth import AuthService

        scope = await AuthService(session).scope_for_user(super_admin)
        assert scope.unrestricted is True

    async def test_group_scoped_role_is_restricted(self, session: AsyncSession) -> None:
        from netsecops.services.auth import AuthService

        engineer = await make_user(session, username="scoped_eng", roles={Role.NETWORK_ENGINEER})
        group = await make_group(session)
        await UserService(session).set_group_scopes(engineer, {group.id}, actor=principal(engineer))

        scope = await AuthService(session).scope_for_user(engineer)
        assert scope.unrestricted is False
        assert scope.allows_group(group.id)
        assert not scope.allows_group(uuid.uuid4())

    async def test_a_second_unrestricted_role_lifts_scoping(self, session: AsyncSession) -> None:
        """Holding Analyst alongside Engineer means full visibility, not a narrowed one."""
        from netsecops.services.auth import AuthService

        user = await make_user(
            session,
            username="dual_role",
            roles={Role.NETWORK_ENGINEER, Role.SECURITY_ANALYST},
        )
        scope = await AuthService(session).scope_for_user(user)
        assert scope.unrestricted is True


class TestPasswordLifecycle:
    async def test_history_blocks_reuse_across_several_changes(
        self, session: AsyncSession, super_admin: User
    ) -> None:
        from netsecops.core.errors import PasswordPolicyError
        from netsecops.services.auth import AuthService

        auth = AuthService(session)
        user = await make_user(session, username="rotator")
        actor = principal(super_admin)

        passwords = ["First-P4ssword!", "Second-P4ssword!", "Third-P4ssword!"]
        for pwd in passwords:
            await auth.set_password(user, pwd, actor=actor)

        # The original and every intermediate password must now be refused.
        for pwd in [TEST_PASSWORD, *passwords]:
            with pytest.raises(PasswordPolicyError):
                await auth.set_password(user, pwd, actor=actor)

    async def test_password_change_revokes_sessions(
        self, session: AsyncSession, super_admin: User
    ) -> None:
        from netsecops.db.models import RefreshToken
        from netsecops.services.auth import AuthService

        auth = AuthService(session)
        user = await make_user(session, username="sessionkiller")

        await auth._issue_tokens(user, ip_address=None, user_agent=None)
        await auth.set_password(user, "Brand-New-P4ss!", actor=principal(super_admin))
        await session.flush()

        rows = (
            (await session.execute(select(RefreshToken).where(RefreshToken.user_id == user.id)))
            .scalars()
            .all()
        )
        assert rows and all(r.revoked_at is not None for r in rows)
