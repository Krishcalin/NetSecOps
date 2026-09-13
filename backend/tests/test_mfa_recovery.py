"""MFA recovery and re-enrolment (FR-AUTH-03, FR-ADM-02).

An operator who loses their authenticator cannot disable MFA through the API, because
doing so needs a session and MFA is what blocks sign-in. These tests cover the
break-glass path that resolves that, and the re-enrolment that has to work afterwards.
"""

from __future__ import annotations

import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import PermissionDeniedError
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import AuditLog, MFASecret, User
from netsecops.services.auth import AuthService
from tests.conftest import TEST_PASSWORD, make_user


def principal(user: User) -> Principal:
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def enrol(auth: AuthService, user: User) -> str:
    """Enrol and confirm MFA, returning the TOTP secret."""
    enrolment = await auth.begin_mfa_enrolment(user)
    await auth.confirm_mfa_enrolment(user, pyotp.TOTP(enrolment.secret).now())
    return enrolment.secret


async def secret_count(session: AsyncSession, user: User) -> int:
    result = await session.execute(
        select(func.count()).select_from(MFASecret).where(MFASecret.user_id == user.id)
    )
    return int(result.scalar_one())


class TestBreakGlassReset:
    async def test_clearing_mfa_restores_password_only_sign_in(
        self, session: AsyncSession, vault
    ) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="locked_out")
        await enrol(auth, user)
        assert user.mfa_enabled is True

        # The operator clears it out-of-band, as netsecops-cli reset-mfa does.
        await auth.disable_mfa(user, principal(user))
        await session.flush()

        assert user.mfa_enabled is False
        result = await auth.authenticate(user.username, TEST_PASSWORD)
        assert hasattr(result, "access_token"), "password alone should now sign in"

    async def test_reset_removes_the_secret_row(self, session: AsyncSession, vault) -> None:
        """Regression: a stale relationship could leave the row behind."""
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="orphan_check")
        await enrol(auth, user)
        assert await secret_count(session, user) == 1

        await auth.disable_mfa(user, principal(user))
        await session.flush()

        assert await secret_count(session, user) == 0

    async def test_reset_is_audited(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="audited_reset")
        await enrol(auth, user)
        await auth.disable_mfa(user, principal(user))
        await session.flush()

        actions = (
            (
                await session.execute(
                    select(AuditLog.action).where(AuditLog.object_id == str(user.id))
                )
            )
            .scalars()
            .all()
        )
        assert "mfa.disabled" in actions

    async def test_reset_is_idempotent(self, session: AsyncSession, vault) -> None:
        """Clearing MFA on an account that never had it must not error."""
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="never_enrolled")

        await auth.disable_mfa(user, principal(user))
        assert user.mfa_enabled is False


class TestReEnrolmentAfterReset:
    async def test_can_enrol_again_with_a_fresh_secret(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="re_enroller")

        first = await enrol(auth, user)
        await auth.disable_mfa(user, principal(user))
        await session.flush()

        second = await enrol(auth, user)

        assert second != first, "re-enrolment must mint a new secret"
        assert user.mfa_enabled is True
        assert await secret_count(session, user) == 1

    async def test_old_secret_no_longer_works(self, session: AsyncSession, vault) -> None:
        """The lost authenticator must not still open the account."""
        from netsecops.core.errors import AuthenticationError

        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="old_secret_dead")

        old = await enrol(auth, user)
        await auth.disable_mfa(user, principal(user))
        await session.flush()
        await enrol(auth, user)

        challenge = await auth.authenticate(user.username, TEST_PASSWORD)
        with pytest.raises(AuthenticationError, match="Invalid verification code"):
            await auth.complete_mfa(challenge.mfa_token, pyotp.TOTP(old).now())  # type: ignore[union-attr]

    async def test_abandoned_enrolment_is_replaced_not_duplicated(
        self, session: AsyncSession, vault
    ) -> None:
        """Starting enrolment twice must leave exactly one pending secret."""
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="abandoner")

        await auth.begin_mfa_enrolment(user)
        second = await auth.begin_mfa_enrolment(user)
        await session.flush()

        assert await secret_count(session, user) == 1
        await auth.confirm_mfa_enrolment(user, pyotp.TOTP(second.secret).now())
        assert user.mfa_enabled is True


class TestPermissions:
    async def test_owner_may_disable_their_own(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="self_disable")
        await enrol(auth, user)

        await auth.disable_mfa(user, principal(user))
        assert user.mfa_enabled is False

    async def test_super_admin_may_disable_another(
        self, session: AsyncSession, vault, super_admin: User
    ) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="admin_disabled")
        await enrol(auth, user)

        await auth.disable_mfa(user, principal(super_admin))
        assert user.mfa_enabled is False

    async def test_another_user_may_not(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        target = await make_user(session, username="mfa_target")
        await enrol(auth, target)
        intruder = await make_user(session, username="mfa_intruder", roles={Role.SECURITY_ANALYST})

        with pytest.raises(PermissionDeniedError, match="owner or a Super Admin"):
            await auth.disable_mfa(target, principal(intruder))

        assert target.mfa_enabled is True


class TestFirstTimeEnrolmentIsReachable:
    """A fresh account must be able to sign in with a password and then enrol."""

    async def test_new_user_is_not_challenged(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        user = await make_user(session, username="fresh_account")

        response = await client.post(
            "/api/v1/auth/login",
            json={"username": user.username, "password": TEST_PASSWORD},
        )

        assert response.status_code == 200
        assert response.json()["mfa_required"] is False, (
            "a user who has never enrolled must not be asked for a code"
        )

    async def test_enrolment_endpoint_is_reachable_once_signed_in(
        self, client: AsyncClient, session: AsyncSession, authenticate
    ) -> None:
        user = await make_user(session, username="enrol_reachable")
        authenticate(user)

        response = await client.post("/api/v1/auth/mfa/enroll")

        assert response.status_code == 200
        assert response.json()["provisioning_uri"].startswith("otpauth://totp/")
