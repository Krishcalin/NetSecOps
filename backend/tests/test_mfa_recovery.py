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

from netsecops.core.errors import AuthenticationError, PermissionDeniedError
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.core.security import create_mfa_pending_token
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
        await auth.disable_mfa(user, principal(user), proof_required=False)
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

        await auth.disable_mfa(user, principal(user), proof_required=False)
        await session.flush()

        assert await secret_count(session, user) == 0

    async def test_reset_is_audited(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="audited_reset")
        await enrol(auth, user)
        await auth.disable_mfa(user, principal(user), proof_required=False)
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

        await auth.disable_mfa(user, principal(user), proof_required=False)
        assert user.mfa_enabled is False


class TestReEnrolmentAfterReset:
    async def test_can_enrol_again_with_a_fresh_secret(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="re_enroller")

        first = await enrol(auth, user)
        await auth.disable_mfa(user, principal(user), proof_required=False)
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
        await auth.disable_mfa(user, principal(user), proof_required=False)
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


class TestTurningItOffReprovesBothFactors:
    """Removing the second factor from a borrowed unlocked browser was one click.

    A session is proof that somebody signed in once; it is not proof that the person
    at the keyboard now is the account holder. And this is the single change that
    weakens every future sign-in, so it is the one worth asking twice about.
    """

    async def test_it_needs_the_password(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="needs_password")
        secret = await enrol(auth, user)

        with pytest.raises(AuthenticationError, match="password"):
            await auth.disable_mfa(user, principal(user), code=pyotp.TOTP(secret).now())

        assert user.mfa_enabled is True

    async def test_it_needs_a_code(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="needs_code")
        await enrol(auth, user)

        with pytest.raises(AuthenticationError, match="verification code"):
            await auth.disable_mfa(user, principal(user), password=TEST_PASSWORD)

        assert user.mfa_enabled is True

    async def test_a_wrong_password_is_refused(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="wrong_password")
        secret = await enrol(auth, user)

        with pytest.raises(AuthenticationError):
            await auth.disable_mfa(
                user, principal(user), password="not-it", code=pyotp.TOTP(secret).now()
            )

        assert user.mfa_enabled is True

    async def test_both_together_turn_it_off(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="proves_both")
        secret = await enrol(auth, user)

        await auth.disable_mfa(
            user, principal(user), password=TEST_PASSWORD, code=pyotp.TOTP(secret).now()
        )

        assert user.mfa_enabled is False

    async def test_a_recovery_code_works_when_the_phone_is_gone(
        self, session: AsyncSession, vault
    ) -> None:
        """Which is the whole point of issuing them. Without this, losing the phone
        means an operator with server access, for a change the owner is entitled to
        make."""
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="lost_phone")
        enrolment = await auth.begin_mfa_enrolment(user)
        await auth.confirm_mfa_enrolment(user, pyotp.TOTP(enrolment.secret).now())

        await auth.disable_mfa(
            user,
            principal(user),
            password=TEST_PASSWORD,
            code=enrolment.recovery_codes[0],
        )

        assert user.mfa_enabled is False


class TestEnrolmentIsScannable:
    """`qrcode` shipped as a dependency from Phase 0 and nothing imported it, so the
    screen said "scan this into your authenticator app" above a bare base32 string."""

    async def test_it_returns_a_qr_code(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="scannable")

        enrolment = await auth.begin_mfa_enrolment(user)

        assert enrolment.qr_svg.startswith("<svg")
        assert "<path" in enrolment.qr_svg

    async def test_the_secret_is_not_in_the_qr_markup(self, session: AsyncSession, vault) -> None:
        """What makes it safe to inline. The SVG factory emits one path of numeric
        coordinates, so no part of the URI reaches the document as text."""
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="qr_safe")

        enrolment = await auth.begin_mfa_enrolment(user)

        assert enrolment.secret not in enrolment.qr_svg
        assert "otpauth" not in enrolment.qr_svg

    async def test_the_qr_carries_the_same_secret_as_the_key(
        self, session: AsyncSession, vault
    ) -> None:
        """Three ways in, one secret. A QR encoding a different URI from the one the
        typed key belongs to would enrol a device that never produces a valid code."""
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="one_secret")

        enrolment = await auth.begin_mfa_enrolment(user)

        assert enrolment.secret in enrolment.provisioning_uri
        assert enrolment.formatted_secret.replace(" ", "") == enrolment.secret

    def test_the_qr_actually_encodes_its_input(self) -> None:
        """A QR encoding the wrong URI enrols a device that never produces a valid
        code, and the person blames their authenticator.

        Asserted as "depends on the input and is stable for it" rather than by
        decoding, which would mean a QR reader in the test dependencies. It is enough
        to kill the mutation that matters — an encoder wired to a constant — without
        pretending to verify more than it does.
        """
        from netsecops.core.security import mfa_qr_svg

        one = mfa_qr_svg("otpauth://totp/NetSecOps:a@b.c?secret=AAAAAAAAAAAAAAAA")
        two = mfa_qr_svg("otpauth://totp/NetSecOps:a@b.c?secret=BBBBBBBBBBBBBBBB")

        assert one != two
        assert one == mfa_qr_svg("otpauth://totp/NetSecOps:a@b.c?secret=AAAAAAAAAAAAAAAA")

    async def test_the_key_is_grouped_for_typing(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="grouped")

        enrolment = await auth.begin_mfa_enrolment(user)

        assert " " in enrolment.formatted_secret
        assert all(len(part) <= 4 for part in enrolment.formatted_secret.split())


class TestRecoveryCodesRemaining:
    async def test_a_fresh_enrolment_reports_its_codes(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="counts_codes")
        enrolment = await auth.begin_mfa_enrolment(user)
        await auth.confirm_mfa_enrolment(user, pyotp.TOTP(enrolment.secret).now())

        assert await auth.recovery_codes_left(user) == len(enrolment.recovery_codes)

    async def test_spending_one_lowers_the_count(self, session: AsyncSession, vault) -> None:
        # Nought left is a lockout waiting for a lost phone, and it was not visible
        # anywhere until the count was exposed.
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="spends_codes")
        enrolment = await auth.begin_mfa_enrolment(user)
        await auth.confirm_mfa_enrolment(user, pyotp.TOTP(enrolment.secret).now())
        before = await auth.recovery_codes_left(user)

        await auth.complete_mfa(
            create_mfa_pending_token(str(user.id))[0], enrolment.recovery_codes[0]
        )

        assert await auth.recovery_codes_left(user) == before - 1

    async def test_an_account_without_mfa_reports_none(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="no_mfa_codes")

        assert await auth.recovery_codes_left(user) == 0


class TestPermissions:
    async def test_owner_may_disable_their_own(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="self_disable")
        secret = await enrol(auth, user)

        await auth.disable_mfa(
            user, principal(user), password=TEST_PASSWORD, code=pyotp.TOTP(secret).now()
        )
        assert user.mfa_enabled is False

    async def test_super_admin_may_disable_another(
        self, session: AsyncSession, vault, super_admin: User
    ) -> None:
        auth = AuthService(session, vault=vault)
        user = await make_user(session, username="admin_disabled")
        await enrol(auth, user)

        await auth.disable_mfa(user, principal(super_admin), proof_required=False)
        assert user.mfa_enabled is False

    async def test_another_user_may_not(self, session: AsyncSession, vault) -> None:
        auth = AuthService(session, vault=vault)
        target = await make_user(session, username="mfa_target")
        await enrol(auth, target)
        intruder = await make_user(session, username="mfa_intruder", roles={Role.SECURITY_ANALYST})

        with pytest.raises(PermissionDeniedError, match="owner or a Super Admin"):
            await auth.disable_mfa(target, principal(intruder), proof_required=False)

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
