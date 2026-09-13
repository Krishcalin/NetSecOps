"""End-to-end authentication flow tests.

Phase 0 acceptance: "login/MFA works". These exercise the HTTP surface, not the service
layer, so cookie flags, problem-details shape and status codes are covered too.
"""

from __future__ import annotations

import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.api.deps import ACCESS_COOKIE, CSRF_COOKIE, REFRESH_COOKIE
from netsecops.core.rbac import Role
from netsecops.db.models import AuditLog, RefreshToken, User
from tests.conftest import TEST_PASSWORD, make_user

LOGIN = "/api/v1/auth/login"


async def _login(client: AsyncClient, username: str, password: str = TEST_PASSWORD):
    return await client.post(LOGIN, json={"username": username, "password": password})


class TestPasswordLogin:
    async def test_successful_login_returns_access_token(
        self, client: AsyncClient, analyst: User
    ) -> None:
        response = await _login(client, analyst.username)

        assert response.status_code == 200
        body = response.json()
        assert body["mfa_required"] is False
        assert body["token_type"] == "bearer"
        assert body["access_token"]

    async def test_login_sets_httponly_cookies(self, client: AsyncClient, analyst: User) -> None:
        """FR-AUTH-02 — tokens are delivered as HttpOnly cookies."""
        response = await _login(client, analyst.username)

        cookies = {c.split("=")[0]: c for c in response.headers.get_list("set-cookie")}
        assert ACCESS_COOKIE in cookies
        assert REFRESH_COOKIE in cookies
        assert CSRF_COOKIE in cookies

        assert "HttpOnly" in cookies[ACCESS_COOKIE]
        assert "HttpOnly" in cookies[REFRESH_COOKIE]
        assert "SameSite=strict" in cookies[ACCESS_COOKIE].lower().replace("samesite", "SameSite")
        # The CSRF cookie must be readable by the SPA for double-submit (SEC-03).
        assert "HttpOnly" not in cookies[CSRF_COOKIE]

    async def test_refresh_cookie_is_path_scoped(self, client: AsyncClient, analyst: User) -> None:
        """The refresh token should not ride along on every ordinary request."""
        response = await _login(client, analyst.username)
        refresh = next(
            c for c in response.headers.get_list("set-cookie") if c.startswith(REFRESH_COOKIE)
        )
        assert "Path=/api/v1/auth" in refresh

    @pytest.mark.parametrize(
        ("username", "password"),
        [("analyst_user", "wrong-password"), ("no-such-user", TEST_PASSWORD)],
    )
    async def test_bad_credentials_give_identical_errors(
        self, client: AsyncClient, analyst: User, username: str, password: str
    ) -> None:
        """SEC-05 — the response must not reveal whether the username exists."""
        response = await _login(client, username, password)

        assert response.status_code == 401
        assert response.json()["detail"] == "Invalid username or password."

    async def test_error_is_problem_json(self, client: AsyncClient, analyst: User) -> None:
        response = await _login(client, analyst.username, "wrong")

        assert response.headers["content-type"].startswith("application/problem+json")
        body = response.json()
        assert body["status"] == 401
        assert body["type"].endswith("/authentication-failed")
        assert body["instance"] == LOGIN

    async def test_inactive_account_cannot_log_in(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        user = await make_user(session, username="disabled_user", is_active=False)
        assert (await _login(client, user.username)).status_code == 401

    async def test_no_password_in_the_response(self, client: AsyncClient, analyst: User) -> None:
        response = await _login(client, analyst.username)
        assert TEST_PASSWORD not in response.text


class TestLockout:
    """FR-AUTH-06 — lock after 5 consecutive failures."""

    async def test_account_locks_after_five_failures(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        user = await make_user(session, username="lockme")

        for _ in range(5):
            assert (await _login(client, user.username, "wrong")).status_code == 401

        # The sixth attempt is refused as locked, even with the correct password.
        response = await _login(client, user.username)
        assert response.status_code == 423
        assert response.json()["type"].endswith("/account-locked")

    async def test_successful_login_resets_the_counter(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        user = await make_user(session, username="resetme")

        for _ in range(4):
            await _login(client, user.username, "wrong")
        assert (await _login(client, user.username)).status_code == 200

        await session.refresh(user)
        assert user.failed_login_count == 0
        assert user.locked_until is None

    async def test_lockout_is_audited(self, client: AsyncClient, session: AsyncSession) -> None:
        user = await make_user(session, username="auditlock")
        for _ in range(5):
            await _login(client, user.username, "wrong")

        actions = (
            (await session.execute(select(AuditLog.action).where(AuditLog.actor_id == user.id)))
            .scalars()
            .all()
        )
        assert "login.locked" in actions


class TestMFA:
    """FR-AUTH-03 — TOTP second factor."""

    async def test_enrolment_then_login_challenge(
        self, client: AsyncClient, session: AsyncSession, authenticate
    ) -> None:
        user = await make_user(session, username="mfauser")
        authenticate(user)

        enroll = await client.post("/api/v1/auth/mfa/enroll")
        assert enroll.status_code == 200
        payload = enroll.json()
        assert payload["provisioning_uri"].startswith("otpauth://totp/")
        assert len(payload["recovery_codes"]) == 10

        secret = payload["secret"]
        confirm = await client.post(
            "/api/v1/auth/mfa/confirm", json={"code": pyotp.TOTP(secret).now()}
        )
        assert confirm.status_code == 204

        await session.refresh(user)
        assert user.mfa_enabled is True

        # Password alone now yields a challenge, not a session.
        client.cookies.clear()
        login = await _login(client, user.username)
        assert login.status_code == 200
        assert login.json()["mfa_required"] is True
        assert "access_token" not in login.json()

    async def test_challenge_completes_with_a_valid_code(
        self, client: AsyncClient, session: AsyncSession, authenticate
    ) -> None:
        user = await make_user(session, username="mfaverify")
        authenticate(user)

        secret = (await client.post("/api/v1/auth/mfa/enroll")).json()["secret"]
        await client.post("/api/v1/auth/mfa/confirm", json={"code": pyotp.TOTP(secret).now()})
        client.cookies.clear()

        mfa_token = (await _login(client, user.username)).json()["mfa_token"]
        verified = await client.post(
            "/api/v1/auth/mfa/verify",
            json={"mfa_token": mfa_token, "code": pyotp.TOTP(secret).now()},
        )

        assert verified.status_code == 200
        assert verified.json()["access_token"]

    async def test_wrong_code_is_refused(
        self, client: AsyncClient, session: AsyncSession, authenticate
    ) -> None:
        user = await make_user(session, username="mfawrong")
        authenticate(user)

        secret = (await client.post("/api/v1/auth/mfa/enroll")).json()["secret"]
        await client.post("/api/v1/auth/mfa/confirm", json={"code": pyotp.TOTP(secret).now()})
        client.cookies.clear()

        mfa_token = (await _login(client, user.username)).json()["mfa_token"]
        response = await client.post(
            "/api/v1/auth/mfa/verify", json={"mfa_token": mfa_token, "code": "000000"}
        )
        assert response.status_code == 401

    async def test_recovery_code_works_once(
        self, client: AsyncClient, session: AsyncSession, authenticate
    ) -> None:
        user = await make_user(session, username="mfarecover")
        authenticate(user)

        enrolment = (await client.post("/api/v1/auth/mfa/enroll")).json()
        await client.post(
            "/api/v1/auth/mfa/confirm", json={"code": pyotp.TOTP(enrolment["secret"]).now()}
        )
        recovery_code = enrolment["recovery_codes"][0]
        client.cookies.clear()

        mfa_token = (await _login(client, user.username)).json()["mfa_token"]
        first = await client.post(
            "/api/v1/auth/mfa/verify", json={"mfa_token": mfa_token, "code": recovery_code}
        )
        assert first.status_code == 200

        # The same code must not work a second time.
        client.cookies.clear()
        mfa_token = (await _login(client, user.username)).json()["mfa_token"]
        second = await client.post(
            "/api/v1/auth/mfa/verify", json={"mfa_token": mfa_token, "code": recovery_code}
        )
        assert second.status_code == 401

    async def test_confirm_requires_a_valid_code(
        self, client: AsyncClient, session: AsyncSession, authenticate
    ) -> None:
        user = await make_user(session, username="mfabadconfirm")
        authenticate(user)

        await client.post("/api/v1/auth/mfa/enroll")
        response = await client.post("/api/v1/auth/mfa/confirm", json={"code": "000000"})

        assert response.status_code == 401
        await session.refresh(user)
        assert user.mfa_enabled is False


class TestRefreshRotation:
    """FR-AUTH-02 — rotating, revocable refresh tokens."""

    async def test_refresh_issues_a_new_pair(self, client: AsyncClient, analyst: User) -> None:
        await _login(client, analyst.username)
        response = await client.post("/api/v1/auth/refresh")

        assert response.status_code == 200
        assert response.json()["access_token"]

    async def test_old_refresh_token_is_revoked_after_rotation(
        self, client: AsyncClient, analyst: User, session: AsyncSession
    ) -> None:
        await _login(client, analyst.username)
        original = client.cookies.get(REFRESH_COOKIE, path="/api/v1/auth")

        await client.post("/api/v1/auth/refresh")
        await session.flush()

        rows = (
            (
                await session.execute(
                    select(RefreshToken)
                    .where(RefreshToken.user_id == analyst.id)
                    .order_by(RefreshToken.created_at)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 2
        assert rows[0].revoked_at is not None
        assert rows[0].revoked_reason == "rotated"
        assert rows[0].replaced_by_jti == rows[1].jti
        assert original is not None

    async def test_reusing_a_rotated_token_revokes_every_session(
        self, client: AsyncClient, analyst: User, session: AsyncSession
    ) -> None:
        """Replay of a rotated token is the signal that it was stolen."""
        await _login(client, analyst.username)
        stolen = client.cookies.get(REFRESH_COOKIE, path="/api/v1/auth")
        await client.post("/api/v1/auth/refresh")

        client.cookies.set(REFRESH_COOKIE, stolen, path="/api/v1/auth")
        response = await client.post("/api/v1/auth/refresh")

        assert response.status_code == 401
        assert "revoked" in response.json()["detail"].lower()

        await session.flush()
        rows = (
            (await session.execute(select(RefreshToken).where(RefreshToken.user_id == analyst.id)))
            .scalars()
            .all()
        )
        assert all(r.revoked_at is not None for r in rows)

    async def test_refresh_without_a_cookie_is_rejected(self, client: AsyncClient) -> None:
        assert (await client.post("/api/v1/auth/refresh")).status_code == 401


class TestSessionEndpoints:
    async def test_me_returns_permissions(
        self, client: AsyncClient, analyst: User, authenticate
    ) -> None:
        authenticate(analyst)
        response = await client.get("/api/v1/auth/me")

        assert response.status_code == 200
        body = response.json()
        assert body["username"] == analyst.username
        assert body["roles"] == [Role.SECURITY_ANALYST.value]
        assert "device:read" in body["permissions"]
        assert body["unrestricted_scope"] is True

    async def test_me_requires_authentication(self, client: AsyncClient) -> None:
        assert (await client.get("/api/v1/auth/me")).status_code == 401

    async def test_logout_clears_cookies(self, client: AsyncClient, analyst: User) -> None:
        await _login(client, analyst.username)
        csrf = client.cookies.get(CSRF_COOKIE)

        response = await client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf or ""})
        assert response.status_code == 204

        cleared = " ".join(response.headers.get_list("set-cookie"))
        assert ACCESS_COOKIE in cleared and REFRESH_COOKIE in cleared

    async def test_roles_catalogue_lists_every_role(
        self, client: AsyncClient, analyst: User, authenticate
    ) -> None:
        authenticate(analyst)
        response = await client.get("/api/v1/auth/roles")

        assert response.status_code == 200
        assert {r["role"] for r in response.json()} == {r.value for r in Role}


class TestPasswordChange:
    async def test_change_password_then_old_one_fails(
        self, client: AsyncClient, session: AsyncSession, authenticate
    ) -> None:
        user = await make_user(session, username="changer")
        authenticate(user)

        response = await client.post(
            "/api/v1/auth/password",
            json={"current_password": TEST_PASSWORD, "new_password": "Brand-New-P4ss!"},
        )
        assert response.status_code == 204

        client.cookies.clear()
        assert (await _login(client, user.username, TEST_PASSWORD)).status_code == 401
        assert (await _login(client, user.username, "Brand-New-P4ss!")).status_code == 200

    async def test_wrong_current_password_is_refused(
        self, client: AsyncClient, session: AsyncSession, authenticate
    ) -> None:
        user = await make_user(session, username="badcurrent")
        authenticate(user)

        response = await client.post(
            "/api/v1/auth/password",
            json={"current_password": "not-it", "new_password": "Brand-New-P4ss!"},
        )
        assert response.status_code == 401

    async def test_weak_new_password_is_refused(
        self, client: AsyncClient, session: AsyncSession, authenticate
    ) -> None:
        user = await make_user(session, username="weaknew")
        authenticate(user)

        response = await client.post(
            "/api/v1/auth/password",
            json={"current_password": TEST_PASSWORD, "new_password": "short"},
        )
        assert response.status_code == 422

    async def test_password_reuse_is_refused(
        self, client: AsyncClient, session: AsyncSession, authenticate
    ) -> None:
        """FR-AUTH-01 — no reuse within the history window."""
        user = await make_user(session, username="reuser")
        authenticate(user)

        await client.post(
            "/api/v1/auth/password",
            json={"current_password": TEST_PASSWORD, "new_password": "Second-P4ssword!"},
        )
        response = await client.post(
            "/api/v1/auth/password",
            json={"current_password": "Second-P4ssword!", "new_password": TEST_PASSWORD},
        )

        assert response.status_code == 422
        assert "last 5 passwords" in response.json()["detail"]


class TestRateLimiting:
    async def test_login_endpoint_is_rate_limited(
        self, client: AsyncClient, session: AsyncSession
    ) -> None:
        """SEC-05 — repeated attempts get 429 before they get an answer."""
        user = await make_user(session, username="floodme")

        statuses = [(await _login(client, user.username, "wrong")).status_code for _ in range(15)]
        assert 429 in statuses
