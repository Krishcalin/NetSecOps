"""Authentication endpoints (SRS §4.2 ``/auth/*``)."""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Response, status

from netsecops.api.deps import (
    ACCESS_COOKIE,
    CSRF_COOKIE,
    REFRESH_COOKIE,
    AuthServiceDep,
    ClientIPDep,
    CurrentUserDep,
    PrincipalDep,
    SettingsDep,
    UserServiceDep,
    verify_csrf,
)
from netsecops.core.config import Settings
from netsecops.core.rbac import ROLE_DESCRIPTIONS, ROLE_PERMISSIONS, Role
from netsecops.schemas.auth import (
    CurrentUserResponse,
    LoginRequest,
    MFAChallengeResponse,
    MFAConfirmRequest,
    MFAEnrolmentResponse,
    MFAVerifyRequest,
    PasswordChangeRequest,
    RoleInfo,
    TokenResponse,
)
from netsecops.services.auth import MFAChallenge, TokenPair

router = APIRouter(prefix="/auth", tags=["auth"])

#: The refresh cookie is scoped here so it is only sent to the endpoints that rotate it.
REFRESH_COOKIE_PATH = "/api/v1/auth"


def _set_auth_cookies(response: Response, pair: TokenPair, settings: Settings) -> None:
    """Deliver tokens as ``Secure; HttpOnly; SameSite=Strict`` cookies (FR-AUTH-02).

    The CSRF cookie is deliberately readable by JavaScript — the SPA must echo it in a
    header for the double-submit check (SEC-03).
    """
    response.set_cookie(
        ACCESS_COOKIE,
        pair.access_token,
        httponly=True,
        max_age=settings.access_token_ttl_minutes * 60,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        path="/",
    )
    response.set_cookie(
        REFRESH_COOKIE,
        pair.refresh_token,
        httponly=True,
        max_age=settings.refresh_token_ttl_hours * 3600,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        # Scoped to the refresh endpoint so it is not sent with every ordinary request.
        path=REFRESH_COOKIE_PATH,
    )
    response.set_cookie(
        CSRF_COOKIE,
        secrets.token_urlsafe(32),
        httponly=False,
        max_age=settings.refresh_token_ttl_hours * 3600,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        path="/",
    )


def _clear_auth_cookies(response: Response, settings: Settings) -> None:
    for name, path in (
        (ACCESS_COOKIE, "/"),
        (REFRESH_COOKIE, REFRESH_COOKIE_PATH),
        (CSRF_COOKIE, "/"),
    ):
        response.delete_cookie(
            name,
            path=path,
            domain=settings.cookie_domain,
            secure=settings.cookie_secure,
            samesite=settings.cookie_samesite,
        )


@router.post(
    "/login",
    response_model=TokenResponse | MFAChallengeResponse,
    responses={
        401: {"description": "Invalid credentials"},
        423: {"description": "Account locked (FR-AUTH-06)"},
        429: {"description": "Rate limited"},
    },
    summary="Authenticate with username and password",
)
async def login(
    payload: LoginRequest,
    response: Response,
    auth: AuthServiceDep,
    settings: SettingsDep,
    ip: ClientIPDep,
) -> TokenResponse | MFAChallengeResponse:
    result = await auth.authenticate(
        payload.username, payload.password, ip_address=ip, user_agent=None
    )

    if isinstance(result, MFAChallenge):
        return MFAChallengeResponse(mfa_token=result.mfa_token, expires_at=result.expires_at)

    _set_auth_cookies(response, result, settings)
    return TokenResponse(
        access_token=result.access_token,
        expires_at=result.access_expires_at,
        refresh_expires_at=result.refresh_expires_at,
    )


@router.post(
    "/mfa/verify",
    response_model=TokenResponse,
    summary="Complete sign-in with a TOTP or recovery code (FR-AUTH-03)",
)
async def verify_mfa(
    payload: MFAVerifyRequest,
    response: Response,
    auth: AuthServiceDep,
    settings: SettingsDep,
    ip: ClientIPDep,
) -> TokenResponse:
    pair = await auth.complete_mfa(payload.mfa_token, payload.code, ip_address=ip)
    _set_auth_cookies(response, pair, settings)
    return TokenResponse(
        access_token=pair.access_token,
        expires_at=pair.access_expires_at,
        refresh_expires_at=pair.refresh_expires_at,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate the refresh token and issue a new access token (FR-AUTH-02)",
)
async def refresh(
    response: Response,
    auth: AuthServiceDep,
    settings: SettingsDep,
    ip: ClientIPDep,
    refresh_cookie: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
) -> TokenResponse:
    from netsecops.core.errors import AuthenticationError

    if not refresh_cookie:
        raise AuthenticationError("No refresh token supplied.")

    pair = await auth.refresh(refresh_cookie, ip_address=ip)
    _set_auth_cookies(response, pair, settings)
    return TokenResponse(
        access_token=pair.access_token,
        expires_at=pair.access_expires_at,
        refresh_expires_at=pair.refresh_expires_at,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(verify_csrf)],
    summary="Revoke the current session",
)
async def logout(
    response: Response,
    auth: AuthServiceDep,
    principal: PrincipalDep,
    settings: SettingsDep,
    ip: ClientIPDep,
    all_sessions: bool = False,
    refresh_cookie: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
) -> None:
    await auth.logout(refresh_cookie, principal, ip_address=ip, all_sessions=all_sessions)
    _clear_auth_cookies(response, settings)


@router.get("/me", response_model=CurrentUserResponse, summary="The calling user")
async def me(principal: PrincipalDep, users: UserServiceDep) -> CurrentUserResponse:
    user = await users.get(principal.id)
    return CurrentUserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_service_account=user.is_service_account,
        mfa_enabled=user.mfa_enabled,
        must_change_password=user.must_change_password,
        roles=sorted(user.role_set, key=lambda r: r.value),
        last_login_at=user.last_login_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
        permissions=sorted(principal.permissions, key=lambda p: p.value),
        device_group_ids=sorted(principal.scope.device_group_ids),
        unrestricted_scope=principal.scope.unrestricted,
    )


@router.post(
    "/password",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(verify_csrf)],
    summary="Change your own password (FR-AUTH-01)",
)
async def change_password(
    payload: PasswordChangeRequest,
    response: Response,
    auth: AuthServiceDep,
    principal: PrincipalDep,
    settings: SettingsDep,
    user: CurrentUserDep,
) -> None:
    await auth.change_password(
        user, payload.current_password, payload.new_password, actor=principal
    )
    # Every session was revoked; force a fresh sign-in.
    _clear_auth_cookies(response, settings)


@router.post(
    "/mfa/enroll",
    response_model=MFAEnrolmentResponse,
    dependencies=[Depends(verify_csrf)],
    summary="Begin TOTP enrolment (FR-AUTH-03)",
)
async def enroll_mfa(
    auth: AuthServiceDep,
    user: CurrentUserDep,
) -> MFAEnrolmentResponse:
    enrolment = await auth.begin_mfa_enrolment(user)
    return MFAEnrolmentResponse(
        secret=enrolment.secret,
        provisioning_uri=enrolment.provisioning_uri,
        recovery_codes=enrolment.recovery_codes,
    )


@router.post(
    "/mfa/confirm",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(verify_csrf)],
    summary="Confirm TOTP enrolment by proving the authenticator works",
)
async def confirm_mfa(
    payload: MFAConfirmRequest,
    auth: AuthServiceDep,
    user: CurrentUserDep,
) -> None:
    await auth.confirm_mfa_enrolment(user, payload.code)


@router.delete(
    "/mfa",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(verify_csrf)],
    summary="Disable MFA for your own account",
)
async def disable_mfa(
    auth: AuthServiceDep,
    principal: PrincipalDep,
    user: CurrentUserDep,
) -> None:
    await auth.disable_mfa(user, principal)


@router.get(
    "/roles",
    response_model=list[RoleInfo],
    summary="Role catalogue and the permissions each role grants",
)
async def list_roles(_: PrincipalDep) -> list[RoleInfo]:
    return [
        RoleInfo(
            role=role,
            description=ROLE_DESCRIPTIONS[role],
            permissions=sorted(ROLE_PERMISSIONS[role], key=lambda p: p.value),
        )
        for role in Role
    ]
