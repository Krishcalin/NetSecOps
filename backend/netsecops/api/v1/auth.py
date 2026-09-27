"""Authentication endpoints (SRS §4.2 ``/auth/*``)."""

from __future__ import annotations

import secrets
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Cookie, Depends, Response, status
from fastapi.responses import RedirectResponse

from netsecops.api.deps import (
    ACCESS_COOKIE,
    CSRF_COOKIE,
    REFRESH_COOKIE,
    AuthServiceDep,
    ClientIPDep,
    CurrentUserDep,
    PrincipalDep,
    SettingsDep,
    SSOServiceDep,
    UserServiceDep,
    require,
    verify_csrf,
)
from netsecops.core.config import Settings
from netsecops.core.errors import AccountLockedError, AuthenticationError
from netsecops.core.logging import get_logger
from netsecops.core.oidc import OIDCError
from netsecops.core.rbac import ROLE_DESCRIPTIONS, ROLE_PERMISSIONS, Permission, Role
from netsecops.schemas.auth import (
    CurrentUserResponse,
    LoginRequest,
    MFAChallengeResponse,
    MFAConfirmRequest,
    MFADisableRequest,
    MFAEnrolmentResponse,
    MFAStatusResponse,
    MFAVerifyRequest,
    PasswordChangeRequest,
    RoleInfo,
    SSORoleMapping,
    SSORoleMapRead,
    SSORoleMapWrite,
    SSOStartRequest,
    SSOStartResponse,
    SSOStatusResponse,
    TokenResponse,
)
from netsecops.services.auth import MFAChallenge, TokenPair
from netsecops.services.sso import MAPPABLE_ROLES

log = get_logger(__name__)

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


# ─────────────────────────── single sign-on (FR-AUTH-04) ───────────────────────────


@router.get(
    "/sso/status",
    response_model=SSOStatusResponse,
    summary="Whether single sign-on is available (FR-AUTH-04)",
)
async def sso_status(settings: SettingsDep) -> SSOStatusResponse:
    """Unauthenticated on purpose: the sign-in screen has to know whether to offer the
    button before anybody has signed in. It reveals that SSO is configured and what to
    call it, and nothing about the provider beyond a name somebody chose to display."""
    return SSOStatusResponse(
        enabled=settings.oidc_enabled,
        button_label=settings.oidc_button_label if settings.oidc_enabled else None,
    )


@router.post(
    "/sso/start",
    response_model=SSOStartResponse,
    responses={401: {"description": "Single sign-on is not enabled"}},
    summary="Begin an OIDC sign-in and get the provider URL (FR-AUTH-04)",
)
async def sso_start(
    sso: SSOServiceDep, ip: ClientIPDep, payload: SSOStartRequest | None = None
) -> SSOStartResponse:
    """Returns the URL rather than redirecting to it.

    The console is a single-page application: it needs to set the browser's location
    itself, and a 302 from `fetch` would be followed by the fetch rather than by the
    page. It also keeps this endpoint's failures — an unreachable provider, a bad
    issuer — visible as JSON problems instead of a redirect into nowhere.
    """
    begun = await sso.begin(redirect_to=payload.redirect_to if payload else None, ip_address=ip)
    return SSOStartResponse(authorization_url=begun.authorization_url)


@router.get(
    "/sso/callback",
    response_class=RedirectResponse,
    status_code=status.HTTP_303_SEE_OTHER,
    responses={303: {"description": "Signed in, or sent back to the login screen"}},
    summary="Where the identity provider returns the browser (FR-AUTH-04)",
)
async def sso_callback(
    response: Response,
    sso: SSOServiceDep,
    settings: SettingsDep,
    ip: ClientIPDep,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
) -> RedirectResponse:
    """A browser lands here, so every outcome is a redirect rather than a problem document.

    The user is at the end of a round trip through another website and has no way to
    read a JSON body; a failure has to put them back on the login screen with something
    to act on. The reason travels as a short code in the query string — never the
    provider's own message, which quotes back whatever it was sent.
    """

    def back(reason: str) -> RedirectResponse:
        return RedirectResponse(
            f"{settings.sso_console_login_path}?sso_error={reason}",
            status_code=status.HTTP_303_SEE_OTHER,
        )

    if error:
        # The provider refused — consent declined, or the client is not entitled to the
        # application. Logged with its description; the browser gets the code alone.
        log.warning("sso.provider_error", error=error, description=error_description)
        return back("provider_denied")

    if not code or not state:
        return back("incomplete")

    try:
        result, redirect_to = await sso.complete(code=code, state=state, ip_address=ip)
    except AccountLockedError:
        return back("locked")
    except AuthenticationError:
        return back("denied")
    except OIDCError:
        return back("provider_unreachable")

    if isinstance(result, MFAChallenge):
        # The provider vouched for them; the second factor has not been given yet. The
        # pending token goes in the URL because there is no other channel on a
        # redirect — it is single-use, expires in minutes, and grants nothing on its
        # own without a TOTP code.
        redirect = RedirectResponse(
            f"{settings.sso_console_login_path}?mfa_token={quote(result.mfa_token)}",
            status_code=status.HTTP_303_SEE_OTHER,
        )
        return redirect

    redirect = RedirectResponse(
        redirect_to or settings.sso_console_home_path, status_code=status.HTTP_303_SEE_OTHER
    )
    _set_auth_cookies(redirect, result, settings)
    return redirect


@router.get(
    "/sso/role-map",
    response_model=SSORoleMapRead,
    dependencies=[Depends(require(Permission.ROLE_READ))],
    summary="Which identity-provider groups grant which roles (FR-AUTH-04)",
)
async def get_sso_role_map(sso: SSOServiceDep) -> SSORoleMapRead:
    mappings = await sso.get_role_map()
    return SSORoleMapRead(
        mappings=[SSORoleMapping(group=m.group, role=m.role) for m in mappings],
        mappable_roles=sorted(MAPPABLE_ROLES, key=lambda role: role.value),
    )


@router.put(
    "/sso/role-map",
    response_model=SSORoleMapRead,
    dependencies=[Depends(require(Permission.ROLE_WRITE)), Depends(verify_csrf)],
    summary="Replace the group-to-role mapping (FR-AUTH-04)",
)
async def put_sso_role_map(
    payload: SSORoleMapWrite, sso: SSOServiceDep, principal: PrincipalDep
) -> SSORoleMapRead:
    """The whole mapping at once, not one row at a time.

    It is read as a set on every sign-in, and a partial update would leave a window in
    which somebody signs in against half of it. Replacing it is also what makes the
    audit record legible: one entry holding what the mapping became.
    """
    mappings = await sso.set_role_map(
        [m.model_dump(mode="json") for m in payload.mappings],
        actor_id=principal.id,
        actor_username=principal.username,
    )
    return SSORoleMapRead(
        mappings=[SSORoleMapping(group=m.group, role=m.role) for m in mappings],
        mappable_roles=sorted(MAPPABLE_ROLES, key=lambda role: role.value),
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
        formatted_secret=enrolment.formatted_secret,
        provisioning_uri=enrolment.provisioning_uri,
        qr_svg=enrolment.qr_svg,
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


@router.get(
    "/mfa",
    response_model=MFAStatusResponse,
    summary="Whether MFA is on, and how much recovery is left (FR-AUTH-03)",
)
async def mfa_status(auth: AuthServiceDep, user: CurrentUserDep) -> MFAStatusResponse:
    """Recovery codes remaining is the part worth surfacing.

    They are single-use and can never be redisplayed — only reissued by turning the
    factor off and on. Nought left is a lockout waiting for a lost phone, and until
    now the only way to discover the number was to reach it.
    """
    return MFAStatusResponse(
        enabled=user.mfa_enabled,
        recovery_codes_left=await auth.recovery_codes_left(user),
    )


@router.delete(
    "/mfa",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(verify_csrf)],
    summary="Disable MFA for your own account, re-proving both factors",
)
async def disable_mfa(
    payload: MFADisableRequest,
    auth: AuthServiceDep,
    principal: PrincipalDep,
    user: CurrentUserDep,
) -> None:
    """Takes a password and a code, which a session alone used to stand in for.

    Removing the second factor from a borrowed unlocked browser was one click, and it
    is the one change that weakens every future sign-in on the account.
    """
    await auth.disable_mfa(user, principal, password=payload.password, code=payload.code)


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
