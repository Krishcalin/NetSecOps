"""FastAPI dependencies: authentication, authorization, common request context.

Endpoints declare the *permission* they require via :func:`require`, never a list of
roles — so the authorization matrix stays defined in one place (``core/rbac.py``).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable, Coroutine
from typing import Annotated, Any

from fastapi import Cookie, Depends, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.config import Settings, get_settings
from netsecops.core.crypto import SecretVault, build_vault
from netsecops.core.errors import AuthenticationError, PermissionDeniedError
from netsecops.core.rbac import Permission, Principal
from netsecops.core.security import API_TOKEN_PREFIX, TokenType, decode_token
from netsecops.db.models import User
from netsecops.db.session import get_session
from netsecops.services.audit import AuditService
from netsecops.services.auth import AuthService
from netsecops.services.users import UserService

ACCESS_COOKIE = "netsecops_access"
REFRESH_COOKIE = "netsecops_refresh"
CSRF_COOKIE = "netsecops_csrf"
CSRF_HEADER = "X-CSRF-Token"


async def db_session() -> AsyncIterator[AsyncSession]:
    async for session in get_session():
        yield session


SessionDep = Annotated[AsyncSession, Depends(db_session)]


def settings_dep() -> Settings:
    return get_settings()


SettingsDep = Annotated[Settings, Depends(settings_dep)]


def vault_dep(settings: SettingsDep) -> SecretVault:
    """The credential vault (FR-CRED-02).

    Injected rather than constructed inside services so a test can supply a vault built
    from a throwaway master key, instead of every service reaching for global config.
    """
    return build_vault(settings)


VaultDep = Annotated[SecretVault, Depends(vault_dep)]


def auth_service(session: SessionDep, vault: VaultDep) -> AuthService:
    return AuthService(session, vault=vault)


def user_service(session: SessionDep) -> UserService:
    return UserService(session)


def audit_service(session: SessionDep) -> AuditService:
    return AuditService(session)


AuthServiceDep = Annotated[AuthService, Depends(auth_service)]
UserServiceDep = Annotated[UserService, Depends(user_service)]
AuditServiceDep = Annotated[AuditService, Depends(audit_service)]


def client_ip(request: Request) -> str | None:
    """Client address, honouring a single trusted reverse proxy (deploy/ uses Caddy)."""
    if forwarded := request.headers.get("x-forwarded-for"):
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else None


ClientIPDep = Annotated[str | None, Depends(client_ip)]


async def current_principal(
    request: Request,
    auth: AuthServiceDep,
    users: UserServiceDep,
    access_cookie: Annotated[str | None, Cookie(alias=ACCESS_COOKIE)] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    """Resolve the caller from an access cookie, a bearer JWT, or an API token.

    Cookie first, because the SPA is the primary client (FR-AUTH-02); the Authorization
    header serves service accounts and direct API consumers (FR-AUTH-07, FR-INT-04).
    """
    token: str | None = access_cookie

    if authorization:
        scheme, _, credential = authorization.partition(" ")
        if scheme.lower() == "bearer" and credential:
            token = credential.strip()

    if not token:
        raise AuthenticationError("Not authenticated.")

    # Service-account tokens are opaque and carry a recognisable prefix.
    if token.startswith(API_TOKEN_PREFIX):
        principal = await auth.principal_for_api_token(token)
        request.state.principal = principal
        return principal

    claims = decode_token(token, expected_type=TokenType.ACCESS)
    user = await users.get(uuid.UUID(claims["sub"]))

    if not user.is_active:
        raise AuthenticationError("Account is no longer active.")
    if user.is_locked:
        raise AuthenticationError("Account is locked.")

    principal = await auth.principal_for_user(user)
    request.state.principal = principal
    return principal


PrincipalDep = Annotated[Principal, Depends(current_principal)]


async def current_user_model(principal: PrincipalDep, users: UserServiceDep) -> User:
    """The ORM ``User`` behind the principal, for handlers that need to mutate it."""
    return await users.get(principal.id)


CurrentUserDep = Annotated[User, Depends(current_user_model)]


def require(
    *permissions: Permission,
) -> Callable[[Principal], Coroutine[Any, Any, Principal]]:
    """Dependency factory enforcing that the caller holds *all* given permissions.

    Usage::

        @router.get("/users", dependencies=[Depends(require(Permission.USER_READ))])
    """

    async def _guard(principal: PrincipalDep) -> Principal:
        if not principal.has(*permissions):
            missing = sorted(p.value for p in permissions if p not in principal.permissions)
            raise PermissionDeniedError(
                "You do not have permission to perform this action.",
                required=missing,
            )
        return principal

    return _guard


def require_any(
    *permissions: Permission,
) -> Callable[[Principal], Coroutine[Any, Any, Principal]]:
    """As :func:`require`, but any one of the permissions suffices."""

    async def _guard(principal: PrincipalDep) -> Principal:
        if not principal.has_any(*permissions):
            raise PermissionDeniedError(
                "You do not have permission to perform this action.",
                required_any=sorted(p.value for p in permissions),
            )
        return principal

    return _guard


async def require_super_admin(principal: PrincipalDep) -> Principal:
    if not principal.is_super_admin:
        raise PermissionDeniedError("This action requires the Super Admin role.")
    return principal


def verify_csrf(
    request: Request,
    csrf_cookie: Annotated[str | None, Cookie(alias=CSRF_COOKIE)] = None,
    csrf_header: Annotated[str | None, Header(alias=CSRF_HEADER)] = None,
) -> None:
    """Double-submit CSRF check for cookie-authenticated state changes (SEC-03).

    Skipped when the caller used an Authorization header: that request could not have
    been forged by a browser riding on an ambient cookie.
    """
    if request.method in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        return
    if request.headers.get("authorization"):
        return
    if not request.cookies.get(ACCESS_COOKIE):
        return

    from netsecops.core.security import constant_time_compare

    if not csrf_cookie or not csrf_header or not constant_time_compare(csrf_cookie, csrf_header):
        raise PermissionDeniedError("CSRF token missing or invalid.")


CSRFDep = Annotated[None, Depends(verify_csrf)]
