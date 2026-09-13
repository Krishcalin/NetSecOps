"""User, role-assignment and API-token administration endpoints."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from netsecops.api.deps import (
    AuthServiceDep,
    PrincipalDep,
    UserServiceDep,
    require,
    require_super_admin,
    verify_csrf,
)
from netsecops.core.rbac import Permission, Role
from netsecops.db.models import User
from netsecops.schemas.auth import (
    ApiTokenCreate,
    ApiTokenCreatedResponse,
    ApiTokenRead,
    PaginatedUsers,
    PasswordResetRequest,
    UserCreate,
    UserRead,
    UserRolesUpdate,
    UserScopeUpdate,
    UserUpdate,
)

router = APIRouter(tags=["users"])


def _to_read(user: User) -> UserRead:
    return UserRead(
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
    )


# ────────────────────────────────── users ───────────────────────────────────


@router.get(
    "/users",
    response_model=PaginatedUsers,
    dependencies=[Depends(require(Permission.USER_READ))],
    summary="List users",
)
async def list_users(
    users: UserServiceDep,
    search: str | None = None,
    role: Role | None = None,
    is_active: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PaginatedUsers:
    rows, total = await users.list(
        search=search, role=role, is_active=is_active, limit=limit, offset=offset
    )
    return PaginatedUsers(
        data=[_to_read(u) for u in rows],
        meta={"total": total, "limit": limit, "offset": offset},
    )


@router.post(
    "/users",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.USER_WRITE)), Depends(verify_csrf)],
    summary="Create a user",
)
async def create_user(
    payload: UserCreate, users: UserServiceDep, principal: PrincipalDep
) -> UserRead:
    user = await users.create(
        username=payload.username,
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
        roles=set(payload.roles),
        actor=principal,
        must_change_password=payload.must_change_password,
    )
    return _to_read(user)


@router.get(
    "/users/{user_id}",
    response_model=UserRead,
    dependencies=[Depends(require(Permission.USER_READ))],
    summary="Fetch one user",
)
async def get_user(user_id: uuid.UUID, users: UserServiceDep) -> UserRead:
    return _to_read(await users.get(user_id))


@router.patch(
    "/users/{user_id}",
    response_model=UserRead,
    dependencies=[Depends(require(Permission.USER_WRITE)), Depends(verify_csrf)],
    summary="Update a user",
)
async def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    users: UserServiceDep,
    principal: PrincipalDep,
) -> UserRead:
    user = await users.get(user_id)
    updated = await users.update(
        user,
        actor=principal,
        email=payload.email,
        full_name=payload.full_name,
        is_active=payload.is_active,
    )
    return _to_read(updated)


@router.delete(
    "/users/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_super_admin), Depends(verify_csrf)],
    summary="Delete a user (Super Admin only)",
)
async def delete_user(user_id: uuid.UUID, users: UserServiceDep, principal: PrincipalDep) -> None:
    await users.delete(await users.get(user_id), actor=principal)


@router.put(
    "/users/{user_id}/roles",
    response_model=UserRead,
    dependencies=[Depends(require_super_admin), Depends(verify_csrf)],
    summary="Replace a user's roles (Super Admin only)",
)
async def set_roles(
    user_id: uuid.UUID,
    payload: UserRolesUpdate,
    users: UserServiceDep,
    principal: PrincipalDep,
) -> UserRead:
    user = await users.get(user_id)
    return _to_read(await users.set_roles(user, set(payload.roles), actor=principal))


@router.put(
    "/users/{user_id}/scope",
    response_model=UserRead,
    dependencies=[Depends(require_super_admin), Depends(verify_csrf)],
    summary="Set the Device Groups a group-scoped user may see (FR-AUTH-05)",
)
async def set_scope(
    user_id: uuid.UUID,
    payload: UserScopeUpdate,
    users: UserServiceDep,
    principal: PrincipalDep,
) -> UserRead:
    user = await users.get(user_id)
    return _to_read(
        await users.set_group_scopes(user, set(payload.device_group_ids), actor=principal)
    )


@router.post(
    "/users/{user_id}/password",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_super_admin), Depends(verify_csrf)],
    summary="Reset another user's password (Super Admin only)",
)
async def reset_password(
    user_id: uuid.UUID,
    payload: PasswordResetRequest,
    users: UserServiceDep,
    auth: AuthServiceDep,
    principal: PrincipalDep,
) -> None:
    user = await users.get(user_id)
    await auth.set_password(user, payload.new_password, actor=principal, reason="reset")
    user.must_change_password = payload.must_change_password


# ──────────────────────────────── API tokens ────────────────────────────────


@router.get(
    "/api-tokens",
    response_model=list[ApiTokenRead],
    dependencies=[Depends(require(Permission.API_TOKEN_READ))],
    summary="List API tokens (FR-AUTH-07)",
)
async def list_api_tokens(
    users: UserServiceDep,
    principal: PrincipalDep,
    mine_only: bool = True,
) -> list[ApiTokenRead]:
    owner_id = principal.id if (mine_only or not principal.is_super_admin) else None
    return [ApiTokenRead.model_validate(t) for t in await users.list_api_tokens(owner_id=owner_id)]


@router.post(
    "/api-tokens",
    response_model=ApiTokenCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.API_TOKEN_WRITE)), Depends(verify_csrf)],
    summary="Create a scoped API token — the plaintext is returned only once",
)
async def create_api_token(
    payload: ApiTokenCreate,
    users: UserServiceDep,
    principal: PrincipalDep,
) -> ApiTokenCreatedResponse:
    from netsecops.core.errors import PermissionDeniedError

    owner_id = payload.owner_id or principal.id
    if owner_id != principal.id and not principal.is_super_admin:
        raise PermissionDeniedError("Only a Super Admin may issue tokens for another user.")

    issued = await users.create_api_token(
        name=payload.name,
        owner=await users.get(owner_id),
        scopes=set(payload.scopes),
        expires_at=payload.expires_at,
        actor=principal,
    )
    return ApiTokenCreatedResponse(
        **ApiTokenRead.model_validate(issued.token).model_dump(),
        token=issued.plaintext,
    )


@router.delete(
    "/api-tokens/{token_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.API_TOKEN_WRITE)), Depends(verify_csrf)],
    summary="Revoke an API token",
)
async def revoke_api_token(
    token_id: uuid.UUID, users: UserServiceDep, principal: PrincipalDep
) -> None:
    await users.revoke_api_token(token_id, actor=principal)
