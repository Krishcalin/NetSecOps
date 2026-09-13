"""User, role and API-token administration (FR-AUTH-05, FR-AUTH-07, FR-AUTH-08)."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ConflictError, NotFoundError, PermissionDeniedError
from netsecops.core.rbac import Permission, Principal, Role, permissions_for_roles
from netsecops.core.security import (
    generate_api_token,
    hash_password,
    validate_password_policy,
)
from netsecops.db.models.audit import AuditAction, AuditOutcome
from netsecops.db.models.user import ApiToken, User, UserDeviceGroupScope, UserRole
from netsecops.services.audit import AuditService


@dataclass(frozen=True, slots=True)
class IssuedApiToken:
    token: ApiToken
    #: Shown exactly once, never retrievable afterwards (mirrors FR-CRED-03).
    plaintext: str


class UserService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.audit = AuditService(session)

    # ─────────────────────────────── reads ──────────────────────────────

    async def get(self, user_id: uuid.UUID) -> User:
        user = (
            await self.session.execute(select(User).where(User.id == user_id))
        ).scalar_one_or_none()
        if user is None:
            raise NotFoundError("User not found.")
        return user

    async def get_by_username(self, username: str) -> User | None:
        return (
            await self.session.execute(select(User).where(User.username == username))
        ).scalar_one_or_none()

    async def list(
        self,
        *,
        search: str | None = None,
        role: Role | None = None,
        is_active: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[Sequence[User], int]:
        stmt = select(User)
        count_stmt = select(func.count()).select_from(User)

        if search:
            pattern = f"%{search}%"
            condition = or_(
                User.username.ilike(pattern),
                User.email.ilike(pattern),
                User.full_name.ilike(pattern),
            )
            stmt = stmt.where(condition)
            count_stmt = count_stmt.where(condition)

        if is_active is not None:
            stmt = stmt.where(User.is_active == is_active)
            count_stmt = count_stmt.where(User.is_active == is_active)

        if role is not None:
            # Explicit onclause: user_roles has two foreign keys to users
            # (user_id and granted_by_id), so the join is otherwise ambiguous.
            onclause = UserRole.user_id == User.id
            stmt = stmt.join(UserRole, onclause).where(UserRole.role == role.value)
            count_stmt = count_stmt.join(UserRole, onclause).where(UserRole.role == role.value)

        total = int((await self.session.execute(count_stmt)).scalar_one())
        rows = (
            (await self.session.execute(stmt.order_by(User.username).limit(limit).offset(offset)))
            .scalars()
            .all()
        )
        return rows, total

    # ─────────────────────────────── writes ─────────────────────────────

    async def create(
        self,
        *,
        username: str,
        email: str,
        password: str,
        full_name: str | None = None,
        roles: set[Role] | None = None,
        actor: Principal | None = None,
        must_change_password: bool = True,
        is_service_account: bool = False,
    ) -> User:
        validate_password_policy(password)
        await self._assert_unique(username, email)

        user = User(
            username=username,
            email=email,
            full_name=full_name,
            password_hash=hash_password(password),
            password_changed_at=datetime.now(UTC),
            must_change_password=must_change_password,
            is_service_account=is_service_account,
        )
        self.session.add(user)
        await self.session.flush()

        for role in roles or set():
            self.session.add(
                UserRole(
                    user_id=user.id, role=role.value, granted_by_id=actor.id if actor else None
                )
            )
        await self.session.flush()
        await self.session.refresh(user)

        await self.audit.record(
            AuditAction.USER_CREATED,
            actor_id=actor.id if actor else None,
            actor_username=actor.username if actor else "system",
            object_type="user",
            object_id=user.id,
            details={
                "username": username,
                "email": email,
                "roles": sorted(r.value for r in (roles or set())),
            },
        )
        return user

    async def update(
        self,
        user: User,
        *,
        actor: Principal,
        email: str | None = None,
        full_name: str | None = None,
        is_active: bool | None = None,
    ) -> User:
        changes: dict[str, object] = {}

        if email is not None and email != user.email:
            await self._assert_unique(None, email, exclude_id=user.id)
            changes["email"] = {"from": user.email, "to": email}
            user.email = email

        if full_name is not None and full_name != user.full_name:
            changes["full_name"] = {"from": user.full_name, "to": full_name}
            user.full_name = full_name

        if is_active is not None and is_active != user.is_active:
            if not is_active and user.id == actor.id:
                raise ConflictError("You cannot deactivate your own account.")
            if not is_active:
                await self._assert_not_last_super_admin(user)
            changes["is_active"] = {"from": user.is_active, "to": is_active}
            user.is_active = is_active

        if changes:
            await self.audit.record(
                AuditAction.USER_UPDATED,
                actor_id=actor.id,
                actor_username=actor.username,
                object_type="user",
                object_id=user.id,
                details={"changes": changes},
            )
            # `updated_at` is server-generated via onupdate, so the flush inside the
            # audit write expires it. Refresh now, while we are still in async context;
            # otherwise serialising the response triggers lazy IO and MissingGreenlet.
            await self.session.flush()
            await self.session.refresh(user)
        return user

    async def delete(self, user: User, *, actor: Principal) -> None:
        if user.id == actor.id:
            raise ConflictError("You cannot delete your own account.")
        await self._assert_not_last_super_admin(user)

        username = user.username
        await self.session.delete(user)
        await self.session.flush()

        await self.audit.record(
            AuditAction.USER_DELETED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="user",
            object_id=user.id,
            details={"username": username},
        )

    # ──────────────────────────────── roles ─────────────────────────────

    async def set_roles(self, user: User, roles: set[Role], *, actor: Principal) -> User:
        """Replace a user's roles, auditing each grant and revoke separately."""
        current = user.role_set
        granted = roles - current
        revoked = current - roles

        if Role.SUPER_ADMIN in revoked:
            await self._assert_not_last_super_admin(user)

        for role in revoked:
            for row in [r for r in user.roles if r.role == role.value]:
                await self.session.delete(row)
            await self.audit.record(
                AuditAction.ROLE_REVOKED,
                actor_id=actor.id,
                actor_username=actor.username,
                object_type="user",
                object_id=user.id,
                details={"role": role.value},
            )

        for role in granted:
            self.session.add(UserRole(user_id=user.id, role=role.value, granted_by_id=actor.id))
            await self.audit.record(
                AuditAction.ROLE_GRANTED,
                actor_id=actor.id,
                actor_username=actor.username,
                object_type="user",
                object_id=user.id,
                details={"role": role.value},
            )

        await self.session.flush()
        await self.session.refresh(user)
        return user

    async def set_group_scopes(
        self, user: User, group_ids: set[uuid.UUID], *, actor: Principal
    ) -> User:
        """Assign the Device Groups a group-scoped role may see (FR-AUTH-05)."""
        existing = {s.device_group_id for s in user.group_scopes}

        for row in [s for s in user.group_scopes if s.device_group_id not in group_ids]:
            await self.session.delete(row)
        for group_id in group_ids - existing:
            self.session.add(UserDeviceGroupScope(user_id=user.id, device_group_id=group_id))

        await self.session.flush()
        await self.session.refresh(user)

        await self.audit.record(
            AuditAction.SCOPE_CHANGED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="user",
            object_id=user.id,
            details={"device_group_ids": sorted(str(g) for g in group_ids)},
        )
        return user

    # ────────────────────────────── API tokens ──────────────────────────

    async def create_api_token(
        self,
        *,
        name: str,
        owner: User,
        scopes: set[Permission],
        expires_at: datetime | None,
        actor: Principal,
    ) -> IssuedApiToken:
        """Mint a scoped API token (FR-AUTH-07).

        A token can never grant more than its owner holds — otherwise a token becomes a
        privilege-escalation path around RBAC.
        """
        owner_permissions = permissions_for_roles(owner.role_set)
        if excess := scopes - set(owner_permissions):
            raise PermissionDeniedError(
                "Token scopes exceed the owner's permissions.",
                excess_scopes=sorted(p.value for p in excess),
            )

        plaintext, prefix, token_hash = generate_api_token()
        token = ApiToken(
            org_id=owner.org_id,
            name=name,
            prefix=prefix,
            token_hash=token_hash,
            owner_id=owner.id,
            scopes=sorted(p.value for p in scopes),
            expires_at=expires_at,
            created_by_id=actor.id,
        )
        self.session.add(token)
        await self.session.flush()

        await self.audit.record(
            AuditAction.API_TOKEN_CREATED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="api_token",
            object_id=token.id,
            details={
                "name": name,
                "owner": owner.username,
                "scopes": token.scopes,
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
        )
        return IssuedApiToken(token=token, plaintext=plaintext)

    async def revoke_api_token(self, token_id: uuid.UUID, *, actor: Principal) -> ApiToken:
        token = (
            await self.session.execute(select(ApiToken).where(ApiToken.id == token_id))
        ).scalar_one_or_none()
        if token is None:
            raise NotFoundError("API token not found.")

        if token.owner_id != actor.id and not actor.is_super_admin:
            raise PermissionDeniedError("You may only revoke your own API tokens.")

        if token.revoked_at is None:
            token.revoked_at = datetime.now(UTC)

        await self.audit.record(
            AuditAction.API_TOKEN_REVOKED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="api_token",
            object_id=token.id,
            details={"name": token.name},
        )
        return token

    async def list_api_tokens(self, *, owner_id: uuid.UUID | None = None) -> Sequence[ApiToken]:
        stmt = select(ApiToken).order_by(ApiToken.created_at.desc())
        if owner_id is not None:
            stmt = stmt.where(ApiToken.owner_id == owner_id)
        return (await self.session.execute(stmt)).scalars().all()

    # ─────────────────────────────── guards ─────────────────────────────

    async def _assert_unique(
        self, username: str | None, email: str | None, *, exclude_id: uuid.UUID | None = None
    ) -> None:
        conditions = []
        if username:
            conditions.append(User.username == username)
        if email:
            conditions.append(User.email == email)
        if not conditions:
            return

        stmt = select(User).where(or_(*conditions))
        if exclude_id is not None:
            stmt = stmt.where(User.id != exclude_id)

        if (await self.session.execute(stmt)).scalar_one_or_none() is not None:
            raise ConflictError("A user with that username or email already exists.")

    async def _assert_not_last_super_admin(self, user: User) -> None:
        """Refuse changes that would leave the platform with no Super Admin."""
        if Role.SUPER_ADMIN not in user.role_set:
            return

        remaining = int(
            (
                await self.session.execute(
                    select(func.count())
                    .select_from(UserRole)
                    .join(User, User.id == UserRole.user_id)
                    .where(
                        UserRole.role == Role.SUPER_ADMIN.value,
                        UserRole.user_id != user.id,
                        User.is_active.is_(True),
                    )
                )
            ).scalar_one()
        )
        if remaining == 0:
            await self.audit.record(
                AuditAction.USER_UPDATED,
                outcome=AuditOutcome.DENIED,
                object_type="user",
                object_id=user.id,
                details={"reason": "would_remove_last_super_admin"},
            )
            raise ConflictError("At least one active Super Admin must remain.")
