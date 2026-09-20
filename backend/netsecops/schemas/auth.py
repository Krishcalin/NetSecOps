"""Request/response models for authentication (SEC-04).

FR-CRED-03's principle applies throughout: secret material is write-only. No response
model here contains a password, TOTP secret or token hash.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from netsecops.core.rbac import Permission, Role


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=150)
    password: str = Field(min_length=1, max_length=256)


class MFAVerifyRequest(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=32, description="TOTP code or recovery code")


class TokenResponse(BaseModel):
    """Tokens are also set as HttpOnly cookies (FR-AUTH-02).

    The body carries expiry metadata so the SPA can schedule a refresh, but never the
    refresh token itself — that lives only in the cookie, out of reach of JavaScript.
    """

    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - scheme label
    access_token: str
    expires_at: datetime
    refresh_expires_at: datetime
    mfa_required: Literal[False] = False


class MFAChallengeResponse(BaseModel):
    mfa_required: Literal[True] = True
    mfa_token: str
    expires_at: datetime


class MFAEnrolmentResponse(BaseModel):
    secret: str = Field(description="Base32 TOTP secret — shown once, at enrolment")
    provisioning_uri: str = Field(description="otpauth:// URI for authenticator apps")
    recovery_codes: list[str] = Field(description="Single-use codes — shown once")


class MFAConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class RoleInfo(BaseModel):
    role: Role
    description: str
    permissions: list[Permission]


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: EmailStr
    full_name: str | None = None
    is_active: bool
    is_service_account: bool
    mfa_enabled: bool
    must_change_password: bool
    roles: list[Role] = Field(default_factory=list)
    #: The Device Groups *assigned* to this user (FR-AUTH-05) — what `PUT
    #: /users/{id}/scope` last wrote, not necessarily what is in force. An unrestricted
    #: role ignores the assignment, so read this beside `roles`; empty on a group-scoped
    #: role means they see nothing, because the scope filter fails closed.
    #:
    #: ``/auth/me`` is the exception and reports the scope actually in force, with
    #: `unrestricted_scope` beside it to say which of the two an empty list means.
    #:
    #: Present at all because `PUT /users/{id}/scope` wrote something no endpoint
    #: returned: an administrator could set a scope and had no way to read back what a
    #: user's scope currently was, which makes it effectively a write-only setting.
    device_group_ids: list[uuid.UUID] = Field(default_factory=list)
    last_login_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class CurrentUserResponse(UserRead):
    """``/auth/me`` — adds the effective permission set so the SPA can gate its UI."""

    permissions: list[Permission] = Field(default_factory=list)
    unrestricted_scope: bool = True


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=150, pattern=r"^[a-zA-Z0-9._-]+$")
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    full_name: str | None = Field(default=None, max_length=255)
    roles: list[Role] = Field(default_factory=list)
    must_change_password: bool = True


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = Field(default=None, max_length=255)
    is_active: bool | None = None


class UserRolesUpdate(BaseModel):
    roles: list[Role]


class UserScopeUpdate(BaseModel):
    device_group_ids: list[uuid.UUID] = Field(default_factory=list)


class PasswordResetRequest(BaseModel):
    new_password: str = Field(min_length=12, max_length=256)
    must_change_password: bool = True


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    scopes: list[Permission] = Field(min_length=1)
    expires_at: datetime | None = None
    owner_id: uuid.UUID | None = Field(
        default=None, description="Defaults to the calling user when omitted"
    )


class ApiTokenRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    prefix: str
    scopes: list[str]
    owner_id: uuid.UUID
    expires_at: datetime | None
    revoked_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime


class ApiTokenCreatedResponse(ApiTokenRead):
    """FR-AUTH-07 — the plaintext token is returned exactly once, at creation."""

    token: str = Field(description="Store this now; it cannot be retrieved again")


class PaginatedUsers(BaseModel):
    data: list[UserRead]
    meta: dict[str, int]
