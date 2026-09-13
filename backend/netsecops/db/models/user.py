"""Identity tables: users, roles, API tokens, MFA secrets, refresh tokens.

Implements the storage side of FR-AUTH-01 … FR-AUTH-07.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netsecops.core.rbac import Role
from netsecops.db.base import Base, OrgMixin, TimestampMixin, UUIDPrimaryKeyMixin


class User(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(150), nullable=False, unique=True, index=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True, index=True)
    full_name: Mapped[str | None] = mapped_column(String(255))

    #: Argon2id hash (FR-AUTH-01). Never exposed by any API.
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    #: True for the identity behind an API service account (FR-AUTH-07).
    is_service_account: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    # ── Lockout state (FR-AUTH-06) ──────────────────────────────────────────
    failed_login_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_ip: Mapped[str | None] = mapped_column(INET)

    # ── MFA (FR-AUTH-03) ────────────────────────────────────────────────────
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    #: Identity-provider subject when the user signs in via OIDC (FR-AUTH-04, Phase 7).
    external_idp_subject: Mapped[str | None] = mapped_column(String(255), index=True)

    # UserRole has two foreign keys to users (user_id, granted_by_id), so the join
    # column must be named explicitly.
    roles: Mapped[list[UserRole]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
        foreign_keys="UserRole.user_id",
    )
    mfa_secret: Mapped[MFASecret | None] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False, lazy="selectin"
    )
    group_scopes: Mapped[list[UserDeviceGroupScope]] = relationship(
        back_populates="user", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def role_set(self) -> frozenset[Role]:
        return frozenset(Role(r.role) for r in self.roles)

    @property
    def is_locked(self) -> bool:
        from datetime import UTC

        return self.locked_until is not None and self.locked_until > datetime.now(UTC)


class UserRole(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Role assignment. Roles are an enum in code, not rows, so they cannot drift."""

    __tablename__ = "user_roles"
    __table_args__ = (UniqueConstraint("user_id", "role", name="uq_user_roles_user_id_role"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    granted_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    user: Mapped[User] = relationship(back_populates="roles", foreign_keys=[user_id])


class UserDeviceGroupScope(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Object-level scoping for group-scoped roles (FR-AUTH-05)."""

    __tablename__ = "user_device_group_scopes"
    __table_args__ = (
        UniqueConstraint(
            "user_id", "device_group_id", name="uq_user_device_group_scopes_user_group"
        ),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: Deleting a group removes the grants that referenced it, rather than leaving a
    #: scope row pointing at nothing. (The foreign key was deferred until Phase 1,
    #: when device_groups came into existence.)
    device_group_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("device_groups.id", ondelete="CASCADE"),
        nullable=False,
    )

    user: Mapped[User] = relationship(back_populates="group_scopes")


class MFASecret(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """TOTP shared secret, sealed with the credential vault (FR-CRED-02 applies here too)."""

    __tablename__ = "mfa_secrets"

    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    #: Envelope-encrypted base32 TOTP secret. AAD is the owning user id (DATA-01).
    encrypted_secret: Mapped[bytes] = mapped_column(nullable=False)
    #: Envelope-encrypted JSON array of unused single-use recovery codes.
    encrypted_recovery_codes: Mapped[bytes | None] = mapped_column()
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    #: Last accepted TOTP step, to reject replay of a code inside its validity window.
    last_used_step: Mapped[int | None] = mapped_column(Integer)

    user: Mapped[User] = relationship(back_populates="mfa_secret")


class RefreshToken(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Rotating, revocable refresh tokens (FR-AUTH-02).

    Only the SHA-256 of the token is stored. Rotation links each token to the one that
    replaced it, so reuse of an already-rotated token is detectable — the classic signal
    that a refresh token was stolen.
    """

    __tablename__ = "refresh_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    jti: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(String(100))
    replaced_by_jti: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    ip_address: Mapped[str | None] = mapped_column(INET)

    @property
    def is_active(self) -> bool:
        from datetime import UTC

        return self.revoked_at is None and self.expires_at > datetime.now(UTC)


class ApiToken(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Scoped service-account tokens (FR-AUTH-07)."""

    __tablename__ = "api_tokens"

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    #: First few characters of the token, for identification in the UI and fast lookup.
    prefix: Mapped[str] = mapped_column(String(16), nullable=False, unique=True, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: Subset of Permission values this token may exercise.
    scopes: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    owner: Mapped[User] = relationship(foreign_keys=[owner_id], lazy="selectin")

    @property
    def is_active(self) -> bool:
        from datetime import UTC

        if self.revoked_at is not None:
            return False
        return self.expires_at is None or self.expires_at > datetime.now(UTC)


class PasswordHistory(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Previous password hashes, to enforce the no-reuse window (FR-AUTH-01)."""

    __tablename__ = "password_history"
    __table_args__ = (Index("ix_password_history_user_created", "user_id", "created_at"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)


class LoginAttempt(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Every authentication attempt, for lockout accounting and rate limiting (SEC-05).

    ``username`` is recorded as free text rather than a foreign key so attempts against
    non-existent accounts are captured too — those are the interesting ones.
    """

    __tablename__ = "login_attempts"
    __table_args__ = (Index("ix_login_attempts_username_created", "username", "created_at"),)

    username: Mapped[str] = mapped_column(String(150), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    succeeded: Mapped[bool] = mapped_column(Boolean, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(String(100))
    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
