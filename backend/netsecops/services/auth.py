"""Authentication service (FR-AUTH-01 … FR-AUTH-07).

Login is deliberately uniform in both its error messages and its work: an unknown
username still pays the cost of an Argon2 verification against a dummy hash, so response
timing cannot be used to enumerate accounts (SEC-05).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.config import Settings, get_settings
from netsecops.core.crypto import SecretVault, build_vault
from netsecops.core.errors import (
    AccountLockedError,
    AuthenticationError,
    ConflictError,
    NotFoundError,
    PasswordPolicyError,
    PermissionDeniedError,
)
from netsecops.core.logging import get_logger
from netsecops.core.rbac import GROUP_SCOPED_ROLES, Permission, Principal, Role, Scope
from netsecops.core.security import (
    TokenType,
    create_access_token,
    create_mfa_pending_token,
    create_refresh_token,
    decode_token,
    generate_mfa_secret,
    generate_recovery_codes,
    hash_password,
    hash_token,
    mfa_provisioning_uri,
    needs_rehash,
    validate_password_policy,
    verify_password,
    verify_totp,
)
from netsecops.db.models.audit import AuditAction, AuditOutcome
from netsecops.db.models.user import (
    ApiToken,
    LoginAttempt,
    MFASecret,
    PasswordHistory,
    RefreshToken,
    User,
)
from netsecops.services.audit import AuditService

log = get_logger(__name__)

#: A real Argon2id hash of a random value. Verified against when the username does not
#: exist, so failed lookups cost the same as failed passwords (timing-oracle defence).
_DUMMY_HASH = hash_password("not-a-real-password-" + uuid.uuid4().hex)


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_at: datetime
    refresh_expires_at: datetime
    refresh_jti: str


@dataclass(frozen=True, slots=True)
class MFAChallenge:
    """Password accepted; a TOTP code is still required (FR-AUTH-03)."""

    mfa_token: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class MFAEnrolment:
    secret: str
    provisioning_uri: str
    recovery_codes: list[str]


LoginResult = TokenPair | MFAChallenge


class AuthService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings | None = None,
        vault: SecretVault | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self._vault = vault
        self.audit = AuditService(session)

    @property
    def vault(self) -> SecretVault:
        if self._vault is None:
            self._vault = build_vault(self.settings)
        return self._vault

    # ───────────────────────────── login ────────────────────────────────

    async def authenticate(
        self,
        username: str,
        password: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> LoginResult:
        user = await self._get_user_by_username(username)

        if user is None:
            verify_password(password, _DUMMY_HASH)  # equalise timing
            await self._record_attempt(
                username, None, False, "unknown_user", ip_address, user_agent
            )
            await self.audit.record(
                AuditAction.LOGIN_FAILURE,
                outcome=AuditOutcome.FAILURE,
                actor_username=username,
                details={"reason": "unknown_user"},
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise AuthenticationError("Invalid username or password.")

        if user.is_locked:
            await self._record_attempt(username, user.id, False, "locked", ip_address, user_agent)
            await self.audit.record(
                AuditAction.LOGIN_LOCKED,
                outcome=AuditOutcome.DENIED,
                actor_id=user.id,
                actor_username=user.username,
                details={
                    "locked_until": user.locked_until.isoformat() if user.locked_until else None
                },
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise AccountLockedError(
                "Account is temporarily locked due to repeated failed sign-in attempts."
            )

        if not user.is_active:
            await self._record_attempt(username, user.id, False, "inactive", ip_address, user_agent)
            await self.audit.record(
                AuditAction.LOGIN_FAILURE,
                outcome=AuditOutcome.DENIED,
                actor_id=user.id,
                actor_username=user.username,
                details={"reason": "inactive"},
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise AuthenticationError("Invalid username or password.")

        if user.is_service_account:
            # Service accounts authenticate with API tokens only (FR-AUTH-07).
            await self._record_attempt(
                username, user.id, False, "service_account", ip_address, user_agent
            )
            raise AuthenticationError("Invalid username or password.")

        if not verify_password(password, user.password_hash):
            await self._register_failure(user, ip_address, user_agent)
            raise AuthenticationError("Invalid username or password.")

        # Opportunistically upgrade hashes written under older Argon2 parameters.
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)

        if user.mfa_enabled:
            await self._record_attempt(
                username, user.id, True, "password_ok_mfa_pending", ip_address, user_agent
            )
            token, _, expires_at = create_mfa_pending_token(str(user.id), settings=self.settings)
            return MFAChallenge(mfa_token=token, expires_at=expires_at)

        return await self._complete_login(user, ip_address=ip_address, user_agent=user_agent)

    async def complete_mfa(
        self,
        mfa_token: str,
        code: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> TokenPair:
        claims = decode_token(
            mfa_token, expected_type=TokenType.MFA_PENDING, settings=self.settings
        )
        user = await self._get_user_by_id(uuid.UUID(claims["sub"]))
        if user is None or not user.is_active:
            raise AuthenticationError("Invalid username or password.")

        secret_row = await self._mfa_secret_for(user)

        if secret_row is None or secret_row.confirmed_at is None:
            raise AuthenticationError("MFA is not configured for this account.")

        secret = self.vault.open(secret_row.encrypted_secret, aad=str(user.id)).decode("utf-8")

        if not verify_totp(secret, code, self.settings):
            if not await self._consume_recovery_code(secret_row, user, code):
                await self._register_failure(user, ip_address, user_agent, reason="bad_totp")
                await self.audit.record(
                    AuditAction.MFA_CHALLENGE_FAILED,
                    outcome=AuditOutcome.FAILURE,
                    actor_id=user.id,
                    actor_username=user.username,
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
                raise AuthenticationError("Invalid verification code.")
        else:
            # Reject replay of a code that is still inside its validity window.
            step = int(datetime.now(UTC).timestamp()) // self.settings.mfa_totp_period_seconds
            if secret_row.last_used_step is not None and step <= secret_row.last_used_step:
                raise AuthenticationError("This verification code has already been used.")
            secret_row.last_used_step = step

        return await self._complete_login(user, ip_address=ip_address, user_agent=user_agent)

    async def _complete_login(
        self, user: User, *, ip_address: str | None, user_agent: str | None
    ) -> TokenPair:
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = datetime.now(UTC)
        user.last_login_ip = ip_address

        await self._record_attempt(user.username, user.id, True, None, ip_address, user_agent)
        await self.audit.record(
            AuditAction.LOGIN_SUCCESS,
            actor_id=user.id,
            actor_username=user.username,
            details={"mfa": user.mfa_enabled},
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return await self._issue_tokens(user, ip_address=ip_address, user_agent=user_agent)

    async def _issue_tokens(
        self, user: User, *, ip_address: str | None, user_agent: str | None
    ) -> TokenPair:
        roles = sorted(r.value for r in user.role_set)
        access, _, access_exp = create_access_token(
            str(user.id), settings=self.settings, username=user.username, roles=roles
        )
        refresh, refresh_jti, refresh_exp = create_refresh_token(
            str(user.id), settings=self.settings
        )

        self.session.add(
            RefreshToken(
                org_id=user.org_id,
                user_id=user.id,
                jti=refresh_jti,
                token_hash=hash_token(refresh),
                expires_at=refresh_exp,
                ip_address=ip_address,
                user_agent=(user_agent or "")[:512] or None,
            )
        )
        await self.session.flush()

        return TokenPair(
            access_token=access,
            refresh_token=refresh,
            access_expires_at=access_exp,
            refresh_expires_at=refresh_exp,
            refresh_jti=refresh_jti,
        )

    # ────────────────────────── refresh rotation ────────────────────────

    async def refresh(
        self,
        refresh_token: str,
        *,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> TokenPair:
        """Rotate a refresh token (FR-AUTH-02).

        Presenting a token that was already rotated means someone is replaying a stolen
        one. The whole family is revoked and the event audited, rather than quietly
        issuing a new pair.
        """
        claims = decode_token(
            refresh_token, expected_type=TokenType.REFRESH, settings=self.settings
        )
        jti = claims["jti"]

        stored = (
            await self.session.execute(select(RefreshToken).where(RefreshToken.jti == jti))
        ).scalar_one_or_none()

        if stored is None:
            raise AuthenticationError("Refresh token is not recognised.")

        if stored.revoked_at is not None:
            await self._revoke_all_for_user(stored.user_id, reason="reuse_detected")
            await self.audit.record(
                AuditAction.TOKEN_REUSE_DETECTED,
                outcome=AuditOutcome.DENIED,
                actor_id=stored.user_id,
                details={"jti": jti, "replaced_by": stored.replaced_by_jti},
                ip_address=ip_address,
                user_agent=user_agent,
            )
            raise AuthenticationError("Refresh token has already been used. All sessions revoked.")

        if not stored.is_active:
            raise AuthenticationError("Refresh token has expired.")

        user = await self._get_user_by_id(stored.user_id)
        if user is None or not user.is_active:
            raise AuthenticationError("Account is no longer active.")

        pair = await self._issue_tokens(user, ip_address=ip_address, user_agent=user_agent)

        stored.revoked_at = datetime.now(UTC)
        stored.revoked_reason = "rotated"
        stored.replaced_by_jti = pair.refresh_jti

        await self.audit.record(
            AuditAction.TOKEN_REFRESH,
            actor_id=user.id,
            actor_username=user.username,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return pair

    async def logout(
        self,
        refresh_token: str | None,
        principal: Principal | None = None,
        *,
        ip_address: str | None = None,
        all_sessions: bool = False,
    ) -> None:
        if refresh_token:
            try:
                claims = decode_token(
                    refresh_token, expected_type=TokenType.REFRESH, settings=self.settings
                )
            except AuthenticationError:
                claims = {}
            if jti := claims.get("jti"):
                stored = (
                    await self.session.execute(select(RefreshToken).where(RefreshToken.jti == jti))
                ).scalar_one_or_none()
                if stored is not None and stored.revoked_at is None:
                    stored.revoked_at = datetime.now(UTC)
                    stored.revoked_reason = "logout"

        if all_sessions and principal is not None:
            await self._revoke_all_for_user(principal.id, reason="logout_all")

        if principal is not None:
            await self.audit.record(
                AuditAction.LOGOUT,
                actor_id=principal.id,
                actor_username=principal.username,
                details={"all_sessions": all_sessions},
                ip_address=ip_address,
            )

    async def _revoke_all_for_user(self, user_id: uuid.UUID, *, reason: str) -> None:
        rows = (
            (
                await self.session.execute(
                    select(RefreshToken).where(
                        RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None)
                    )
                )
            )
            .scalars()
            .all()
        )
        now = datetime.now(UTC)
        for row in rows:
            row.revoked_at = now
            row.revoked_reason = reason

    # ──────────────────────────────── MFA ───────────────────────────────

    async def _mfa_secret_for(self, user: User) -> MFASecret | None:
        """Load the MFA row by query.

        ``user.mfa_secret`` is populated when the User is first loaded, so it goes
        stale the moment enrolment changes within the same session — and a stale None
        is indistinguishable from "never enrolled".
        """
        return (
            await self.session.execute(select(MFASecret).where(MFASecret.user_id == user.id))
        ).scalar_one_or_none()

    async def begin_mfa_enrolment(self, user: User) -> MFAEnrolment:
        if user.mfa_enabled:
            raise ConflictError("MFA is already enabled for this account.")

        secret = generate_mfa_secret()
        recovery_codes = generate_recovery_codes()

        sealed_secret = self.vault.seal(secret, aad=str(user.id))
        sealed_codes = self.vault.seal(
            json.dumps([hash_token(c) for c in recovery_codes]), aad=str(user.id)
        )

        # Replace an abandoned, unconfirmed enrolment. Query rather than trusting the
        # relationship, which may be stale within this session.
        if (existing := await self._mfa_secret_for(user)) is not None:
            await self.session.delete(existing)
            await self.session.flush()

        self.session.add(
            MFASecret(
                org_id=user.org_id,
                user_id=user.id,
                encrypted_secret=sealed_secret,
                encrypted_recovery_codes=sealed_codes,
            )
        )
        await self.session.flush()

        await self.audit.record(
            AuditAction.MFA_ENROLLED,
            actor_id=user.id,
            actor_username=user.username,
            object_type="user",
            object_id=user.id,
        )
        return MFAEnrolment(
            secret=secret,
            provisioning_uri=mfa_provisioning_uri(secret, user.email, self.settings),
            recovery_codes=recovery_codes,
        )

    async def confirm_mfa_enrolment(self, user: User, code: str) -> None:
        """Enrolment only takes effect once the user proves the authenticator works."""
        secret_row = await self._mfa_secret_for(user)
        if secret_row is None:
            raise NotFoundError("No pending MFA enrolment for this account.")

        secret = self.vault.open(secret_row.encrypted_secret, aad=str(user.id)).decode("utf-8")
        if not verify_totp(secret, code, self.settings):
            raise AuthenticationError("Invalid verification code.")

        secret_row.confirmed_at = datetime.now(UTC)
        user.mfa_enabled = True

        await self.audit.record(
            AuditAction.MFA_CONFIRMED,
            actor_id=user.id,
            actor_username=user.username,
            object_type="user",
            object_id=user.id,
        )

    async def disable_mfa(self, user: User, actor: Principal) -> None:
        if not (actor.id == user.id or actor.is_super_admin):
            raise PermissionDeniedError("Only the account owner or a Super Admin may disable MFA.")

        # Query rather than trusting the relationship: a stale None here would leave
        # an orphaned secret row behind while the account reported MFA as off.
        if (secret_row := await self._mfa_secret_for(user)) is not None:
            await self.session.delete(secret_row)
        user.mfa_enabled = False
        await self.session.flush()

        await self.audit.record(
            AuditAction.MFA_DISABLED,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="user",
            object_id=user.id,
        )

    async def _consume_recovery_code(self, secret_row: MFASecret, user: User, code: str) -> bool:
        """Accept and burn a single-use recovery code."""
        if secret_row.encrypted_recovery_codes is None:
            return False

        stored: list[str] = json.loads(
            self.vault.open(secret_row.encrypted_recovery_codes, aad=str(user.id)).decode("utf-8")
        )
        candidate = hash_token(code.strip())
        if candidate not in stored:
            return False

        stored.remove(candidate)
        secret_row.encrypted_recovery_codes = self.vault.seal(json.dumps(stored), aad=str(user.id))
        return True

    # ────────────────────────── password changes ────────────────────────

    async def change_password(
        self, user: User, current_password: str, new_password: str, *, actor: Principal
    ) -> None:
        if not verify_password(current_password, user.password_hash):
            raise AuthenticationError("Current password is incorrect.")
        await self.set_password(user, new_password, actor=actor, reason="changed")

    async def set_password(
        self, user: User, new_password: str, *, actor: Principal, reason: str = "reset"
    ) -> None:
        validate_password_policy(new_password, self.settings)

        if verify_password(new_password, user.password_hash):
            raise PasswordPolicyError("New password must differ from the current password.")

        history = (
            (
                await self.session.execute(
                    select(PasswordHistory)
                    .where(PasswordHistory.user_id == user.id)
                    .order_by(PasswordHistory.created_at.desc())
                    .limit(self.settings.password_history)
                )
            )
            .scalars()
            .all()
        )
        if any(verify_password(new_password, h.password_hash) for h in history):
            raise PasswordPolicyError(
                f"New password must not match your last {self.settings.password_history} passwords."
            )

        self.session.add(
            PasswordHistory(org_id=user.org_id, user_id=user.id, password_hash=user.password_hash)
        )

        user.password_hash = hash_password(new_password)
        user.password_changed_at = datetime.now(UTC)
        user.must_change_password = False

        # A password change invalidates every existing session.
        await self._revoke_all_for_user(user.id, reason="password_changed")
        await self._trim_password_history(user)

        await self.audit.record(
            AuditAction.PASSWORD_CHANGED if reason == "changed" else AuditAction.PASSWORD_RESET,
            actor_id=actor.id,
            actor_username=actor.username,
            object_type="user",
            object_id=user.id,
        )

    async def _trim_password_history(self, user: User) -> None:
        keep = self.settings.password_history
        rows = (
            (
                await self.session.execute(
                    select(PasswordHistory)
                    .where(PasswordHistory.user_id == user.id)
                    .order_by(PasswordHistory.created_at.desc())
                )
            )
            .scalars()
            .all()
        )
        for stale in rows[keep:]:
            await self.session.delete(stale)

    # ─────────────────────────── API tokens ─────────────────────────────

    async def principal_for_api_token(self, plaintext: str) -> Principal:
        """Resolve a service-account token to a principal (FR-AUTH-07)."""
        token_hash = hash_token(plaintext)
        stored = (
            await self.session.execute(select(ApiToken).where(ApiToken.token_hash == token_hash))
        ).scalar_one_or_none()

        if stored is None or not stored.is_active:
            raise AuthenticationError("API token is invalid or revoked.")

        owner = await self._get_user_by_id(stored.owner_id)
        if owner is None or not owner.is_active:
            raise AuthenticationError("API token owner is not active.")

        stored.last_used_at = datetime.now(UTC)

        scopes = frozenset(Permission(s) for s in stored.scopes if s in set(Permission))
        return Principal(
            id=owner.id,
            username=owner.username,
            roles=owner.role_set or frozenset({Role.API_SERVICE}),
            scope=await self.scope_for_user(owner),
            is_service_account=True,
            token_id=stored.id,
            token_scopes=scopes,
        )

    # ───────────────────────────── helpers ──────────────────────────────

    async def scope_for_user(self, user: User) -> Scope:
        """Resolve object-level visibility for a user (FR-AUTH-05)."""
        roles = user.role_set
        if not roles or not roles.issubset(GROUP_SCOPED_ROLES):
            # Any unrestricted role (Super Admin, Security Analyst) lifts group scoping.
            return Scope.all()
        return Scope(
            unrestricted=False,
            device_group_ids=frozenset(s.device_group_id for s in user.group_scopes),
        )

    async def principal_for_user(self, user: User) -> Principal:
        return Principal(
            id=user.id,
            username=user.username,
            roles=user.role_set,
            scope=await self.scope_for_user(user),
            is_service_account=user.is_service_account,
        )

    async def _get_user_by_username(self, username: str) -> User | None:
        result = await self.session.execute(select(User).where(User.username == username))
        return result.scalar_one_or_none()

    async def _get_user_by_id(self, user_id: uuid.UUID) -> User | None:
        result = await self.session.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def _register_failure(
        self,
        user: User,
        ip_address: str | None,
        user_agent: str | None,
        reason: str = "bad_password",
    ) -> None:
        """Increment the failure counter and lock the account at the threshold (FR-AUTH-06)."""
        user.failed_login_count += 1
        locked = user.failed_login_count >= self.settings.lockout_max_attempts

        if locked:
            user.locked_until = datetime.now(UTC) + timedelta(
                minutes=self.settings.lockout_duration_minutes
            )
            user.failed_login_count = 0

        await self._record_attempt(user.username, user.id, False, reason, ip_address, user_agent)
        await self.audit.record(
            AuditAction.LOGIN_LOCKED if locked else AuditAction.LOGIN_FAILURE,
            outcome=AuditOutcome.DENIED if locked else AuditOutcome.FAILURE,
            actor_id=user.id,
            actor_username=user.username,
            details={"reason": reason, "locked": locked},
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def _record_attempt(
        self,
        username: str,
        user_id: uuid.UUID | None,
        succeeded: bool,
        failure_reason: str | None,
        ip_address: str | None,
        user_agent: str | None,
    ) -> None:
        self.session.add(
            LoginAttempt(
                username=username[:150],
                user_id=user_id,
                succeeded=succeeded,
                failure_reason=failure_reason,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        )
        await self.session.flush()
