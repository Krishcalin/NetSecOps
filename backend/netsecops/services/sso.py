"""Single sign-on: turning a verified assertion into a session (FR-AUTH-04).

`core/oidc.py` decides whether the identity provider really said what it appears to have
said. Everything here decides what NetSecOps does about it, and the three rules it
follows were chosen deliberately.

**The provider says who is signing in. It does not say who may.** An assertion for a
subject with no account is refused and audited; no account is created. A directory group
is a statement about employment, and the products that treat one as an authorisation
grant are the reason a mis-scoped group becomes a breach. An administrator decides who
has an account here.

**Roles follow the mapping, and the mapping is an administrator's document.** Once an
account exists, the group claim drives the roles *that the mapping mentions* — that is
the point of having one, and it is what makes leaving a group take effect. Roles the
mapping never mentions are left exactly as they were, so a grant made by hand is not
silently undone by a login. Super Admin cannot be mapped at all: it is the role that can
rewrite the mapping, and a directory group should not be able to reach it.

**Single sign-on replaces the password, not the second factor.** A user with MFA enabled
is challenged for their TOTP after the provider has vouched for them, exactly as after a
correct password. The provider may well have done its own MFA; it may equally be a
single password in a directory nobody has audited, and the assertion does not reliably
distinguish the two.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core import oidc
from netsecops.core.config import Settings, get_settings
from netsecops.core.crypto import SecretVault, build_vault
from netsecops.core.errors import AccountLockedError, AuthenticationError, ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.core.rbac import Role
from netsecops.db.models.audit import AuditAction, AuditOutcome, Setting
from netsecops.db.models.user import OIDCLoginState, User, UserRole
from netsecops.services.audit import AuditService
from netsecops.services.auth import AuthService, LoginResult

log = get_logger(__name__)

#: Where the group-to-role mapping lives. The `settings` table rather than a table of
#: its own: it is a handful of rows of platform policy, which is what FR-ADM-01's
#: key/value store is for, and it gets that surface's audit trail for free.
ROLE_MAP_KEY = "auth.oidc.role_map"

#: Roles a directory group may be mapped to. Super Admin is absent on purpose — see the
#: module docstring — and API Service is absent because it belongs to a token, not a
#: person who signs in.
MAPPABLE_ROLES = frozenset({Role.SECURITY_ANALYST, Role.NETWORK_ENGINEER, Role.AUDITOR})


@dataclass(frozen=True, slots=True)
class RoleMapping:
    group: str
    role: Role


@dataclass(frozen=True, slots=True)
class BeginLogin:
    authorization_url: str
    state: str


def parse_role_map(value: object) -> list[RoleMapping]:
    """Read the stored mapping, discarding entries that cannot be applied.

    Discarding rather than raising, because this is read during a login: one bad entry
    left by an older release must not stop everybody signing in. Each one is logged by
    name, since an entry that is quietly skipped and an entry that grants nothing look
    identical from the outside.
    """
    if not isinstance(value, dict):
        return []
    raw = value.get("mappings")
    if not isinstance(raw, list):
        return []

    mappings: list[RoleMapping] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        group = entry.get("group")
        role_name = entry.get("role")
        if not isinstance(group, str) or not isinstance(role_name, str) or not group.strip():
            continue
        try:
            role = Role(role_name)
        except ValueError:
            log.warning("sso.role_map_unknown_role", group=group, role=role_name)
            continue
        if role not in MAPPABLE_ROLES:
            log.warning("sso.role_map_forbidden_role", group=group, role=role_name)
            continue
        mappings.append(RoleMapping(group=group.strip(), role=role))
    return mappings


def validate_role_map(mappings: list[dict[str, Any]]) -> list[RoleMapping]:
    """Check a mapping an administrator is saving, refusing anything unusable.

    The counterpart to `parse_role_map`: read is forgiving so a login still works, write
    is strict so the thing being stored is one that will.
    """
    seen: set[tuple[str, Role]] = set()
    result: list[RoleMapping] = []

    for index, entry in enumerate(mappings):
        group = str(entry.get("group", "")).strip()
        role_name = str(entry.get("role", "")).strip()

        if not group:
            raise ValidationProblem(f"Mapping {index + 1} has no identity-provider group.")
        if len(group) > 255:
            raise ValidationProblem(f"Mapping {index + 1}: the group name is too long.")

        try:
            role = Role(role_name)
        except ValueError as exc:
            allowed = ", ".join(sorted(r.value for r in MAPPABLE_ROLES))
            raise ValidationProblem(
                f"Mapping {index + 1}: {role_name!r} is not a role. Choose one of {allowed}."
            ) from exc

        if role not in MAPPABLE_ROLES:
            raise ValidationProblem(
                f"Mapping {index + 1}: {role.value!r} cannot be granted by an identity-"
                f"provider group. Super Admin can rewrite this mapping and revoke any "
                f"role, so it is granted here by hand or not at all; api_service "
                f"belongs to a token rather than to somebody who signs in."
            )

        if (group, role) in seen:
            raise ValidationProblem(
                f"Mapping {index + 1}: {group!r} → {role.value} is listed twice."
            )
        seen.add((group, role))
        result.append(RoleMapping(group=group, role=role))

    return result


def safe_redirect(target: str | None) -> str | None:
    """Keep the post-login redirect inside the console.

    The callback sends the browser wherever this says, so an absolute URL here is an
    open redirect wearing a sign-in flow as cover — and one that arrives looking like it
    came from the identity provider. Only a plain absolute path survives; `//evil.test`
    is rejected because a browser reads it as protocol-relative and leaves the site.
    """
    if not target:
        return None
    if not target.startswith("/") or target.startswith("//"):
        return None
    if "\\" in target or "\n" in target or "\r" in target:
        return None
    return target[:512]


class SSOService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        settings: Settings | None = None,
        vault: SecretVault | None = None,
        http: httpx.AsyncClient | None = None,
        auth: AuthService | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self._vault = vault
        self._http = http
        self.audit = AuditService(session)
        self.auth = auth or AuthService(session, settings=self.settings, vault=vault)

    @property
    def vault(self) -> SecretVault:
        if self._vault is None:
            self._vault = build_vault(self.settings)
        return self._vault

    @property
    def enabled(self) -> bool:
        return self.settings.oidc_enabled

    def _require_enabled(self) -> None:
        if not self.enabled:
            # 404 would be more discreet, but the console only offers the button when
            # the unauthenticated status endpoint says SSO is on, so reaching here means
            # a configuration that changed underneath somebody mid-sign-in.
            raise AuthenticationError("Single sign-on is not enabled on this deployment.")

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(follow_redirects=False)
        return self._http

    # ──────────────────────────── the redirect out ───────────────────────

    async def begin(
        self, *, redirect_to: str | None = None, ip_address: str | None = None
    ) -> BeginLogin:
        """Start a sign-in: store what the callback will need, return where to send the browser."""
        self._require_enabled()

        client = await self._client()
        metadata = await oidc.METADATA_CACHE.metadata(self.settings, client=client)

        pkce = oidc.PKCEPair.generate()
        state = secrets.token_urlsafe(32)[:64]
        nonce = secrets.token_urlsafe(24)[:64]

        self.session.add(
            OIDCLoginState(
                state=state,
                # Bound to the state rather than to the row id: the row id is not known
                # until the flush, and binding to `state` means a verifier blob moved
                # onto another row will not open.
                encrypted_verifier=self.vault.seal(pkce.verifier, aad=state),
                nonce=nonce,
                redirect_to=safe_redirect(redirect_to),
                expires_at=datetime.now(UTC)
                + timedelta(seconds=self.settings.oidc_login_timeout_seconds),
                ip_address=ip_address,
            )
        )
        await self.session.flush()

        return BeginLogin(
            authorization_url=oidc.authorization_url(
                metadata,
                self.settings,
                state=state,
                nonce=nonce,
                challenge=pkce.challenge,
            ),
            state=state,
        )

    # ──────────────────────────── the callback back ──────────────────────

    async def complete(
        self,
        *,
        code: str,
        state: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[LoginResult, str | None]:
        """Finish a sign-in, returning the session and where to land."""
        self._require_enabled()

        row = (
            await self.session.execute(select(OIDCLoginState).where(OIDCLoginState.state == state))
        ).scalar_one_or_none()

        if row is None:
            # Either this callback has already been used, or the `state` was not one we
            # issued — which is the case `state` exists to catch.
            await self._deny("unknown_state", ip_address=ip_address, user_agent=user_agent)
            raise AuthenticationError("This sign-in could not be completed. Please try again.")

        expired = row.is_expired
        verifier = self.vault.open(row.encrypted_verifier, aad=row.state).decode("utf-8")
        nonce = row.nonce
        redirect_to = row.redirect_to

        # Single use, before anything can fail: a row left behind after a failure is a
        # second attempt at the same state, which is exactly what must not be possible.
        await self.session.delete(row)
        await self.session.flush()

        if expired:
            await self._deny("expired_state", ip_address=ip_address, user_agent=user_agent)
            raise AuthenticationError("This sign-in took too long. Please try again.")

        client = await self._client()
        metadata = await oidc.METADATA_CACHE.metadata(self.settings, client=client)
        tokens = await oidc.exchange_code(
            metadata, self.settings, code=code, verifier=verifier, client=client
        )
        signing_key = await oidc.METADATA_CACHE.signing_key(
            tokens["id_token"], metadata, self.settings, client=client
        )
        identity = oidc.verify_id_token(
            tokens["id_token"],
            metadata,
            self.settings,
            signing_key=signing_key,
            nonce=nonce,
        )

        user = await self._resolve_user(identity, ip_address=ip_address, user_agent=user_agent)
        await self._apply_role_map(user, identity)

        result = await self.auth.complete_federated_login(
            user,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"idp_subject": identity.subject, "issuer": metadata.issuer},
        )
        return result, redirect_to

    # ─────────────────────────── account resolution ──────────────────────

    async def _resolve_user(
        self,
        identity: oidc.VerifiedIdentity,
        *,
        ip_address: str | None,
        user_agent: str | None,
    ) -> User:
        """Find the account this assertion belongs to. Never create one."""
        user = (
            await self.session.execute(
                select(User).where(User.external_idp_subject == identity.subject)
            )
        ).scalar_one_or_none()

        if user is None and identity.email and identity.email_verified:
            # First sign-in for an account an administrator has already created. Matched
            # on email, case-insensitively, because directories and humans disagree
            # about capitalisation and nothing else in the assertion is stable enough.
            #
            # Only when the provider asserted `email_verified: true`. Many providers let a
            # user set an arbitrary, unverified profile email, so matching (and then
            # linking the subject to) an existing account on an unverified address is
            # account takeover: an attacker sets their IdP email to a Super Admin's
            # address and is handed that account. An unverified email is treated as no
            # match — the account must be pre-linked by subject or linked by an admin.
            user = (
                await self.session.execute(
                    select(User).where(func.lower(User.email) == identity.email.strip().lower())
                )
            ).scalar_one_or_none()

            if user is not None:
                if user.external_idp_subject is not None:
                    # The address now belongs to a different subject at the provider —
                    # an account recreated there, or two accounts sharing an address.
                    # Rebinding on our own initiative would hand one person's session to
                    # whoever holds the new subject.
                    await self._deny(
                        "subject_conflict",
                        ip_address=ip_address,
                        user_agent=user_agent,
                        username=user.username,
                        user_id=user.id,
                    )
                    raise AuthenticationError(
                        "This account is linked to a different identity-provider user. "
                        "An administrator must unlink it first."
                    )

                user.external_idp_subject = identity.subject
                await self.audit.record(
                    AuditAction.SSO_SUBJECT_LINKED,
                    actor_id=user.id,
                    actor_username=user.username,
                    details={"subject": identity.subject, "matched_on": "email"},
                    ip_address=ip_address,
                    user_agent=user_agent,
                )

        if user is None:
            await self._deny(
                "no_account",
                ip_address=ip_address,
                user_agent=user_agent,
                username=identity.email or identity.subject,
            )
            raise AuthenticationError(
                "No NetSecOps account matches this sign-in. An administrator must "
                "create the account before it can be used."
            )

        if user.is_locked:
            await self._deny(
                "locked",
                ip_address=ip_address,
                user_agent=user_agent,
                username=user.username,
                user_id=user.id,
            )
            raise AccountLockedError(
                "Account is temporarily locked due to repeated failed sign-in attempts."
            )

        if not user.is_active:
            await self._deny(
                "inactive",
                ip_address=ip_address,
                user_agent=user_agent,
                username=user.username,
                user_id=user.id,
            )
            raise AuthenticationError("This account is not active.")

        if user.is_service_account:
            # A service account has no person behind it and authenticates with a token
            # (FR-AUTH-07). Letting one arrive through SSO would give it an interactive
            # session with a full role set.
            await self._deny(
                "service_account",
                ip_address=ip_address,
                user_agent=user_agent,
                username=user.username,
                user_id=user.id,
            )
            raise AuthenticationError("This account cannot sign in interactively.")

        return user

    # ──────────────────────────── role mapping ───────────────────────────

    async def _apply_role_map(self, user: User, identity: oidc.VerifiedIdentity) -> None:
        """Bring the mapped roles into line with the provider's groups.

        Only roles the mapping mentions are touched. A role an administrator granted by
        hand and that no mapping covers survives every login — otherwise turning SSO on
        would silently strip the permissions of everybody who had been set up before it.
        """
        mappings = parse_role_map(await self._stored_role_map())
        if not mappings:
            return

        governed = {mapping.role for mapping in mappings}
        groups = {group.casefold() for group in identity.groups}
        should_have = {mapping.role for mapping in mappings if mapping.group.casefold() in groups}

        current = user.role_set
        granted = sorted(r.value for r in should_have - current)
        revoked = sorted(r.value for r in (governed & current) - should_have)

        for role in should_have - current:
            self.session.add(UserRole(org_id=user.org_id, user_id=user.id, role=role.value))
        if revoked:
            await self.session.execute(
                delete(UserRole).where(UserRole.user_id == user.id, UserRole.role.in_(revoked))
            )

        await self.session.flush()
        await self.session.refresh(user, ["roles"])

        await self.audit.record(
            AuditAction.SSO_ROLES_APPLIED,
            actor_id=user.id,
            actor_username=user.username,
            # Recorded even when nothing changed. "No event" would otherwise mean both
            # "the mapping ran and agreed" and "the mapping never ran", and the second
            # is the one somebody investigating a missing permission needs to rule out.
            details={
                "groups": sorted(identity.groups),
                "granted": granted,
                "revoked": revoked,
                "roles": sorted(r.value for r in user.role_set),
            },
        )

    async def _stored_role_map(self) -> object:
        row = (
            await self.session.execute(select(Setting).where(Setting.key == ROLE_MAP_KEY))
        ).scalar_one_or_none()
        return row.value if row is not None else None

    async def get_role_map(self) -> list[RoleMapping]:
        return parse_role_map(await self._stored_role_map())

    async def set_role_map(
        self,
        mappings: list[dict[str, Any]],
        *,
        actor_id: uuid.UUID | None,
        actor_username: str | None,
    ) -> list[RoleMapping]:
        validated = validate_role_map(mappings)

        row = (
            await self.session.execute(select(Setting).where(Setting.key == ROLE_MAP_KEY))
        ).scalar_one_or_none()
        payload = {"mappings": [{"group": m.group, "role": m.role.value} for m in validated]}

        if row is None:
            self.session.add(
                Setting(
                    key=ROLE_MAP_KEY,
                    value=payload,
                    description="Identity-provider groups and the roles they grant (FR-AUTH-04).",
                    updated_by_id=actor_id,
                )
            )
        else:
            row.value = payload
            row.updated_by_id = actor_id

        await self.session.flush()
        await self.audit.record(
            AuditAction.SSO_ROLE_MAP_CHANGED,
            actor_id=actor_id,
            actor_username=actor_username,
            details={"mappings": payload["mappings"]},
        )
        return validated

    # ───────────────────────────── bookkeeping ───────────────────────────

    async def _deny(
        self,
        reason: str,
        *,
        ip_address: str | None,
        user_agent: str | None,
        username: str | None = None,
        user_id: uuid.UUID | None = None,
    ) -> None:
        log.warning("sso.login_denied", reason=reason, username=username)
        await self.audit.record(
            AuditAction.SSO_LOGIN_FAILURE,
            outcome=AuditOutcome.DENIED,
            actor_id=user_id,
            actor_username=username,
            details={"reason": reason},
            ip_address=ip_address,
            user_agent=user_agent,
        )

    async def purge_expired_states(self) -> int:
        """Remove sign-ins nobody came back from.

        A browser closed at the provider's login screen leaves a row behind, and without
        this the table only grows.
        """
        result = await self.session.execute(
            delete(OIDCLoginState).where(OIDCLoginState.expires_at <= datetime.now(UTC))
        )
        # `rowcount` is on CursorResult, which is what a DELETE returns at runtime; the
        # annotation on execute() is the narrower Result. Same shape as `feeds.py`.
        return int(getattr(result, "rowcount", 0) or 0)


__all__ = [
    "MAPPABLE_ROLES",
    "ROLE_MAP_KEY",
    "BeginLogin",
    "RoleMapping",
    "SSOService",
    "parse_role_map",
    "safe_redirect",
    "validate_role_map",
]
