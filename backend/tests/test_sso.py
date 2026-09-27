"""OIDC single sign-on (FR-AUTH-04).

This is the one subsystem where a passing test proves least. Every check below has a
cheap way to make it pass that also makes the feature an unauthenticated login
endpoint — decode the ID token instead of verifying it, accept any issuer, skip the
nonce — and the flow *works* in all of them. So most of what follows asserts refusals,
and the mutation pass that accompanies it removes each check in turn.

The three product decisions are asserted as behaviour, not read off the config:

* an assertion for somebody with no account is refused, and no account is created;
* the group mapping governs only the roles it names, so a hand-granted role survives;
* MFA is still asked for, because the provider's word replaces the password and not
  the second factor.
"""

from __future__ import annotations

import base64
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.utils import to_base64url_uint
from sqlalchemy import select

from netsecops.core import oidc
from netsecops.core.config import Settings
from netsecops.core.errors import AccountLockedError, AuthenticationError, ValidationProblem
from netsecops.core.rbac import Role
from netsecops.db.models.audit import AuditAction, AuditLog
from netsecops.db.models.user import OIDCLoginState, User
from netsecops.services.auth import MFAChallenge, TokenPair
from netsecops.services.sso import (
    MAPPABLE_ROLES,
    SSOService,
    parse_role_map,
    safe_redirect,
    validate_role_map,
)
from tests.conftest import make_user

ISSUER = "https://idp.example.test"
CLIENT_ID = "netsecops-console"

# One key for the whole module: generating RSA keys is the slowest thing here.
_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_KID = "test-key-1"


def _jwks() -> dict[str, Any]:
    numbers = _KEY.public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": _KID,
                "use": "sig",
                "alg": "RS256",
                "n": to_base64url_uint(numbers.n).decode("ascii"),
                "e": to_base64url_uint(numbers.e).decode("ascii"),
            }
        ]
    }


def id_token(**overrides: Any) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "idp-subject-001",
        "iat": now,
        "exp": now + 300,
        "email": "dana@example.com",
        "name": "Dana Okafor",
        "groups": ["net-admins"],
        "nonce": "NONCE",
    }
    claims.update(overrides)
    for key, value in list(claims.items()):
        if value is None:
            del claims[key]
    return pyjwt.encode(claims, _KEY, algorithm="RS256", headers={"kid": _KID})


def sso_settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "oidc_enabled": True,
        "oidc_issuer": ISSUER,
        "oidc_client_id": CLIENT_ID,
        "oidc_client_secret": "client-secret",
        "oidc_redirect_url": "https://netsecops.example.test/api/v1/auth/sso/callback",
        "secret_key": "x" * 48,
        "master_key": base64.b64encode(b"k" * 32).decode(),
    }
    base.update(overrides)
    return Settings(**base)


class FakeIdP:
    """The provider, as three URLs. Enough to drive the whole flow without a network."""

    def __init__(self, *, discovery: dict[str, Any] | None = None) -> None:
        self.token_response: dict[str, Any] = {"id_token": id_token()}
        self.token_status = 200
        self.discovery = discovery or {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "jwks_uri": f"{ISSUER}/jwks",
        }
        self.token_requests: list[dict[str, Any]] = []

    def client(self) -> httpx.AsyncClient:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("openid-configuration"):
                return httpx.Response(200, json=self.discovery)
            if request.url.path.endswith("/jwks"):
                return httpx.Response(200, json=_jwks())
            if request.url.path.endswith("/token"):
                body = dict(httpx.QueryParams(request.content.decode()))
                self.token_requests.append(body)
                return httpx.Response(self.token_status, json=self.token_response)
            return httpx.Response(404)

        return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def _clear_metadata_cache():
    oidc.METADATA_CACHE.invalidate(ISSUER)
    yield
    oidc.METADATA_CACHE.invalidate(ISSUER)


@pytest.fixture
def idp() -> FakeIdP:
    return FakeIdP()


@pytest.fixture
def service(session, vault, idp: FakeIdP) -> SSOService:
    return SSOService(session, settings=sso_settings(), vault=vault, http=idp.client())


# ─────────────────────────────── configuration ────────────────────────────────


class TestItRefusesToStartHalfConfigured:
    def test_enabled_without_a_client_secret_will_not_start(self) -> None:
        """At startup, in front of whoever set it up — rather than at the first sign-in,
        in front of whoever the rollout was for."""
        with pytest.raises(ValueError, match="oidc_client_secret"):
            sso_settings(oidc_client_secret=None)

    def test_an_http_issuer_is_refused(self) -> None:
        """Every endpoint the flow uses is discovered from the issuer and trusted
        because it came from there."""
        with pytest.raises(ValueError, match="https"):
            sso_settings(oidc_issuer="http://idp.example.test")

    def test_openid_is_added_when_an_operator_leaves_it_out(self) -> None:
        """Without it the provider runs plain OAuth and returns no ID token — the only
        part of the response that says who signed in."""
        settings = sso_settings(oidc_scopes=["profile", "email"])

        assert settings.oidc_scopes[0] == "openid"

    def test_scopes_parse_from_the_space_separated_form_the_spec_uses(self) -> None:
        assert sso_settings(oidc_scopes="openid profile groups").oidc_scopes == [
            "openid",
            "profile",
            "groups",
        ]

    def test_disabled_needs_nothing(self) -> None:
        """The overwhelmingly common configuration, and it must not be made to carry
        fields it will never use."""
        assert Settings(secret_key="x" * 48).oidc_enabled is False


# ──────────────────────────── verifying the provider ──────────────────────────


class TestTheAssertionIsVerifiedNotRead:
    @pytest.mark.anyio
    async def test_a_token_signed_by_somebody_else_is_refused(self, service, idp) -> None:
        """The whole feature in one test. An ID token arrives through a browser the
        user controls, so a signature that is decoded rather than verified makes this
        an endpoint anybody can mint a session at."""
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        begun = await service.begin()
        row = (await service.session.execute(select(OIDCLoginState))).scalar_one()
        idp.token_response = {
            "id_token": pyjwt.encode(
                {
                    "iss": ISSUER,
                    "aud": CLIENT_ID,
                    "sub": "attacker",
                    "iat": int(time.time()),
                    "exp": int(time.time()) + 300,
                    "nonce": row.nonce,
                },
                other,
                algorithm="RS256",
                headers={"kid": _KID},
            )
        }

        with pytest.raises(oidc.OIDCError):
            await service.complete(code="c", state=begun.state)

    @pytest.mark.anyio
    async def test_a_token_for_another_audience_is_refused(self, service, idp) -> None:
        """An ID token minted for a different application at the same provider is a
        valid, correctly signed token — and accepting it would let any other client of
        that IdP issue NetSecOps sessions."""
        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(aud="some-other-app", nonce=row.nonce)}

        with pytest.raises(oidc.OIDCError):
            await service.complete(code="c", state=begun.state)

    @pytest.mark.anyio
    async def test_an_expired_token_is_refused(self, service, idp) -> None:
        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(exp=int(time.time()) - 3600, nonce=row.nonce)}

        with pytest.raises(oidc.OIDCError):
            await service.complete(code="c", state=begun.state)

    @pytest.mark.anyio
    async def test_a_token_from_another_login_cannot_be_replayed(self, service, idp) -> None:
        """What `nonce` is for, and the check most easily left out: an ID token captured
        from somebody else's sign-in to this same application is otherwise valid in
        every respect."""
        begun, _ = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce="a-nonce-from-another-login")}

        with pytest.raises(oidc.OIDCError):
            await service.complete(code="c", state=begun.state)

    @pytest.mark.anyio
    async def test_a_provider_claiming_a_different_issuer_is_refused(self, session, vault) -> None:
        """OpenID Connect Discovery §4.3. Without it the document could have been served
        by whatever the URL resolved to, and every endpoint in it would be that thing's."""
        idp = FakeIdP(
            discovery={
                "issuer": "https://someone-else.example.test",
                "authorization_endpoint": f"{ISSUER}/authorize",
                "token_endpoint": f"{ISSUER}/token",
                "jwks_uri": f"{ISSUER}/jwks",
            }
        )
        service = SSOService(session, settings=sso_settings(), vault=vault, http=idp.client())

        with pytest.raises(oidc.OIDCError, match="issuer"):
            await service.begin()

    def test_symmetric_algorithms_are_not_accepted(self) -> None:
        """`HS256` would verify an ID token against the client secret, which both sides
        hold — so anyone who could read it could mint an assertion for any user."""
        assert "HS256" not in oidc.ALLOWED_ALGORITHMS
        assert "none" not in oidc.ALLOWED_ALGORITHMS
        assert all(alg[:2] in {"RS", "ES", "PS"} for alg in oidc.ALLOWED_ALGORITHMS)


# ──────────────────────────────── the state row ───────────────────────────────


class TestStateIsSingleUse:
    @pytest.mark.anyio
    async def test_a_state_nobody_issued_is_refused(self, service) -> None:
        with pytest.raises(AuthenticationError):
            await service.complete(code="c", state="not-a-state-we-issued")

    @pytest.mark.anyio
    async def test_the_same_callback_cannot_be_replayed(self, service, idp, session) -> None:
        """The row is deleted before anything can fail, so a second delivery of the same
        callback — a refresh, a retry, a captured URL — finds nothing."""
        await _seed_dana(session)

        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce)}
        await service.complete(code="c", state=begun.state)

        with pytest.raises(AuthenticationError):
            await service.complete(code="c", state=begun.state)

    @pytest.mark.anyio
    async def test_the_verifier_is_not_stored_in_the_clear(self, service, session) -> None:
        """For the minutes it lives, this row holds everything but the authorization
        code needed to finish somebody else's sign-in."""
        await service.begin()
        row = (await session.execute(select(OIDCLoginState))).scalar_one()

        assert b"code_verifier" not in row.encrypted_verifier
        # The sealed blob does not contain the plaintext it seals.
        opened = service.vault.open(row.encrypted_verifier, aad=row.state).decode()
        assert opened.encode() not in row.encrypted_verifier

    @pytest.mark.anyio
    async def test_the_pkce_challenge_is_the_hash_not_the_verifier(self, service, session) -> None:
        """Sending the verifier itself would make PKCE decorative: anybody who captured
        the authorization request could complete the exchange."""
        begun = await service.begin()
        row = (await session.execute(select(OIDCLoginState))).scalar_one()
        verifier = service.vault.open(row.encrypted_verifier, aad=row.state).decode()

        assert "code_challenge_method=S256" in begun.authorization_url
        assert verifier not in begun.authorization_url

    @pytest.mark.anyio
    async def test_the_verifier_is_sent_on_the_exchange(self, service, idp, session) -> None:
        """Held back, the provider rejects every exchange and SSO never works at all."""
        await _seed_dana(session)
        begun, row = await _begin(service)
        verifier = service.vault.open(row.encrypted_verifier, aad=row.state).decode()
        idp.token_response = {"id_token": id_token(nonce=row.nonce)}

        await service.complete(code="c", state=begun.state)

        assert idp.token_requests[0]["code_verifier"] == verifier

    @pytest.mark.anyio
    async def test_a_sign_in_that_took_too_long_is_refused(self, service, idp, session) -> None:
        """An authorization code left in a browser tab overnight, or a callback URL
        copied out of history. The window is the point of having an expiry, and a row
        that is merely swept eventually is still usable until the sweep runs."""
        await _seed_dana(session)
        begun, row = await _begin(service)
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.flush()
        idp.token_response = {"id_token": id_token(nonce=row.nonce)}

        with pytest.raises(AuthenticationError, match="took too long"):
            await service.complete(code="c", state=begun.state)

    @pytest.mark.anyio
    async def test_an_expired_sign_in_is_still_consumed(self, service, session) -> None:
        """Refusing it has to also spend it. Leaving the row behind would let the same
        state be retried until something else let it through."""
        begun, row = await _begin(service)
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.flush()

        with pytest.raises(AuthenticationError):
            await service.complete(code="c", state=begun.state)

        assert (await session.execute(select(OIDCLoginState))).scalars().all() == []

    @pytest.mark.anyio
    async def test_the_nightly_job_sweeps_abandoned_sign_ins(self, service, session) -> None:
        """A cleanup nothing calls is a table that grows forever — and `/auth/sso/start`
        has to be unauthenticated, so anybody who can reach the login page can grow it.

        The first version of this shipped with the sweep written and wired to nothing,
        which is the defect this codebase keeps finding in itself: the capability
        existed, every test of it passed, and it never ran.
        """
        from netsecops.db.models.jobs import Job
        from netsecops.services.jobs import JobService
        from netsecops.workers.runner import _run_retention

        _, row = await _begin(service)
        row.expires_at = datetime.now(UTC) - timedelta(hours=1)
        job = Job(org_id=1, job_type="retention", status="running", started_at=datetime.now(UTC))
        session.add(job)
        await session.flush()

        completed = await _run_retention(session, job, JobService(session))

        assert completed.stats["sign_ins_swept"] == 1
        assert (await session.execute(select(OIDCLoginState))).scalars().all() == []

    @pytest.mark.anyio
    async def test_expired_sign_ins_are_swept(self, service, session) -> None:
        await service.begin()
        row = (await session.execute(select(OIDCLoginState))).scalar_one()
        row.expires_at = row.created_at.replace(year=2020)
        await session.flush()

        assert await service.purge_expired_states() == 1


# ───────────────────────────── who gets an account ────────────────────────────


class TestTheProviderSaysWhoNotWhether:
    @pytest.mark.anyio
    async def test_an_unknown_subject_is_refused_and_no_account_appears(
        self, service, idp, session
    ) -> None:
        """The decision this deployment made: a directory group is a statement about
        employment, not an authorisation grant."""

        before = len((await session.execute(select(User))).all())
        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce)}

        with pytest.raises(AuthenticationError, match="administrator must create"):
            await service.complete(code="c", state=begun.state)

        after = len((await session.execute(select(User))).all())
        assert after == before

    @pytest.mark.anyio
    async def test_a_refusal_is_audited(self, service, idp, session) -> None:
        """Otherwise the only trace of somebody being turned away is its absence."""
        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce)}

        with pytest.raises(AuthenticationError):
            await service.complete(code="c", state=begun.state)

        entries = (
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.action == AuditAction.SSO_LOGIN_FAILURE)
                )
            )
            .scalars()
            .all()
        )
        assert [e.details["reason"] for e in entries] == ["no_account"]

    @pytest.mark.anyio
    async def test_the_first_sign_in_links_the_subject_to_the_existing_account(
        self, service, idp, session
    ) -> None:
        user = await _seed_dana(session)
        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce)}

        await service.complete(code="c", state=begun.state)
        await session.refresh(user)

        assert user.external_idp_subject == "idp-subject-001"

    @pytest.mark.anyio
    async def test_the_email_match_ignores_capitalisation(self, service, idp, session) -> None:
        """Directories and humans disagree about it, and a case-sensitive match turns
        that disagreement into 'no account matches this sign-in'."""
        user = await _seed_dana(session, email="Dana@Example.com")
        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce, email="dana@example.com")}

        await service.complete(code="c", state=begun.state)
        await session.refresh(user)

        assert user.external_idp_subject == "idp-subject-001"

    @pytest.mark.anyio
    async def test_a_second_subject_claiming_a_linked_address_is_refused(
        self, service, idp, session
    ) -> None:
        """An account recreated at the provider, or two directory accounts sharing an
        address. Rebinding unasked would hand one person's session to whoever holds the
        new subject."""
        user = await _seed_dana(session)
        user.external_idp_subject = "idp-subject-original"
        await session.flush()

        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce, sub="idp-subject-999")}

        with pytest.raises(AuthenticationError, match="unlink"):
            await service.complete(code="c", state=begun.state)

        await session.refresh(user)
        assert user.external_idp_subject == "idp-subject-original"

    @pytest.mark.anyio
    async def test_a_deactivated_account_cannot_sign_in(self, service, idp, session) -> None:
        """Deactivating somebody has to end their access by every door, or it is not
        deactivation."""
        user = await _seed_dana(session)
        user.is_active = False
        await session.flush()

        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce)}

        with pytest.raises(AuthenticationError):
            await service.complete(code="c", state=begun.state)

    @pytest.mark.anyio
    async def test_a_locked_account_stays_locked(self, service, idp, session) -> None:
        """A lockout that SSO walks past is not a lockout (FR-AUTH-06)."""

        user = await _seed_dana(session)
        user.locked_until = datetime.now(UTC) + timedelta(minutes=15)
        await session.flush()

        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce)}

        with pytest.raises(AccountLockedError):
            await service.complete(code="c", state=begun.state)

    @pytest.mark.anyio
    async def test_a_service_account_cannot_sign_in_interactively(
        self, service, idp, session
    ) -> None:
        """It has no person behind it and authenticates with a token (FR-AUTH-07)."""
        user = await _seed_dana(session)
        user.is_service_account = True
        await session.flush()

        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce)}

        with pytest.raises(AuthenticationError):
            await service.complete(code="c", state=begun.state)


# ──────────────────────────────── role mapping ────────────────────────────────


class TestTheMappingGovernsOnlyWhatItNames:
    @pytest.mark.anyio
    async def test_a_mapped_group_grants_its_role(self, service, idp, session) -> None:
        user = await _seed_dana(session, roles=set())
        await service.set_role_map(
            [{"group": "net-admins", "role": "network_engineer"}],
            actor_id=None,
            actor_username="admin",
        )

        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce, groups=["net-admins"])}
        await service.complete(code="c", state=begun.state)
        await session.refresh(user, ["roles"])

        assert Role.NETWORK_ENGINEER in user.role_set

    @pytest.mark.anyio
    async def test_leaving_the_group_revokes_it(self, service, idp, session) -> None:
        """The reason for having a mapping at all. A grant that only ever accumulates
        makes SSO a way of collecting permissions."""
        user = await _seed_dana(session, roles={Role.NETWORK_ENGINEER})
        await service.set_role_map(
            [{"group": "net-admins", "role": "network_engineer"}],
            actor_id=None,
            actor_username="admin",
        )

        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce, groups=["other-team"])}
        await service.complete(code="c", state=begun.state)
        await session.refresh(user, ["roles"])

        assert Role.NETWORK_ENGINEER not in user.role_set

    @pytest.mark.anyio
    async def test_a_role_the_mapping_never_mentions_survives(self, service, idp, session) -> None:
        """Otherwise switching SSO on silently strips the permissions of everybody who
        was set up before it."""
        user = await _seed_dana(session, roles={Role.AUDITOR})
        await service.set_role_map(
            [{"group": "net-admins", "role": "network_engineer"}],
            actor_id=None,
            actor_username="admin",
        )

        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce, groups=[])}
        await service.complete(code="c", state=begun.state)
        await session.refresh(user, ["roles"])

        assert Role.AUDITOR in user.role_set

    @pytest.mark.anyio
    async def test_no_mapping_configured_changes_nothing(self, service, idp, session) -> None:
        """The state every deployment starts in. Treating an empty mapping as
        'no groups, revoke everything' would lock out the estate on the first login."""
        user = await _seed_dana(session, roles={Role.SECURITY_ANALYST})

        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce)}
        await service.complete(code="c", state=begun.state)
        await session.refresh(user, ["roles"])

        assert Role.SECURITY_ANALYST in user.role_set
        # And it says nothing, rather than recording that a mapping was applied. An
        # audit trail claiming roles were reconciled against a mapping that does not
        # exist is worse than silence: it answers a question wrongly.
        applied = (
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.action == AuditAction.SSO_ROLES_APPLIED)
                )
            )
            .scalars()
            .all()
        )
        assert applied == []

    @pytest.mark.anyio
    async def test_the_mapping_is_applied_even_when_it_changes_nothing(
        self, service, idp, session
    ) -> None:
        """An audit trail where 'no event' means both 'agreed' and 'never ran' cannot
        answer the question somebody investigating a missing permission is asking."""
        await _seed_dana(session, roles={Role.NETWORK_ENGINEER})
        await service.set_role_map(
            [{"group": "net-admins", "role": "network_engineer"}],
            actor_id=None,
            actor_username="admin",
        )

        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce, groups=["net-admins"])}
        await service.complete(code="c", state=begun.state)

        applied = (
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.action == AuditAction.SSO_ROLES_APPLIED)
                )
            )
            .scalars()
            .all()
        )
        assert len(applied) == 1
        assert applied[0].details["granted"] == []
        assert applied[0].details["revoked"] == []

    def test_super_admin_cannot_be_mapped(self) -> None:
        """It is the role that can rewrite this mapping and revoke any other, so a
        directory group must not be able to reach it."""
        assert Role.SUPER_ADMIN not in MAPPABLE_ROLES
        with pytest.raises(ValidationProblem, match="Super Admin"):
            validate_role_map([{"group": "everyone", "role": "super_admin"}])

    def test_api_service_cannot_be_mapped(self) -> None:
        assert Role.API_SERVICE not in MAPPABLE_ROLES
        with pytest.raises(ValidationProblem):
            validate_role_map([{"group": "everyone", "role": "api_service"}])

    def test_a_role_that_does_not_exist_is_refused_when_saving(self) -> None:
        with pytest.raises(ValidationProblem, match="is not a role"):
            validate_role_map([{"group": "net-admins", "role": "adminstrator"}])

    def test_a_forbidden_role_already_stored_is_skipped_rather_than_breaking_login(
        self,
    ) -> None:
        """Read is forgiving and write is strict: one bad entry left by an older
        release must not stop everybody signing in."""
        parsed = parse_role_map(
            {
                "mappings": [
                    {"group": "a", "role": "super_admin"},
                    {"group": "b", "role": "auditor"},
                ]
            }
        )

        assert [(m.group, m.role) for m in parsed] == [("b", Role.AUDITOR)]


# ─────────────────────────────── MFA still applies ────────────────────────────


class TestSSOReplacesThePasswordNotTheSecondFactor:
    @pytest.mark.anyio
    async def test_an_enrolled_user_is_still_challenged(self, service, idp, session) -> None:
        """The decision this deployment made. The provider may have done its own MFA or
        may be checking one directory password, and the assertion does not reliably
        distinguish them."""
        await _seed_dana(session, mfa_enabled=True)
        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce)}

        result, _ = await service.complete(code="c", state=begun.state)

        assert isinstance(result, MFAChallenge)

    @pytest.mark.anyio
    async def test_a_user_without_mfa_gets_a_session(self, service, idp, session) -> None:
        await _seed_dana(session)
        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce)}

        result, _ = await service.complete(code="c", state=begun.state)

        assert isinstance(result, TokenPair)

    @pytest.mark.anyio
    async def test_the_federation_is_audited_before_the_second_factor(
        self, service, idp, session
    ) -> None:
        """Two events with two meanings: the provider vouched, and a session was
        issued. With MFA outstanding the first happens and the second does not, and
        that gap is what an auditor is looking for."""
        await _seed_dana(session, mfa_enabled=True)
        begun, row = await _begin(service)
        idp.token_response = {"id_token": id_token(nonce=row.nonce)}

        await service.complete(code="c", state=begun.state)

        actions = [e.action for e in ((await session.execute(select(AuditLog))).scalars().all())]
        assert AuditAction.SSO_LOGIN_SUCCESS in actions
        assert AuditAction.LOGIN_SUCCESS not in actions


# ──────────────────────────────── the redirect ────────────────────────────────


class TestTheRedirectCannotLeaveTheConsole:
    @pytest.mark.parametrize(
        "target",
        [
            "https://evil.test/steal",
            "//evil.test/steal",
            "http://evil.test",
            "/\\evil.test",
            "/ok\nLocation: https://evil.test",
        ],
    )
    def test_anything_that_leaves_the_site_is_discarded(self, target: str) -> None:
        """An open redirect wearing a sign-in flow as cover, and one that arrives
        looking like it came from the identity provider."""
        assert safe_redirect(target) is None

    @pytest.mark.parametrize("target", ["/findings", "/devices/42", "/reports?tab=archive"])
    def test_a_path_inside_the_console_is_kept(self, target: str) -> None:
        """The page somebody was trying to reach when they were sent to sign in."""
        assert safe_redirect(target) == target

    @pytest.mark.anyio
    async def test_a_hostile_redirect_never_reaches_the_database(self, service, session) -> None:
        await service.begin(redirect_to="https://evil.test")
        row = (await session.execute(select(OIDCLoginState))).scalar_one()

        assert row.redirect_to is None


# ────────────────────────────── disabled deployments ──────────────────────────


class TestSwitchedOff:
    @pytest.mark.anyio
    async def test_starting_a_sign_in_is_refused(self, session, vault) -> None:
        service = SSOService(session, settings=Settings(secret_key="x" * 48), vault=vault)

        with pytest.raises(AuthenticationError):
            await service.begin()

    @pytest.mark.anyio
    async def test_a_callback_is_refused(self, session, vault) -> None:
        """Even holding a state issued while it was on."""
        service = SSOService(session, settings=Settings(secret_key="x" * 48), vault=vault)

        with pytest.raises(AuthenticationError):
            await service.complete(code="c", state="whatever")


# ───────────────────────────── the group claim's shapes ───────────────────────


class TestTheGroupClaim:
    def test_a_list_is_read(self) -> None:
        assert oidc._groups({"groups": ["a", "b"]}, "groups") == ("a", "b")

    def test_a_single_group_sent_as_a_string_is_read(self) -> None:
        """Some providers send one group as a bare string, and reading it as a sequence
        of characters would match no mapping while looking like it tried."""
        assert oidc._groups({"groups": "net-admins"}, "groups") == ("net-admins",)

    def test_a_space_separated_string_is_read(self) -> None:
        assert oidc._groups({"groups": "a b"}, "groups") == ("a", "b")

    def test_an_absent_claim_is_empty_not_an_error(self) -> None:
        """Groups decide role; the sign-in itself does not depend on them."""
        assert oidc._groups({}, "groups") == ()

    def test_a_shape_nobody_planned_for_is_empty(self) -> None:
        assert oidc._groups({"groups": {"nested": True}}, "groups") == ()


# ─────────────────────────────────── helpers ──────────────────────────────────


async def _begin(service: SSOService):
    """Start a sign-in and hand back the row, so a test can use the real nonce."""
    import sqlalchemy

    begun = await service.begin()
    row = (
        await service.session.execute(
            sqlalchemy.select(OIDCLoginState).where(OIDCLoginState.state == begun.state)
        )
    ).scalar_one()
    return begun, row


async def _seed_dana(session, *, email: str = "dana@example.com", roles=None, mfa_enabled=False):
    user = await make_user(
        session,
        username=f"dana_{uuid.uuid4().hex[:6]}",
        roles=roles if roles is not None else {Role.AUDITOR},
        mfa_enabled=mfa_enabled,
    )
    user.email = email
    await session.flush()
    return user
