"""The OpenID Connect protocol, with nothing in it that touches a database (FR-AUTH-04).

Discovery, the PKCE pair, the authorization URL, the token exchange, and verification of
the ID token that comes back. `services/oidc.py` turns the verified claims into a
session; this module is only concerned with whether the provider said what it appears to
have said.

**Everything here is verified, not read.** An ID token is a bearer assertion about who a
person is, delivered through a browser that a user controls, and the difference between
checking its signature and decoding it is the difference between single sign-on and an
unauthenticated login endpoint. So: the signature against the provider's published keys,
the issuer against the one configured, the audience against our client id, the expiry,
and the nonce against the one this login started with. A failure at any point is a
refusal — never a fallback to the unverified claims, which are right there and would
work.

**The discovery document is the root of that trust.** Every endpoint the flow talks to
comes out of it, so it is fetched over HTTPS from the configured issuer and its own
`issuer` field is checked against that URL (OpenID Connect Discovery §4.3). Without that
check a redirect could swap the whole provider for another one.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWK, PyJWKSet
from jwt.exceptions import PyJWKSetError

from netsecops.core.config import Settings
from netsecops.core.errors import ProblemError
from netsecops.core.logging import get_logger

log = get_logger(__name__)

#: Signature algorithms accepted on an ID token.
#:
#: Asymmetric only. `HS256` would verify an ID token against the *client secret*, which
#: both parties hold, so anyone who could read the secret could mint an assertion for any
#: user. `none` needs no comment. Both are refused by listing what is allowed rather than
#: what is not, so a new algorithm has to be admitted deliberately.
ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS512")

#: How much clock skew between us and the provider is tolerated on `exp` and `iat`.
LEEWAY_SECONDS = 60


class OIDCError(ProblemError):
    """The provider, or the response from it, was not usable.

    Separate from `AuthenticationError` because the causes are different in kind: a
    misconfigured issuer or an unreachable provider is an operator's problem, and
    reporting it as "invalid username or password" sends them looking in the wrong
    place. It is still coarse about *which* check failed in anything a browser sees —
    the detail goes to the log and the audit trail.
    """

    status_code = 502
    title = "Single sign-on failed"
    problem_type = "sso-failed"


@dataclass(frozen=True, slots=True)
class PKCEPair:
    """RFC 7636. The verifier stays here; only its hash crosses the network."""

    verifier: str
    challenge: str

    @classmethod
    def generate(cls) -> PKCEPair:
        # 32 bytes → 43 base64url characters, the length the RFC recommends.
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return cls(verifier=verifier, challenge=challenge)


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """The parts of the discovery document this flow uses."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    end_session_endpoint: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    """What the provider asserted, once every check has passed."""

    subject: str
    email: str | None
    full_name: str | None
    groups: tuple[str, ...]
    #: Every claim, for the audit record. Read by nothing that makes a decision.
    claims: dict[str, Any] = field(default_factory=dict, repr=False)


def discovery_url(issuer: str) -> str:
    return f"{issuer.rstrip('/')}/.well-known/openid-configuration"


class MetadataCache:
    """Discovery documents and their JWKS clients, held for `oidc_metadata_ttl_seconds`.

    Cached because the alternative is two extra round trips to the identity provider on
    every single sign-in, and expiring because signing keys rotate — a cache with no end
    turns a routine rotation into every login failing with a signature error, which
    looks exactly like the provider being broken.
    """

    def __init__(self) -> None:
        self._metadata: dict[str, tuple[float, ProviderMetadata]] = {}
        self._jwks: dict[str, tuple[float, PyJWKSet]] = {}

    def invalidate(self, issuer: str) -> None:
        self._metadata.pop(issuer, None)
        self._jwks.pop(issuer, None)

    async def metadata(self, settings: Settings, *, client: httpx.AsyncClient) -> ProviderMetadata:
        issuer = settings.oidc_issuer or ""
        cached = self._metadata.get(issuer)
        if cached is not None and cached[0] > time.monotonic():
            return cached[1]

        url = discovery_url(issuer)
        try:
            response = await client.get(url, timeout=10.0)
            response.raise_for_status()
            document = response.json()
        except httpx.HTTPError as exc:
            raise OIDCError(
                f"The identity provider's configuration could not be read from {url}."
            ) from exc
        except ValueError as exc:
            raise OIDCError(f"{url} did not return a JSON configuration document.") from exc

        metadata = _parse_metadata(document, expected_issuer=issuer)
        self._metadata[issuer] = (
            time.monotonic() + settings.oidc_metadata_ttl_seconds,
            metadata,
        )
        return metadata

    async def jwks(
        self,
        metadata: ProviderMetadata,
        settings: Settings,
        *,
        client: httpx.AsyncClient,
        refresh: bool = False,
    ) -> PyJWKSet:
        """The provider's signing keys.

        Fetched here rather than by PyJWT's own `PyJWKClient`, which does a blocking
        `urllib` request — inside an async request handler that stalls the event loop
        for every other caller, and it would bypass the timeouts and transport this
        deployment is configured with.
        """
        cached = self._jwks.get(metadata.issuer)
        if cached is not None and cached[0] > time.monotonic() and not refresh:
            return cached[1]

        try:
            response = await client.get(metadata.jwks_uri, timeout=10.0)
            response.raise_for_status()
            document = response.json()
        except httpx.HTTPError as exc:
            raise OIDCError(
                f"The identity provider's signing keys could not be read from {metadata.jwks_uri}."
            ) from exc
        except ValueError as exc:
            raise OIDCError("The identity provider's signing keys are not valid JSON.") from exc

        try:
            key_set = PyJWKSet.from_dict(document)
        except PyJWKSetError as exc:
            raise OIDCError("The identity provider's signing keys could not be read.") from exc

        self._jwks[metadata.issuer] = (
            time.monotonic() + settings.oidc_metadata_ttl_seconds,
            key_set,
        )
        return key_set

    async def signing_key(
        self,
        token: str,
        metadata: ProviderMetadata,
        settings: Settings,
        *,
        client: httpx.AsyncClient,
    ) -> PyJWK:
        """The key that signed this token, re-fetching once if it is unknown.

        Providers rotate signing keys without warning and publish the new one at the
        same URL. Without the retry, every sign-in fails from the moment a rotation
        happens until the cache expires — a signature error that looks exactly like an
        attack and is nothing of the sort. With it, one unknown `kid` costs one extra
        fetch. The retry is bounded to a single attempt so a token naming a key that
        does not exist cannot be used to make us hammer the provider.
        """
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.InvalidTokenError as exc:
            raise OIDCError("The ID token is malformed.") from exc

        for refresh in (False, True):
            key_set = await self.jwks(metadata, settings, client=client, refresh=refresh)
            for key in key_set.keys:
                if kid is None or key.key_id == kid:
                    return key

        raise OIDCError("The ID token was signed with a key the provider does not publish.")


def _parse_metadata(document: Any, *, expected_issuer: str) -> ProviderMetadata:
    if not isinstance(document, dict):
        raise OIDCError("The identity provider's configuration document is not an object.")

    declared = document.get("issuer")
    if declared != expected_issuer.rstrip("/") and declared != expected_issuer:
        # OpenID Connect Discovery §4.3. Without this the document could have been
        # served by anything the URL resolved to, and every endpoint below would be
        # whatever that thing chose.
        raise OIDCError(
            f"The identity provider says its issuer is {declared!r}, but NetSecOps is "
            f"configured for {expected_issuer!r}. Sign-in is refused rather than "
            f"trusting endpoints published under the wrong name."
        )

    missing = [
        key
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri")
        if not document.get(key)
    ]
    if missing:
        raise OIDCError(
            f"The identity provider's configuration is missing {', '.join(sorted(missing))}."
        )

    return ProviderMetadata(
        issuer=str(declared),
        authorization_endpoint=str(document["authorization_endpoint"]),
        token_endpoint=str(document["token_endpoint"]),
        jwks_uri=str(document["jwks_uri"]),
        end_session_endpoint=(
            str(document["end_session_endpoint"]) if document.get("end_session_endpoint") else None
        ),
        raw=document,
    )


def authorization_url(
    metadata: ProviderMetadata, settings: Settings, *, state: str, nonce: str, challenge: str
) -> str:
    """Where to send the browser to start a sign-in."""
    query = {
        "response_type": "code",
        "client_id": settings.oidc_client_id or "",
        "redirect_uri": settings.oidc_redirect_url or "",
        "scope": " ".join(settings.oidc_scopes),
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    separator = "&" if "?" in metadata.authorization_endpoint else "?"
    return f"{metadata.authorization_endpoint}{separator}{urlencode(query)}"


async def exchange_code(
    metadata: ProviderMetadata,
    settings: Settings,
    *,
    code: str,
    verifier: str,
    client: httpx.AsyncClient,
) -> dict[str, Any]:
    """Trade the authorization code for tokens."""
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.oidc_redirect_url or "",
        "client_id": settings.oidc_client_id or "",
        "code_verifier": verifier,
    }
    secret = settings.oidc_client_secret
    if secret is None:
        # `Settings._guard_oidc` refuses to start with SSO on and no client secret, so
        # reaching here means configuration changed under a running process. Stated as
        # a refusal rather than sending an unauthenticated request the provider would
        # reject with something far less clear.
        raise OIDCError("No OIDC client secret is configured.")
    auth = (settings.oidc_client_id or "", secret.get_secret_value())

    try:
        response = await client.post(
            metadata.token_endpoint,
            data=form,
            auth=auth,
            headers={"Accept": "application/json"},
            timeout=15.0,
        )
    except httpx.HTTPError as exc:
        raise OIDCError("The identity provider's token endpoint could not be reached.") from exc

    if response.status_code >= 400:
        # The body carries an OAuth error code that names the cause — an expired code, a
        # redirect_uri that does not match what was registered. It goes to the log,
        # never to the browser.
        log.warning(
            "oidc.token_exchange_failed",
            status=response.status_code,
            body=response.text[:500],
        )
        raise OIDCError("The identity provider rejected the sign-in.")

    try:
        payload = response.json()
    except ValueError as exc:
        raise OIDCError("The identity provider's token response was not JSON.") from exc

    if not isinstance(payload, dict) or not payload.get("id_token"):
        raise OIDCError(
            "The identity provider returned no ID token. Check that the 'openid' scope "
            "is granted to this client."
        )
    return payload


def verify_id_token(
    id_token: str,
    metadata: ProviderMetadata,
    settings: Settings,
    *,
    signing_key: PyJWK,
    nonce: str,
) -> VerifiedIdentity:
    """Verify signature, issuer, audience, expiry and nonce, in that order.

    The nonce check is the one that is easy to leave out and the one that matters here:
    without it an ID token captured from another sign-in — to this same application, for
    a different person — can be replayed into this one.
    """
    try:
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=list(ALLOWED_ALGORITHMS),
            audience=settings.oidc_client_id,
            issuer=metadata.issuer,
            leeway=LEEWAY_SECONDS,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.InvalidTokenError as exc:
        log.warning("oidc.id_token_rejected", error=str(exc))
        raise OIDCError("The identity provider's response could not be verified.") from exc

    if claims.get("nonce") != nonce:
        log.warning("oidc.nonce_mismatch")
        raise OIDCError("The identity provider's response could not be verified.")

    subject = str(claims.get("sub") or "")
    if not subject:
        raise OIDCError("The ID token carries no subject.")

    return VerifiedIdentity(
        subject=subject,
        email=_claim_str(claims, "email"),
        full_name=_claim_str(claims, "name") or _claim_str(claims, "preferred_username"),
        groups=_groups(claims, settings.oidc_group_claim),
        claims=claims,
    )


def _claim_str(claims: dict[str, Any], key: str) -> str | None:
    value = claims.get(key)
    return value.strip() or None if isinstance(value, str) else None


def _groups(claims: dict[str, Any], claim_name: str) -> tuple[str, ...]:
    """The group claim, which providers render three different ways.

    A list is the common case; a single group sometimes arrives as a bare string; and
    some providers space-separate them. A claim that is present but of a shape not
    handled returns empty rather than raising — groups decide role, and the sign-in
    itself does not depend on them.
    """
    value = claims.get(claim_name)
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(part for part in value.replace(",", " ").split() if part)
    if isinstance(value, list):
        return tuple(str(item) for item in value if isinstance(item, str | int))
    log.warning("oidc.group_claim_unreadable", claim=claim_name, type=type(value).__name__)
    return ()


#: Process-wide, because the documents it holds are the same for every request.
METADATA_CACHE = MetadataCache()


__all__ = [
    "ALLOWED_ALGORITHMS",
    "LEEWAY_SECONDS",
    "METADATA_CACHE",
    "MetadataCache",
    "OIDCError",
    "PKCEPair",
    "ProviderMetadata",
    "VerifiedIdentity",
    "authorization_url",
    "discovery_url",
    "exchange_code",
    "verify_id_token",
]
