"""HTTPS transport for API-driven platforms (FR-COL-02, FR-COL-05, FR-COL-10).

PAN-OS, Panorama, FortiManager and the Check Point management server have no
configuration to read over SSH — the policy lives behind an API. Until this existed the
job runner built an SSH session for every device, so a collection against a PAN-OS
firewall sent `GET /api/?type=config&action=show` down a shell channel. It failed
closed, because the guard rejects a command the platform's allow-list does not carry,
but it failed.

Like :class:`SSHTransport`, this moves bytes and decides nothing. The read-only guard in
``readonly.py`` remains the single point of control, and :class:`DeviceSession` remains
the only route to it.

**Authentication is not performed here, on purpose.** Every one of these platforms
authenticates with an API call — Check Point's `login`, FortiManager's
`exec /sys/login/user`, PAN-OS's `type=keygen` — and each is *already* on that
platform's allow-list in ``policies.py``, because SRS §8.2 lists them as explicit
exceptions. Performing them inside ``connect()`` would route a device-facing call around
the guard and keep it out of the audit trail, which is exactly the property the session
design exists to prevent. So the runner authenticates *through* the session, and hands
the resulting token back here with :meth:`use_token`. The login then appears in the
audit log alongside every other call, which is where an auditor would look for it.

**Certificate pinning (FR-COL-10).** The TLS certificate is fingerprinted on first
contact and compared on every later one, the same trust-on-first-use discipline as the
SSH host key. A changed certificate is reported, never silently accepted — on a
management network a firewall whose certificate changed overnight is either a planned
renewal or the thing you most need to know about.
"""

from __future__ import annotations

import hashlib
import json
import ssl
from dataclasses import dataclass, field
from typing import Any

import httpx

from netsecops.adapters.session import Transport
from netsecops.adapters.transport import DeviceAuthError, DeviceUnreachableError
from netsecops.core.errors import ProblemError
from netsecops.core.logging import get_logger

log = get_logger(__name__)


class CertificateChangedError(ProblemError):
    """FR-COL-10 — a changed TLS certificate is reported, never silently accepted."""

    status_code = 502
    title = "Device TLS certificate changed"
    problem_type = "tls-certificate-changed"


def certificate_fingerprint(der: bytes) -> str:
    """SHA-256 over the DER form, in the spelling browsers and vendors print."""
    digest = hashlib.sha256(der).hexdigest().upper()
    return "SHA256:" + ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


@dataclass(slots=True)
class HttpCredentials:
    """What the runner has; what it *means* is the platform's business.

    A pre-issued PAN-OS API key needs no login exchange, which is why `api_key` is
    separate from the username/password pair rather than being derived from it.
    """

    username: str | None = None
    password: str | None = None
    api_key: str | None = None
    #: Check Point domain / FortiManager ADOM, where the login needs one.
    domain: str | None = None


@dataclass(slots=True)
class TokenState:
    """The session token the platform issued, and how to present it.

    Set by the runner after it has authenticated *through the guard*. Kept here because
    the transport is what has to attach it to every subsequent request.
    """

    #: Header name → value, e.g. `{"X-chkp-sid": "..."}` or `{"X-PAN-KEY": "..."}`.
    headers: dict[str, str] = field(default_factory=dict)
    #: Query parameters to append, for PAN-OS's `&key=...`.
    query: dict[str, str] = field(default_factory=dict)
    #: Body fields to merge into every JSON-RPC call, for FortiManager's `session`.
    body_fields: dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.headers or self.query or self.body_fields)


class HttpTransport(Transport):
    """httpx client for API-driven platforms.

    ``send`` is deliberately unimplemented: these platforms have no CLI here, and an
    adapter that reached for one would be reaching for a surface that has no allow-list.
    Raising is louder than quietly returning nothing.
    """

    def __init__(
        self,
        host: str,
        credentials: HttpCredentials,
        *,
        port: int = 443,
        verify_tls: bool = True,
        known_fingerprint: str | None = None,
        connect_timeout: int = 15,
    ) -> None:
        self.host = host
        self.credentials = credentials
        self.port = port
        self.verify_tls = verify_tls
        self.known_fingerprint = known_fingerprint
        self.connect_timeout = connect_timeout

        self.observed_fingerprint: str | None = None
        self.token = TokenState()
        self._client: httpx.AsyncClient | None = None

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    # ── lifecycle ───────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Open the client and pin the certificate. Sends no device-facing request."""
        context = ssl.create_default_context()
        if not self.verify_tls:
            # Management interfaces very often carry a self-signed certificate, and a
            # customer who cannot change that would otherwise be unable to use the
            # product at all. The fingerprint pin below is what supplies continuity in
            # that case: the first connection is trusted, and a later change is
            # reported. Turning verification off is per-device and explicit.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            verify=context,
            timeout=httpx.Timeout(self.connect_timeout, read=float(self.connect_timeout)),
            follow_redirects=False,
        )

    async def disconnect(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self.token = TokenState()

    def use_token(self, token: TokenState) -> None:
        """Accept the credential the runner obtained through the guarded session."""
        self.token = token

    # ── the one thing it does ───────────────────────────────────────────

    async def send(self, command: str, *, timeout: int) -> tuple[str, int | None]:
        raise NotImplementedError(
            "This platform is collected over its API, not a shell. Issue the request "
            "through DeviceSession.request() so the HTTP rules in policies.py apply."
        )

    async def request(
        self, method: str, path: str, *, body: Any = None, timeout: int
    ) -> tuple[int, str]:
        if self._client is None:
            raise DeviceUnreachableError("The HTTP session is not open.")

        merged_body = body
        if self.token.body_fields and isinstance(body, dict):
            merged_body = {**body, **self.token.body_fields}

        target = path
        if self.token.query:
            separator = "&" if "?" in target else "?"
            target = target + separator + "&".join(f"{k}={v}" for k, v in self.token.query.items())

        try:
            response = await self._client.request(
                method.upper(),
                target,
                json=merged_body if merged_body is not None else None,
                headers=self.token.headers or None,
                timeout=timeout,
            )
        except httpx.ConnectError as exc:
            raise DeviceUnreachableError(f"Could not reach {self.host}: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise DeviceUnreachableError(f"{self.host} did not answer within {timeout}s.") from exc

        self._check_certificate(response)

        if response.status_code in (401, 403):
            # Distinguished from a transport failure because the remedies differ
            # entirely: one is a credential to fix, the other a network path.
            raise DeviceAuthError(
                f"{self.host} rejected the credential (HTTP {response.status_code})."
            )

        return response.status_code, response.text

    # ── FR-COL-10 ───────────────────────────────────────────────────────

    def _check_certificate(self, response: httpx.Response) -> None:
        """Pin on first contact; report a change rather than accepting it."""
        der = _peer_certificate(response)
        if der is None:
            return

        observed = certificate_fingerprint(der)
        self.observed_fingerprint = observed

        if self.known_fingerprint and observed != self.known_fingerprint:
            raise CertificateChangedError(
                f"The TLS certificate for {self.host} has changed. Expected "
                f"{self.known_fingerprint}, got {observed}. This is a planned renewal or "
                f"an interception; NetSecOps will not collect until the pin is updated "
                f"deliberately."
            )


def _peer_certificate(response: httpx.Response) -> bytes | None:
    """The peer's certificate in DER, where httpx exposes it.

    Returns None rather than raising when the transport does not surface one — a proxy
    or a test double. The caller then skips pinning, which is honest: we cannot pin what
    we cannot see, and pretending otherwise would give false assurance.
    """
    stream = getattr(response, "stream", None)
    for holder in (stream, getattr(response, "extensions", {})):
        if holder is None:
            continue
        if isinstance(holder, dict):
            ssl_object = holder.get("network_stream")
            if ssl_object is not None:
                inner = ssl_object.get_extra_info("ssl_object")
                if inner is not None:
                    return inner.getpeercert(binary_form=True)  # type: ignore[no-any-return]
    return None


# ───────────────────── per-platform authentication ──────────────────────────
#
# Each entry says how to ask a platform for a session, and how to read its answer. The
# *request* is issued by the runner through the guarded session — never from here — so
# every one of these appears in the audit trail. Each is already on its platform's
# allow-list in policies.py, because SRS §8.2 lists them as explicit exceptions.


@dataclass(frozen=True, slots=True)
class AuthExchange:
    """One login call, and how to turn its response into a :class:`TokenState`."""

    method: str
    path: str
    #: None where the platform needs no login call at all (PAN-OS with a pre-issued key).
    body: dict[str, Any] | None
    platform: str

    def token_from(self, status_code: int, response_body: str) -> TokenState:
        if not 200 <= status_code < 300:
            raise DeviceAuthError(
                f"The {self.platform} login returned HTTP {status_code}. The credential "
                f"is wrong, or the API is not enabled for this account."
            )
        return _READ_TOKEN[self.platform](response_body)


def _checkpoint_token(body: str) -> TokenState:
    try:
        sid = json.loads(body).get("sid")
    except ValueError as exc:
        raise DeviceAuthError("The Check Point login response was not JSON.") from exc
    if not sid:
        raise DeviceAuthError("The Check Point login returned no session id.")
    return TokenState(headers={"X-chkp-sid": str(sid)})


def _fortimanager_token(body: str) -> TokenState:
    try:
        payload = json.loads(body)
    except ValueError as exc:
        raise DeviceAuthError("The FortiManager login response was not JSON.") from exc

    session = payload.get("session")
    if not session:
        raise DeviceAuthError("The FortiManager login returned no session token.")
    # FortiManager carries the session in the JSON-RPC envelope, not a header.
    return TokenState(body_fields={"session": session})


def _panos_token(body: str) -> TokenState:
    """`type=keygen` answers with `<response><result><key>…</key></result></response>`."""
    from defusedxml.ElementTree import ParseError, fromstring

    try:
        root = fromstring(body)
    except ParseError as exc:
        raise DeviceAuthError("The PAN-OS keygen response was not valid XML.") from exc

    key = root.findtext(".//key")
    if not key:
        raise DeviceAuthError("The PAN-OS keygen response carried no API key.")
    return TokenState(query={"key": key.strip()})


_READ_TOKEN = {
    "checkpoint_mgmt": _checkpoint_token,
    "fortimanager": _fortimanager_token,
    "panos": _panos_token,
    "panorama": _panos_token,
}


def auth_exchange(platform: str, credentials: HttpCredentials) -> AuthExchange | None:
    """The login call for a platform, or None where none is needed.

    PAN-OS with a pre-issued API key needs no exchange: the key goes straight onto every
    request. That is the preferred shape, because it means NetSecOps never holds the
    administrator's password at all.
    """
    if platform in {"panos", "panorama"}:
        if credentials.api_key:
            return None
        return AuthExchange(
            method="GET",
            path=(
                f"/api/?type=keygen&user={credentials.username or ''}"
                f"&password={credentials.password or ''}"
            ),
            body=None,
            platform=platform,
        )

    if platform == "checkpoint_mgmt":
        body: dict[str, Any] = {
            "command": "login",
            "user": credentials.username,
            "password": credentials.password,
            "read-only": True,
        }
        if credentials.domain:
            body["domain"] = credentials.domain
        return AuthExchange("POST", "/web_api/login", body, platform)

    if platform == "fortimanager":
        return AuthExchange(
            "POST",
            "/jsonrpc",
            {
                "method": "exec",
                "params": [
                    {
                        "url": "/sys/login/user",
                        "data": {
                            "user": credentials.username,
                            "passwd": credentials.password,
                        },
                    }
                ],
            },
            platform,
        )

    return None


def pre_issued_token(platform: str, credentials: HttpCredentials) -> TokenState | None:
    """The token for a platform that needs no login exchange."""
    if platform in {"panos", "panorama"} and credentials.api_key:
        return TokenState(query={"key": credentials.api_key})
    return None


def logout_exchange(platform: str) -> tuple[str, str, dict[str, Any] | None] | None:
    """How to release a session, so a collection does not leave one open.

    Check Point in particular allows a limited number of concurrent API sessions, and an
    estate collected nightly would exhaust them within a week if every run leaked one.
    """
    if platform == "checkpoint_mgmt":
        return ("POST", "/web_api/logout", {"command": "logout"})
    if platform == "fortimanager":
        return ("POST", "/jsonrpc", {"method": "exec", "params": [{"url": "/sys/logout"}]})
    return None


__all__ = [
    "AuthExchange",
    "CertificateChangedError",
    "HttpCredentials",
    "HttpTransport",
    "TokenState",
    "auth_exchange",
    "certificate_fingerprint",
    "logout_exchange",
    "pre_issued_token",
]
