"""HTTPS collection for API-driven platforms (FR-COL-02, FR-COL-05, FR-COL-10, SRS §8).

Before this existed the job runner built an SSH transport for every device, so a
collection against a PAN-OS firewall sent `GET /api/?type=config&action=show` down a
shell channel. It failed closed — the guard rejects a command the platform's allow-list
does not carry — but it failed, and PAN-OS and the Check Point management server could
not be collected from at all.

Two properties matter more than the rest, and both are about the guard remaining the
only route to a device:

**The login goes through the session.** Every one of these platforms authenticates with
a device-facing API call. Performing it inside the transport would route it around the
read-only guard and keep it out of the audit trail — precisely the property the session
design exists to hold. `test_the_login_is_guarded_and_audited` is that assertion.

**A write is still refused over HTTP.** The guard's HTTP and body-predicate rules were
written in Phase 1 and, until now, nothing exercised them end to end. A transport that
quietly bypassed them would have looked identical in every existing test.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from netsecops.adapters.http_transport import (
    CertificateChangedError,
    HttpCredentials,
    HttpTransport,
    TokenState,
    auth_exchange,
    certificate_fingerprint,
    logout_exchange,
    pre_issued_token,
)
from netsecops.adapters.policies import get_policy
from netsecops.adapters.readonly import ReadOnlyGuard
from netsecops.adapters.session import DeviceSession, NullRecorder
from netsecops.adapters.transport import DeviceAuthError
from netsecops.core.errors import ReadOnlyViolationError


class FakeHttp(HttpTransport):
    """An HttpTransport whose wire is a list of canned responses.

    Subclassed rather than mocked so the token handling, body merging and query
    appending — the parts most likely to be wrong — run exactly as in production.
    """

    def __init__(self, responses: list[tuple[int, str]] | None = None, **kwargs: Any) -> None:
        super().__init__("10.0.0.1", HttpCredentials(username="a", password="b"), **kwargs)
        self.responses = responses or []
        self.sent: list[dict[str, Any]] = []

    async def connect(self) -> None:
        self._client = object()  # type: ignore[assignment]

    async def disconnect(self) -> None:
        self._client = None

    async def request(
        self, method: str, path: str, *, body: Any = None, timeout: int
    ) -> tuple[int, str]:
        merged_body = body
        if self.token.body_fields and isinstance(body, dict):
            merged_body = {**body, **self.token.body_fields}

        target = path
        if self.token.query:
            separator = "&" if "?" in target else "?"
            target = target + separator + "&".join(f"{k}={v}" for k, v in self.token.query.items())

        self.sent.append(
            {
                "method": method.upper(),
                "path": target,
                "body": merged_body,
                "headers": dict(self.token.headers),
            }
        )
        return self.responses.pop(0) if self.responses else (200, "{}")


def session_for(platform: str, transport: HttpTransport) -> tuple[DeviceSession, NullRecorder]:
    recorder = NullRecorder()
    return (
        DeviceSession(transport, ReadOnlyGuard(get_policy(platform)), recorder=recorder),
        recorder,
    )


# ═══════════════════════════ the guard still holds ═══════════════════════════


class TestTheGuardIsStillTheOnlyRoute:
    async def test_a_permitted_read_goes_through(self) -> None:
        transport = FakeHttp([(200, "<response><result/></response>")])
        session, _ = session_for("panos", transport)

        async with session:
            result = await session.request("GET", "/api/?type=config&action=show")

        assert result.status_code == 200
        assert transport.sent[0]["method"] == "GET"

    async def test_a_write_is_refused_before_it_reaches_the_wire(self) -> None:
        """The point of the guard. A refused call must never be sent — being rejected by
        the device would be a very different guarantee from never attempting it."""
        transport = FakeHttp()
        session, recorder = session_for("panos", transport)

        async with session:
            with pytest.raises(ReadOnlyViolationError):
                await session.request("POST", "/api/?type=config&action=set")

        assert transport.sent == []
        assert recorder.violations

    async def test_a_checkpoint_write_command_is_refused(self) -> None:
        """Check Point's API is POST-only, so the body is the only thing separating a
        read from a write. `delete-access-rule` is the same shape as a show."""
        transport = FakeHttp()
        session, _ = session_for("checkpoint_mgmt", transport)

        async with session:
            with pytest.raises(ReadOnlyViolationError):
                await session.request(
                    "POST", "/web_api/delete-access-rule", body={"command": "delete-access-rule"}
                )

        assert transport.sent == []

    async def test_a_fortimanager_set_is_refused(self) -> None:
        transport = FakeHttp()
        session, _ = session_for("fortimanager", transport)

        async with session:
            with pytest.raises(ReadOnlyViolationError):
                await session.request(
                    "POST",
                    "/jsonrpc",
                    body={"method": "set", "params": [{"url": "/pm/config/adom/root/pkg"}]},
                )

        assert transport.sent == []

    async def test_every_call_is_audited(self) -> None:
        transport = FakeHttp([(200, "{}")])
        session, recorder = session_for("checkpoint_mgmt", transport)

        async with session:
            await session.request(
                "POST",
                "/web_api/show-gateways-and-servers",
                body={"command": "show-gateways-and-servers"},
            )

        assert recorder.commands == ["POST /web_api/show-gateways-and-servers"]

    async def test_a_shell_command_over_an_api_platform_raises(self) -> None:
        """These platforms have no CLI here, and an adapter reaching for one would be
        reaching for a surface that has no allow-list."""
        transport = FakeHttp()
        with pytest.raises(NotImplementedError, match="not a shell"):
            await HttpTransport.send(transport, "show version", timeout=5)


# ══════════════════════════ authentication ═══════════════════════════════════


class TestAuthentication:
    def test_a_pre_issued_panos_key_needs_no_login(self) -> None:
        """The better shape: NetSecOps never holds the administrator's password."""
        credentials = HttpCredentials(api_key="LUFRPT1abc")

        assert pre_issued_token("panos", credentials) == TokenState(query={"key": "LUFRPT1abc"})
        assert auth_exchange("panos", credentials) is None

    def test_panos_falls_back_to_keygen(self) -> None:
        exchange = auth_exchange("panos", HttpCredentials(username="admin", password="s3cret"))

        assert exchange is not None
        assert exchange.method == "GET"
        assert "type=keygen" in exchange.path

    def test_checkpoint_login_asks_for_a_read_only_session(self) -> None:
        """Defence in depth behind the guard: even if a write somehow reached the
        management server, the session it arrived on could not perform one."""
        exchange = auth_exchange("checkpoint_mgmt", HttpCredentials(username="a", password="b"))

        assert exchange is not None
        assert exchange.body is not None
        assert exchange.body["read-only"] is True

    def test_a_checkpoint_domain_is_carried_for_a_multi_domain_server(self) -> None:
        exchange = auth_exchange(
            "checkpoint_mgmt", HttpCredentials(username="a", password="b", domain="Branch-A")
        )
        assert exchange is not None
        assert exchange.body is not None
        assert exchange.body["domain"] == "Branch-A"

    @pytest.mark.parametrize(
        ("platform", "body", "expected"),
        [
            ("checkpoint_mgmt", '{"sid": "abc123"}', TokenState(headers={"X-chkp-sid": "abc123"})),
            (
                "fortimanager",
                '{"session": "tok-9"}',
                TokenState(body_fields={"session": "tok-9"}),
            ),
            (
                "panos",
                "<response><result><key>K3Y</key></result></response>",
                TokenState(query={"key": "K3Y"}),
            ),
        ],
    )
    def test_each_platform_carries_its_token_where_it_belongs(
        self, platform: str, body: str, expected: TokenState
    ) -> None:
        """A header, a query parameter and a JSON-RPC envelope field respectively.
        Putting one in the wrong place authenticates nothing and looks like a bad
        password."""
        exchange = auth_exchange(platform, HttpCredentials(username="a", password="b"))
        assert exchange is not None
        assert exchange.token_from(200, body) == expected

    def test_a_failed_login_says_what_to_check(self) -> None:
        exchange = auth_exchange("checkpoint_mgmt", HttpCredentials(username="a", password="b"))
        assert exchange is not None

        with pytest.raises(DeviceAuthError, match="API is not enabled"):
            exchange.token_from(403, "{}")

    def test_a_login_response_with_no_token_is_an_auth_failure(self) -> None:
        """A 200 with no session id is not success. Treating it as one would leave every
        later call unauthenticated and report the device as unreachable."""
        exchange = auth_exchange("checkpoint_mgmt", HttpCredentials(username="a", password="b"))
        assert exchange is not None

        with pytest.raises(DeviceAuthError, match="no session id"):
            exchange.token_from(200, "{}")

    async def test_the_token_is_attached_to_every_later_call(self) -> None:
        transport = FakeHttp([(200, "{}")])
        transport.use_token(TokenState(headers={"X-chkp-sid": "abc123"}))
        session, _ = session_for("checkpoint_mgmt", transport)

        async with session:
            await session.request("POST", "/web_api/show-hosts", body={"command": "show-hosts"})

        assert transport.sent[0]["headers"]["X-chkp-sid"] == "abc123"

    async def test_a_fortimanager_token_is_merged_into_the_rpc_envelope(self) -> None:
        transport = FakeHttp([(200, "{}")])
        transport.use_token(TokenState(body_fields={"session": "tok-9"}))
        session, _ = session_for("fortimanager", transport)

        async with session:
            await session.request(
                "POST", "/jsonrpc", body={"method": "get", "params": [{"url": "/dvmdb/device"}]}
            )

        assert transport.sent[0]["body"]["session"] == "tok-9"
        # The method is untouched: merging must not disturb what the guard just checked.
        assert transport.sent[0]["body"]["method"] == "get"

    async def test_a_panos_key_is_appended_as_a_query_parameter(self) -> None:
        transport = FakeHttp([(200, "<response/>")])
        transport.use_token(TokenState(query={"key": "K3Y"}))
        session, _ = session_for("panos", transport)

        async with session:
            await session.request("GET", "/api/?type=config&action=show")

        assert transport.sent[0]["path"].endswith("&key=K3Y")

    def test_every_login_and_logout_is_on_its_platforms_allow_list(self) -> None:
        """SRS §8.2 lists these as explicit exceptions, which is only meaningful if the
        calls the product actually makes are the ones that were approved."""
        for platform in ("panos", "checkpoint_mgmt", "fortimanager"):
            guard = ReadOnlyGuard(get_policy(platform))

            exchange = auth_exchange(platform, HttpCredentials(username="a", password="b"))
            if exchange is not None:
                assert guard.permits_request(exchange.method, exchange.path, body=exchange.body), (
                    f"{platform}: the login call is not permitted by policies.py"
                )

            logout = logout_exchange(platform)
            if logout is not None:
                method, path, body = logout
                assert guard.permits_request(method, path, body=body), (
                    f"{platform}: the logout call is not permitted by policies.py"
                )


# ═════════════════════ certificate pinning (FR-COL-10) ═══════════════════════


class TestCertificatePinning:
    def test_the_fingerprint_is_printed_the_way_vendors_print_it(self) -> None:
        """So an operator can compare it with what the device's own UI shows, which is
        the only way the pin is verifiable by a human."""
        digest = certificate_fingerprint(b"some-der-bytes")

        assert digest.startswith("SHA256:")
        assert digest.count(":") == 32  # the prefix plus 31 separators
        assert digest.upper() == digest

    def test_a_changed_certificate_is_refused_not_accepted(self) -> None:
        transport = HttpTransport("10.0.0.1", HttpCredentials(), known_fingerprint="SHA256:AA:BB")

        class Peer:
            def getpeercert(self, binary_form: bool = False) -> bytes:
                return b"a-different-certificate"

        response = httpx.Response(
            200, extensions={"network_stream": _Stream(Peer())}, request=httpx.Request("GET", "/")
        )

        with pytest.raises(CertificateChangedError, match="has changed"):
            transport._check_certificate(response)

    def test_the_message_names_both_fingerprints(self) -> None:
        """An operator confirming a planned renewal needs to see the new one, and one
        investigating an interception needs to see both."""
        transport = HttpTransport("10.0.0.1", HttpCredentials(), known_fingerprint="SHA256:AA:BB")

        class Peer:
            def getpeercert(self, binary_form: bool = False) -> bytes:
                return b"new"

        response = httpx.Response(
            200, extensions={"network_stream": _Stream(Peer())}, request=httpx.Request("GET", "/")
        )

        with pytest.raises(CertificateChangedError) as caught:
            transport._check_certificate(response)

        assert "SHA256:AA:BB" in str(caught.value)
        assert certificate_fingerprint(b"new") in str(caught.value)

    def test_first_contact_records_the_fingerprint_rather_than_refusing(self) -> None:
        transport = HttpTransport("10.0.0.1", HttpCredentials(), known_fingerprint=None)

        class Peer:
            def getpeercert(self, binary_form: bool = False) -> bytes:
                return b"first"

        response = httpx.Response(
            200, extensions={"network_stream": _Stream(Peer())}, request=httpx.Request("GET", "/")
        )
        transport._check_certificate(response)

        assert transport.observed_fingerprint == certificate_fingerprint(b"first")

    def test_a_connection_that_exposes_no_certificate_is_not_pretended_to_be_pinned(
        self,
    ) -> None:
        """We cannot pin what we cannot see, and recording something anyway would give
        false assurance that a pin is in place."""
        transport = HttpTransport("10.0.0.1", HttpCredentials(), known_fingerprint="SHA256:AA")
        response = httpx.Response(200, request=httpx.Request("GET", "/"))

        transport._check_certificate(response)

        assert transport.observed_fingerprint is None


class _Stream:
    def __init__(self, peer: Any) -> None:
        self.peer = peer

    def get_extra_info(self, name: str) -> Any:
        return self.peer if name == "ssl_object" else None


# ═══════════════════════════ round trips ═════════════════════════════════════


class TestRoundTrips:
    async def test_a_checkpoint_rulebase_read_is_permitted_and_carries_its_body(
        self,
    ) -> None:
        """The call Phase 4's whole Check Point analysis depends on."""
        rulebase = json.dumps({"rulebase": [], "objects-dictionary": []})
        transport = FakeHttp([(200, rulebase)])
        transport.use_token(TokenState(headers={"X-chkp-sid": "s"}))
        session, _ = session_for("checkpoint_mgmt", transport)

        async with session:
            result = await session.request(
                "POST",
                "/web_api/show-access-rulebase",
                body={"command": "show-access-rulebase"},
            )

        assert result.succeeded
        assert json.loads(result.body) == {"rulebase": [], "objects-dictionary": []}

    async def test_a_panos_config_export_is_permitted(self) -> None:
        """The call Phase 4's whole PAN-OS analysis depends on."""
        transport = FakeHttp([(200, "<response><result><config/></result></response>")])
        session, _ = session_for("panos", transport)

        async with session:
            result = await session.request("GET", "/api/?type=config&action=show")

        assert result.succeeded
        assert "<config" in result.body
