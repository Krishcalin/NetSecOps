"""The read-only contract for a Barracuda Web Application Firewall (SRS §1.3.1, §8.1).

Unlike Check Point's Management API, this is a genuine REST API: the reads are GETs and
the guard's method restriction carries the guarantee. **Login is the one POST**, which
SRS §8.1 item 3 permits for authentication specifically.

The risk here is not the method, it is the *prefix*. A single rule spelled
`HttpRule("POST", "/restapi/")` would read as "POST is allowed for authentication" and
would in fact admit a POST to every object on the appliance — which on this API is how
a service is created rather than read. So the login paths are enumerated per version
and the tests below hold them to it.

There is no collection profile and no parser yet, and that is deliberate rather than
unfinished: only `services` is a confirmed object path, and nothing in Barracuda's
public documentation names the field that says whether a service blocks or merely logs
— the single most important fact about a WAF. What can be reviewed today is what
NetSecOps would be permitted to send.
"""

from __future__ import annotations

import pytest

from netsecops.adapters.policies import POLICIES
from netsecops.adapters.profiles import PROFILES
from netsecops.adapters.readonly import ReadOnlyGuard
from netsecops.core.errors import ReadOnlyViolationError
from netsecops.parsers.registry import PARSERS


@pytest.fixture
def guard() -> ReadOnlyGuard:
    return ReadOnlyGuard(POLICIES["barracuda_waf"])


class TestReadsAreGets:
    @pytest.mark.parametrize(
        "path",
        [
            "/restapi/v3.2/services",
            "/restapi/v3.2/services/service_app1",
            "/restapi/v3.2/vsites/1/service_groups/2",
            "/restapi/v3.1/services",
        ],
    )
    def test_an_object_read_is_permitted(self, guard: ReadOnlyGuard, path: str) -> None:
        guard.check_request("GET", path)

    def test_a_version_the_policy_does_not_name_is_refused(self, guard: ReadOnlyGuard) -> None:
        """A firmware carrying a new API version is a deliberate addition, not a
        silent one — the object paths may have moved with it."""
        with pytest.raises(ReadOnlyViolationError):
            guard.check_request("GET", "/restapi/v4.0/services")

    def test_nothing_outside_the_api_is_reachable(self, guard: ReadOnlyGuard) -> None:
        with pytest.raises(ReadOnlyViolationError):
            guard.check_request("GET", "/cgi-mod/index.cgi")


class TestLoginIsTheOnlyPost:
    def test_the_token_endpoint_is_permitted(self, guard: ReadOnlyGuard) -> None:
        guard.check_request("POST", "/restapi/v3.2/login", body={"username": "x", "password": "y"})

    def test_the_older_firmware_can_still_authenticate(self, guard: ReadOnlyGuard) -> None:
        guard.check_request("POST", "/restapi/v3.1/login", body={"username": "x", "password": "y"})

    @pytest.mark.parametrize(
        "path",
        [
            "/restapi/v3.2/services",
            "/restapi/v3.2/security_policies",
            "/restapi/v3.2/certificates",
            "/restapi/v3.2/vsites/1/service_groups",
        ],
    )
    def test_posting_to_an_object_creates_one_and_is_refused(
        self, guard: ReadOnlyGuard, path: str
    ) -> None:
        """The reason the login rule names a path instead of a prefix.

        `POST /restapi/v3.2/services` is how a service is *created* on this API. A rule
        spelled `HttpRule("POST", "/restapi/")` would read as "POST for authentication"
        and permit every one of these.
        """
        with pytest.raises(ReadOnlyViolationError):
            guard.check_request("POST", path, body={"name": "new"})

    @pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
    def test_no_other_method_is_permitted_anywhere(self, guard: ReadOnlyGuard, method: str) -> None:
        """Enforced by `check_request` before the policy is consulted, not by this
        policy's contents.

        Worth knowing where: adding `HttpRule("PUT", …)` to this platform changes
        nothing, because the method is refused two lines earlier. A mutation proving
        that is an equivalent one, and the property is still worth asserting per
        platform — it is what a reviewer reading this file needs to be true.
        """
        with pytest.raises(ReadOnlyViolationError):
            guard.check_request(method, "/restapi/v3.2/services/service_app1")

    def test_the_policy_declares_exactly_two_posts(self) -> None:
        # Pinned as a count as well as by path: a third POST rule added later is a
        # decision somebody should have to make deliberately.
        posts = [rule for rule in POLICIES["barracuda_waf"].http if rule.method == "POST"]

        assert [rule.path_prefix for rule in posts] == [
            "/restapi/v3.2/login",
            "/restapi/v3.1/login",
        ]
        assert all(rule.reason for rule in posts), "a POST rule must say why it exists"


class TestItIsCollectableNow:
    """This class used to assert the opposite, and the reason it did was sound.

    A profile implies a parser, a parser needs field names, and public documentation did
    not carry them — the ISE `admin/settings` divergence in `vendor-research.md` §4a is
    the same mistake and it cost a permanently empty NCM section.

    What changed is the evidence, not the standard: Barracuda publish the **v3.2 OpenAPI
    specification** in their own `barracudanetworks/waf-automation` repository, which
    defines every object's properties — including `mode: Active|Passive`, the field the
    old note said nothing named.
    """

    def test_the_platform_is_now_fully_wired(self) -> None:
        assert "barracuda_waf" in POLICIES
        assert "barracuda_waf" in PROFILES
        assert "barracuda_waf" in PARSERS

    def test_the_profile_reads_the_field_that_was_missing(self) -> None:
        # The specific thing whose absence blocked this platform. A WAF that publishes
        # services and cannot say whether any of them enforce is not worth collecting.
        assert any(
            "basic-security" in command for command in PROFILES["barracuda_waf"].all_commands()
        )
