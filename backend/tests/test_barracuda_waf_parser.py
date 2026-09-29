"""Barracuda WAF over the v3.2 REST API (SRS §1.3.1, FR-PARSE-01 … FR-PARSE-05).

`barracuda_waf` had a read-only allow-list and no parser, and the recorded reason was
specific: nothing in public documentation named the field that says whether a service
**blocks or merely logs**, which is the single most important fact about a WAF.

Barracuda publish the v3.2 OpenAPI specification in their own `waf-automation`
repository. `Service_basic_security.json` defines `mode` with the enum
`["Passive", "Active"]`. That is the field, and this module is built around it — a
passive WAF reports attacks in exactly the way an enforcing one does, so an appliance's
own dashboard cannot distinguish them and neither can anything else in the collection.

**The field names are authoritative; the response envelope is not.** The specification
defines every object's properties and gives no schema for a GET response. So the parser
accepts all three plausible envelopes and these tests exercise each — because a parser
that assumed the wrong one would read nothing at all, and a WAF with no services looks
exactly like an appliance nobody has configured yet.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import pytest

from netsecops.adapters.policies import get_policy
from netsecops.adapters.profiles import PROFILES
from netsecops.adapters.readonly import ReadOnlyGuard
from netsecops.ncm.models import NormalisedConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURE = Path(__file__).parent / "fixtures" / "barracuda" / "waf" / "11.0" / "bundle.json"


def parse(text: str) -> NormalisedConfig:
    return get_parser("barracuda_waf").parse(ParseContext(text=text))


@pytest.fixture(scope="module")
def ncm() -> NormalisedConfig:
    return parse(FIXTURE.read_text(encoding="utf-8"))


def listener(ncm: NormalisedConfig, name: str):
    server = next(v for v in ncm.load_balancer.virtual_servers if v.id == name)
    return server.services[0]


# ───────────────────── the commands are issued ──────────────────────────


class TestTheProfileExists:
    def test_the_platform_has_a_profile(self) -> None:
        assert "barracuda_waf" in PROFILES

    def test_it_asks_the_question_that_was_blocking_this(self) -> None:
        # `GET /services` says what the appliance publishes. It does not say whether any
        # of it is protected, and that is the endpoint this platform exists to read.
        issued = list(PROFILES["barracuda_waf"].all_commands())
        assert any("basic-security" in command for command in issued)

    def test_every_command_it_issues_is_approved(self) -> None:
        # Through the guard, which is the thing that actually runs before a request
        # leaves — asserting against the policy data alone would prove the list and not
        # the enforcement. The templated `{service}` is substituted because the guard
        # sees the expanded path.
        guard = ReadOnlyGuard(get_policy("barracuda_waf"))
        for command in PROFILES["barracuda_waf"].all_commands():
            method, _, path = command.partition(" ")
            guard.check_request(method, path.replace("{service}", "corp-www"))


# ───────────────────────── the envelope ─────────────────────────────────


class TestTheResponseEnvelope:
    """The one thing the published specification does not pin down.

    Guessing wrong reads nothing and reports a WAF with no services — indistinguishable
    from an appliance nobody has configured. So all three shapes are accepted, and each
    is tested rather than assumed.
    """

    SERVICE: ClassVar[dict[str, object]] = {
        "name": "app",
        "ip-address": "10.0.0.1",
        "port": 443,
        "type": "HTTPS",
    }

    def test_a_list_under_data(self) -> None:
        ncm = parse(json.dumps({"/services": {"data": [self.SERVICE]}}))
        assert [v.id for v in ncm.load_balancer.virtual_servers] == ["app"]

    def test_a_bare_list(self) -> None:
        ncm = parse(json.dumps({"/services": [self.SERVICE]}))
        assert [v.id for v in ncm.load_balancer.virtual_servers] == ["app"]

    def test_an_object_keyed_by_name(self) -> None:
        # The only shape where the name lives *outside* the object, so a reader that
        # only looks at the `name` field produces a service with no id.
        body = {"/services": {"data": {"app": {"ip-address": "10.0.0.1", "port": 443}}}}
        ncm = parse(json.dumps(body))
        assert [v.id for v in ncm.load_balancer.virtual_servers] == ["app"]

    def test_invalid_json_is_a_parse_failure_not_an_empty_waf(self) -> None:
        ncm = parse("{not json")
        assert ncm.parse_failed is True
        assert ncm.load_balancer.virtual_servers == []

    def test_an_empty_bundle_is_a_parse_failure(self) -> None:
        # Nothing was collected. Reporting it as a WAF publishing nothing would render
        # the most hardened appliance imaginable out of an empty file.
        assert parse("{}").parse_failed is True


# ─────────────────────── what it publishes ──────────────────────────────


class TestTheServices:
    def test_every_service(self, ncm: NormalisedConfig) -> None:
        assert {v.id for v in ncm.load_balancer.virtual_servers} == {
            "corp-www",
            "legacy-intranet",
            "retired-portal",
        }

    def test_address_and_port(self, ncm: NormalisedConfig) -> None:
        corp = next(v for v in ncm.load_balancer.virtual_servers if v.id == "corp-www")
        assert corp.address == "203.0.113.10"
        assert corp.services[0].port == 443

    def test_a_disabled_service_is_recorded_as_off_not_absent(self, ncm: NormalisedConfig) -> None:
        # `status: Off` is an answer. A service left configured but switched off is
        # hygiene, and it is only hygiene if it can be told from one nobody described.
        retired = next(v for v in ncm.load_balancer.virtual_servers if v.id == "retired-portal")
        assert retired.enabled is False

    def test_the_service_type_is_kept_as_the_vendor_wrote_it(self, ncm: NormalisedConfig) -> None:
        # `HTTP` against `HTTPS` is the cleartext question, and normalising both into a
        # boolean would lose which of several listeners was the cleartext one.
        assert listener(ncm, "legacy-intranet").service == "HTTP"


class TestEnforcement:
    """The field this whole platform was blocked on."""

    def test_an_enforcing_service_reads_as_active(self, ncm: NormalisedConfig) -> None:
        assert listener(ncm, "corp-www").enforcement == "active"

    def test_a_monitoring_only_service_reads_as_passive(self, ncm: NormalisedConfig) -> None:
        # The finding. This service inspects everything and stops nothing, and its
        # attack log looks identical to the enforcing one above.
        assert listener(ncm, "legacy-intranet").enforcement == "passive"

    def test_a_service_whose_security_was_not_collected_stays_unknown(
        self, ncm: NormalisedConfig
    ) -> None:
        # `retired-portal` has no `/basic-security` in the bundle. None, not "passive":
        # reporting an uncollected service as unprotected is a confident wrong answer,
        # and the check should say Not Evaluated.
        assert listener(ncm, "retired-portal").enforcement is None

    def test_the_policy_name_is_carried(self, ncm: NormalisedConfig) -> None:
        assert listener(ncm, "legacy-intranet").policy == "sharepoint2013"


class TestTlsPosture:
    def test_only_the_versions_actually_enabled(self, ncm: NormalisedConfig) -> None:
        assert listener(ncm, "corp-www").tls_versions == ["TLSv1.2", "TLSv1.3"]

    def test_a_listener_still_offering_tls_1_0(self, ncm: NormalisedConfig) -> None:
        # Invisible from the management plane's own TLS settings, which is why this is
        # recorded per listener rather than per device.
        assert "TLSv1.0" in listener(ncm, "legacy-intranet").tls_versions

    def test_a_version_the_appliance_did_not_mention_is_not_listed(self) -> None:
        # Absent is not disabled and it is not enabled. Listing an unmentioned version
        # as accepted invents an exposure; the empty list says nothing was read.
        body = {"/services": {"data": [{"name": "app", "port": 443}]},
                "/services/app/ssl-security": {"data": {"status": "On"}}}
        ncm = parse(json.dumps(body))
        assert listener(ncm, "app").tls_versions == []

    def test_hsts(self, ncm: NormalisedConfig) -> None:
        assert listener(ncm, "corp-www").hsts is True
        assert listener(ncm, "legacy-intranet").hsts is False

    def test_the_preset_is_named_in_the_vendors_words(self, ncm: NormalisedConfig) -> None:
        # More useful to an operator than the cipher list it expands to, and it is what
        # they would actually change.
        assert listener(ncm, "corp-www").ssl_policy == "Mozilla Modern Compatibility"


class TestBackEnds:
    def test_servers_behind_a_service(self, ncm: NormalisedConfig) -> None:
        addresses = {s.address for s in ncm.load_balancer.real_servers}
        assert {"10.20.0.11", "10.20.0.12", "intranet-app.corp.local"} <= addresses

    def test_only_in_service_counts_as_enabled(self, ncm: NormalisedConfig) -> None:
        # Three of the four statuses are forms of out-of-service. Treating anything but
        # `In Service` as live would report a maintenance node as taking traffic.
        by_address = {s.address: s for s in ncm.load_balancer.real_servers}
        assert by_address["10.20.0.11"].enabled is True
        assert by_address["10.20.0.12"].enabled is False

    def test_a_server_identified_by_hostname(self, ncm: NormalisedConfig) -> None:
        # `identifier` may be `IP Address` or `Hostname`, and a reader that only looks
        # at `ip-address` drops every back end defined by name.
        by_address = {s.address: s for s in ncm.load_balancer.real_servers}
        assert by_address["intranet-app.corp.local"].port == 8080


# ──────────────────────────── honesty ───────────────────────────────────


class TestWhatItDoesNotRead:
    def test_an_endpoint_nothing_reads_is_reported(self, ncm: NormalisedConfig) -> None:
        # Line coverage means nothing for JSON, so the honest measure is which endpoints
        # were understood. One the collector fetched and nothing reads is the gap
        # `raw_unparsed` exists to show.
        assert any("/system/security" in line for line in ncm.raw_unparsed)

    def test_the_endpoints_it_does_read_are_not_reported_as_gaps(
        self, ncm: NormalisedConfig
    ) -> None:
        joined = "\n".join(ncm.raw_unparsed)
        assert "/services'" not in joined
        assert "basic-security" not in joined

    def test_the_vendor_and_platform_are_stamped(self, ncm: NormalisedConfig) -> None:
        assert (ncm.device.vendor, ncm.device.platform) == ("barracuda", "barracuda_waf")
