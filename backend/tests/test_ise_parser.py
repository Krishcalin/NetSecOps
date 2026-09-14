"""Cisco ISE parser (FR-AAA-02).

ISE is the service the rest of the estate authenticates against, so its parser answers a
different question from every other one here: not "is this device configured safely" but
"what is this server prepared to accept, and from whom".

Two things are worth more than the rest.

**The allowed-protocols list.** ISE ships a default protocol set permitting PAP, CHAP,
MS-CHAPv1 and EAP-MD5, and almost nobody narrows it because doing so breaks whichever
forgotten device still needs one. Every weak method any policy will accept is flattened
into a single list, because a single rule still accepting MS-CHAPv1 is a way in
regardless of how careful the other forty are.

**The network-device list.** It is half of the FR-AAA-05 correlation: a switch
configured on ISE and absent from inventory is a device being authenticated against and
assessed by nothing.

Also pinned here: a real `False` from ISE must survive as `False`. `admin_mfa_enabled`
came through as None because the code read two keys with `or`, and `False or None` is
None — so a deployment that explicitly reported MFA *disabled*, which is the finding,
was reported as "not determined" and the check said Not Evaluated.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from netsecops.ncm.models import AaaServerConfig
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURE = Path(__file__).parent / "fixtures/cisco/ise/3.2/ise_deployment.json"


@pytest.fixture(scope="module")
def bundle_text() -> str:
    return FIXTURE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ncm(bundle_text: str) -> dict[str, Any]:
    return get_parser("cisco_ise").parse(ParseContext(text=bundle_text)).to_storage()


def server(ncm: dict[str, Any]) -> dict[str, Any]:
    return ncm["aaa_server"]


class TestTheApiShapes:
    """ERS and OpenAPI disagree about everything, including how to wrap a list."""

    def test_an_ers_search_result_is_read(self, ncm: dict[str, Any]) -> None:
        """`{"SearchResult": {"resources": [...]}}` — the legacy shape."""
        assert len(server(ncm)["clients"]) == 3

    def test_a_bare_openapi_list_is_read(self, ncm: dict[str, Any]) -> None:
        """`[...]` — the newer shape, used here for identity stores and policies."""
        assert any(s["type"] == "ldap" for s in server(ncm)["identity_stores"])

    def test_a_response_wrapper_is_read(self) -> None:
        config = json.dumps({"networkdevice": {"response": [{"name": "sw-1"}]}})
        parsed = get_parser("cisco_ise").parse(ParseContext(text=config)).to_storage()
        assert parsed["aaa_server"]["clients"][0]["name"] == "sw-1"

    def test_an_ers_detail_object_is_unwrapped(self) -> None:
        """A single-object ERS response nests it under its own type name."""
        config = json.dumps({"networkdevice": {"NetworkDevice": {"name": "sw-detail"}}})
        parsed = get_parser("cisco_ise").parse(ParseContext(text=config)).to_storage()
        assert parsed["aaa_server"]["clients"][0]["name"] == "sw-detail"


class TestNetworkDevices:
    def test_every_client_is_listed(self, ncm: dict[str, Any]) -> None:
        names = {c["name"] for c in server(ncm)["clients"]}
        assert names == {"core-sw-01", "campus-wlc-01", "branch-sw-99"}

    def test_addresses_are_extracted_for_the_correlation(self, ncm: dict[str, Any]) -> None:
        """FR-AAA-05 matches these against inventory, so an address that failed to parse
        would silently drop a device out of the correlation and report it as neither
        present nor orphaned."""
        by_name = {c["name"]: c for c in server(ncm)["clients"]}
        assert by_name["core-sw-01"]["address"] == "198.51.100.31"
        assert by_name["branch-sw-99"]["address"] == "10.77.0.9"

    def test_a_shared_secret_is_recorded_as_present_not_stored(self, ncm: dict[str, Any]) -> None:
        assert all(c["secret_configured"] for c in server(ncm)["clients"])

    def test_the_secret_fingerprint_is_none_because_ise_never_exposes_one(
        self, ncm: dict[str, Any]
    ) -> None:
        """FR-AAA-05 asks that shared-secret reuse be flagged as *unknown* where the
        source does not expose the secret. ISE returns `********`, so a fingerprint of
        it would be identical for every device and would report the whole estate as
        sharing one key — a confident, completely wrong finding."""
        assert all(c["secret_fingerprint"] is None for c in server(ncm)["clients"])

    def test_dtls_is_carried(self, ncm: dict[str, Any]) -> None:
        by_name = {c["name"]: c for c in server(ncm)["clients"]}
        assert by_name["campus-wlc-01"]["tls"] is True
        assert by_name["core-sw-01"]["tls"] is False


class TestAllowedProtocols:
    def test_every_permitted_protocol_is_collected(self, ncm: dict[str, Any]) -> None:
        protocols = set(server(ncm)["allowed_protocols"])
        assert {"PAP", "CHAP", "MS-CHAPv1", "MS-CHAPv2", "EAP-MD5", "EAP-TLS", "PEAP"} <= protocols

    def test_a_disabled_protocol_is_not_listed(self, ncm: dict[str, Any]) -> None:
        """LEAP is `false` in the fixture. Listing it would produce a finding about
        something nobody has enabled."""
        assert "LEAP" not in server(ncm)["allowed_protocols"]

    def test_inner_eap_methods_are_collected_too(self, ncm: dict[str, Any]) -> None:
        """A PEAP tunnel that still permits MS-CHAPv1 inside it is the classic ISE
        finding, and the setting is nested one level down where a flat scan misses it."""
        assert "MS-CHAPv2" in server(ncm)["allowed_protocols"]

    def test_the_weak_ones_are_identified(self, ncm: dict[str, Any]) -> None:
        weak = AaaServerConfig.model_validate(server(ncm)).weak_protocols
        assert weak == ["CHAP", "EAP-MD5", "MS-CHAPv1", "PAP"]

    def test_tls_versions_are_named_not_sliced(self, ncm: dict[str, Any]) -> None:
        """Deriving the version from character positions in the key produced "TLSLS1.2",
        which is not a TLS version and would never match a check comparing against
        "TLS1.0"."""
        assert server(ncm)["tls_versions"] == ["TLS1.2"]


class TestPolicyAndIdentity:
    def test_authentication_and_authorisation_rules_keep_their_order(
        self, ncm: dict[str, Any]
    ) -> None:
        """Order decides which rule wins, exactly as in a firewall rulebase."""
        auth = [p for p in server(ncm)["policies"] if p["kind"] == "authentication"]
        assert [p["order"] for p in auth] == [1, 2]
        assert auth[0]["name"] == "Wired 802.1X"

    def test_a_disabled_rule_is_marked_disabled(self, ncm: dict[str, Any]) -> None:
        by_name = {p["name"]: p for p in server(ncm)["policies"]}
        assert by_name["Legacy printers"]["enabled"] is False
        assert by_name["Corp laptops"]["enabled"] is True

    def test_a_condition_is_summarised_readably(self, ncm: dict[str, Any]) -> None:
        """The full ISE condition is a nested tree that is unreadable in a finding and
        enormous in the NCM. The summary is enough to recognise the rule in the
        console, which is where the whole thing should be read."""
        by_name = {p["name"]: p for p in server(ncm)["policies"]}
        assert by_name["Wired 802.1X"]["condition"] == "Radius-NAS-Port-Type equals Ethernet"

    def test_identity_stores_are_listed_with_their_transport(self, ncm: dict[str, Any]) -> None:
        """An LDAP identity source without TLS carries credentials across the network on
        every authentication."""
        stores = {s["name"]: s for s in server(ncm)["identity_stores"]}
        assert stores["corp-ad"]["type"] == "active-directory"
        assert stores["partner-ldap"]["tls"] is False


class TestCommandSetsAndAdmins:
    def test_command_sets_are_parsed(self, ncm: dict[str, Any]) -> None:
        sets = {c["name"]: c for c in server(ncm)["command_sets"]}
        assert sets["ReadOnly-Commands"]["commands"] == ["PERMIT show", "DENY configure"]

    def test_permit_unmatched_is_surfaced(self, ncm: dict[str, Any]) -> None:
        """A set permitting anything unmatched makes every rule in it advisory. It is
        one boolean among many in the console and easy to miss."""
        sets = {c["name"]: c for c in server(ncm)["command_sets"]}
        assert sets["NetworkAdmin"]["permit_unmatched"] is True
        assert sets["ReadOnly-Commands"]["permit_unmatched"] is False

    def test_administrators_and_their_roles(self, ncm: dict[str, Any]) -> None:
        users = {u["name"]: u for u in ncm["users"]}
        assert users["iseadmin"]["privilege"] == 15
        assert users["auditor"]["privilege"] is None

    def test_the_admin_session_timeout_is_converted_to_seconds(self, ncm: dict[str, Any]) -> None:
        assert server(ncm)["admin_session_timeout_s"] == 1800

    def test_mfa_disabled_survives_as_false_not_unknown(self, ncm: dict[str, Any]) -> None:
        """The bug this pins: the code read two keys with `or`, and `False or None` is
        None. A deployment explicitly reporting MFA *disabled* — the finding — came
        through as "not determined", so the check reported Not Evaluated and nobody saw
        it. A real False is an answer.
        """
        assert server(ncm)["admin_mfa_enabled"] is False

    def test_an_absent_mfa_setting_is_still_unknown(self) -> None:
        """The other direction: a deployment that did not report it must not be reported
        as having MFA off."""
        config = json.dumps({"admin/settings": [{"sessionTimeout": 10}]})
        parsed = get_parser("cisco_ise").parse(ParseContext(text=config)).to_storage()
        assert parsed["aaa_server"]["admin_mfa_enabled"] is None


class TestParserHealth:
    def test_no_section_fails_silently(
        self, bundle_text: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            get_parser("cisco_ise").parse(ParseContext(text=bundle_text))

        failures = [r for r in caplog.records if "section_failed" in r.getMessage()]
        assert not failures, [r.getMessage() for r in failures]

    def test_the_product_is_identified(self, ncm: dict[str, Any]) -> None:
        """Which server-side checks apply turns on this."""
        assert server(ncm)["product"] == "ise"

    def test_a_response_nothing_reads_is_reported(self) -> None:
        """A response the collector fetched and no rule here reads is a silent gap: the
        data arrived, the check that needed it reported Not Evaluated, and nothing
        connected the two. Asked of the bundle as it is read, so the claim cannot drift
        from the code the way a hand-kept list of "endpoints we read" did."""
        config = json.dumps(
            {
                "networkdevice": {"SearchResult": {"resources": [{"name": "sw"}]}},
                "show-unicorns": {"response": [{"horn": True}]},
            }
        )
        parsed = get_parser("cisco_ise").parse(ParseContext(text=config)).to_storage()

        assert parsed["raw_unparsed"] == ["1: no rule reads the response to 'show-unicorns'"]

    def test_every_response_the_collector_asks_for_is_read(self, ncm: dict[str, Any]) -> None:
        """The regression guard for the drift this replaced. The fixture mirrors what the
        collection profile requests, so an endpoint added to the profile without a rule
        to read it fails here rather than being quietly listed as "known"."""
        assert ncm["raw_unparsed"] == []

    def test_an_endpoint_whose_section_crashed_is_reported_unread(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Correct, and the more useful answer. The response was collected and its
        contents did not reach the NCM, which is what the reader needs to know —
        reporting it as read because a rule *tried* would hide a broken parser."""
        parser = get_parser("cisco_ise")
        monkeypatch.setattr(
            type(parser),
            "_parse_network_devices",
            lambda self, bundle, result: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        config = json.dumps({"networkdevice": {"SearchResult": {"resources": [{"name": "sw"}]}}})

        parsed = parser.parse(ParseContext(text=config)).to_storage()

        assert parsed["raw_unparsed"] == ["1: no rule reads the response to 'networkdevice'"]

    def test_a_partial_collection_still_yields_what_arrived(self) -> None:
        """FR-COL-08. If the policy endpoint returned 403 because the account lacks the
        role, the network devices are still read and only the policy checks report Not
        Evaluated."""
        config = json.dumps({"networkdevice": {"SearchResult": {"resources": [{"name": "sw"}]}}})
        parsed = get_parser("cisco_ise").parse(ParseContext(text=config)).to_storage()

        assert len(parsed["aaa_server"]["clients"]) == 1
        assert parsed["aaa_server"]["policies"] == []
        assert parsed["aaa_server"]["allowed_protocols"] == []

    def test_malformed_json_produces_a_snapshot_rather_than_an_exception(self) -> None:
        result = get_parser("cisco_ise").parse(ParseContext(text='{"truncated": '))

        assert result.device.vendor == "cisco"
        assert result.raw_unparsed and "not valid JSON" in result.raw_unparsed[0]

    def test_an_empty_artefact_does_not_raise(self) -> None:
        assert get_parser("cisco_ise").parse(ParseContext(text="")).device.hostname is None

    def test_a_switch_ncm_has_an_empty_aaa_server_block(self) -> None:
        """The block is additive to NCM v1, so a snapshot from before Phase 5
        deserialises unchanged and every server-side check on an ordinary switch reports
        Not Evaluated — which is the honest answer for a device that is not an AAA
        server."""
        from netsecops.ncm.models import NormalisedConfig

        assert NormalisedConfig().aaa_server.clients == []
        assert NormalisedConfig().aaa_server.product is None


# ═════════════════════ the rest of FR-AAA-02's list ═════════════════════════


class TestDeviceGroups:
    def test_the_hierarchy_survives_rather_than_being_one_opaque_string(
        self, ncm: dict[str, Any]
    ) -> None:
        """An ISE rule reads `Device Type#All Device Types#Switches`. Stored whole, the
        group is unsearchable and its place in the tree is invisible; split, a reader can
        see what the rule actually matches."""
        groups = {g["name"]: g for g in server(ncm)["device_groups"]}

        assert groups["Switches"]["parent"] == "Device Type#All Device Types"
        assert groups["Switches"]["kind"] == "Device Type"
        assert groups["Campus-North"]["kind"] == "Location"

    def test_a_root_group_has_no_parent(self, ncm: dict[str, Any]) -> None:
        groups = {g["name"]: g for g in server(ncm)["device_groups"]}

        assert groups["All Device Types"]["parent"] is None


class TestInternalUsers:
    def test_accounts_in_ise_own_store_are_recorded(self, ncm: dict[str, Any]) -> None:
        """These survive a directory outage and, more often, a leaver process built
        entirely around the directory."""
        names = [u["name"] for u in ncm["users"]]

        assert "svc-guest-sponsor" in names
        assert "contractor-jm" in names

    def test_no_password_material_is_invented(self, ncm: dict[str, Any]) -> None:
        """ISE returns no hash, so the weak-hash checks must report Not Evaluated rather
        than concluding anything from the silence."""
        user = next(u for u in ncm["users"] if u["name"] == "svc-guest-sponsor")

        assert user["secret_type"] is None
        assert user["weak_hash"] is None


class TestGuestAccess:
    def test_self_registration_without_sponsor_approval_is_visible(
        self, ncm: dict[str, Any]
    ) -> None:
        """The pairing is the finding. Self-registration alone is a deliberate choice;
        self-registration with no sponsor approval is network access for anyone within
        radio range, and it is the shipped default."""
        guest = server(ncm)["guest"]

        assert guest["self_registration"] is True
        assert guest["sponsor_approval_required"] is False

    def test_the_block_is_absent_rather_than_empty_when_not_collected(self) -> None:
        """An empty object reads as "we looked and there is no guest access", which is a
        different claim from "the endpoint was not collected"."""
        parsed = get_parser("cisco_ise").parse(ParseContext(text="{}")).to_storage()

        assert parsed["aaa_server"]["guest"] is None

    def test_account_duration_and_portals_are_carried(self, ncm: dict[str, Any]) -> None:
        guest = server(ncm)["guest"]

        assert guest["max_account_duration_days"] == 90
        assert "Self-Registered Guest Portal" in guest["portals"]


class TestRepositoriesAndBackup:
    def test_an_unencrypted_transport_is_marked(self, ncm: dict[str, Any]) -> None:
        """An ISE backup holds every shared secret and certificate in the estate, so FTP
        here moves the estate's credentials across the network in the clear."""
        repositories = {r["name"]: r for r in server(ncm)["repositories"]}

        assert repositories["campus-backup"]["encrypted_transport"] is True
        assert repositories["legacy-ftp"]["encrypted_transport"] is False

    def test_an_unrecognised_protocol_stays_unknown(self) -> None:
        """None, not False. Defaulting to False would assert an insecurity nobody
        observed, and a finding invented that way is worse than a gap."""
        config = json.dumps({"repository": {"response": [{"name": "x", "protocol": "quic-ish"}]}})
        parsed = get_parser("cisco_ise").parse(ParseContext(text=config)).to_storage()

        assert parsed["aaa_server"]["repositories"][0]["encrypted_transport"] is None

    def test_backup_status_separates_scheduled_from_succeeding(self, ncm: dict[str, Any]) -> None:
        """A schedule that has been failing since a password change looks identical to a
        healthy one in the configuration alone."""
        backup = server(ncm)["backup"]

        assert backup["scheduled"] is True
        assert backup["last_backup_status"] == "SUCCESS"
        assert backup["repository"] == "campus-backup"

    def test_the_date_is_kept_as_the_device_printed_it(self, ncm: dict[str, Any]) -> None:
        """Interpretation belongs in `ncm.certificates`, where the formats are listed and
        tested together. A parser that reformats a date can reformat it wrong."""
        assert server(ncm)["backup"]["last_backup_at"] == "Wed Sep 10 02:00:00 UTC 2026"
