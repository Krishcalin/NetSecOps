"""Cisco WLC AireOS parser (FR-PARSE-01 … FR-PARSE-05, Phase 5 wireless).

AireOS is a flat list of `config ...` commands with no blocks, and a WLAN's settings are
scattered across a dozen lines that share only a numeric id. Two things follow, and both
are the kind of defect that produces a confident wrong answer rather than an obvious
failure:

**The id is the last token, not the first.** `config wlan security wpa enable 3` and
`... enable 13` differ only in a trailing character, so a parser that matched loosely
would apply one WLAN's security to another. `test_similar_ids_do_not_bleed_into_each_other`
is the guard, and the fixture carries WLAN 1 and WLAN 13 deliberately.

**Security is derived from three separate settings**, and a wrong verdict here drives the
"no open SSIDs" and "no PSK on an enterprise network" checks. Reporting a WLAN as
`wpa2-psk` when it is open is the worst outcome this parser can produce, so `_classify`
returns None on incomplete evidence rather than guessing.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURE = Path(__file__).parent / "fixtures/cisco/wlc/8.10/campus_wlc.txt"

#: Secrets planted in the fixture. Every one must be absent from the NCM, from provenance
#: excerpts and from raw_unparsed.
PLANTED = (
    "Sup3rS3cret!",
    "Aud1tP4ss!",
    "R4d1usK3y!Secret",
    "T4c4csK3y!Secret",
    "Ro-Community-9f3a",
)


@pytest.fixture(scope="module")
def config_text() -> str:
    return FIXTURE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ncm(config_text: str) -> dict[str, Any]:
    return get_parser("cisco_wlc_aireos").parse(ParseContext(text=config_text)).to_storage()


def wlans(ncm: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {w["ssid"]: w for w in ncm["wireless"]["wlans"]}


class TestDeviceIdentity:
    def test_identity(self, ncm: dict[str, Any]) -> None:
        device = ncm["device"]
        assert device["hostname"] == "campus-wlc-01"
        assert device["vendor"] == "cisco"
        assert device["platform"] == "cisco_wlc_aireos"

    def test_the_version_comes_from_show_sysinfo(self, ncm: dict[str, Any]) -> None:
        """The command list carries no version; `show sysinfo` does, and the collection
        appends it. Without this the vulnerability matcher has nothing to match on."""
        assert ncm["device"]["version"] == "8.10.190.0"
        assert ncm["device"]["model"] == "AIR-CT5520-K9"


class TestWlanSecurityClassification:
    @pytest.mark.parametrize(
        ("ssid", "expected"),
        [
            ("Corp-WiFi", "wpa2-ent"),
            ("Guest-WiFi", "open"),
            ("Legacy-Scanners", "wpa1"),
            ("Staff-PSK", "wpa2-psk"),
            ("Contractor-WiFi", "wpa3-sae"),
        ],
    )
    def test_each_wlan_is_classified(self, ncm: dict[str, Any], ssid: str, expected: str) -> None:
        """AireOS has no single line saying what a WLAN's security is — it is the
        combination of WPA version, AKM and cipher. This is the assembly."""
        assert wlans(ncm)[ssid]["security"] == expected

    def test_similar_ids_do_not_bleed_into_each_other(self, ncm: dict[str, Any]) -> None:
        """WLAN 1 is enterprise and WLAN 13 is WPA3-SAE. They differ by a trailing
        character on every line, and a loose match would give one the other's security.
        """
        found = wlans(ncm)
        assert found["Corp-WiFi"]["security"] == "wpa2-ent"
        assert found["Contractor-WiFi"]["security"] == "wpa3-sae"
        assert found["Corp-WiFi"]["pmf"] == "required"

    def test_an_open_network_is_never_reported_as_protected(self, ncm: dict[str, Any]) -> None:
        """The worst possible failure of this parser: reporting a genuinely open guest
        network as secured means nobody ever looks at it."""
        assert wlans(ncm)["Guest-WiFi"]["security"] == "open"

    def test_incomplete_evidence_yields_none_rather_than_a_guess(self) -> None:
        """A WLAN that turned security on without saying which kind. Unknown makes the
        check report Not Evaluated; "open" would be a serious false positive and
        "wpa2" a serious false negative."""
        config = "config wlan create 7 Odd Odd\nconfig wlan security wpa enable 7\n"
        parsed = get_parser("cisco_wlc_aireos").parse(ParseContext(text=config)).to_storage()

        assert parsed["wireless"]["wlans"][0]["security"] is None


class TestWlanSettings:
    def test_enabled_state(self, ncm: dict[str, Any]) -> None:
        found = wlans(ncm)
        assert found["Corp-WiFi"]["enabled"] is True
        assert found["Contractor-WiFi"]["enabled"] is False

    def test_broadcast_and_pmf(self, ncm: dict[str, Any]) -> None:
        found = wlans(ncm)
        assert found["Legacy-Scanners"]["broadcast"] is False
        assert found["Legacy-Scanners"]["pmf"] == "disable"
        assert found["Staff-PSK"]["pmf"] == "optional"

    def test_client_isolation_distinguishes_off_from_unstated(self, ncm: dict[str, Any]) -> None:
        """`peer-blocking disable` on a guest network is the finding. Unstated is not the
        same fact, and must not be reported as though someone turned it off."""
        found = wlans(ncm)
        assert found["Guest-WiFi"]["client_isolation"] is False
        assert found["Staff-PSK"]["client_isolation"] is True
        assert found["Corp-WiFi"]["client_isolation"] is None

    def test_fast_transition(self, ncm: dict[str, Any]) -> None:
        assert wlans(ncm)["Corp-WiFi"]["fast_transition"] is True

    def test_rogue_detection_state_is_recorded(self, ncm: dict[str, Any]) -> None:
        assert ncm["wireless"]["rogue_detection"]["enabled"] is True


class TestAaaAndManagement:
    def test_radius_and_tacacs_servers_are_parsed(self, ncm: dict[str, Any]) -> None:
        servers = ncm["aaa"]["servers"]
        by_type = {(s["type"], s["host"]) for s in servers}

        assert ("radius", "10.100.5.60") in by_type
        assert ("tacacs", "10.100.5.70") in by_type

    def test_a_configured_secret_is_recorded_without_storing_it(self, ncm: dict[str, Any]) -> None:
        """C-2: the check needs to know a secret is present, never what it is."""
        assert all(s["key_configured"] for s in ncm["aaa"]["servers"])
        assert "key" not in json.dumps(ncm["aaa"]["servers"]).lower().replace("key_", "")

    def test_the_management_auth_order_is_recorded(self, ncm: dict[str, Any]) -> None:
        """`config aaa auth mgmt local tacacs+` would mean the controller never asks the
        AAA server. The order is the finding, so it is stored as a list."""
        methods = ncm["aaa"]["authentication"][0]["methods"]
        assert methods == ["tacacs+", "local"]
        assert ncm["aaa"]["local_fallback"] is True

    def test_management_services(self, ncm: dict[str, Any]) -> None:
        services = ncm["management"]["services"]
        assert services["telnet"]["enabled"] is False
        assert services["ssh"]["enabled"] is True
        # `webmode` is AireOS for plain HTTP administration.
        assert services["http"]["enabled"] is True
        assert services["https"]["enabled"] is True

    def test_the_timeout_is_converted_to_seconds(self, ncm: dict[str, Any]) -> None:
        assert ncm["management"]["session"]["exec_timeout_s"] == 1800

    def test_administrators_and_their_roles(self, ncm: dict[str, Any]) -> None:
        users = {u["name"]: u for u in ncm["users"]}
        assert users["admin"]["role"] == "read-write"
        assert users["admin"]["privilege"] == 15
        assert users["auditor"]["privilege"] is None

    def test_snmp_communities_are_masked_and_the_default_is_flagged(
        self, ncm: dict[str, Any]
    ) -> None:
        communities = ncm["snmp"]["v1v2c_communities"]
        assert len(communities) == 2
        assert any(c["is_default"] for c in communities)
        assert not any("public" in c["name_masked"] for c in communities)

    def test_syslog_ntp_and_interfaces(self, ncm: dict[str, Any]) -> None:
        assert [s["host"] for s in ncm["logging"]["syslog_servers"]] == ["10.100.5.10"]
        assert len(ncm["ntp"]["servers"]) == 2

        interfaces = {i["name"]: i for i in ncm["interfaces"]}
        assert interfaces["management"]["ip_addresses"] == ["10.100.0.30"]
        assert interfaces["guest-30"]["vlan"] == 30


class TestParserHealth:
    def test_no_section_fails_silently(
        self, config_text: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The tripwire carried from FortiOS and PAN-OS, where it has caught three real
        silent failures."""
        with caplog.at_level(logging.WARNING):
            get_parser("cisco_wlc_aireos").parse(ParseContext(text=config_text))

        failures = [r for r in caplog.records if "section_failed" in r.getMessage()]
        assert not failures, [r.getMessage() for r in failures]

    def test_coverage_meets_the_parser_floor(self, config_text: str, ncm: dict[str, Any]) -> None:
        meaningful = [line for line in config_text.splitlines() if line.strip()]
        coverage = 100 * (len(meaningful) - len(ncm["raw_unparsed"])) / len(meaningful)
        assert coverage >= 90, f"{coverage:.1f}% — unparsed: {ncm['raw_unparsed'][:10]}"

    def test_no_secret_reaches_the_ncm(self, ncm: dict[str, Any]) -> None:
        """C-2, and the reason two AireOS redaction rules exist.

        AireOS puts its secrets in *positional* arguments — `config radius auth add 1
        10.0.0.1 1812 ascii <secret>` — so none of the keyword-driven rules written for
        IOS or FortiOS matched, and all five planted secrets reached provenance excerpts
        on the first run of this parser.
        """
        serialised = json.dumps(ncm)
        leaked = [secret for secret in PLANTED if secret in serialised]
        assert not leaked, f"{leaked} reached the NCM"

    def test_every_planted_secret_is_actually_in_the_fixture(self, config_text: str) -> None:
        """A leak test that searches for a string no fixture contains proves nothing."""
        for secret in PLANTED:
            assert secret in config_text, f"{secret} is not planted; the leak test is vacuous"

    def test_provenance_points_at_real_lines(self, config_text: str, ncm: dict[str, Any]) -> None:
        line_count = len(config_text.splitlines())
        entries = ncm["provenance"]["entries"]

        assert entries
        for path, entry in entries.items():
            assert 1 <= entry["line_start"] <= line_count, f"{path} points outside the file"

    def test_garbage_does_not_raise(self) -> None:
        assert (
            get_parser("cisco_wlc_aireos").parse(ParseContext(text="config\n\x00\nwlan"))
            is not None
        )

    def test_an_empty_configuration_does_not_raise(self) -> None:
        parsed = get_parser("cisco_wlc_aireos").parse(ParseContext(text=""))
        assert parsed.device.hostname is None
        assert parsed.wireless.wlans == []

    def test_a_setting_for_a_wlan_that_was_never_created_is_kept(self) -> None:
        """Evidence that something exists which we failed to read fully is still
        evidence. Dropping it would hide a WLAN rather than report it incompletely."""
        config = "config wlan security wpa wpa2 enable 9\nconfig wlan enable 9\n"
        parsed = get_parser("cisco_wlc_aireos").parse(ParseContext(text=config)).to_storage()

        assert parsed["wireless"]["wlans"][0]["ssid"] == "wlan-9"


class TestTheRedactionRulesThisParserNeeded:
    """Both directions, because the first fix over-matched.

    The unanchored `community` rule — needed for ASA's inline
    `snmp-server host <ip> community <secret>` — matched AireOS's
    `config snmp community create <name>` and redacted the word *create*, leaving the
    real community in a line that now contained a placeholder and so looked handled. A
    rule that half-fires is worse than one that misses: a miss is caught by the leak
    tests, and that was not.
    """

    @pytest.mark.parametrize(
        "line",
        [
            "config radius auth add 1 10.0.0.1 1812 ascii R4d1usK3y!Secret",
            "config radius acct add 1 10.0.0.1 1813 ascii R4d1usK3y!Secret",
            "config tacacs auth add 1 10.0.0.2 49 ascii T4c4csK3y!Secret",
            "config mgmtuser add admin Sup3rS3cret! read-write",
            "config snmp community create Ro-Community-9f3a",
        ],
    )
    def test_an_aireos_secret_is_redacted(self, line: str) -> None:
        from netsecops.core.redaction import redact_line

        redacted, _ = redact_line(line)
        assert "«redacted:" in redacted
        for token in ("R4d1usK3y!Secret", "T4c4csK3y!Secret", "Sup3rS3cret!", "Ro-Community-9f3a"):
            assert token not in redacted

    def test_the_management_role_survives_redaction(self) -> None:
        """The role is what the least-privilege check reads. Redacting the whole tail of
        the line would protect the password and blind the check."""
        from netsecops.core.redaction import redact_line

        redacted, _ = redact_line("config mgmtuser add admin Sup3rS3cret! read-write")
        assert redacted.endswith("read-write")

    @pytest.mark.parametrize(
        "line",
        [
            "snmp-server community S3cretCommunity RO",
            "snmp-server host 10.0.0.1 community S3cretCommunity version 2c",
        ],
    )
    def test_the_ios_and_asa_forms_still_redact(self, line: str) -> None:
        """The lookahead added for AireOS must not have narrowed the rule that was
        already working."""
        from netsecops.core.redaction import redact_line

        redacted, _ = redact_line(line)
        assert "S3cretCommunity" not in redacted

    def test_an_aireos_line_with_no_secret_is_left_alone(self) -> None:
        from netsecops.core.redaction import redact_line

        redacted, _ = redact_line("config snmp community mode enable")
        assert redacted == "config snmp community mode enable"
