"""Wireless parsing across all three controller platforms (Phase 5).

Three vendors express the same fact three different ways, and the NCM has one
vocabulary so a check never has to know which controller a WLAN came from. That makes
the *mapping* the risk, and each platform has its own trap:

**Catalyst 9800 states security by negation.** `no security wpa` is what makes a WLAN
open. This codebase has been bitten three times by a regex anchored so it cannot match
the negated form, leaving the interesting state unrecorded and the check reporting Not
Evaluated forever. Here the negated state *is* the finding.

**AireOS assembles it from three separate lines** joined by a numeric id that sits at the
end of each — covered in `test_wlc_parser.py`.

**FortiOS states it in one token whose name lies.** `wpa-only-personal` is WPA2 Personal
*only*; it is `wpa-personal`, without the `-only-`, that is the mixed WPA1/WPA2 legacy
mode. Read the wrong way round, every modern FortiAP SSID reports as WPA1 and every
genuinely legacy one reports as fine.

The shared assertion across all three: an open network is never reported as protected,
and incomplete evidence yields None rather than a guess.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURES = Path(__file__).parent / "fixtures"
NINE_THOUSAND = FIXTURES / "cisco/ios/17.9/wlc_9800.cfg"
FORTIGATE = FIXTURES / "fortinet/fortios/7.2/edge_fortigate.cfg"
AIREOS = FIXTURES / "cisco/wlc/8.10/campus_wlc.txt"


def parse(platform: str, path: Path) -> dict[str, Any]:
    return (
        get_parser(platform).parse(ParseContext(text=path.read_text(encoding="utf-8"))).to_storage()
    )


@pytest.fixture(scope="module")
def ninenine() -> dict[str, Any]:
    return parse("cisco_ios", NINE_THOUSAND)


@pytest.fixture(scope="module")
def fortigate() -> dict[str, Any]:
    return parse("fortios", FORTIGATE)


def wlans(ncm: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {w["ssid"]: w for w in ncm["wireless"]["wlans"]}


# ═══════════════════════ Catalyst 9800 (IOS-XE) ══════════════════════════════


class TestCatalyst9800:
    @pytest.mark.parametrize(
        ("ssid", "expected"),
        [
            ("Corp-WiFi", "wpa2-ent"),
            ("Guest-WiFi", "open"),
            ("Staff-PSK", "wpa2-psk"),
            ("IoT-Hidden", "wpa2-psk"),
            ("Modern-SAE", "wpa3-sae"),
        ],
    )
    def test_security_is_classified(
        self, ninenine: dict[str, Any], ssid: str, expected: str
    ) -> None:
        assert wlans(ninenine)[ssid]["security"] == expected

    def test_an_open_wlan_is_seen_as_open(self, ninenine: dict[str, Any]) -> None:
        """The negation trap, and the reason this test exists.

        A 9800 makes a WLAN open by *removing* security: `no security wpa`. A rule
        matching only the positive form would leave the WLAN unclassified, and an open
        guest network would report as Not Evaluated rather than as the finding it is.
        """
        assert wlans(ninenine)["Guest-WiFi"]["security"] == "open"

    def test_dot1x_is_normalised_to_the_ncm_vocabulary(self, ninenine: dict[str, Any]) -> None:
        """IOS-XE says `dot1x` where AireOS says `802.1x`. The NCM says `wpa2-ent` for
        both, so a check does not need a per-vendor branch (C-6)."""
        assert wlans(ninenine)["Corp-WiFi"]["security"] == "wpa2-ent"

    def test_a_9800_wlan_is_down_unless_no_shutdown_is_present(
        self, ninenine: dict[str, Any]
    ) -> None:
        """The default is the opposite of AireOS's, and the wording is inverted on top.
        `IoT-Hidden` carries a bare `shutdown`."""
        found = wlans(ninenine)
        assert found["Corp-WiFi"]["enabled"] is True
        assert found["IoT-Hidden"]["enabled"] is False

    def test_negated_broadcast_is_false_not_missing(self, ninenine: dict[str, Any]) -> None:
        found = wlans(ninenine)
        assert found["IoT-Hidden"]["broadcast"] is False
        assert found["Corp-WiFi"]["broadcast"] is True

    def test_pmf_states(self, ninenine: dict[str, Any]) -> None:
        found = wlans(ninenine)
        assert found["Corp-WiFi"]["pmf"] == "mandatory"
        assert found["Staff-PSK"]["pmf"] == "optional"
        assert found["IoT-Hidden"]["pmf"] == "disabled"

    def test_client_isolation_distinguishes_negated_from_unstated(
        self, ninenine: dict[str, Any]
    ) -> None:
        found = wlans(ninenine)
        assert found["Guest-WiFi"]["client_isolation"] is False
        assert found["Staff-PSK"]["client_isolation"] is True
        assert found["Corp-WiFi"]["client_isolation"] is None

    def test_the_authentication_list_is_carried(self, ninenine: dict[str, Any]) -> None:
        """Which RADIUS group serves the WLAN, for the FR-AAA-05 correlation."""
        assert wlans(ninenine)["Corp-WiFi"]["radius_group"] == "RADIUS-GROUP"

    def test_rogue_detection(self, ninenine: dict[str, Any]) -> None:
        assert ninenine["wireless"]["rogue_detection"]["enabled"] is True

    def test_a_switch_with_no_wireless_gets_an_empty_block_not_a_failure(self) -> None:
        """Most IOS devices are switches. The wireless section must be a no-op on them
        rather than a parse error, and must not invent a WLAN list."""
        switch = parse("cisco_ios", FIXTURES / "cisco/ios/17.9/hardened_switch.cfg")
        assert switch["wireless"]["wlans"] == []


# ══════════════════════════════ FortiGate ════════════════════════════════════


class TestFortiGateWireless:
    @pytest.mark.parametrize(
        ("ssid", "expected"),
        [
            ("Corp-WiFi", "wpa2-ent"),
            ("Guest-WiFi", "open"),
            ("Legacy-WiFi", "wpa1"),
        ],
    )
    def test_security_is_mapped(self, fortigate: dict[str, Any], ssid: str, expected: str) -> None:
        assert wlans(fortigate)[ssid]["security"] == expected

    def test_the_only_in_a_mode_name_does_not_mean_wpa1(self) -> None:
        """`wpa-only-personal` is WPA2 Personal *only* — the "only" excludes the WPA1
        fallback. It is `wpa-personal` that is the mixed legacy mode. Reading them the
        wrong way round reports every modern FortiAP SSID as WPA1 and every genuinely
        legacy one as fine, and the names give no hint which way it goes.
        """
        from netsecops.parsers.fortinet.fortios import FortiOsParser

        mapping = FortiOsParser._SECURITY
        assert mapping["wpa-only-personal"] == "wpa2-psk"
        assert mapping["wpa-personal"] == "wpa1"

    def test_a_captive_portal_is_an_open_network(self, fortigate: dict[str, Any]) -> None:
        """A splash page is not encryption. Traffic on it is in the clear, so it is the
        same finding as an open SSID."""
        assert wlans(fortigate)["Guest-WiFi"]["security"] == "open"

    def test_an_unrecognised_mode_is_unknown_rather_than_guessed(self) -> None:
        """A future FortiOS release adding a security mode must make the check report
        Not Evaluated, never silently classify it as open or as secure."""
        config = (
            "config wireless-controller vap\n"
            '    edit "future"\n'
            '        set ssid "Future"\n'
            "        set security wpa5-quantum\n"
            "    next\n"
            "end\n"
        )
        parsed = get_parser("fortios").parse(ParseContext(text=config)).to_storage()
        assert parsed["wireless"]["wlans"][0]["security"] is None

    def test_broadcast_suppression_is_inverted_correctly(self, fortigate: dict[str, Any]) -> None:
        found = wlans(fortigate)
        assert found["Corp-WiFi"]["broadcast"] is True
        assert found["Legacy-WiFi"]["broadcast"] is False

    def test_intra_vap_privacy_is_client_isolation(self, fortigate: dict[str, Any]) -> None:
        found = wlans(fortigate)
        assert found["Guest-WiFi"]["client_isolation"] is True
        assert found["Corp-WiFi"]["client_isolation"] is False

    def test_the_vlan_is_carried(self, fortigate: dict[str, Any]) -> None:
        assert wlans(fortigate)["Guest-WiFi"]["vlan"] == 30

    def test_access_points_are_listed(self, fortigate: dict[str, Any]) -> None:
        """FortiAP data reaches NetSecOps only through the parent FortiGate (ADR-003),
        so this is the only place an estate's APs are visible."""
        aps = fortigate["wireless"]["aps"]
        assert [a["name"] for a in aps] == ["ap-floor-1"]
        assert aps[0]["serial"] == "FP231F1234567890"

    def test_a_fortigate_with_no_wireless_is_not_a_failure(self) -> None:
        config = "config system global\n    set hostname fw1\nend\n"
        parsed = get_parser("fortios").parse(ParseContext(text=config)).to_storage()
        assert parsed["wireless"]["wlans"] == []


# ═════════════════ what all three platforms agree on ═════════════════════════


class TestTheSharedVocabulary:
    def test_every_platform_uses_the_same_security_values(self) -> None:
        """The point of the NCM. A check asks "is this WLAN open" once, not three times
        with a vendor branch (C-6)."""
        platforms = {
            "9800": wlans(parse("cisco_ios", NINE_THOUSAND)),
            "aireos": wlans(parse("cisco_wlc_aireos", AIREOS)),
            "fortios": wlans(parse("fortios", FORTIGATE)),
        }

        for name, found in platforms.items():
            assert found["Corp-WiFi"]["security"] == "wpa2-ent", name
            assert found["Guest-WiFi"]["security"] == "open", name

    @pytest.mark.parametrize(
        ("platform", "path"),
        [
            ("cisco_ios", NINE_THOUSAND),
            ("cisco_wlc_aireos", AIREOS),
            ("fortios", FORTIGATE),
        ],
    )
    def test_no_wireless_secret_reaches_the_ncm(self, platform: str, path: Path) -> None:
        """C-2. Each platform spells its pre-shared key differently, and each needed its
        own redaction rule: IOS-XE's `security wpa psk set-key ascii 0 <key>` and
        FortiOS's `set passphrase ENC <key>` both reached provenance excerpts before
        rules were written for them.
        """
        serialised = json.dumps(parse(platform, path))
        for secret in (
            "St4ffW1FiPsk",
            "SH2abcdefghijklmnopqrstuvwxyz0123456789",
            "R4d1usK3y!Secret",
        ):
            assert secret not in serialised, f"{platform}: {secret} leaked"

    @pytest.mark.parametrize(
        "line",
        [
            " security wpa psk set-key ascii 0 St4ffW1FiPsk",
            "        set passphrase ENC SH2abcdefghijklmnop",
        ],
    )
    def test_the_wireless_key_syntaxes_redact(self, line: str) -> None:
        from netsecops.core.redaction import redact_line

        redacted, _ = redact_line(line)
        assert "«redacted:" in redacted
        assert "St4ffW1FiPsk" not in redacted
        assert "SH2abcdefghijklmnop" not in redacted
