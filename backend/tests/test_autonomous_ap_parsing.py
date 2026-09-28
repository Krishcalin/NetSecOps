"""SSIDs on a standalone Aironet access point (SRS §1.3.1).

A lightweight AP holds no configuration — its controller does. An autonomous one holds
all of it and nothing else in the estate knows what is on it, which is why it is the
only kind of access point NetSecOps collects from. It runs IOS, so it is onboarded as
`cisco_ios` with the `wireless_ap` device class and needs no platform of its own; only
the WLAN syntax differs.

**The syntax differs in a way that can invert a finding.** The cipher is not on the
SSID — it is on the radio interface, keyed by the SSID's VLAN:

    dot11 ssid OLD-HANDHELD          interface Dot11Radio0
     vlan 40                          encryption vlan 40 mode wep mandatory
     authentication open              ssid OLD-HANDHELD

Read the `dot11 ssid` block alone and that is an open network. Read the join and it is
WEP. Both are findings and they are not the same one — and `authentication open` is
WEP's *normal* pairing, so the wrong reading is the likely one rather than an edge case.
That is the AireOS trap ("assembles it from three separate lines joined by a numeric
id") in a second place, which is what this file is mostly about.

The vocabulary is the NCM's, shared with the AireOS, 9800 and FortiOS parsers, so a
check never has to know which kind of access point a WLAN came from.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE = FIXTURES / "cisco/ios/15.3/autonomous_ap.cfg"


@pytest.fixture(scope="module")
def wlans() -> dict[str, dict[str, Any]]:
    ncm = (
        get_parser("cisco_ios")
        .parse(ParseContext(text=FIXTURE.read_text(encoding="utf-8")))
        .to_storage()
    )
    return {w["ssid"]: w for w in ncm["wireless"]["wlans"]}


class TestTheCipherComesFromTheRadio:
    def test_an_open_ssid_on_a_wep_vlan_is_reported_as_wep(self, wlans) -> None:
        """The one that decides the design.

        `OLD-HANDHELD` says `authentication open` and nothing else. Its VLAN carries
        `encryption vlan 40 mode wep mandatory` on the radio, so it is a WEP network —
        and open authentication is exactly how WEP is normally configured, which makes
        reading the SSID block alone the plausible mistake rather than a contrived one.
        """
        assert wlans["OLD-HANDHELD"]["security"] == "wep"

    def test_a_genuinely_open_ssid_is_still_open(self, wlans) -> None:
        # `CONTRACTOR` has no key management and its VLAN has no encryption line. The
        # test above must not be satisfied by calling everything WEP.
        assert wlans["CONTRACTOR"]["security"] == "open"

    def test_tkip_under_wpa1_reads_as_wpa1(self, wlans) -> None:
        # A bare `authentication key-management wpa` with no version is WPA1, and WPA1
        # is broken however it is keyed — so it collapses to one value, matching the
        # AireOS classifier and the exact string `wlan-no-legacy-encryption` matches.
        assert wlans["LEGACY-SCANNERS"]["security"] == "wpa1"


class TestTheSecurityVocabularyIsTheSharedOne:
    @pytest.mark.parametrize(
        ("ssid", "expected"),
        [
            ("CORP-SECURE", "wpa2-ent"),
            ("PLANT-PSK", "wpa2-psk"),
            ("LEGACY-SCANNERS", "wpa1"),
            ("OLD-HANDHELD", "wep"),
            ("CONTRACTOR", "open"),
        ],
    )
    def test_each_ssid_classifies(self, wlans, ssid: str, expected: str) -> None:
        assert wlans[ssid]["security"] == expected

    def test_enterprise_is_told_from_personal_by_the_eap_list(self, wlans) -> None:
        # `authentication network-eap <group>` is what makes it 802.1X, and the group
        # name is worth keeping: an SSID pointing at a RADIUS group that does not exist
        # is a network nobody can join, and only the name shows it.
        assert wlans["CORP-SECURE"]["radius_group"] == "rad_eap"
        assert wlans["PLANT-PSK"]["radius_group"] is None

    def test_the_legacy_check_would_fire_on_both_legacy_networks(self, wlans) -> None:
        """Pins the vocabulary against the check that consumes it.

        `wlan-no-legacy-encryption` matches `security == 'wep' || security == 'wpa1'`
        exactly. A finer value here — `wpa1-psk`, say — would be more precise and would
        silently pass a check it should fail.
        """
        legacy = {ssid for ssid, w in wlans.items() if w["security"] in {"wep", "wpa1"}}

        assert legacy == {"OLD-HANDHELD", "LEGACY-SCANNERS"}


class TestBroadcastAndBinding:
    def test_an_ssid_is_broadcast_only_when_it_says_so(self, wlans) -> None:
        # The opposite of the 9800, where absence is ambiguous. On autonomous IOS
        # `guest-mode` is what puts the SSID in the beacon, so its absence is a fact
        # about a block that was fully parsed rather than silence.
        assert wlans["CORP-SECURE"]["broadcast"] is True
        assert wlans["CONTRACTOR"]["broadcast"] is False

    def test_an_ssid_bound_to_no_radio_is_not_on_the_air(self, wlans) -> None:
        """`DECOMMISSIONED` is configured and bound to nothing.

        Reporting it as live would raise a finding about a network no client can see,
        which is the 9800's unbound-WLAN trap in the same shape.
        """
        assert wlans["DECOMMISSIONED"]["enabled"] is False
        assert wlans["CORP-SECURE"]["enabled"] is True


class TestItClaimsNothingItCannotKnow:
    def test_pmf_and_fast_transition_are_unknown_rather_than_off(self, wlans) -> None:
        # Autonomous IOS has neither on these releases. False would be the access point
        # answering "no"; it cannot answer at all, and `wlan-pmf-enabled` reports Not
        # Evaluated on a None — which is the honest outcome.
        assert wlans["CORP-SECURE"]["pmf"] is None
        assert wlans["CORP-SECURE"]["fast_transition"] is None

    def test_client_isolation_is_unknown(self, wlans) -> None:
        # `bridge-group <n> port-protected` is per radio, and a radio carries five
        # SSIDs here. There is no honest per-SSID answer to read.
        assert wlans["CONTRACTOR"]["client_isolation"] is None

    def test_the_vlan_is_kept(self, wlans) -> None:
        # It is what the cipher was joined through, so recording it lets an operator
        # check the join that produced the verdict.
        assert wlans["CORP-SECURE"]["vlan"] == 10
        assert wlans["OLD-HANDHELD"]["vlan"] == 40


class TestItDoesNotDisturbOrdinaryIosDevices:
    def test_each_ssid_appears_exactly_once(self) -> None:
        """Two WLAN parsers now run over every IOS configuration.

        `_parse_wireless` reads the 9800's `wlan` blocks and `_parse_autonomous_ssids`
        reads an Aironet's `dot11 ssid` blocks, and one config never has both — but a
        pattern loosened to match either would double every WLAN on the platform it
        overlapped.

        This is asserted on the list rather than on a lookup because every other test
        in this file and in `test_wireless_parsing.py` builds `{w["ssid"]: w}` first,
        and a dict is exactly the shape that makes a duplicate invisible.
        """
        ncm = (
            get_parser("cisco_ios")
            .parse(ParseContext(text=FIXTURE.read_text(encoding="utf-8")))
            .to_storage()
        )
        names = [w["ssid"] for w in ncm["wireless"]["wlans"]]

        assert len(names) == len(set(names)), f"duplicated: {sorted(names)}"
        assert len(names) == 6

    def test_a_9800_configuration_is_read_once_by_the_other_parser(self) -> None:
        # The overlap in the other direction, on the fixture that actually has `wlan`
        # blocks. Same reason, and the count is what catches it.
        config = (FIXTURES / "cisco/c9800/17.9/wlc_9800.cfg").read_text(encoding="utf-8")

        ncm = get_parser("cisco_c9800").parse(ParseContext(text=config)).to_storage()
        names = [w["ssid"] for w in ncm["wireless"]["wlans"]]

        assert names, "the 9800 fixture parsed no WLANs at all"
        assert len(names) == len(set(names)), f"duplicated: {sorted(names)}"

    def test_a_switch_configuration_yields_no_wlans(self) -> None:
        # `_parse_autonomous_ssids` runs on every IOS device. A configuration with no
        # `dot11 ssid` block must produce no wireless section rather than an empty one
        # that reads as an access point with nothing configured.
        config = (
            "hostname sw-access-01\n!\ninterface GigabitEthernet1/0/1\n switchport mode access\n!\n"
        )

        ncm = get_parser("cisco_ios").parse(ParseContext(text=config)).to_storage()

        assert ncm["wireless"]["wlans"] == []

    def test_the_rest_of_the_access_point_still_parses(self) -> None:
        # The AP is an IOS device as well as a radio: it has an enable secret, AAA, NTP
        # and VTY lines, and the 43 IOS checks apply to it. A wireless parser that cost
        # those would be a bad trade.
        ncm = (
            get_parser("cisco_ios")
            .parse(ParseContext(text=FIXTURE.read_text(encoding="utf-8")))
            .to_storage()
        )

        assert ncm["device"]["hostname"] == "ap-plant-01"
        assert ncm["aaa"]["new_model"] is True
        assert [server["host"] for server in ncm["aaa"]["servers"]] == ["10.20.0.10"]
