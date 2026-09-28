"""The access points a Catalyst 9800 is actually carrying (SRS §1.3, FR-INV-05).

**A controller's AP list cannot come from its running configuration.** It learns the
list when APs join, so this is the one part of a wireless controller's posture that only
a show command carries — and `CISCO_IOS_PROFILE` never asked for it, while the AireOS
profile has since Phase 5. An estate running both generations therefore showed an AireOS
controller listing its access points and a Catalyst 9800 beside it listing none, as an
empty list rather than as an error: this codebase's named failure mode, in the one place
where "no APs joined" and "we could not read the table" are genuinely different facts.

The row rule is the risk. `show ap summary` is a column table whose columns are neither
stable across releases nor safely splittable — Cisco's own documented sample prints
`-UN 20.20.20.52`, one space between the regulatory domain and the address, so a split on
runs of whitespace merges them and a split on two-or-more spaces misses the boundary. So
the parser reads shapes rather than positions, and these tests are mostly about proving
it does not quietly read positions after all.

**This parser has never been run against a real controller.** The fixture is Cisco's
published sample output extended with three more rows. That is the strongest evidence
available without an appliance, and `Number of APs` exists so that when the evidence
turns out to be wrong the result is a recorded shortfall rather than a short list.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from netsecops.adapters.profiles import PROFILES
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser

FIXTURES = Path(__file__).parent / "fixtures"
AP_SUMMARY = (FIXTURES / "operational/cisco_c9800/show_ap_summary.txt").read_text(encoding="utf-8")

CONFIG = """\
hostname wlc-9800
!
wlan Corp-WiFi 1 Corp-WiFi
 security wpa wpa2
 security wpa akm dot1x
 no shutdown
!
"""


def parse(*, config: str = CONFIG, summary: str | None = AP_SUMMARY) -> dict[str, Any]:
    supporting = {"show ap summary": summary} if summary is not None else {}
    context = ParseContext(text=config, supporting=supporting)
    return get_parser("cisco_c9800").parse(context).to_storage()


@pytest.fixture(scope="module")
def wireless() -> dict[str, Any]:
    return parse()["wireless"]


class TestTheCommandIsActuallyIssued:
    """The half that was missing, and the reason this whole slice exists.

    Every other test here hands the parser an artefact directly, so all of them pass
    with a profile that never asks for one. That is the shape of the original defect
    exactly: `show ap summary` had been on the `cisco_ios` allow-list since SRS §8.2
    was written, permitted and never sent, and a parser that could read it would have
    changed nothing at all.
    """

    def test_the_9800_asks_for_its_access_points(self) -> None:
        assert "show ap summary" in PROFILES["cisco_c9800"].all_commands()

    def test_and_asks_for_the_rest_of_the_approved_wireless_set(self) -> None:
        issued = set(PROFILES["cisco_c9800"].all_commands())

        assert {
            "show wireless summary",
            "show wlan summary",
            "show wlan all",
            "show wireless profile policy summary",
        } <= issued

    def test_it_still_asks_for_everything_an_iosxe_device_is_asked(self) -> None:
        # A 9800 is a router and a switch as well as a controller: VTY lines, SSH,
        # SNMP, AAA, NTP. A wireless-only profile would trade 43 checks for 5.
        assert set(PROFILES["cisco_iosxe"].all_commands()) <= set(
            PROFILES["cisco_c9800"].all_commands()
        )

    def test_a_plain_switch_is_not_asked_any_of_it(self) -> None:
        """Why this is a profile of its own rather than six lines added to the IOS one.

        `CISCO_IOS_PROFILE` is every switch and router in the estate. A Catalyst 2960
        sent `show ap summary` rejects it and records a failed artefact — harmless under
        FR-COL-08, and six pointless commands per device across a whole estate, in an
        evidence trail that is meant to be read.
        """
        issued = set(PROFILES["cisco_iosxe"].all_commands())

        assert not {command for command in issued if "wireless" in command or "ap " in command}


class TestTheApTableIsRead:
    def test_every_access_point_is_listed(self, wireless) -> None:
        assert [ap["name"] for ap in wireless["aps"]] == [
            "AP-B2E0",
            "AP-Floor1",
            "AP-Floor2",
            "AP-Yard",
        ]

    def test_the_model_comes_from_beside_the_mac_not_from_a_column(self, wireless) -> None:
        # The model is the token immediately before the first dotted MAC.
        assert [ap["model"] for ap in wireless["aps"]] == [
            "CW9178I",
            "9130AXI",
            "9120AXI",
            "9105AXI",
        ]

    def test_an_inserted_column_does_not_shift_the_model(self) -> None:
        """The assertion above passes just as well for `tokens[2]`.

        Every row in Cisco's published sample puts the MAC at index three, so reading
        the model by fixed position and reading it relative to the MAC are the same
        answer there — and a release that inserts a column is exactly when they stop
        being. This row carries a priority column between the slots and the model, and
        a positional parser calls its model `1`.
        """
        summary = (
            "Number of APs: 1\n"
            "AP-Extra  2  1  9130AXI  aabb.ccdd.ee01  aabb.ccdd.ee10  IN  -D  10.1.1.1  Registered\n"
        )

        result = parse(summary=summary)

        assert [ap["model"] for ap in result["wireless"]["aps"]] == ["9130AXI"]

    def test_the_address_survives_being_jammed_against_the_column_before_it(self, wireless) -> None:
        """`-UN 20.20.20.52` is one space apart in Cisco's own documented output.

        This is the row that decides the whole design. Splitting on runs of whitespace
        merges those two into one token; splitting on two-or-more spaces does not see a
        boundary at all. Only a search for the address *shape* reads it.
        """
        assert wireless["aps"][0]["ip"] == "20.20.20.52"
        assert [ap["ip"] for ap in wireless["aps"][1:]] == [
            "10.20.30.41",
            "10.20.30.42",
            "10.20.30.43",
        ]

    def test_the_controllers_own_count_is_kept(self, wireless) -> None:
        # Not checked and discarded. It is the only thing that can tell a controller
        # with no APs joined from a table we failed to read, and both are a list of
        # length nought.
        assert wireless["aps_declared"] == 4
        assert len(wireless["aps"]) == wireless["aps_declared"]


class TestItDoesNotInventRows:
    def test_the_header_and_rule_lines_are_not_access_points(self, wireless) -> None:
        # `AP Name    Slots  AP Model …` and the dashed rule both look like rows to a
        # parser that only counts tokens. Neither carries a MAC, which is why the MAC
        # is what a row is recognised by.
        names = [ap["name"] for ap in wireless["aps"]]
        assert "AP" not in names
        assert not any(name.startswith("-") for name in names)

    def test_a_mac_on_a_line_of_its_own_is_not_a_row(self) -> None:
        """`show ap config general` repeats a MAC with nothing before it.

        A rule that accepted any line containing a MAC would turn every one of those
        into an access point named after whatever word preceded it.
        """
        result = parse(summary="Number of APs: 0\nMAC Address : c414.a26f.b2e0\n")

        assert result["wireless"]["aps"] == []

    def test_a_row_with_no_mac_is_skipped(self) -> None:
        result = parse(summary="Number of APs: 0\nAP-Ghost   2   9130AXI   10.1.1.1  Registered\n")

        assert result["wireless"]["aps"] == []


class TestWhatHappensWithoutTheArtefact:
    def test_an_offline_upload_reports_no_access_points_and_no_count(self) -> None:
        """An operator pasting a running configuration has no `show ap summary`.

        `aps_declared` stays None rather than becoming nought — nought would be the
        controller asserting it has no access points, which nothing here has asked it.
        """
        result = parse(summary=None)

        assert result["wireless"]["aps"] == []
        assert result["wireless"]["aps_declared"] is None

    def test_the_wlans_are_still_parsed(self) -> None:
        # The AP table is supplementary; the configuration is what is required. A
        # missing artefact must not cost the section that did parse.
        result = parse(summary=None)

        assert [w["ssid"] for w in result["wireless"]["wlans"]] == ["Corp-WiFi"]


class TestTheShortfallIsRecorded:
    def test_reading_fewer_rows_than_the_controller_declared_is_visible(self) -> None:
        """The guard on a parser that has never met a real controller.

        If the row rule turns out to be wrong for some release, the NCM says so: four
        declared against one read is a number an operator can see, where a list of one
        is not.
        """
        summary = "Number of APs: 4\nAP-Only  2  9130AXI  aabb.ccdd.ee01  10.1.1.1  Registered\n"

        result = parse(summary=summary)

        assert result["wireless"]["aps_declared"] == 4
        assert len(result["wireless"]["aps"]) == 1

    def test_a_table_with_no_count_line_still_parses_its_rows(self) -> None:
        # Older releases and filtered output may carry no count. The rows are the
        # useful part; the count is the check on them.
        summary = "AP-One  2  9130AXI  aabb.ccdd.ee01  10.1.1.1  Registered\n"

        result = parse(summary=summary)

        assert [ap["name"] for ap in result["wireless"]["aps"]] == ["AP-One"]
        assert result["wireless"]["aps_declared"] is None
