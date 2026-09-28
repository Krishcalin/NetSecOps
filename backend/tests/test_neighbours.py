"""Layer-2 adjacency from CDP and LLDP (FR-TOPO-01).

**Why this is a different kind of fact.** Every other edge in the topology graph is
inferred: a route names a next hop, the next hop falls inside an interface's subnet, and
the product concludes the two are connected. A neighbour entry is a device *stating* that
a cable runs from this port to that one. The graph had only the inferred kind, and the
two commands that carry the stated kind had been approved in SRS §8.2 since Phase 2,
issued by no profile and read by nothing — found by `test_unconsumed_capability.py`,
which exists because that had happened nine times.

Almost every failure here is silent. A device with CDP disabled reports no neighbours; so
does a parser whose regex matches the wrong spelling of a label. A neighbour whose name
carries a chassis serial looks like a neighbour right up to the moment the topology tries
to match it to a device in the inventory and matches nothing. So these tests are written
against what the fixture files literally contain, read by hand, and are shaped to catch
the silent failures rather than to walk the happy path twice.

**The fixtures are Cisco's published output shapes, not captures from this estate.** The
label variations they carry — `Entry address(es)` against `Interface address(es)`,
`IP address:` against a bare `IP:`, a description beside its label against beneath it —
are each in vendor documentation, and each one of them broke the first draft of the
parser.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from netsecops.adapters.profiles import PROFILES
from netsecops.parsers.base import ParseContext
from netsecops.parsers.neighbours import parse_cdp_detail, parse_lldp_detail
from netsecops.parsers.registry import get_parser

FIXTURES = Path(__file__).parent / "fixtures" / "operational"


def load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def on(neighbours, interface):
    """The neighbour seen on a local port, which is the question this data answers."""
    matches = [n for n in neighbours if n.local_interface == interface]
    assert matches, f"no neighbour on {interface}"
    return matches[0]


# ─────────────────────── the half that was missing ──────────────────────


class TestTheCommandsAreActuallyIssued:
    """Every other test in this module hands a parser an artefact directly.

    All of them pass against a profile that never sends the command — which is the
    original defect exactly, and the reason the sweep that found it was written. A
    parser that can read output nobody collects changes nothing.
    """

    def test_ios_asks_for_both_protocols(self) -> None:
        issued = set(PROFILES["cisco_ios"].all_commands())
        assert {"show cdp neighbors detail", "show lldp neighbors detail"} <= issued

    def test_nxos_asks_for_cdp(self) -> None:
        assert "show cdp neighbors detail" in PROFILES["cisco_nxos"].all_commands()

    def test_nxos_does_not_ask_for_lldp(self) -> None:
        # Not an oversight and not a gap to close here: `show lldp neighbors detail` is
        # not on the NX-OS allow-list, and a profile may not widen one. SRS §8.2 is
        # closed precisely so it cannot grow an entry at a time.
        assert "show lldp neighbors detail" not in PROFILES["cisco_nxos"].all_commands()


class TestTheParsersAreWired:
    """And that the artefact reaches the NCM, not just the parsing function.

    `_parse_l2` calling `_parse_neighbours` is the join between the two halves above.
    Tested directly because a missing call is invisible: `l2.neighbours` is empty, which
    is also what a switch with neither protocol enabled produces.
    """

    def storage(self, platform: str, command: str, fixture: str) -> dict[str, Any]:
        context = ParseContext(text="hostname sw01\n!\n", supporting={command: load(fixture)})
        return get_parser(platform).parse(context).to_storage()

    def test_ios_cdp_reaches_the_ncm(self) -> None:
        stored = self.storage(
            "cisco_ios", "show cdp neighbors detail", "cisco_ios/show_cdp_neighbors_detail.txt"
        )
        assert len(stored["l2"]["neighbours"]) == 3

    def test_ios_reads_both_protocols_into_one_list(self) -> None:
        context = ParseContext(
            text="hostname sw01\n!\n",
            supporting={
                "show cdp neighbors detail": load("cisco_ios/show_cdp_neighbors_detail.txt"),
                "show lldp neighbors detail": load("cisco_ios/show_lldp_neighbors_detail.txt"),
            },
        )
        neighbours = get_parser("cisco_ios").parse(context).to_storage()["l2"]["neighbours"]

        # Six entries, not three: the protocols are deliberately not merged. They
        # disagree about the same link often enough — one filtered on a port, the other
        # disabled on the far end — that collapsing them loses which one saw what.
        assert len(neighbours) == 6
        assert {n["protocol"] for n in neighbours} == {"cdp", "lldp"}

    def test_nxos_cdp_reaches_the_ncm(self) -> None:
        stored = self.storage(
            "cisco_nxos", "show cdp neighbors detail", "cisco_nxos/show_cdp_neighbors_detail.txt"
        )
        assert len(stored["l2"]["neighbours"]) == 2

    def test_no_artefact_is_not_an_error(self) -> None:
        # A switch with CDP disabled collects nothing, and that is a fact `features.cdp`
        # already records. The parser must not treat the absence as a parse failure.
        context = ParseContext(text="hostname sw01\n!\n", supporting={})
        assert get_parser("cisco_ios").parse(context).to_storage()["l2"]["neighbours"] == []


# ──────────────────────────── Cisco IOS: CDP ────────────────────────────


class TestCiscoIosCdp:
    @pytest.fixture
    def neighbours(self):
        return parse_cdp_detail(load("cisco_ios/show_cdp_neighbors_detail.txt"))

    def test_every_record_and_no_trailer(self, neighbours):
        # Three records. `Total cdp entries displayed : 3` trails the last one with no
        # rule after it, inside the same block — a fourth entry if it were read.
        assert len(neighbours) == 3

    def test_local_and_remote_ports_come_off_one_line(self, neighbours):
        # IOS prints `Interface: Gi0/1,  Port ID (outgoing port): Gi1/0/24` on a single
        # line; IOS-XR splits it in two. Matched independently for that reason, so both
        # halves have to be checked or the single-line layout can quietly yield one.
        uplink = on(neighbours, "GigabitEthernet0/1")
        assert uplink.remote_interface == "GigabitEthernet1/0/24"

    def test_the_far_end_is_named_and_addressed(self, neighbours):
        uplink = on(neighbours, "GigabitEthernet0/1")
        assert (uplink.remote_device, uplink.remote_address) == (
            "core-sw01.example.local",
            "10.10.10.1",
        )

    def test_platform_stops_before_the_capabilities(self, neighbours):
        # `Platform: cisco WS-C3850-24T,  Capabilities: Switch IGMP` is one line holding
        # two fields. Read to the end of the line the model becomes a sentence.
        assert on(neighbours, "GigabitEthernet0/1").platform == "cisco WS-C3850-24T"

    def test_capabilities_separate(self, neighbours):
        assert on(neighbours, "GigabitEthernet0/1").capabilities == ["Switch", "IGMP"]

    def test_a_remote_port_may_contain_a_space(self, neighbours):
        # An IP phone reports `Port 1`. A reader that takes the last whitespace-delimited
        # token gets "1", which names no port on anything.
        assert on(neighbours, "GigabitEthernet0/5").remote_interface == "Port 1"

    def test_a_phone_is_identifiable_as_a_phone(self, neighbours):
        # The question this field answers is whether an unmanaged neighbour is
        # interesting. A phone and an access point on an access port are not the same
        # finding.
        phone = on(neighbours, "GigabitEthernet0/5")
        assert phone.platform == "Cisco IP Phone 8845"
        assert "Phone" in phone.capabilities

    def test_an_entry_with_no_address_is_kept(self, neighbours):
        # The third record prints `Entry address(es):` with nothing beneath it. Dropping
        # it loses a real adjacency; the local port and the far end's name are still
        # true, and those are what the entry is for.
        ap = on(neighbours, "GigabitEthernet0/9")
        assert (ap.remote_device, ap.remote_address) == ("ap-floor2-01", None)

    def test_the_version_banner_is_not_read_as_fields(self, neighbours):
        # Each record carries several lines of free text under `Version :`, including
        # commas and colons. None of it may reach a field.
        assert all(n.platform is None or "Version" not in n.platform for n in neighbours)

    def test_every_entry_names_its_protocol(self, neighbours):
        assert {n.protocol for n in neighbours} == {"cdp"}


# ─────────────────────────── Cisco IOS: LLDP ────────────────────────────


class TestCiscoIosLldp:
    @pytest.fixture
    def neighbours(self):
        return parse_lldp_detail(load("cisco_ios/show_lldp_neighbors_detail.txt"))

    def test_every_record(self, neighbours):
        assert len(neighbours) == 3

    def test_local_intf_is_the_ios_spelling(self, neighbours):
        # IOS prints `Local Intf`, IOS-XR `Local Interface`. Matching one spelling
        # reports no neighbours at all on the platforms using the other — silently,
        # because a device with LLDP off reports none either.
        assert {n.local_interface for n in neighbours} == {"Gi0/2", "Gi0/7", "Gi0/11"}

    def test_the_management_address_is_read(self, neighbours):
        # LLDP prints a bare `IP:` beneath `Management Addresses:` where CDP prints
        # `IP address:`. A pattern that requires the word "address" reads no LLDP
        # address anywhere, on any device, and reports None as though none were sent.
        assert on(neighbours, "Gi0/2").remote_address == "10.10.30.3"

    def test_the_description_sits_under_its_label(self, neighbours):
        # `System Description:` is printed with the text on the FOLLOWING line. A
        # pattern needing a value beside the label matches nothing and every LLDP
        # neighbour loses the one field that says what it is.
        assert on(neighbours, "Gi0/2").platform.startswith("Cisco IOS Software, C2960X Software")

    def test_enabled_capabilities_win_over_system_capabilities(self, neighbours):
        # The fixture advertises `System Capabilities: B,R` then `Enabled
        # Capabilities: B`. What the far end is doing beats what it could do, and the
        # order they arrive in is what makes last-one-wins correct.
        assert on(neighbours, "Gi0/2").capabilities == ["B"]

    def test_not_advertised_does_not_become_a_device_name(self, neighbours):
        # The second record is a default-configured host: it answers `not advertised` to
        # almost everything. Taken at face value an estate grows dozens of neighbours
        # named "not advertised", which a topology builder merges into one node that
        # every switch appears to be cabled to.
        quiet = on(neighbours, "Gi0/7")
        assert quiet.remote_device is None
        assert quiet.platform is None
        assert quiet.capabilities == []

    def test_a_silent_neighbour_is_still_a_neighbour(self, neighbours):
        # Kept rather than dropped: "something is plugged in here and will not say what"
        # is a more interesting fact than silence, and the two ports are still true.
        assert on(neighbours, "Gi0/7").remote_interface == "0050.5699.1a2b"

    def test_an_absent_description_does_not_swallow_the_next_field(self, neighbours):
        # `System Description: not advertised` is followed by `Time remaining: 106
        # seconds`. A continuation reader that does not check what it is reading gives
        # that neighbour a platform of "Time remaining: 106 seconds".
        assert on(neighbours, "Gi0/7").platform is None

    def test_a_non_cisco_neighbour_reads_the_same(self, neighbours):
        # The point of carrying LLDP at all. CDP would not see this device.
        ups = on(neighbours, "Gi0/11")
        assert (ups.remote_device, ups.platform) == (
            "ups-comms-rack4",
            "Network Management Card 2 AP9640",
        )

    def test_every_entry_names_its_protocol(self, neighbours):
        assert {n.protocol for n in neighbours} == {"lldp"}


# ────────────────────────────── NX-OS: CDP ──────────────────────────────


class TestNxosCdp:
    @pytest.fixture
    def neighbours(self):
        return parse_cdp_detail(load("cisco_nxos/show_cdp_neighbors_detail.txt"))

    def test_both_records(self, neighbours):
        assert len(neighbours) == 2

    def test_interface_addresses_is_the_nxos_spelling(self, neighbours):
        # NX-OS prints `Interface address(es):` and `IPv4 Address:` where IOS prints
        # `Entry address(es):` and `IP address:`. Three spellings, one meaning.
        assert on(neighbours, "Ethernet1/1").remote_address == "10.10.20.2"

    def test_the_system_name_is_preferred_over_the_device_id(self, neighbours):
        # NX-OS gives both, and `Device ID:dist-sw02.example.local(FDO21120ABC)` carries
        # the chassis serial. Stored verbatim it matches no hostname in the inventory:
        # the neighbour list looks complete and every topology edge from it is dropped.
        assert on(neighbours, "Ethernet1/1").remote_device == "dist-sw02.example.local"

    def test_the_serial_is_stripped_when_there_is_no_system_name(self, neighbours):
        # The second record has no `System Name` line, which is the common case for a
        # fabric extender. The fallback has to do the stripping itself.
        assert on(neighbours, "Ethernet1/47").remote_device == "fex-101"

    def test_device_id_with_no_space_after_the_colon(self, neighbours):
        # `Device ID:dist-sw02…` — NX-OS omits the space that IOS prints.
        assert all(n.remote_device for n in neighbours)

    def test_capabilities_with_no_double_space_before_them(self, neighbours):
        # IOS separates `Platform:` from `Capabilities:` with two spaces, NX-OS with one.
        fex = on(neighbours, "Ethernet1/47")
        assert (fex.platform, fex.capabilities) == (
            "N2K-C2248TP-1GE",
            ["Host", "Supports-STP-Dispute"],
        )


# ─────────────────────────────── robustness ─────────────────────────────


class TestRobustness:
    def test_crlf_is_handled(self):
        # Device output arrives over SSH with CRLF. A stray carriage return on the end of
        # every line turns each port name into one that matches no interface.
        text = "----\r\nDevice ID: sw1\r\nInterface: Gi0/1,  Port ID (outgoing port): Gi0/2\r\n"
        assert parse_cdp_detail(text)[0].remote_interface == "Gi0/2"

    def test_empty_input_yields_no_neighbours(self):
        assert parse_cdp_detail("") == []
        assert parse_lldp_detail("") == []

    def test_a_record_without_a_local_port_is_dropped(self):
        # The local port is what makes an entry useful — it is what "what is plugged into
        # this port" is asked of — and an entry without one cannot be placed on a device.
        assert parse_cdp_detail("----\nDevice ID: sw1\nPlatform: cisco 2960\n") == []

    def test_a_trailing_record_with_no_rule_after_it_is_kept(self):
        # How a real capture ends. Requiring a closing rule loses the last neighbour on
        # every device.
        assert len(parse_cdp_detail("----\nInterface: Gi0/1,  Port ID (outgoing port): Gi0/2\n")) == 1

    def test_preamble_before_the_first_rule_is_not_a_record(self):
        text = "Capability Codes: R - Router, T - Trans-Bridge\n----\nInterface: Gi0/1\n"
        assert len(parse_cdp_detail(text)) == 1

    @pytest.mark.parametrize("declined", ["not advertised", "none", "N/A", "n/a", "unknown"])
    def test_the_ways_a_device_declines_to_answer(self, declined):
        text = f"----\nLocal Intf: Gi0/1\nPort id: Gi0/2\nSystem Name: {declined}\n"
        assert parse_lldp_detail(text)[0].remote_device is None

    def test_a_real_name_that_merely_begins_with_a_declining_word(self):
        # `_UNADVERTISED` matches the whole value for this reason. A device genuinely
        # called "Not advertised by policy" has a name, and dropping it is a data loss
        # that looks exactly like the thing the rule is there to prevent.
        text = "----\nLocal Intf: Gi0/1\nSystem Name: Not advertised by policy\n"
        assert parse_lldp_detail(text)[0].remote_device == "Not advertised by policy"

    def test_a_device_named_with_parentheses_keeps_them(self):
        # The serial strip is anchored to the end for this reason. `lab(test)-sw1` is a
        # legal hostname and its parentheses are not a chassis serial.
        text = "----\nDevice ID: lab(test)-sw1\nInterface: Gi0/1\n"
        assert parse_cdp_detail(text)[0].remote_device == "lab(test)-sw1"

    def test_a_malformed_address_is_not_stored(self):
        # A wrong address answers confidently; a missing one asks a human. The second is
        # the safe failure, and the same rule the route parser follows.
        text = "----\nInterface: Gi0/1\nIP address: 999.999.999.999\n"
        assert parse_cdp_detail(text)[0].remote_address is None
