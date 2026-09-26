"""Every parser's NAT, in one shape the path walk can read (FR-TOPO-03, FR-FW-04).

The legacy `NatRule.original` could not be matched against a packet, and the reason was
data rather than effort: it holds the rule's *source* members on PAN-OS whatever the
rule translates, a VIP's *external* address on FortiOS, joined object names on Check
Point, and nothing at all on ASA. Four parsers, four meanings, one field.

These tests pin the normalised fields against each platform's real syntax, because that
is the only thing that makes the translation engine trustworthy — and a normalisation
that is wrong on one platform is worse than none, since nothing in the output says
which platform an answer came from.

The other half of what is tested here is the refusals. `translation_unreadable` has to
be set wherever the configuration genuinely does not say what a packet becomes, and a
parser quietly leaving the fields empty instead would turn "could not read this" into
"no translation here" — which is the failure the whole design is arranged against.
"""

from __future__ import annotations

from netsecops.ncm.models import NatRule
from netsecops.parsers.cisco.asa import _normalise_object_nat, _normalise_twice_nat


def asa_twice(line: str, direction: str | None = None) -> NatRule:
    rule = NatRule(order=1, raw=line, direction=direction)
    _normalise_twice_nat(rule)
    return rule


def asa_object(line: str, object_name: str | None) -> NatRule:
    rule = NatRule(order=1, raw=line)
    _normalise_object_nat(rule, object_name)
    return rule


class TestCiscoAsaTwiceNat:
    """ASA ships no structured NAT at all, so the grammar is read from the line."""

    def test_static_source_translation(self) -> None:
        rule = asa_twice(
            "nat (dmz,outside) source static OBJ-WEB-SERVER OBJ-WEB-PUBLIC",
            direction="dmz,outside",
        )

        assert rule.original_source == ["OBJ-WEB-SERVER"]
        assert rule.translated_source == ["OBJ-WEB-PUBLIC"]
        assert rule.translation_unreadable is None

    def test_destination_static_reverses_its_arguments(self) -> None:
        """The single most-confused thing in ASA's syntax, and getting it backwards
        inverts the answer. In `source static A B`, A is real and B is mapped; in
        `destination static C D`, C is *mapped* and D is *real*."""
        rule = asa_twice(
            "nat (outside,dmz) source static any any destination static PUBLIC-VIP REAL-WEB",
            direction="outside,dmz",
        )

        assert rule.original_destination == ["PUBLIC-VIP"]
        assert rule.translated_destination == ["REAL-WEB"]

    def test_interface_is_not_an_address_and_says_so(self) -> None:
        """`interface` means whichever address that interface currently holds, which is
        not in this line. Recording it as translated-to-"interface" would make the
        engine try to resolve a keyword as a hostname."""
        rule = asa_twice(
            "nat (inside,outside) source dynamic OBJ-INSIDE-NET interface",
            direction="inside,outside",
        )

        assert rule.original_source == ["OBJ-INSIDE-NET"]
        assert rule.translated_source == []
        assert rule.translation_unreadable is not None
        assert "outside" in rule.translation_unreadable

    def test_a_service_clause_is_recorded_as_the_matched_ports(self) -> None:
        rule = asa_twice(
            "nat (dmz,outside) source static OBJ-WEB-SERVER interface service SVC-HTTPS SVC-HTTPS",
            direction="dmz,outside",
        )

        assert rule.original_ports == ["SVC-HTTPS"]

    def test_any_as_a_match_condition_means_no_constraint(self) -> None:
        """`any` and an omitted condition are the same thing, and both have to come out
        as an empty list — a literal "any" would be looked up as an object name and
        fail to resolve, turning a matching rule into an unreadable one."""
        rule = asa_twice(
            "nat (outside,dmz) source any any destination static VIP REAL",
            direction="outside,dmz",
        )

        assert rule.original_source == []


class TestCiscoAsaObjectNat:
    def test_the_enclosing_object_is_the_real_address(self) -> None:
        """The line never names what it translates — the object it sits inside is the
        real address — which is why the name has to be threaded in."""
        rule = asa_object("nat (inside,outside) static 203.0.113.10", "OBJ-WEB-SERVER")

        assert rule.original_source == ["OBJ-WEB-SERVER"]
        assert rule.translated_source == ["203.0.113.10"]

    def test_without_the_object_name_it_refuses_rather_than_inventing(self) -> None:
        rule = asa_object("nat (inside,outside) static 203.0.113.10", None)

        assert rule.original_source == []
        assert rule.translation_unreadable is not None

    def test_interface_translation_is_unreadable_here_too(self) -> None:
        rule = asa_object("nat (inside,outside) dynamic interface", "OBJ-INSIDE-NET")

        assert rule.translated_source == []
        assert rule.translation_unreadable is not None


class TestTheLegacyFieldsAreUntouched:
    """The NAT *hygiene* analysis and the rulebase viewer read `original`, `translated`,
    `service` and `direction`. Normalisation added fields; it must not have changed the
    meaning of the ones already in use, or every existing NAT finding shifts."""

    def test_normalising_a_twice_nat_line_leaves_raw_and_direction_alone(self) -> None:
        line = "nat (inside,outside) source dynamic OBJ-INSIDE-NET interface"
        rule = asa_twice(line, direction="inside,outside")

        assert rule.raw == line
        assert rule.direction == "inside,outside"
        assert rule.original is None, "the legacy field was never set on ASA and still is not"
