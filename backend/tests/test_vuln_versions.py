"""Vendor version parsing and comparison (FR-VUL-01).

Every vulnerability verdict is a version comparison, so the failures here are not
cosmetic: getting one wrong reports a patched device as exploitable, or an exploitable
one as patched, with a CVE number attached to lend it authority.

The tests are organised around the three ways this can be wrong rather than around the
functions, because the functions are small and the failure modes are what matter:

* a version that parses into the wrong structure,
* two versions ordered when they should not be,
* two versions left unordered when the answer was available.
"""

from __future__ import annotations

from typing import ClassVar

import pytest

from netsecops.vuln.versions import DeviceVersion, Ordering, Scheme, compare, parse


def v(raw: str, platform: str | None = None) -> DeviceVersion:
    """Parse, insisting it succeeded — most tests are about what comes after parsing."""
    parsed = parse(raw, platform=platform)
    assert parsed is not None, f"{raw!r} did not parse"
    return parsed


# ═══════════════════════════════ parsing ═════════════════════════════════════


class TestCiscoIos:
    """The train form, which is the one the rest of the module exists for."""

    def test_the_classic_form_splits_into_release_train_and_rebuild(self) -> None:
        parsed = v("15.2(7)E3", "cisco_ios")

        assert parsed.scheme is Scheme.IOS
        assert parsed.release == (15, 2, 7)
        assert parsed.train == "E"
        assert parsed.rebuild == (3,)
        assert parsed.raw == "15.2(7)E3", "the operator's own string survives verbatim"

    def test_a_maintenance_letter_inside_the_bracket(self) -> None:
        parsed = v("15.2(4a)E1", "cisco_ios")

        assert parsed.release == (15, 2, 4)
        assert parsed.rebuild == ("a", 1)

    def test_a_train_with_no_rebuild(self) -> None:
        parsed = v("12.4(24)T", "cisco_ios")

        assert parsed.train == "T"
        assert parsed.rebuild == ()

    def test_multi_letter_trains(self) -> None:
        assert v("15.1(2)SY7", "cisco_ios").train == "SY"

    def test_an_unbranched_release_has_no_train(self) -> None:
        """`15.2(4)` is IOS-shaped but on no branch. None means trunk, not unknown."""
        parsed = v("15.2(4)", "cisco_ios")

        assert parsed.scheme is Scheme.IOS
        assert parsed.train is None

    def test_the_ios_shape_wins_over_the_platform_label(self) -> None:
        """A box onboarded as iosxe that answers in the train form is running IOS.

        The label is how someone filled in a form; the version string is what the device
        said about itself, and only one of those is evidence.
        """
        assert v("15.2(7)E3", "cisco_iosxe").scheme is Scheme.IOS


class TestOtherSchemes:
    @pytest.mark.parametrize(
        ("raw", "platform", "scheme", "release", "rebuild"),
        [
            ("17.9.4a", "cisco_iosxe", Scheme.IOSXE, (17, 9, 4), ("a",)),
            ("10.3(4a)", "cisco_nxos", Scheme.NXOS, (10, 3, 4), ("a",)),
            ("9.3(11)", "cisco_nxos", Scheme.NXOS, (9, 3, 11), ()),
            ("9.18(2)", "cisco_asa", Scheme.ASA, (9, 18, 2), ()),
            ("9.12(4)56", "cisco_asa", Scheme.ASA, (9, 12, 4), (56,)),
            ("8.10.190.0", "cisco_wlc_aireos", Scheme.AIREOS, (8, 10, 190, 0), ()),
            ("11.0.3-h1", "panos", Scheme.PANOS, (11, 0, 3), (1,)),
            ("11.0.3", "panos", Scheme.PANOS, (11, 0, 3), ()),
            ("7.2.5", "fortios", Scheme.FORTIOS, (7, 2, 5), ()),
            ("R81.20", "checkpoint_gaia", Scheme.GAIA, (81, 20), ()),
            ("R80", "checkpoint_gaia", Scheme.GAIA, (80, 0), ()),
            ("3.2.0.542", "cisco_ise", Scheme.DOTTED, (3, 2, 0, 542), ()),
        ],
    )
    def test_each_vendor_form(
        self,
        raw: str,
        platform: str,
        scheme: Scheme,
        release: tuple[int, ...],
        rebuild: tuple[object, ...],
    ) -> None:
        parsed = v(raw, platform)

        assert parsed.scheme is scheme
        assert parsed.release == release
        assert parsed.rebuild == rebuild

    def test_a_gaia_jumbo_take_is_kept(self) -> None:
        assert v("R81.20 Take 89", "checkpoint_gaia").rebuild == (89,)


class TestUnparseable:
    """What happens to a string this module does not understand.

    None, every time. A version that cannot be read is a device the matcher must decline
    to rule on, and a best guess here becomes a CVE number on someone's report.
    """

    @pytest.mark.parametrize(
        "raw",
        [
            None,
            "",
            "   ",
            "unknown",
            "Cisco IOS Software, Version 15.2",  # a whole banner, not a version
            "15.2(7)E3 [build 42]",
            "not-a-version",
        ],
    )
    def test_nothing_is_invented(self, raw: str | None) -> None:
        assert parse(raw, platform="cisco_ios") is None


# ═══════════════════════════════ ordering ════════════════════════════════════


class TestWithinATrain:
    """Where a comparison is available, it must be right."""

    def test_a_later_rebuild_is_greater(self) -> None:
        assert compare(v("15.2(7)E3", "cisco_ios"), v("15.2(7)E6", "cisco_ios")) is Ordering.LESS

    def test_rebuilds_compare_numerically_not_as_text(self) -> None:
        """E10 is later than E9. As strings, '10' < '9' and the device looks patched."""
        assert compare(v("15.2(7)E9", "cisco_ios"), v("15.2(7)E10", "cisco_ios")) is Ordering.LESS

    def test_the_base_release_precedes_its_rebuilds(self) -> None:
        assert compare(v("12.4(24)T", "cisco_ios"), v("12.4(24)T1", "cisco_ios")) is Ordering.LESS

    def test_identical_versions_are_equal(self) -> None:
        assert compare(v("15.2(7)E3", "cisco_ios"), v("15.2(7)E3", "cisco_ios")) is Ordering.EQUAL

    def test_the_release_number_outranks_the_rebuild(self) -> None:
        assert compare(v("15.2(4)E9", "cisco_ios"), v("15.2(7)E1", "cisco_ios")) is Ordering.LESS


class TestIncomparable:
    """The answers this module refuses to give.

    Each of these would be produced by any library that assumes a total order, and each
    would be acted on by someone who trusted it.
    """

    def test_different_ios_trains_are_not_ordered(self) -> None:
        """The reason this module exists.

        E and M are parallel branches with independent fix schedules. An advisory fixed
        in 15.2(4)M5 says nothing about a switch on 15.2(7)E3 — and either ordering
        invented here produces a confident, unfounded verdict.
        """
        assert compare(v("15.2(7)E3", "cisco_ios"), v("15.2(4)M5", "cisco_ios")) is None
        assert compare(v("15.2(4)M5", "cisco_ios"), v("15.2(7)E3", "cisco_ios")) is None

    def test_identical_numbers_in_different_trains_are_still_not_ordered(self) -> None:
        """Not even equal. They are different images that share a numbering."""
        assert compare(v("15.2(7)E3", "cisco_ios"), v("15.2(7)M3", "cisco_ios")) is None

    def test_a_trunk_release_is_not_ordered_against_a_branch(self) -> None:
        assert compare(v("15.2(4)", "cisco_ios"), v("15.2(4)M5", "cisco_ios")) is None

    def test_different_vendors_share_no_scale(self) -> None:
        assert compare(v("7.2.5", "fortios"), v("7.2.5", "cisco_iosxe")) is None

    def test_gaia_and_fortios_do_not_compare(self) -> None:
        assert compare(v("R81.20", "checkpoint_gaia"), v("81.20", "fortios")) is None

    def test_there_is_no_less_than_operator(self) -> None:
        """`<` cannot express "not ordered", so it is not offered.

        A caller reaching for it would get a silent total order back from Python's
        default dataclass behaviour if this were ever relaxed, which is exactly the
        false certainty the module is built to prevent.
        """
        left, right = v("15.2(7)E3", "cisco_ios"), v("15.2(4)M5", "cisco_ios")

        with pytest.raises(TypeError):
            _ = left < right  # type: ignore[operator]


class TestBracketedAndDottedSpellings:
    """The same release, written two ways by two sources.

    A Cisco device reports `9.18(2)` from `show version`; the NVD states the same
    release as `9.18.2`. If those are different schemes they are incomparable, and every
    NVD advisory against an ASA or a Nexus returns "not evaluated" — a whole vendor's
    matching dead, silently, with no error anywhere. Found by the NVD parser's tests.
    """

    def test_an_asa_bracketed_and_dotted_version_are_equal(self) -> None:
        assert compare(v("9.18(4)", "cisco_asa"), v("9.18.4", "cisco_asa")) is Ordering.EQUAL

    def test_an_asa_range_bound_from_nvd_compares_against_a_device(self) -> None:
        assert compare(v("9.18(2)", "cisco_asa"), v("9.18.4", "cisco_asa")) is Ordering.LESS

    def test_a_nexus_bracketed_and_dotted_version_compare(self) -> None:
        assert compare(v("10.3(4)", "cisco_nxos"), v("10.3.5", "cisco_nxos")) is Ordering.LESS

    def test_a_longer_nvd_bound_still_compares(self) -> None:
        """NVD writes `9.12.4.67`; the device says `9.12(4)`. Padding makes them rank."""
        assert compare(v("9.12(4)", "cisco_asa"), v("9.12.4.67", "cisco_asa")) is Ordering.LESS

    def test_an_asa_interim_build_inside_the_bracket_parses(self) -> None:
        """`9.1(7.245)` is an ordinary ASA interim release, and did not parse at all.

        Found by running a thousand real NVD records through the matcher: the bracketed
        pattern allowed only a bare integer inside the parentheses, so every ASA advisory
        stating an interim build returned "cannot parse" and the device could be neither
        ruled in nor out. Around a third of the unevaluated ASA verdicts in that sample
        were this one shape.
        """
        parsed = v("9.1(7.245)", "cisco_asa")

        assert parsed is not None
        assert parsed.release == (9, 1, 7, 245)

    def test_an_interim_build_compares_against_the_dotted_spelling(self) -> None:
        """Which is the whole point: NVD writes the same release as `9.1.7.245`."""
        assert compare(v("9.1(7.245)", "cisco_asa"), v("9.1.7.245", "cisco_asa")) is Ordering.EQUAL

    def test_interim_builds_order_within_a_maintenance_release(self) -> None:
        assert compare(v("9.1(7.245)", "cisco_asa"), v("9.1(7.246)", "cisco_asa")) is Ordering.LESS
        assert compare(v("9.1(7.245)", "cisco_asa"), v("9.1(6.1)", "cisco_asa")) is Ordering.GREATER

    def test_a_three_part_backbone_before_the_bracket_parses(self) -> None:
        """`9.9.1(1)` appears in NVD's ASA records and matched nothing before."""
        parsed = v("9.9.1(1)", "cisco_asa")

        assert parsed is not None
        assert parsed.release == (9, 9, 1, 1)

    def test_an_interim_release_outranks_its_base(self) -> None:
        """`9.1(7)` is the base; `9.1(7.245)` is a build on top of it, so it is later."""
        assert compare(v("9.1(7)", "cisco_asa"), v("9.1(7.245)", "cisco_asa")) is Ordering.LESS

    def test_the_plain_bracketed_forms_are_unchanged(self) -> None:
        """The shapes that already worked must keep their exact parse.

        Widening the pattern is only safe if it does not re-interpret the versions the
        estate is actually running.
        """
        assert v("9.18(2)", "cisco_asa").release == (9, 18, 2)
        assert v("10.3(4a)", "cisco_nxos").release == (10, 3, 4)
        assert v("10.3(4a)", "cisco_nxos").rebuild == ("a",)
        assert v("9.12(4)56", "cisco_asa").release == (9, 12, 4)
        assert v("9.12(4)56", "cisco_asa").rebuild == (56,)

    def test_a_train_letter_still_wins_over_the_bracketed_reading(self) -> None:
        """`15.2(7)E3` must stay IOS with a train, not become a bracketed ASA release."""
        parsed = v("15.2(7)E3", "cisco_ios")

        assert parsed.scheme is Scheme.IOS
        assert parsed.train == "E"

    def test_ios_is_deliberately_excluded_from_this(self) -> None:
        """The IOS train letter is meaning, not notation.

        A dotted `15.2.7` does not say whether it means the E train or the M train, so
        it stays incomparable with a device on a named train. Unlike the ASA case, the
        silence here is the correct answer rather than a bug.
        """
        assert compare(v("15.2(7)E3", "cisco_ios"), v("15.2.7", "cisco_ios")) is None


class TestPaddingAndSuffixes:
    def test_a_shorter_release_is_padded_with_zeros_not_treated_as_lower(self) -> None:
        """`17.9` and `17.9.0` are one release written two ways."""
        assert compare(v("17.9", "cisco_iosxe"), v("17.9.0", "cisco_iosxe")) is Ordering.EQUAL

    def test_a_rebuild_letter_orders_after_the_bare_release(self) -> None:
        assert compare(v("17.9.4", "cisco_iosxe"), v("17.9.4a", "cisco_iosxe")) is Ordering.LESS

    def test_rebuild_letters_order_alphabetically(self) -> None:
        assert compare(v("17.9.4a", "cisco_iosxe"), v("17.9.4b", "cisco_iosxe")) is Ordering.LESS

    def test_a_panos_hotfix_is_later_than_its_base(self) -> None:
        assert compare(v("11.0.3", "panos"), v("11.0.3-h1", "panos")) is Ordering.LESS

    def test_panos_hotfixes_order_numerically(self) -> None:
        assert compare(v("11.0.3-h2", "panos"), v("11.0.3-h10", "panos")) is Ordering.LESS

    def test_an_asa_interim_build_is_later_than_its_base(self) -> None:
        assert compare(v("9.12(4)", "cisco_asa"), v("9.12(4)56", "cisco_asa")) is Ordering.LESS


class TestOrderingIsConsistent:
    """Properties that must hold for any pair, since the matcher relies on both
    directions of a comparison meaning the same thing."""

    PAIRS: ClassVar[list[tuple[str, str, str]]] = [
        ("15.2(7)E3", "15.2(7)E6", "cisco_ios"),
        ("9.18(2)", "9.18(4)", "cisco_asa"),
        ("11.0.3", "11.0.3-h1", "panos"),
        ("R80.40", "R81.20", "checkpoint_gaia"),
        ("7.2.5", "7.4.1", "fortios"),
        ("15.2(7)E3", "15.2(4)M5", "cisco_ios"),  # the incomparable pair
    ]

    @pytest.mark.parametrize(("left", "right", "platform"), PAIRS)
    def test_reversing_the_arguments_reverses_the_answer(
        self, left: str, right: str, platform: str
    ) -> None:
        forward = compare(v(left, platform), v(right, platform))
        backward = compare(v(right, platform), v(left, platform))

        opposite = {
            Ordering.LESS: Ordering.GREATER,
            Ordering.GREATER: Ordering.LESS,
            Ordering.EQUAL: Ordering.EQUAL,
            None: None,
        }
        assert backward is opposite[forward], (
            "an asymmetric comparison would make a verdict depend on which side of the "
            "advisory the device happened to be placed"
        )

    @pytest.mark.parametrize(("left", "_right", "platform"), PAIRS)
    def test_every_version_equals_itself(self, left: str, _right: str, platform: str) -> None:
        assert compare(v(left, platform), v(left, platform)) is Ordering.EQUAL
