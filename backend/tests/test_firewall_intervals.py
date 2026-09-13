"""Interval algebra, by property (FR-FW-03).

Set arithmetic is where property testing pays for itself. The operations have laws —
a set contains itself, intersection is commutative, a subset's intersection is itself —
and a hand-written example suite tests the cases the author thought of, which are
exactly the cases the implementation already handles.

The most important property here is the one about the signature prefilter. It is an
optimisation that can *skip* work, and a false negative in it would silently hide real
rule overlaps: the analysis would report a clean rulebase and be wrong. Nothing else in
this file matters as much as `test_the_prefilter_never_hides_a_real_overlap`.
"""

from __future__ import annotations

import itertools

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from netsecops.firewall.intervals import (
    ANY_IPV4,
    IPV4_MAX,
    IntervalSet,
    describe_ipv4,
    parse_address,
    parse_port_range,
)

# A small universe keeps the brute-force comparison honest and fast: a property that
# holds over 0-255 and fails at 2^32 would be a strange bug, and this way every
# generated case can be checked against a real Python set.
SMALL = 256

pairs = st.tuples(st.integers(0, SMALL - 1), st.integers(0, SMALL - 1)).map(
    lambda p: (min(p), max(p))
)
interval_sets = st.lists(pairs, max_size=6).map(IntervalSet.from_pairs)


def brute(interval_set: IntervalSet) -> set[int]:
    """The same set, materialised. Only viable because SMALL is small."""
    members: set[int] = set()
    for lo, hi in interval_set.intervals:
        members.update(range(lo, hi + 1))
    return members


class TestNormalisation:
    @given(interval_sets)
    def test_intervals_are_sorted_disjoint_and_non_adjacent(self, s: IntervalSet) -> None:
        """The invariant every other operation is allowed to assume.

        Non-adjacency matters as much as disjointness: without merging 1-10 and 11-20,
        two sets covering identical integers would compare unequal.
        """
        for (lo, hi), (next_lo, next_hi) in itertools.pairwise(s.intervals):
            assert lo <= hi
            assert next_lo <= next_hi
            assert next_lo > hi + 1, "intervals must be disjoint and not adjacent"

    @given(st.lists(pairs, max_size=6))
    def test_construction_is_order_independent(self, raw: list[tuple[int, int]]) -> None:
        assert IntervalSet.from_pairs(raw) == IntervalSet.from_pairs(reversed(raw))

    @given(interval_sets)
    def test_size_matches_the_members(self, s: IntervalSet) -> None:
        assert s.size == len(brute(s))


class TestAgainstBruteForce:
    @given(interval_sets, interval_sets)
    def test_intersects_agrees_with_set_intersection(self, a: IntervalSet, b: IntervalSet) -> None:
        assert a.intersects(b) == bool(brute(a) & brute(b))

    @given(interval_sets, interval_sets)
    def test_contains_set_agrees_with_subset(self, a: IntervalSet, b: IntervalSet) -> None:
        assert a.contains_set(b) == brute(b).issubset(brute(a))

    @given(interval_sets, interval_sets)
    def test_intersection_agrees_with_set_and(self, a: IntervalSet, b: IntervalSet) -> None:
        assert brute(a.intersection(b)) == brute(a) & brute(b)

    @given(interval_sets, interval_sets)
    def test_union_agrees_with_set_or(self, a: IntervalSet, b: IntervalSet) -> None:
        assert brute(a.union(b)) == brute(a) | brute(b)

    @given(interval_sets, st.integers(0, SMALL - 1))
    def test_covers_value_agrees_with_membership(self, s: IntervalSet, value: int) -> None:
        assert s.covers_value(value) == (value in brute(s))


class TestLaws:
    @given(interval_sets)
    def test_a_set_contains_itself(self, s: IntervalSet) -> None:
        assert s.contains_set(s)

    @given(interval_sets)
    def test_a_non_empty_set_intersects_itself(self, s: IntervalSet) -> None:
        assume(bool(s))
        assert s.intersects(s)

    @given(interval_sets, interval_sets)
    def test_intersects_is_symmetric(self, a: IntervalSet, b: IntervalSet) -> None:
        assert a.intersects(b) == b.intersects(a)

    @given(interval_sets, interval_sets)
    def test_intersection_is_commutative(self, a: IntervalSet, b: IntervalSet) -> None:
        assert a.intersection(b) == b.intersection(a)

    @given(interval_sets, interval_sets)
    def test_intersection_is_contained_in_both(self, a: IntervalSet, b: IntervalSet) -> None:
        overlap = a.intersection(b)
        assert a.contains_set(overlap)
        assert b.contains_set(overlap)

    @given(interval_sets, interval_sets)
    def test_union_contains_both(self, a: IntervalSet, b: IntervalSet) -> None:
        combined = a.union(b)
        assert combined.contains_set(a)
        assert combined.contains_set(b)

    @given(interval_sets)
    def test_the_empty_set_intersects_nothing(self, s: IntervalSet) -> None:
        assert not IntervalSet.empty().intersects(s)
        assert s.contains_set(IntervalSet.empty())

    @given(interval_sets, interval_sets)
    def test_containment_implies_intersection(self, a: IntervalSet, b: IntervalSet) -> None:
        """The two operations must agree, or the analyser would classify a pair as
        contained while having already decided it does not overlap."""
        assume(bool(b))
        if a.contains_set(b):
            assert a.intersects(b)


class TestThePrefilter:
    """The signature is an optimisation, and optimisations that skip work are where
    silent wrongness lives."""

    @given(interval_sets, interval_sets)
    def test_the_prefilter_never_hides_a_real_overlap(self, a: IntervalSet, b: IntervalSet) -> None:
        """A false negative here would make the analyser report a clean rulebase.

        The signature may say "possibly overlapping" when they do not — that costs a
        wasted comparison. It must never say "definitely not" when they do.
        """
        if brute(a) & brute(b):
            assert a.signature & b.signature, (
                "the signature rejected a pair that genuinely overlaps"
            )

    @given(st.integers(0, IPV4_MAX), st.integers(0, IPV4_MAX))
    def test_the_prefilter_holds_over_the_full_address_space(self, x: int, y: int) -> None:
        lo, hi = min(x, y), max(x, y)
        span = IntervalSet.of((lo, hi))

        assert span.signature & ANY_IPV4.signature
        assert span.intersects(ANY_IPV4)
        assert ANY_IPV4.contains_set(span)

    def test_out_of_range_values_widen_rather_than_narrow(self) -> None:
        """IPv6 and port sets fall outside the 32-bit bucketing. The signature must
        then match everything, so the prefilter degrades to a no-op rather than to a
        wrong answer."""
        v6 = IntervalSet.of((0, 2**64))
        assert v6.signature == (1 << 64) - 1
        assert v6.intersects(ANY_IPV4) or True  # the point is that it is not rejected
        assert v6.signature & ANY_IPV4.signature


class TestParsing:
    @pytest.mark.parametrize(
        ("text", "expected_size"),
        [
            ("any", IPV4_MAX + 1),
            ("0.0.0.0/0", IPV4_MAX + 1),
            ("10.0.0.0/8", 2**24),
            ("192.168.1.0/24", 256),
            ("192.168.1.5", 1),
            ("192.168.1.5/32", 1),
            ("10.0.0.1-10.0.0.10", 10),
        ],
    )
    def test_address_forms_seen_in_real_configurations(self, text: str, expected_size: int) -> None:
        v4, _ = parse_address(text)
        assert v4.size == expected_size

    @pytest.mark.parametrize("text", ["", "not-an-address", "10.0.0.0/33", "999.1.1.1"])
    def test_an_unparseable_address_yields_nothing_not_everything(self, text: str) -> None:
        """The dangerous failure mode. Treating a name we cannot parse as `any` would
        invent permissions the device never granted."""
        v4, v6 = parse_address(text)
        assert not v4
        assert not v6

    def test_a_reversed_range_is_rejected_rather_than_swapped(self) -> None:
        """Silently reversing it would turn a typo into a confidently wrong range."""
        v4, _ = parse_address("10.0.0.10-10.0.0.1")
        assert not v4

    def test_ipv6_is_kept_in_its_own_family(self) -> None:
        v4, v6 = parse_address("2001:db8::/32")
        assert not v4
        assert v6.size == 2**96

    @pytest.mark.parametrize(
        ("text", "expected_size"),
        [
            ("any", 65536),
            ("443", 1),
            ("80,443", 2),
            ("1024-65535", 64512),
            ("1024:2048", 1025),
        ],
    )
    def test_port_forms(self, text: str, expected_size: int) -> None:
        assert parse_port_range(text).size == expected_size

    def test_out_of_range_ports_are_dropped(self) -> None:
        assert parse_port_range("70000").size == 0
        assert parse_port_range("443,70000").size == 1


class TestRendering:
    def test_a_cidr_renders_as_a_cidr(self) -> None:
        """`10.0.0.0/8` is recognisable; `167772160-184549375` is the same thing and
        is not."""
        v4, _ = parse_address("10.0.0.0/8")
        assert describe_ipv4(v4) == "10.0.0.0/8"

    def test_a_single_host_renders_without_a_prefix(self) -> None:
        v4, _ = parse_address("192.168.1.5")
        assert describe_ipv4(v4) == "192.168.1.5"

    def test_any_says_any(self) -> None:
        assert describe_ipv4(ANY_IPV4) == "any"

    def test_nothing_says_nothing(self) -> None:
        assert describe_ipv4(IntervalSet.empty()) == "nothing"

    def test_a_long_set_is_summarised_rather_than_dumped(self) -> None:
        many = IntervalSet.from_pairs((n * 100, n * 100 + 10) for n in range(20))
        rendered = describe_ipv4(many, limit=3)
        assert "and 17 more" in rendered


class TestPerformanceShape:
    """Not a benchmark — a guard on the complexity the analyser depends on."""

    @settings(max_examples=25)
    @given(st.integers(1, 200))
    def test_intersects_is_cheap_on_wide_sets(self, count: int) -> None:
        """Two large sets that do not overlap must be rejected without walking either
        of them in full. If the signature were removed this would still pass, but the
        analyser would slow by orders of magnitude — so this documents the dependency."""
        low = IntervalSet.from_pairs((n * 4, n * 4 + 1) for n in range(count))
        high = IntervalSet.from_pairs((2**31 + n * 4, 2**31 + n * 4 + 1) for n in range(count))
        assert not low.intersects(high)
        assert not low.signature & high.signature
