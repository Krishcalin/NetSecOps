"""Interval-set algebra over integers (FR-FW-03, NFR-PERF-03).

Rule relationship analysis is set arithmetic: does rule A's traffic overlap rule B's,
and if so does one contain the other. Addresses and ports are both dense integer ranges,
so both reduce to the same primitive — a sorted, merged set of inclusive intervals.

**Why this file exists at all, rather than using Python sets.** A rule permitting
10.0.0.0/8 covers sixteen million addresses. Materialising that is impossible; comparing
`(167772160, 184549375)` against another interval is two integer comparisons. Every
design decision below follows from needing 12.5 million pairwise comparisons to finish
inside two minutes.

The representation is deliberately immutable and pre-normalised: sorted, merged, no
adjacent or overlapping members. That invariant is what makes `intersects` a single
forward walk with an early exit, rather than a nested loop.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Iterator
from typing import Final

#: Inclusive bounds for the two spaces this module is used on.
IPV4_MAX: Final = 2**32 - 1
IPV6_MAX: Final = 2**128 - 1
PORT_MAX: Final = 65535

#: The coarse prefilter divides the IPv4 space into 64 buckets of /6 each, one per bit
#: of a machine word. Testing `a.signature & b.signature` rejects most non-overlapping
#: pairs in a single instruction, which is what keeps the O(n²) walk affordable.
_SIGNATURE_BUCKETS: Final = 64
_SIGNATURE_SHIFT: Final = 32 - 6  # 2**26 addresses per bucket


class IntervalSet:
    """An immutable, sorted, merged set of inclusive integer intervals.

    Construct through :meth:`of` or :meth:`from_pairs`, which normalise. The constructor
    trusts its input so the hot paths can skip re-validating what they just built.
    """

    __slots__ = ("_intervals", "_signature", "_size")

    def __init__(self, intervals: tuple[tuple[int, int], ...], *, signature: int | None = None):
        self._intervals = intervals
        self._signature = signature if signature is not None else _signature_for(intervals)
        self._size = sum(hi - lo + 1 for lo, hi in intervals)

    # ── construction ────────────────────────────────────────────────────

    @classmethod
    def empty(cls) -> IntervalSet:
        return _EMPTY

    @classmethod
    def of(cls, *pairs: tuple[int, int]) -> IntervalSet:
        return cls.from_pairs(pairs)

    @classmethod
    def from_pairs(cls, pairs: Iterable[tuple[int, int]]) -> IntervalSet:
        """Normalise arbitrary pairs into the sorted, merged invariant."""
        ordered = sorted((lo, hi) for lo, hi in pairs if lo <= hi)
        if not ordered:
            return _EMPTY

        merged: list[tuple[int, int]] = []
        current_lo, current_hi = ordered[0]

        for lo, hi in ordered[1:]:
            # `lo <= current_hi + 1` merges adjacent as well as overlapping intervals:
            # 1-10 and 11-20 are one range, and leaving them separate would make two
            # equal sets compare unequal.
            if lo <= current_hi + 1:
                if hi > current_hi:
                    current_hi = hi
            else:
                merged.append((current_lo, current_hi))
                current_lo, current_hi = lo, hi

        merged.append((current_lo, current_hi))
        return cls(tuple(merged))

    # ── inspection ──────────────────────────────────────────────────────

    @property
    def intervals(self) -> tuple[tuple[int, int], ...]:
        return self._intervals

    @property
    def signature(self) -> int:
        """Coarse 64-bit occupancy bitmap, for cheap rejection before the real test."""
        return self._signature

    @property
    def size(self) -> int:
        """How many integers the set covers. Used to rank findings by breadth."""
        return self._size

    def __bool__(self) -> bool:
        return bool(self._intervals)

    def __len__(self) -> int:
        return len(self._intervals)

    def __iter__(self) -> Iterator[tuple[int, int]]:
        return iter(self._intervals)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, IntervalSet) and self._intervals == other._intervals

    def __hash__(self) -> int:
        return hash(self._intervals)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"IntervalSet({list(self._intervals)!r})"

    # ── the operations the analyser actually runs ───────────────────────

    def intersects(self, other: IntervalSet) -> bool:
        """True if any integer is in both sets.

        The hottest function in Phase 4 — called up to three times per rule pair. The
        signature check first rejects the overwhelming majority of pairs for the cost of
        one bitwise AND; the merge walk below only runs on plausible candidates.
        """
        if not self._signature & other._signature:
            return False

        mine = self._intervals
        theirs = other._intervals
        i = j = 0

        while i < len(mine) and j < len(theirs):
            a_lo, a_hi = mine[i]
            b_lo, b_hi = theirs[j]
            if a_hi < b_lo:
                i += 1
            elif b_hi < a_lo:
                j += 1
            else:
                return True

        return False

    def contains_set(self, other: IntervalSet) -> bool:
        """True if `other` is a subset of this set — the test for shadowing."""
        if not other._intervals:
            return True
        if other._size > self._size:
            # Cheap arithmetic rejection before walking: a larger set cannot be
            # contained in a smaller one.
            return False

        mine = self._intervals
        i = 0

        for lo, hi in other._intervals:
            # Advance to the first of our intervals that could cover `lo`.
            while i < len(mine) and mine[i][1] < lo:
                i += 1
            if i == len(mine) or mine[i][0] > lo or mine[i][1] < hi:
                return False

        return True

    def intersection(self, other: IntervalSet) -> IntervalSet:
        """The overlapping portion, for describing *what* two rules share."""
        if not self._signature & other._signature:
            return _EMPTY

        result: list[tuple[int, int]] = []
        mine, theirs = self._intervals, other._intervals
        i = j = 0

        while i < len(mine) and j < len(theirs):
            a_lo, a_hi = mine[i]
            b_lo, b_hi = theirs[j]
            lo, hi = max(a_lo, b_lo), min(a_hi, b_hi)
            if lo <= hi:
                result.append((lo, hi))
            if a_hi < b_hi:
                i += 1
            else:
                j += 1

        return IntervalSet(tuple(result)) if result else _EMPTY

    def union(self, other: IntervalSet) -> IntervalSet:
        if not self._intervals:
            return other
        if not other._intervals:
            return self
        return IntervalSet.from_pairs(self._intervals + other._intervals)

    def covers_value(self, value: int) -> bool:
        """Point membership, for the FR-FW-06 rule query."""
        lo_index, high_index = 0, len(self._intervals) - 1
        while lo_index <= high_index:
            mid = (lo_index + high_index) // 2
            lo, hi = self._intervals[mid]
            if value < lo:
                high_index = mid - 1
            elif value > hi:
                lo_index = mid + 1
            else:
                return True
        return False


def _signature_for(intervals: tuple[tuple[int, int], ...]) -> int:
    """Coarse occupancy bitmap over the IPv4 space.

    Anything outside 32 bits — IPv6, or a port set — sets every bit, which makes the
    prefilter a no-op for those rather than incorrect. Correctness first: a signature
    that ever cleared a bit for an occupied region would silently hide real overlaps.
    """
    if not intervals:
        return 0

    signature = 0
    for lo, hi in intervals:
        if hi > IPV4_MAX:
            return (1 << _SIGNATURE_BUCKETS) - 1
        first = lo >> _SIGNATURE_SHIFT
        last = hi >> _SIGNATURE_SHIFT
        if last - first >= _SIGNATURE_BUCKETS - 1:
            return (1 << _SIGNATURE_BUCKETS) - 1
        for bucket in range(first, last + 1):
            signature |= 1 << bucket

    return signature


#: The empty set, shared. IntervalSet is immutable, so one instance is safe to use as a
#: dataclass default — which is also what keeps ruff's RUF009 quiet without resorting to
#: a factory for a value that can never differ.
EMPTY_INTERVALS: Final = IntervalSet((), signature=0)
_EMPTY: Final = EMPTY_INTERVALS

#: Every IPv4 address, every port. Rules say "any" constantly, so these are built once.
ANY_IPV4: Final = IntervalSet(((0, IPV4_MAX),))
ANY_IPV6: Final = IntervalSet(((0, IPV6_MAX),))
ANY_PORT: Final = IntervalSet(((0, PORT_MAX),))


# ────────────────────────── address parsing ─────────────────────────────────


def parse_address(text: str) -> tuple[IntervalSet, IntervalSet]:
    """Turn one address token into (IPv4 intervals, IPv6 intervals).

    Accepts what firewall configurations actually contain: `any`, a bare address,
    CIDR, a hyphenated range, and PAN-OS's `/32`-implied host form. An unparseable
    token yields two empty sets — the caller decides whether that is a gap worth
    reporting, because silently treating it as `any` would invent permissions the
    device does not grant.
    """
    token = text.strip().lower()
    if not token:
        return _EMPTY, _EMPTY

    if token in {"any", "all", "0.0.0.0/0", "*"}:
        return ANY_IPV4, ANY_IPV6

    if "-" in token and "/" not in token:
        start, _, end = token.partition("-")
        try:
            low = ipaddress.ip_address(start.strip())
            high = ipaddress.ip_address(end.strip())
        except ValueError:
            return _EMPTY, _EMPTY
        if low.version != high.version or int(high) < int(low):
            return _EMPTY, _EMPTY
        span = IntervalSet(((int(low), int(high)),))
        return (span, _EMPTY) if low.version == 4 else (_EMPTY, span)

    try:
        network = ipaddress.ip_network(token, strict=False)
    except ValueError:
        try:
            address = ipaddress.ip_address(token)
        except ValueError:
            return _EMPTY, _EMPTY
        span = IntervalSet(((int(address), int(address)),))
        return (span, _EMPTY) if address.version == 4 else (_EMPTY, span)

    span = IntervalSet(((int(network.network_address), int(network.broadcast_address)),))
    return (span, _EMPTY) if network.version == 4 else (_EMPTY, span)


def parse_port_range(text: str) -> IntervalSet:
    """Turn a port expression into an interval set.

    Handles `443`, `1024-65535`, `80,443,8080` and `any`. Vendors spell ranges with
    both `-` and `:`, so both are accepted.
    """
    token = text.strip().lower()
    if not token or token in {"any", "all", "*", "0-65535"}:
        return ANY_PORT

    pairs: list[tuple[int, int]] = []
    for part in token.replace(" ", "").split(","):
        if not part:
            continue
        separator = "-" if "-" in part else (":" if ":" in part else None)
        try:
            if separator:
                start, _, end = part.partition(separator)
                lo, hi = int(start), int(end)
            else:
                lo = hi = int(part)
        except ValueError:
            continue
        if 0 <= lo <= hi <= PORT_MAX:
            pairs.append((lo, hi))

    return IntervalSet.from_pairs(pairs) if pairs else _EMPTY


def describe_ipv4(intervals: IntervalSet, *, limit: int = 4) -> str:
    """Render an IPv4 interval set for a finding, collapsing to CIDR where exact.

    Findings are read by people. `10.0.0.0/8` is recognisable; `167772160-184549375`
    is not, even though they are the same thing.
    """
    if not intervals:
        return "nothing"
    if intervals == ANY_IPV4:
        return "any"

    parts: list[str] = []
    for lo, hi in intervals.intervals[:limit]:
        try:
            summarised = list(
                ipaddress.summarize_address_range(
                    ipaddress.IPv4Address(lo), ipaddress.IPv4Address(hi)
                )
            )
        except (ipaddress.AddressValueError, ValueError):  # pragma: no cover - guarded by callers
            parts.append(f"{lo}-{hi}")
            continue

        if len(summarised) == 1:
            network = summarised[0]
            parts.append(str(network.network_address) if network.prefixlen == 32 else str(network))
        else:
            parts.append(f"{ipaddress.IPv4Address(lo)}-{ipaddress.IPv4Address(hi)}")

    remaining = len(intervals.intervals) - limit
    if remaining > 0:
        parts.append(f"and {remaining} more")
    return ", ".join(parts)


__all__ = [
    "ANY_IPV4",
    "ANY_IPV6",
    "ANY_PORT",
    "EMPTY_INTERVALS",
    "IPV4_MAX",
    "IPV6_MAX",
    "PORT_MAX",
    "IntervalSet",
    "describe_ipv4",
    "parse_address",
    "parse_port_range",
]
