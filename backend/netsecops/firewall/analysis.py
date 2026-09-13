"""Rule relationship analysis (FR-FW-03, NFR-PERF-03).

The taxonomy is Al-Shaer and Hamed's, which is what "rule relationship analysis" means
in the literature and what firewall auditors expect to be handed:

- **Shadowing** — an earlier rule fully covers a later one with a *different* action.
  The later rule can never fire. This is the finding that matters most, because it means
  the rulebase does not do what it appears to say.
- **Redundancy** — one rule fully covers another with the *same* action. Harmless to
  traffic, but it is dead weight that makes every future change riskier to reason about.
- **Correlation** — partial overlap with different actions. Not a defect, but the order
  is load-bearing: moving either rule changes what the firewall does.
- **Generalisation** — a later rule is broader than an earlier one with a different
  action. This is the normal, intended shape of a specific exception before a general
  rule, and is reported at Info because it is *sometimes* a mistake and never obviously
  one.

**Pairwise, and honest about it.** A rule can also be shadowed by the *union* of several
preceding rules while no single one covers it. Detecting that is a set-cover problem, and
the pairwise analysis is what the literature, and every comparable product, reports.
:func:`analyse` records the limitation rather than leaving a reader to assume otherwise.

**Why it is fast enough.** 5,000 rules is 12.5 million ordered pairs. Three filters run
before any set arithmetic, cheapest first: disabled rules are dropped, zone pairs that
cannot meet are skipped, and a 64-bit address signature rejects the rest with one bitwise
AND. Only survivors reach the interval walk.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.firewall.intervals import describe_ipv4
from netsecops.firewall.model import ResolvedRule

log = get_logger(__name__)


class Relationship(StrEnum):
    SHADOWED = "shadowed"
    REDUNDANT = "redundant"
    CORRELATED = "correlated"
    GENERALISATION = "generalisation"


#: Third-person forms of the actions vendors use. Appending "s" gives "denys", which
#: appears in a finding an operator reads and undermines everything around it.
_ACTION_VERBS: dict[str, str] = {
    "deny": "denies",
    "drop": "drops",
    "allow": "allows",
    "permit": "permits",
    "accept": "accepts",
    "reset": "resets",
    "reject": "rejects",
}


def _third_person(action: str) -> str:
    lowered = action.lower()
    return _ACTION_VERBS.get(lowered, f"{lowered}s")


#: How severe each relationship is, by default. A policy can re-grade them.
RELATIONSHIP_SEVERITY: dict[Relationship, str] = {
    Relationship.SHADOWED: "high",
    Relationship.REDUNDANT: "low",
    Relationship.CORRELATED: "info",
    Relationship.GENERALISATION: "info",
}


@dataclass(frozen=True, slots=True)
class RuleRelationship:
    """One relationship between two rules.

    Holds references to the rules rather than a formatted description, and builds the
    wording only when something asks for it. That is not a micro-optimisation: rendering
    an address range into CIDR calls `summarize_address_range`, and doing it eagerly for
    every pair made a pathological rulebase take 134 seconds against a 120-second budget.
    Almost all of that work was for text nobody would ever read, because the output is
    capped at `MAX_RELATIONSHIPS` anyway.
    """

    kind: Relationship
    #: The rule that comes first and does the covering.
    earlier: ResolvedRule
    #: The rule affected by it.
    later: ResolvedRule
    #: Set for the cases whose wording cannot be derived from the pair alone.
    note: str = ""

    @property
    def earlier_order(self) -> int:
        return self.earlier.order

    @property
    def earlier_name(self) -> str:
        return self.earlier.name

    @property
    def later_order(self) -> int:
        return self.later.order

    @property
    def later_name(self) -> str:
        return self.later.name

    @property
    def severity(self) -> str:
        return RELATIONSHIP_SEVERITY[self.kind]

    @property
    def detail(self) -> str:
        """Built on demand. See the class docstring for why."""
        if self.note:
            return self.note

        earlier, later = self.earlier, self.later
        match self.kind:
            case Relationship.SHADOWED:
                return (
                    f"#{earlier.order} already matches everything #{later.order} does, "
                    f"and {_third_person(earlier.action)} it instead"
                )
            case Relationship.REDUNDANT:
                return f"#{earlier.order} already matches everything #{later.order} does"
            case Relationship.GENERALISATION:
                return (
                    f"#{later.order} is broader than #{earlier.order}, which acts as a "
                    "more specific exception above it"
                )
            case Relationship.CORRELATED:
                return (
                    f"they overlap with different actions ({earlier.action} then "
                    f"{later.action}), so the order between them decides the outcome — "
                    + _overlap_detail(earlier, later)
                )

    def describe(self) -> str:
        return (
            f"Rule #{self.later_order} ({self.later_name}) is {self.kind.value} by "
            f"#{self.earlier_order} ({self.earlier_name}): {self.detail}"
        )


@dataclass(slots=True)
class AnalysisResult:
    #: Materialised relationships, capped at `max_relationships`.
    relationships: list[RuleRelationship] = field(default_factory=list)
    #: Every relationship found, counted by kind, whether materialised or not. A
    #: rulebase with two million correlations has one systemic problem; the count is
    #: the finding, and the first two thousand examples are the evidence.
    total_by_kind: dict[str, int] = field(default_factory=dict)
    rules_analysed: int = 0
    pairs_considered: int = 0
    pairs_compared: int = 0
    duration_ms: int = 0
    truncated: bool = False
    #: Stated on every result so a reader is never left to assume otherwise.
    limitations: tuple[str, ...] = (
        "Relationships are pairwise. A rule shadowed only by the combined effect of "
        "several preceding rules is not reported.",
        "Application identity (App-ID) and user identity are compared by name, not by "
        "the traffic they match, so two rules naming different applications are treated "
        "as non-overlapping.",
    )

    def by_kind(self, kind: Relationship) -> list[RuleRelationship]:
        return [r for r in self.relationships if r.kind is kind]

    @property
    def counts(self) -> dict[str, int]:
        """Totals found, not totals shown. See `total_by_kind`."""
        return dict(self.total_by_kind)

    @property
    def total_found(self) -> int:
        return sum(self.total_by_kind.values())


#: Beyond this many findings the output stops being a report and becomes a data dump.
#: A rulebase with 20,000 relationships has one systemic problem, not 20,000 separate
#: ones, and the operator needs the first hundred plus the count.
MAX_RELATIONSHIPS = 2000


def _identity_overlaps(a: ResolvedRule, b: ResolvedRule) -> bool:
    """Whether two rules can match the same traffic on application and user.

    Compared by name, which is a real limitation and is declared in `limitations`.
    Resolving App-ID to ports would need Palo Alto's application database, which is
    licensed content we do not have and must not guess at.
    """
    if a.applications and b.applications and a.applications.isdisjoint(b.applications):
        if "any" not in a.applications and "any" not in b.applications:
            return False
    if a.users and b.users and a.users.isdisjoint(b.users):
        if "any" not in a.users and "any" not in b.users:
            return False
    return True


def _identity_contains(outer: ResolvedRule, inner: ResolvedRule) -> bool:
    apps_ok = (
        not outer.applications
        or "any" in outer.applications
        or (bool(inner.applications) and inner.applications <= outer.applications)
    )
    users_ok = (
        not outer.users
        or "any" in outer.users
        or (bool(inner.users) and inner.users <= outer.users)
    )
    return bool(apps_ok and users_ok)


def _covers(outer: ResolvedRule, inner: ResolvedRule) -> bool:
    """True if every packet `inner` matches, `outer` also matches."""
    return (
        outer.zones_contain(inner)
        and outer.source.contains(inner.source)
        and outer.destination.contains(inner.destination)
        and outer.services.contains(inner.services)
        and _identity_contains(outer, inner)
    )


def _overlap_detail(earlier: ResolvedRule, later: ResolvedRule) -> str:
    source = earlier.source.v4.intersection(later.source.v4)
    destination = earlier.destination.v4.intersection(later.destination.v4)
    return (
        f"both match {describe_ipv4(source)} → {describe_ipv4(destination)} "
        f"on {later.services.describe()}"
    )


def analyse(
    rules: Sequence[ResolvedRule],
    *,
    include_disabled: bool = False,
    max_relationships: int = MAX_RELATIONSHIPS,
) -> AnalysisResult:
    """Find every pairwise relationship in a rulebase, in evaluation order.

    Rules must be supplied in the order the device evaluates them; the whole analysis
    is a statement about precedence, and sorting them differently would produce
    confident nonsense.
    """
    started = time.perf_counter()

    active = [r for r in rules if include_disabled or r.enabled]
    result = AnalysisResult(rules_analysed=len(active))

    for later_index in range(1, len(active)):
        later = active[later_index]

        for earlier_index in range(later_index):
            earlier = active[earlier_index]
            result.pairs_considered += 1

            # ── filter 1: zones, an integer set test on tiny sets ────────
            if not earlier.zones_intersect(later):
                continue

            # ── filter 2: the address signature, one bitwise AND ─────────
            # Ordered cheapest-first deliberately: this rejects the majority of pairs
            # in a real rulebase, and everything below it is comparatively expensive.
            if not earlier.source.intersects(later.source):
                continue
            if not earlier.destination.intersects(later.destination):
                continue

            # ── filter 3: services, then identity ───────────────────────
            if not earlier.services.intersects(later.services):
                continue
            if not _identity_overlaps(earlier, later):
                continue

            result.pairs_compared += 1

            earlier_covers = _covers(earlier, later)
            later_covers = _covers(later, earlier)
            same_action = earlier.action.lower() == later.action.lower()

            if earlier_covers:
                kind = Relationship.REDUNDANT if same_action else Relationship.SHADOWED
            elif later_covers and not same_action:
                # The later rule is broader. A specific exception above a general rule
                # is the normal shape of a good rulebase, so this is informational.
                kind = Relationship.GENERALISATION
            elif later_covers:
                kind = Relationship.REDUNDANT
            elif same_action:
                # Partial overlap with the same verdict changes nothing about the
                # firewall's behaviour, so it is not worth an operator's attention.
                continue
            else:
                kind = Relationship.CORRELATED

            # Counted always, materialised only while there is room. The count stays
            # truthful — "1.2 million correlations" is itself the finding — without
            # building a million objects nobody will read.
            result.total_by_kind[kind.value] = result.total_by_kind.get(kind.value, 0) + 1

            if len(result.relationships) < max_relationships:
                result.relationships.append(
                    RuleRelationship(kind=kind, earlier=earlier, later=later)
                )
            else:
                result.truncated = True

            # A rule fully shadowed by an earlier one cannot be more shadowed by
            # another. Stopping here is not just an optimisation: reporting the same
            # dead rule five times buries the other four problems.
            if kind is Relationship.SHADOWED:
                break

    result.duration_ms = int((time.perf_counter() - started) * 1000)

    log.info(
        "firewall.analysis_complete",
        rules=result.rules_analysed,
        pairs_considered=result.pairs_considered,
        pairs_compared=result.pairs_compared,
        relationships=result.total_found,
        shown=len(result.relationships),
        duration_ms=result.duration_ms,
        truncated=result.truncated,
    )
    return result


# ─────────────────────────── the rule query (FR-FW-06) ──────────────────────


@dataclass(frozen=True, slots=True)
class QueryResult:
    matched: ResolvedRule | None
    #: Rules that would have matched had the winner not come first, in order. Useful
    #: for "why did my new rule not take effect".
    shadowed_by_match: tuple[ResolvedRule, ...] = ()
    limitations: tuple[str, ...] = (
        "Matching is over addresses, protocol and port only. Application identity and "
        "user identity are not simulated, so a rule that would be narrowed by App-ID "
        "or User-ID may be reported as matching when the device would not match it.",
    )


def first_match(
    rules: Sequence[ResolvedRule],
    *,
    source: int,
    destination: int,
    protocol: int,
    port: int,
    src_zone: str | None = None,
    dst_zone: str | None = None,
) -> QueryResult:
    """Which rule would match this packet (FR-FW-06).

    First-match-wins over the enabled rules, in order. Addresses are integers so the
    caller does the parsing once; the limitations are returned with the answer rather
    than documented elsewhere, because an unqualified "rule 42 matches" would be read
    as a guarantee.
    """
    from netsecops.firewall.model import ANY_PROTOCOL

    later_matches: list[ResolvedRule] = []
    winner: ResolvedRule | None = None

    for rule in rules:
        if not rule.enabled:
            continue
        if src_zone and rule.src_zones and src_zone not in rule.src_zones:
            continue
        if dst_zone and rule.dst_zones and dst_zone not in rule.dst_zones:
            continue
        if not rule.source.v4.covers_value(source):
            continue
        if not rule.destination.v4.covers_value(destination):
            continue

        ports = rule.services.by_protocol.get(protocol) or rule.services.by_protocol.get(
            ANY_PROTOCOL
        )
        if ports is None or not ports.covers_value(port):
            continue

        if winner is None:
            winner = rule
        else:
            later_matches.append(rule)

    return QueryResult(matched=winner, shadowed_by_match=tuple(later_matches))


def summarise(result: AnalysisResult) -> dict[str, Any]:
    """A compact form for storing on a finding or returning from the API."""
    return {
        "rules_analysed": result.rules_analysed,
        "pairs_considered": result.pairs_considered,
        "pairs_compared": result.pairs_compared,
        "duration_ms": result.duration_ms,
        "truncated": result.truncated,
        "counts": result.counts,
        "total_found": result.total_found,
        "shown": len(result.relationships),
        "limitations": list(result.limitations),
    }


__all__ = [
    "MAX_RELATIONSHIPS",
    "RELATIONSHIP_SEVERITY",
    "AnalysisResult",
    "QueryResult",
    "Relationship",
    "RuleRelationship",
    "analyse",
    "first_match",
    "summarise",
]
