"""Object hygiene (FR-FW-05).

Unused objects, duplicates under different names, and groups nested deeper than anyone
can hold in their head. None of these is a vulnerability. All of them make the rulebase
harder to change safely, which is how vulnerabilities get introduced — an operator who
cannot tell which of `WEB-SERVERS`, `Web_Servers` and `websrv-grp` is live picks one and
hopes.

Findings here are Low and Info by design. Reporting object clutter at High would compete
with an any/any rule for the same attention, and lose the reader.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from netsecops.firewall.model import MAX_GROUP_DEPTH, ObjectResolver, ResolvedRule


class HygieneIssue(StrEnum):
    UNUSED_OBJECT = "unused_object"
    DUPLICATE_OBJECT = "duplicate_object"
    DEEP_NESTING = "deep_nesting"
    EMPTY_GROUP = "empty_group"
    UNDEFINED_REFERENCE = "undefined_reference"


HYGIENE_SEVERITY: dict[HygieneIssue, str] = {
    # An undefined reference is the only one that changes what the firewall does — or
    # rather, what we can say about what it does — so it outranks the rest.
    HygieneIssue.UNDEFINED_REFERENCE: "medium",
    HygieneIssue.UNUSED_OBJECT: "info",
    HygieneIssue.DUPLICATE_OBJECT: "low",
    HygieneIssue.DEEP_NESTING: "low",
    HygieneIssue.EMPTY_GROUP: "low",
}

#: Nesting beyond this is reported. Three levels is about the limit of what someone can
#: expand mentally while reading a rule; the resolver's hard stop is much higher
#: (MAX_GROUP_DEPTH) because refusing to resolve is worse than reporting.
COMFORTABLE_NESTING_DEPTH = 3


@dataclass(frozen=True, slots=True)
class HygieneFinding:
    issue: HygieneIssue
    name: str
    message: str

    @property
    def severity(self) -> str:
        return HYGIENE_SEVERITY[self.issue]


@dataclass(slots=True)
class HygieneReport:
    findings: list[HygieneFinding] = field(default_factory=list)
    objects_defined: int = 0
    objects_referenced: int = 0

    def by_issue(self, issue: HygieneIssue) -> list[HygieneFinding]:
        return [f for f in self.findings if f.issue is issue]

    @property
    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.issue.value] = counts.get(finding.issue.value, 0) + 1
        return counts


def _nesting_depth(resolver: ObjectResolver, name: str, seen: frozenset[str]) -> int:
    """How deep a group nests. Cycle-safe: a name already on the path stops the walk."""
    if name in seen:
        return 0
    members = resolver.group_members(name)
    if not members:
        return 0
    return 1 + max(_nesting_depth(resolver, member, seen | {name}) for member in members)


def examine(
    resolver: ObjectResolver,
    rules: Sequence[ResolvedRule],
    *,
    max_reported: int = 200,
) -> HygieneReport:
    """Assess the object catalogue behind a rulebase (FR-FW-05)."""
    defined = resolver.defined_names()
    report = HygieneReport(
        objects_defined=len(defined),
        objects_referenced=len(resolver.referenced),
    )

    # ── objects nothing references ──────────────────────────────────────
    unused = sorted(defined - resolver.referenced)
    for name in unused[:max_reported]:
        report.findings.append(
            HygieneFinding(
                issue=HygieneIssue.UNUSED_OBJECT,
                name=name,
                message=(
                    f"`{name}` is defined but no rule or group references it. Unused "
                    "objects accumulate until nobody can tell which names are live."
                ),
            )
        )
    if len(unused) > max_reported:
        report.findings.append(
            HygieneFinding(
                issue=HygieneIssue.UNUSED_OBJECT,
                name=f"and {len(unused) - max_reported} more",
                message=(
                    f"{len(unused):,} objects in total are defined and never "
                    "referenced. At this scale it is a housekeeping exercise rather "
                    "than a list of individual mistakes."
                ),
            )
        )

    # ── the same value under several names ──────────────────────────────
    by_value: dict[str, list[str]] = defaultdict(list)
    for name, value in resolver.address_values().items():
        by_value[value.strip().lower()].append(name)

    for value, names in sorted(by_value.items()):
        if len(names) < 2:
            continue
        report.findings.append(
            HygieneFinding(
                issue=HygieneIssue.DUPLICATE_OBJECT,
                name=", ".join(sorted(names)),
                message=(
                    f"{len(names)} objects hold the same value `{value}`: "
                    f"{', '.join(sorted(names))}. Changing the address means finding "
                    "every one of them, and missing one leaves a rule pointing at the "
                    "old value."
                ),
            )
        )

    # ── groups nested deeper than anyone can follow ─────────────────────
    for name in sorted(defined):
        members = resolver.group_members(name)
        if not members:
            continue
        if not [m for m in members if m.strip()]:
            report.findings.append(
                HygieneFinding(
                    issue=HygieneIssue.EMPTY_GROUP,
                    name=name,
                    message=(
                        f"Group `{name}` has no members. A rule using it matches "
                        "nothing, which is easy to mistake for a rule that works."
                    ),
                )
            )
            continue

        depth = _nesting_depth(resolver, name, frozenset())
        if depth > COMFORTABLE_NESTING_DEPTH:
            report.findings.append(
                HygieneFinding(
                    issue=HygieneIssue.DEEP_NESTING,
                    name=name,
                    message=(
                        f"Group `{name}` nests {depth} levels deep. Working out what a "
                        "rule using it actually permits means expanding "
                        f"{depth} levels by hand."
                        + (
                            f" The resolver stops at {MAX_GROUP_DEPTH} levels."
                            if depth >= MAX_GROUP_DEPTH
                            else ""
                        )
                    ),
                )
            )

    # ── names referenced but never defined ──────────────────────────────
    for name in sorted(resolver.unresolved)[:max_reported]:
        report.findings.append(
            HygieneFinding(
                issue=HygieneIssue.UNDEFINED_REFERENCE,
                name=name,
                message=(
                    f"`{name}` is referenced by a rule but is not defined in the "
                    "collected configuration. Either the collection is incomplete or "
                    "the rule is broken; either way the rule's real scope is unknown "
                    "and it is excluded from overlap analysis."
                ),
            )
        )

    return report


def summarise(report: HygieneReport) -> dict[str, object]:
    return {
        "objects_defined": report.objects_defined,
        "objects_referenced": report.objects_referenced,
        "counts": report.counts,
        "total": len(report.findings),
    }


__all__ = [
    "COMFORTABLE_NESTING_DEPTH",
    "HYGIENE_SEVERITY",
    "HygieneFinding",
    "HygieneIssue",
    "HygieneReport",
    "examine",
    "summarise",
]
