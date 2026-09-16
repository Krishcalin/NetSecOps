"""Risk scoring (FR-CHK-09).

A risk score is a lossy summary, and the only honest defence of one is that it is
*documented and configurable* — which FR-CHK-09 requires and this module provides. The
formula is here, in one place, with its reasoning, rather than distributed through the
code that happens to need a number.

The design has three properties worth stating, because each is a decision that could
reasonably have gone the other way:

**Severity weights are widely spaced.** A Critical is worth 40 and a Low 3. Under a
linear 5/4/3/2/1 scheme, fourteen Low findings outrank one Critical, and any score with
that property will eventually tell someone to fix the wrong thing first.

**Criticality multiplies, it does not add.** The same weakness on a core firewall and
on a lab switch is the same weakness; what differs is the consequence. A multiplier
says that, where an additive term would let a pile of low-criticality devices produce
the same number as one important one.

**Not Evaluated is visible but does not inflate the score.** A device half of whose
checks could not run is not low risk, but it is not high risk either — it is *unknown*,
and the honest representation is a separate coverage figure rather than a score that
quietly pretends the missing checks passed.

**Every finding kind that says something about the device counts.** The score was
originally computed from check results alone, which meant a firewall whose rulebase
analysis had produced a Critical `any/any/any` finding, or whose software carried a
KEV-listed CVE, could still score **zero** as long as its configuration checks passed.
That is not a lossy summary, it is a wrong one. Rulebase and vulnerability findings now
contribute at their own severity; compliance and coverage stay check-only, because they
answer a different question and a CVE is not a failed control.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from netsecops.checks.schema import Outcome, Severity
from netsecops.db.models.inventory import Criticality

#: Multiplier applied to the weighted finding total, by device criticality.
CRITICALITY_MULTIPLIER: dict[str, float] = {
    Criticality.CRITICAL.value: 1.5,
    Criticality.HIGH.value: 1.2,
    Criticality.MEDIUM.value: 1.0,
    Criticality.LOW.value: 0.8,
}

#: The weighted total that maps to a score of 100. Chosen so that one Critical finding
#: (40) on a critical device (×1.5 = 60) already reads as high risk, while a handful of
#: Lows does not. Above this the score saturates: the difference between "very bad" and
#: "even worse" is not information an operator can act on differently.
SATURATION = 120.0

#: A Warning counts, but at a discount — it is a check that found something worth
#: looking at rather than something that is definitely wrong.
WARNING_FACTOR = 0.4


@dataclass(slots=True)
class RiskBreakdown:
    """A score and the inputs behind it, so it can be explained rather than asserted."""

    score: int
    weighted_total: float
    multiplier: float
    counts: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    #: Findings folded in from sources other than the check engine, counted by kind.
    #: Kept apart from ``counts`` so the compliance figures stay about checks.
    findings_by_kind: dict[str, int] = field(default_factory=dict)

    @property
    def evaluated(self) -> int:
        return (
            self.counts.get("pass", 0) + self.counts.get("fail", 0) + self.counts.get("warning", 0)
        )

    @property
    def compliance_percent(self) -> int | None:
        """Passes as a share of what was actually decided.

        Not Applicable and Not Evaluated are excluded from both halves. Counting them
        as passes would let a device whose collection half-failed score better than one
        that was fully assessed — the exact inversion that makes a compliance number
        untrustworthy.
        """
        total = self.evaluated
        if total == 0:
            return None
        return round(100 * self.counts.get("pass", 0) / total)

    @property
    def coverage_percent(self) -> int | None:
        """How much of the policy actually produced a verdict."""
        attempted = self.evaluated + self.counts.get("not_evaluated", 0)
        if attempted == 0:
            return None
        return round(100 * self.evaluated / attempted)

    def to_components(self) -> dict[str, Any]:
        return {
            "weighted_total": round(self.weighted_total, 2),
            "multiplier": self.multiplier,
            "saturation": SATURATION,
            "counts": self.counts,
            "by_severity": self.by_severity,
            "findings_by_kind": self.findings_by_kind,
            "compliance_percent": self.compliance_percent,
            "coverage_percent": self.coverage_percent,
        }


class _Scorable:
    """Structural type for anything with an outcome and a severity."""

    outcome: Any
    severity: Any


def _value(field_value: Any) -> str:
    return field_value.value if hasattr(field_value, "value") else str(field_value)


def _weight_of(severity: str) -> float:
    try:
        return float(Severity(severity).weight)
    except ValueError:
        # An unrecognised severity should not silently score zero; Medium is the
        # least surprising assumption and the count still shows what happened.
        return float(Severity.MEDIUM.weight)


def score_device(
    results: Iterable[_Scorable] | Sequence[Any],
    *,
    criticality: str | Criticality = Criticality.MEDIUM,
    findings: Iterable[Any] = (),
) -> RiskBreakdown:
    """Compute a device's risk score from its check results and open findings.

    Accepts either engine ``CheckResult`` objects or stored ``check_results`` rows;
    both carry ``outcome`` and ``severity``, and requiring one or the other would mean
    converting at every call site for no benefit.

    ``findings`` carries conclusions the check engine did not reach — rulebase analysis
    and vulnerability matches — as rows with ``severity`` and ``kind``. The caller
    decides which kinds belong here, and must not pass ``config`` findings: those mirror
    the check results already in ``results`` and would be counted twice.

    Findings contribute at full severity weight rather than at the Warning discount.
    A shadowed rule or a KEV-listed CVE is not a hint that something might be wrong; it
    is the conclusion itself.
    """
    counts: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    findings_by_kind: dict[str, int] = {}
    weighted = 0.0

    for result in results:
        outcome = _value(result.outcome)
        counts[outcome] = counts.get(outcome, 0) + 1

        if outcome not in {Outcome.FAIL.value, Outcome.WARNING.value}:
            continue

        severity = _value(result.severity)
        by_severity[severity] = by_severity.get(severity, 0) + 1

        weight = _weight_of(severity)
        if outcome == Outcome.WARNING.value:
            weight *= WARNING_FACTOR
        weighted += weight

    for finding in findings:
        severity = _value(finding.severity)
        by_severity[severity] = by_severity.get(severity, 0) + 1
        kind = _value(getattr(finding, "kind", "unknown"))
        findings_by_kind[kind] = findings_by_kind.get(kind, 0) + 1
        weighted += _weight_of(severity)

    multiplier = CRITICALITY_MULTIPLIER.get(_value(criticality), 1.0)
    total = weighted * multiplier
    score = min(100, round(100 * total / SATURATION))

    return RiskBreakdown(
        score=score,
        weighted_total=total,
        multiplier=multiplier,
        counts=counts,
        by_severity=by_severity,
        findings_by_kind=findings_by_kind,
    )


def roll_up(scores: Sequence[int]) -> int:
    """Aggregate device scores to a group, site or organisation figure.

    The mean would let a thousand clean devices hide one catastrophic firewall, and the
    maximum would make every group with one bad device look identical. This blends the
    two, weighted towards the worst: the group's score is never lower than reality, and
    still moves when the average improves.
    """
    if not scores:
        return 0
    worst = max(scores)
    mean = sum(scores) / len(scores)
    return min(100, round(0.6 * worst + 0.4 * mean))


__all__ = [
    "CRITICALITY_MULTIPLIER",
    "SATURATION",
    "WARNING_FACTOR",
    "RiskBreakdown",
    "roll_up",
    "score_device",
]
