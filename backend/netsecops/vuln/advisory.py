"""The normalised advisory model (FR-VUL-02, FR-VUL-04).

Four vendors publish vulnerability data in four shapes, and the matcher must not know
which one a given advisory came from. Everything ingested lands here first.

**The invariant this model exists to carry.** An advisory says which versions of a
product are affected. Sometimes it says so in a form nothing can interpret — a free-text
range, a product identifier the document never defines, a branch naming a product this
system has no CPE for. The honest response is to record that the statement was made and
could not be read, which is a third answer alongside "affected" and "not affected".

Collapsing that third answer into either of the others is the whole failure mode:

* Treated as *not affected*, the advisory silently disappears and a vulnerable device
  reports clean.
* Treated as *affected*, every device running the product is flagged, the operator
  stops believing the vulnerability view, and the real findings go with it.

So :class:`VersionConstraint` has an ``UNPARSED`` kind that keeps the original text, and
:attr:`Advisory.uninterpretable` counts what came through that way. The matcher reports
those as *Likely* with the raw statement attached, so a human can read what the vendor
actually wrote.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class ConstraintKind(StrEnum):
    """How an advisory expressed the versions it applies to."""

    #: One specific version: `11.0.3`.
    EXACT = "exact"
    #: A bounded or half-bounded range: `>=10.2.0 <10.2.9`, `<11.0.3`.
    RANGE = "range"
    #: The whole product, with no version qualification. Rare and usually a vendor
    #: shorthand for "every supported release".
    ALL = "all"
    #: A statement that was made and could not be read. Never treated as a verdict.
    UNPARSED = "unparsed"


@dataclass(frozen=True, slots=True)
class VersionConstraint:
    """Which versions of a product an advisory covers.

    ``raw`` is always kept. A finding shows the operator what the vendor wrote rather
    than this module's reconstruction of it, and for an ``UNPARSED`` constraint it is the
    only thing there is to show.
    """

    kind: ConstraintKind
    raw: str
    #: Inclusive lower bound, for a RANGE.
    introduced: str | None = None
    #: Exclusive upper bound — the release that contains the fix — for a RANGE.
    fixed: str | None = None
    #: **Inclusive** upper bound — the last release that is affected, where no fix is
    #: named. Distinct from `fixed` and not interchangeable with it: NVD publishes
    #: `versionEndIncluding` wherever a vendor never shipped a fix, and storing that as
    #: `fixed` would report every device on the named release as patched. Before this
    #: existed such a range was marked UNPARSED, which was safe and cost a large share of
    #: real advisories — roughly a fifth of the unevaluated verdicts in a thousand-record
    #: NVD sample.
    last_affected: str | None = None
    #: The single version, for an EXACT.
    version: str | None = None

    @property
    def interpretable(self) -> bool:
        return self.kind is not ConstraintKind.UNPARSED


@dataclass(frozen=True, slots=True)
class AffectedProduct:
    """One product an advisory names, and the versions of it that are affected."""

    vendor: str | None
    product: str | None
    constraint: VersionConstraint
    #: The CPE the advisory itself supplied, when it did. Preferred over the vendor and
    #: product strings for matching, since it is the vendor's own identifier rather than
    #: this system's guess at one.
    cpe: str | None = None
    #: The document's internal identifier, kept so a finding can be traced back into the
    #: source advisory when someone disputes it.
    product_id: str | None = None

    @property
    def identifiable(self) -> bool:
        """Whether there is enough here to match against a device at all."""
        return bool(self.cpe or (self.vendor and self.product))


@dataclass(frozen=True, slots=True)
class FeatureCondition:
    """A condition an advisory places on top of the version match (FR-VUL-03).

    "Affects 15.2(7)E3" is one claim; "affects 15.2(7)E3 *with the HTTP server enabled*"
    is a narrower one, and the difference decides whether a switch needs an outage
    window. FR-VUL-03 requires the narrower reading where a vendor states it.

    ``path`` is a JMESPath expression over the NCM, the same language the check engine
    uses, so a condition is written the way a check is and resolves against the same
    parsed model. ``expected`` is what the path must yield for the device to be affected.

    The three-valued discipline is the whole point of modelling this rather than
    ignoring it: the path may resolve to the expected value (affected), to something
    else (not affected), or to ``None`` — the parser never established it. That last one
    is not "not affected". It is the reason :class:`~netsecops.vuln.matcher.Confidence`
    has a ``LIKELY``.

    CSAF has no standard structure for these; vendors state them in prose. So conditions
    are curated rather than parsed, and an advisory with none is matched on version
    alone — which is the correct reading of an advisory that states no condition.
    """

    path: str
    expected: bool | str | int
    #: Shown to the operator on the finding. A condition without an explanation is a
    #: verdict nobody can check.
    description: str


@dataclass(frozen=True, slots=True)
class Score:
    """A CVSS score as the advisory published it.

    The vector string is carried alongside the number because a base score without its
    vector cannot be re-derived, contested, or adjusted for environment — and FR-VUL-04
    requires both.
    """

    version: str
    base_score: float | None = None
    vector: str | None = None
    severity: str | None = None


@dataclass(slots=True)
class Advisory:
    """One vendor advisory, normalised (FR-VUL-02).

    An advisory may carry several CVEs and a CVE may appear in several advisories, so
    neither is the identity here: ``source`` plus ``advisory_id`` is.
    """

    source: str
    advisory_id: str
    title: str | None = None
    description: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    scores: list[Score] = field(default_factory=list)
    affected: list[AffectedProduct] = field(default_factory=list)
    #: Releases the vendor names as containing the fix, for the upgrade-path view
    #: (FR-VUL-10).
    fixed: list[AffectedProduct] = field(default_factory=list)
    #: Workaround and mitigation text. Informational only and never executed — the same
    #: rule the check library follows for remediation (SRS §8).
    remediations: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    #: Conditions narrowing the advisory beyond its version ranges (FR-VUL-03). Empty
    #: means the version is the whole claim, which is how most advisories read.
    conditions: list[FeatureCondition] = field(default_factory=list)
    published: datetime | None = None
    modified: datetime | None = None
    #: Statements the document made that this parser could not read, kept verbatim.
    #: Never empty-by-default reasoning: an advisory with entries here is one the matcher
    #: must not rule confidently on.
    notes_unparsed: list[str] = field(default_factory=list)

    @property
    def uninterpretable(self) -> int:
        """How many affected-product statements could not be read."""
        return sum(1 for entry in self.affected if not entry.constraint.interpretable)

    @property
    def fully_interpreted(self) -> bool:
        """True when every statement in the document was understood.

        The matcher uses this to decide whether a "not affected" conclusion is safe to
        draw. An advisory that is only partly understood can rule a device *in*, never
        *out*.
        """
        return not self.notes_unparsed and self.uninterpretable == 0

    @property
    def primary_score(self) -> Score | None:
        """The highest CVSS version the advisory published.

        v4 over v3.1 over anything else: a document carrying both is stating the newer
        one as its current assessment.
        """
        if not self.scores:
            return None
        return max(self.scores, key=lambda score: _SCORE_ORDER.get(score.version, 0))


#: Preference order for `primary_score`. Unknown versions sort below every known one.
_SCORE_ORDER = {"2.0": 1, "3.0": 2, "3.1": 3, "4.0": 4}


__all__ = [
    "Advisory",
    "AffectedProduct",
    "ConstraintKind",
    "FeatureCondition",
    "Score",
    "VersionConstraint",
]
