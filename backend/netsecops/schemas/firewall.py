"""Rulebase viewer response models (FR-FW-06, FR-FW-07).

The viewer's job is to let someone look at a rulebase and see what is wrong with it
*in place* — a shadowed rule highlighted where it sits, not listed on a separate page
where its position, the thing that makes it shadowed, is invisible.

So the unit here is the rule, and every problem the analysis found is attached to the
rule it is about. That is a deliberate inversion of how the findings table stores them:
findings are keyed by problem because that is what gets tracked and resolved, and the
viewer is keyed by rule because that is what gets read and edited.

**Addresses are rendered, not raw.** A rule's source is an interval set covering
sixteen million addresses; `10.0.0.0/8` is what an operator recognises. The rendered
form is what the viewer shows and what the CSV export carries, so both say the same
thing as the device's own console.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RuleIssueRead(BaseModel):
    """One problem attached to one rule."""

    #: `shadowed`, `any_any_any`, `no_logging` … the value of the analysis enum, so the
    #: UI can style by category without parsing prose.
    issue: str
    severity: str
    message: str
    #: For a relationship, the rule on the other side of it. Named so the viewer can
    #: scroll to it — a shadowing finding is unreadable without seeing both rules.
    related_rule_order: int | None = None
    related_rule_name: str | None = None


class RuleRead(BaseModel):
    """One rule as the viewer shows it, with its problems attached."""

    order: int
    name: str
    enabled: bool
    action: str
    #: True when the action permits traffic. Sent explicitly rather than inferred in the
    #: UI from the action string, because vendors spell denial four ways and Check Point
    #: has an action that is neither.
    permits: bool
    src_zones: list[str] = Field(default_factory=list)
    dst_zones: list[str] = Field(default_factory=list)
    #: Rendered for reading: `10.0.0.0/8`, `any`, `198.51.100.10-198.51.100.20`.
    source: str
    destination: str
    services: str
    #: The object names as written, so the viewer can show what the rule *says* as well
    #: as what it resolves to. The two differing is often the whole problem.
    source_objects: list[str] = Field(default_factory=list)
    destination_objects: list[str] = Field(default_factory=list)
    service_objects: list[str] = Field(default_factory=list)
    applications: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    #: None where the parser could not tell. The UI must not render that as "no".
    logs: bool | None = None
    has_profiles: bool
    profiles: dict[str, str] = Field(default_factory=dict)
    schedule: str | None = None
    hit_count: int | None = None
    last_hit: str | None = None
    #: Object names the rulebase referenced but did not define. A rule with these is
    #: excluded from overlap analysis, and the viewer says so rather than showing it as
    #: analysed and clean.
    unresolved: list[str] = Field(default_factory=list)
    #: How many addresses the rule covers, for sorting by breadth.
    source_size: int
    destination_size: int
    issues: list[RuleIssueRead] = Field(default_factory=list)

    @property
    def worst_severity(self) -> str:
        order = ["critical", "high", "medium", "low", "info"]
        found = [i.severity for i in self.issues]
        return next((s for s in order if s in found), "none")


class HygieneFindingRead(BaseModel):
    """An object-catalogue problem. Not attached to a rule, because it is not about one."""

    issue: str
    severity: str
    name: str
    message: str


class NatRuleRead(BaseModel):
    order: int
    name: str
    original: str | None = None
    translated: str | None = None
    service: str | None = None
    direction: str | None = None
    issues: list[RuleIssueRead] = Field(default_factory=list)


class RulebaseSummary(BaseModel):
    """The counts, which stay complete even when the rule list is paged or filtered."""

    rules_total: int
    rules_enabled: int
    rules_analysed: int
    #: Relationship counts by kind, over the whole rulebase — not only the materialised
    #: examples. "1.2 million correlations" is itself the finding.
    relationships: dict[str, int] = Field(default_factory=dict)
    policy_issues: dict[str, int] = Field(default_factory=dict)
    hygiene_issues: dict[str, int] = Field(default_factory=dict)
    nat_issues: dict[str, int] = Field(default_factory=dict)
    analysis_ms: int = 0
    #: True when the pairwise analysis hit its cap. The counts above are still exact.
    truncated: bool = False
    #: False when nobody said which zones face the internet, so no exposure conclusion
    #: was drawn. Distinct from "no exposure found" (FR-FW-04).
    exposure_analysed: bool = False
    #: True when the external zones were guessed from their names rather than supplied.
    #: A guess that happens to be right and a confirmed fact are the same value in
    #: ``exposure_analysed``, and an operator reading an exposure finding deserves to
    #: know which one it rests on.
    external_zones_inferred: bool = False
    #: The zones the exposure analysis actually treated as untrusted, inferred or not.
    external_zones: list[str] = Field(default_factory=list)
    #: Stated on every response rather than documented elsewhere: an unqualified
    #: "no shadowed rules" would be read as a guarantee.
    limitations: list[str] = Field(default_factory=list)


class RulebaseRead(BaseModel):
    """The viewer's payload for one device at one snapshot."""

    model_config = ConfigDict(from_attributes=True)

    device_id: Any
    snapshot_id: Any
    platform: str | None = None
    zones: list[str] = Field(default_factory=list)
    summary: RulebaseSummary
    rules: list[RuleRead] = Field(default_factory=list)
    nat_rules: list[NatRuleRead] = Field(default_factory=list)
    hygiene: list[HygieneFindingRead] = Field(default_factory=list)
    #: Total before filtering and paging, so the UI can say "42 of 5,000".
    total: int = 0


class RuleQueryRequest(BaseModel):
    """FR-FW-06: which rule would match this packet."""

    source: str = Field(description="Source IPv4 address")
    destination: str = Field(description="Destination IPv4 address")
    protocol: str = Field(default="tcp", description="tcp, udp, icmp or a protocol number")
    port: int = Field(default=443, ge=0, le=65535)
    src_zone: str | None = None
    dst_zone: str | None = None


class RuleQueryResponse(BaseModel):
    matched: RuleRead | None = None
    #: Rules that would have matched had the winner not come first, in order — the
    #: answer to "why did my new rule not take effect".
    also_matched: list[RuleRead] = Field(default_factory=list)
    #: Returned with every answer. A rule narrowed by App-ID or User-ID may be reported
    #: as matching when the device would not match it, and a bare rule number would be
    #: read as a guarantee.
    limitations: list[str] = Field(default_factory=list)


__all__ = [
    "HygieneFindingRead",
    "NatRuleRead",
    "RuleIssueRead",
    "RuleQueryRequest",
    "RuleQueryResponse",
    "RuleRead",
    "RulebaseRead",
    "RulebaseSummary",
]
