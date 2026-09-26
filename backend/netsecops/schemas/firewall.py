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


class PermissivenessRead(BaseModel):
    """How much traffic a rule admits, 0-100, with the parts that produced it.

    The components are sent because the number alone is not actionable: "73" says
    nothing an operator can change, while "source any, destination 10.0.0.0/8, service
    tcp/443" names the field to narrow. They also let a reviewer disagree with the
    scoring on the evidence rather than on faith.
    """

    score: int
    #: `low` / `moderate` / `high` / `critical`. A colouring convention, not a
    #: measurement — the thresholds live in `netsecops.firewall.permissiveness.BANDS`
    #: so the UI, the CSV export and any report agree on where the lines sit.
    band: str
    source: int
    destination: int
    service: int
    #: True when the rule names objects the rulebase never defined. The resolved sets
    #: are then smaller than the real ones, so every number above is a floor and the UI
    #: must not present it as a measurement.
    understated: bool = False


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
    #: How many addresses the rule covers, for sorting by breadth. IPv4 only, and kept
    #: as the raw count it always was; `permissiveness` is the scored form and is the
    #: one that accounts for IPv6.
    source_size: int
    destination_size: int
    #: How much traffic the rule admits, 0-100, with the components it was built from.
    #: `None` on a deny rule, where breadth is not a fault — see
    #: `netsecops.firewall.permissiveness`.
    permissiveness: PermissivenessRead | None = None
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
    #: Three-state rule usage: `used`, `unused`, `unknown`, and `evidence_complete`.
    #:
    #: `unknown` is the count that makes the other two readable. A rulebase on a platform
    #: that reports no traffic counters produces no unused-rule findings at all, and an
    #: empty list reads as "every rule is in use" to anyone doing a cleanup. Rules are
    #: never placed in `unused` for want of evidence — that is the mistake that gets a
    #: rule carrying live traffic deleted.
    rule_usage: dict[str, int | bool] = Field(default_factory=dict)
    analysis_ms: int = 0
    #: True when the pairwise analysis hit its cap. The counts above are still exact.
    truncated: bool = False
    #: Rules the device holds that this snapshot never received, because the collection
    #: response was paginated. Distinct from `truncated` above, and far more serious:
    #: `truncated` means everything was read and not every pair compared, while this
    #: means the rules themselves are missing and every count on this object is over a
    #: subset. None where the source said nothing about totals.
    rules_not_retrieved: int | None = None
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


class EstateDeviceRules(BaseModel):
    """One device's contribution to an estate-wide rule query.

    Grouped per device rather than merged into one flat table, and that is a
    correctness requirement rather than a layout preference: a rule's position is what
    makes it shadowed, so rules from two devices interleaved in one list would invite
    comparisons between rules that never see the same packet.
    """

    model_config = ConfigDict(from_attributes=True)

    device_id: Any
    hostname: str | None = None
    platform: str | None = None
    snapshot_id: Any | None = None
    #: Matching rules in evaluation order. Never re-sorted, for the reason above.
    rules: list[RuleRead] = Field(default_factory=list)
    #: How many rules matched on this device, and how many it has in total — so a
    #: reader can tell "three of four hundred" from "three of three".
    matched: int = 0
    rules_total: int = 0
    #: Carried up from the per-device summary. A device whose rulebase arrived short
    #: cannot support a claim that it has no matching rules.
    rules_not_retrieved: int | None = None
    truncated: bool = False
    #: Why this device contributed nothing, or None if it was genuinely searched.
    #: Never omitted from the response — see :class:`EstateRulesRead`.
    not_searched: str | None = None


class EstateRulesRead(BaseModel):
    """Rules matching one filter across every device the caller can see (FR-FW-07).

    **Devices that could not be searched are returned, not dropped.** This is the whole
    reason the response is shaped this way. "No device has an any-any-any rule" and "no
    device we could read has one" are different claims, and a list that silently omits
    the firewalls with no snapshot, no rulebase or a failed parse turns the second into
    the first. The same discipline as ``POST /checks/query``.
    """

    devices: list[EstateDeviceRules] = Field(default_factory=list)
    #: Matching rules across every device that was searched.
    matched_total: int = 0
    devices_searched: int = 0
    devices_not_searched: int = 0
    #: Stated on every response, never only when something went wrong.
    limitations: list[str] = Field(default_factory=list)


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
