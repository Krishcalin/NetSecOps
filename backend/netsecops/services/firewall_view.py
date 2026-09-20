"""Assembling the rulebase viewer's payload (FR-FW-06, FR-FW-07).

`FirewallAssessmentService` runs the same analysis to *store* findings. This runs it to
*show* them, and the difference is not cosmetic:

- Findings are keyed by problem, because that is what gets tracked, assigned and
  resolved over time. The viewer is keyed by rule, because a shadowed rule is
  unreadable away from the rules around it — its position is what makes it shadowed.
- Findings are capped, because a findings list of ten thousand rows is unusable. The
  viewer shows everything about the rules on the current page, because the operator is
  looking at those specific rules and the cap would hide exactly what they came for.
- Nothing here writes. The viewer is a read of a stored snapshot, so it can be called
  by anyone with snapshot access without side effects, and it can be called against an
  old snapshot to see what the rulebase looked like then.

**Filtering happens after analysis, never before.** Analysing only the filtered rules
would silently change the answers: a rule is shadowed by its *neighbours*, and a
rulebase filtered to one zone has no neighbours. So the whole rulebase is always
analysed and the filter is applied to the presentation.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.db.models.collection import Snapshot
from netsecops.firewall import (
    ObjectResolver,
    Relationship,
    ResolvedRule,
    analyse,
    examine_hygiene,
    examine_nat,
    examine_policy,
    external_zones_from,
    first_match,
    resolve_rulebase,
)
from netsecops.firewall.analysis import RELATIONSHIP_SEVERITY
from netsecops.firewall.intervals import describe_ipv4
from netsecops.firewall.model import PROTOCOL_NUMBERS
from netsecops.schemas.firewall import (
    HygieneFindingRead,
    NatRuleRead,
    RulebaseRead,
    RulebaseSummary,
    RuleIssueRead,
    RuleQueryRequest,
    RuleQueryResponse,
    RuleRead,
)

log = get_logger(__name__)

#: Relationship kinds the viewer attaches to rules. All four, unlike the findings path —
#: a correlation is not worth a tracked finding, but it is worth seeing when you are
#: looking at the two rules it concerns and wondering whether their order matters.
VIEWER_RELATIONSHIPS = (
    Relationship.SHADOWED,
    Relationship.REDUNDANT,
    Relationship.CORRELATED,
    Relationship.GENERALISATION,
)


@dataclass(slots=True)
class RulebaseFilter:
    """What the viewer is currently showing.

    Every field narrows; an empty filter shows everything. Applied after analysis, so
    the issues on a visible rule are the ones it really has rather than the ones it
    would have if the rulebase ended at the filter boundary.
    """

    #: Free text over rule name, object names, zones and action.
    search: str | None = None
    #: `allow`, `deny`, or None for both. Matched on the resolved permit/deny verdict
    #: rather than the vendor's spelling, so "deny" finds Drop, Reject and deny.
    action: str | None = None
    zone: str | None = None
    #: Only rules carrying this issue — the viewer's "show me the shadowed rules".
    issue: str | None = None
    severity: str | None = None
    #: None shows every rule; False hides disabled ones.
    include_disabled: bool = True
    #: Only rules with at least one problem.
    with_issues_only: bool = False


def _render_services(rule: ResolvedRule) -> str:
    return rule.services.describe()


def _rule_read(rule: ResolvedRule, raw: dict[str, Any], issues: list[RuleIssueRead]) -> RuleRead:
    return RuleRead(
        order=rule.order,
        name=rule.name,
        enabled=rule.enabled,
        action=rule.action,
        permits=rule.permits,
        src_zones=sorted(rule.src_zones),
        dst_zones=sorted(rule.dst_zones),
        source=describe_ipv4(rule.source.v4),
        destination=describe_ipv4(rule.destination.v4),
        services=_render_services(rule),
        # What the rule *says*, alongside what it resolves to. The two differing — an
        # object group whose members are not what its name suggests — is often the
        # entire problem, and a viewer showing only the resolved form hides it.
        source_objects=list(raw.get("src") or []),
        destination_objects=list(raw.get("dst") or []),
        service_objects=list(raw.get("services") or []),
        applications=sorted(rule.applications),
        users=sorted(rule.users),
        logs=rule.logs if rule.logging_known else None,
        has_profiles=rule.has_profiles,
        profiles=dict(rule.profiles),
        schedule=rule.schedule,
        hit_count=rule.hit_count,
        last_hit=rule.last_hit,
        unresolved=list(rule.unresolved),
        source_size=rule.source.v4.size,
        destination_size=rule.destination.v4.size,
        issues=issues,
    )


class FirewallViewService:
    """Read-only assembly of the rulebase viewer payload."""

    def __init__(self, snapshot: Snapshot, *, external_zones: Sequence[str] | None = None) -> None:
        self.snapshot = snapshot
        self.firewall: dict[str, Any] = (snapshot.ncm or {}).get("firewall") or {}
        self._raw_rules: list[dict[str, Any]] = list(self.firewall.get("security_rules") or [])
        self.rules: list[ResolvedRule] = []
        self.resolver: ObjectResolver | None = None
        self._zones_inferred = external_zones is None
        self._external = (
            list(external_zones)
            if external_zones is not None
            else external_zones_from(self.firewall)
        )

    @property
    def has_rulebase(self) -> bool:
        return bool(self._raw_rules)

    def build(self, *, filters: RulebaseFilter | None = None) -> RulebaseRead:
        """Analyse the whole rulebase, then present the part the filter asks for."""
        summary = RulebaseSummary(
            rules_total=len(self._raw_rules), rules_enabled=0, rules_analysed=0
        )
        payload = RulebaseRead(
            device_id=self.snapshot.device_id,
            snapshot_id=self.snapshot.id,
            platform=self.snapshot.parser_platform,
            zones=list(self.firewall.get("zones") or []),
            summary=summary,
        )

        if not self.has_rulebase:
            # A switch has no rulebase, and a failed parse produces the same empty block.
            # The viewer says "no rulebase" rather than "a clean one" — the two look
            # identical in an empty table, and only one of them is good news.
            summary.limitations = [
                "This snapshot carries no firewall rulebase. That is expected for a "
                "switch or router; on a firewall it means the policy was not collected "
                "or could not be parsed, and no conclusion about it should be drawn."
            ]
            return payload

        self.rules, self.resolver = resolve_rulebase(self.firewall)

        analysis = analyse(self.rules)
        policy = examine_policy(self.rules)
        hygiene = examine_hygiene(self.resolver, self.rules)
        nat = examine_nat(self.firewall, self.rules, self.resolver, external_zones=self._external)

        summary.rules_enabled = sum(1 for r in self.rules if r.enabled)
        summary.rules_analysed = analysis.rules_analysed
        summary.relationships = dict(analysis.total_by_kind)
        summary.policy_issues = policy.counts
        summary.hygiene_issues = hygiene.counts
        summary.nat_issues = nat.counts
        summary.rule_usage = {
            "used": policy.usage.used,
            "unused": policy.usage.unused,
            "unknown": policy.usage.unknown,
            "evidence_complete": policy.usage.evidence_complete,
        }
        summary.analysis_ms = analysis.duration_ms
        summary.truncated = analysis.truncated
        summary.exposure_analysed = nat.exposure_analysed
        summary.external_zones = list(self._external)
        summary.external_zones_inferred = self._zones_inferred and bool(self._external)
        summary.limitations = list(analysis.limitations)
        if not policy.usage.evidence_complete:
            # A limitation rather than a finding: it is not a defect in the rulebase, it
            # is the reader's warning that the unused-rule list is shorter than the
            # truth, and by how much. Appended after `limitations` is assigned, not
            # before — an earlier append is silently discarded by that assignment.
            summary.limitations.append(policy.usage.summary)
        if not nat.exposure_analysed and self.firewall.get("nat_rules"):
            summary.limitations.append(
                "No zone was identified as facing an untrusted network, so NAT exposure "
                "was not analysed. This is not a finding of 'no exposure'. Zones are "
                "matched by name; an estate that names its zones after sites or "
                "numbers will match none of them."
            )
        elif summary.external_zones_inferred:
            # A guessed zone list and a confirmed one produce identical findings, and
            # the reader cannot tell them apart without being told.
            summary.limitations.append(
                "Exposure was analysed against "
                f"{', '.join(sorted(self._external))}, identified as external by name "
                "rather than confirmed. A zone facing the internet under a different "
                "name was treated as internal, and anything it publishes is missing "
                "from these findings."
            )

        issues_by_order = self._issues_by_rule(analysis, policy)

        reads = [
            _rule_read(rule, raw, issues_by_order.get(rule.order, []))
            for rule, raw in zip(self.rules, self._raw_rules, strict=False)
        ]

        payload.rules = self._apply(reads, filters or RulebaseFilter())
        payload.total = len(reads)
        payload.nat_rules = self._nat_reads(nat)
        payload.hygiene = [
            HygieneFindingRead(
                issue=f.issue.value, severity=f.severity, name=f.name, message=f.message
            )
            for f in hygiene.findings
        ]
        return payload

    # ── attaching problems to the rules they are about ──────────────────

    def _issues_by_rule(self, analysis: Any, policy: Any) -> dict[int, list[RuleIssueRead]]:
        by_order: dict[int, list[RuleIssueRead]] = {}

        for relationship in analysis.relationships:
            if relationship.kind not in VIEWER_RELATIONSHIPS:
                continue
            subject, cause = relationship.subject, relationship.cause
            by_order.setdefault(subject.order, []).append(
                RuleIssueRead(
                    issue=relationship.kind.value,
                    severity=RELATIONSHIP_SEVERITY[relationship.kind],
                    message=relationship.detail,
                    related_rule_order=cause.order,
                    related_rule_name=cause.name,
                )
            )
            # The other rule gets a mirrored entry, so scrolling to it shows why it was
            # named rather than leaving the operator to work it out from the order.
            by_order.setdefault(cause.order, []).append(
                RuleIssueRead(
                    issue=f"{relationship.kind.value}_cause",
                    severity="info",
                    message=(
                        f"This rule is why #{subject.order} ({subject.name}) is "
                        f"{relationship.kind.value}."
                    ),
                    related_rule_order=subject.order,
                    related_rule_name=subject.name,
                )
            )

        for finding in policy.findings:
            by_order.setdefault(finding.rule_order, []).append(
                RuleIssueRead(
                    issue=finding.issue.value,
                    severity=finding.severity,
                    message=finding.message,
                )
            )

        return by_order

    def _nat_reads(self, nat: Any) -> list[NatRuleRead]:
        by_order: dict[int, list[RuleIssueRead]] = {}
        for finding in nat.findings:
            by_order.setdefault(finding.nat_order, []).append(
                RuleIssueRead(
                    issue=finding.issue.value,
                    severity=finding.severity,
                    message=finding.message,
                    related_rule_order=finding.rule_order,
                    related_rule_name=finding.rule_name,
                )
            )

        return [
            NatRuleRead(
                order=int(raw.get("order", index + 1)),
                name=str(raw.get("name") or f"NAT {index + 1}"),
                original=raw.get("original"),
                translated=raw.get("translated"),
                service=raw.get("service"),
                direction=raw.get("direction"),
                issues=by_order.get(int(raw.get("order", index + 1)), []),
            )
            for index, raw in enumerate(self.firewall.get("nat_rules") or [])
        ]

    # ── presentation ────────────────────────────────────────────────────

    def _apply(self, reads: list[RuleRead], filters: RulebaseFilter) -> list[RuleRead]:
        result = reads

        if not filters.include_disabled:
            result = [r for r in result if r.enabled]

        if filters.action:
            # On the resolved verdict, not the vendor's word: "deny" has to find Drop
            # and Reject too, or the filter lies on three of the four platforms.
            wanted = filters.action.strip().lower()
            if wanted in {"allow", "permit", "accept"}:
                result = [r for r in result if r.permits]
            elif wanted in {"deny", "drop", "reject", "block"}:
                result = [r for r in result if not r.permits]
            else:
                result = [r for r in result if r.action.lower() == wanted]

        if filters.zone:
            zone = filters.zone.strip().lower()
            result = [
                r
                for r in result
                if zone in {z.lower() for z in r.src_zones}
                or zone in {z.lower() for z in r.dst_zones}
            ]

        if filters.issue:
            issue = filters.issue.strip().lower()
            result = [r for r in result if any(i.issue.lower() == issue for i in r.issues)]

        if filters.severity:
            severity = filters.severity.strip().lower()
            result = [r for r in result if any(i.severity.lower() == severity for i in r.issues)]

        if filters.with_issues_only:
            result = [r for r in result if r.issues]

        if filters.search:
            needle = filters.search.strip().lower()
            result = [r for r in result if _matches(r, needle)]

        return result

    # ── the rule query (FR-FW-06) ───────────────────────────────────────

    def query(self, request: RuleQueryRequest) -> RuleQueryResponse:
        """Which rule would match this packet, over the stored rulebase."""
        if not self.has_rulebase:
            raise ValidationProblem(
                "This snapshot carries no firewall rulebase, so there is nothing to "
                "query. Collect a configuration from a firewall first."
            )

        if not self.rules:
            self.rules, self.resolver = resolve_rulebase(self.firewall)

        source = _address(request.source, "source")
        destination = _address(request.destination, "destination")
        protocol = _protocol(request.protocol)

        result = first_match(
            self.rules,
            source=source,
            destination=destination,
            protocol=protocol,
            port=request.port,
            src_zone=request.src_zone,
            dst_zone=request.dst_zone,
        )

        by_order = {raw.get("order", i + 1): raw for i, raw in enumerate(self._raw_rules)}

        def read(rule: ResolvedRule) -> RuleRead:
            return _rule_read(rule, by_order.get(rule.order, {}), [])

        return RuleQueryResponse(
            matched=read(result.matched) if result.matched else None,
            also_matched=[read(r) for r in result.shadowed_by_match],
            limitations=list(result.limitations),
        )


def _matches(rule: RuleRead, needle: str) -> bool:
    haystack = " ".join(
        [
            rule.name,
            rule.action,
            rule.source,
            rule.destination,
            rule.services,
            *rule.source_objects,
            *rule.destination_objects,
            *rule.service_objects,
            *rule.src_zones,
            *rule.dst_zones,
            *rule.applications,
        ]
    ).lower()
    return needle in haystack


def _address(text: str, field: str) -> int:
    try:
        return int(ipaddress.IPv4Address(text.strip()))
    except ValueError as exc:
        raise ValidationProblem(
            f"'{text}' is not a valid IPv4 {field} address. The rule query simulates a "
            "single packet, so it needs one address rather than a range."
        ) from exc


def _protocol(text: str) -> int:
    token = text.strip().lower()
    if token in PROTOCOL_NUMBERS:
        return PROTOCOL_NUMBERS[token]
    if token.isdigit():
        return int(token)
    raise ValidationProblem(
        f"'{text}' is not a protocol this query understands. Use a name "
        f"({', '.join(sorted(PROTOCOL_NUMBERS))}) or an IP protocol number."
    )


__all__ = ["VIEWER_RELATIONSHIPS", "FirewallViewService", "RulebaseFilter"]
