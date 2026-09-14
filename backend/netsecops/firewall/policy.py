"""Rulebase policy findings (FR-FW-02).

Where `analysis.py` asks how rules relate to *each other*, this asks what is wrong with
a rule on its own terms: too broad, unlogged, unprofiled, permitting something nobody
should permit.

Two principles run through all of it.

**Thresholds are configurable and stated.** "Overly broad" is a judgement, and a
hard-coded one would be wrong for somebody. Every threshold lives in
:class:`PolicyThresholds` with its default explained, and a finding says which threshold
it tripped so an operator can disagree with the number rather than with the tool.

**Unknown is not a violation.** A rule whose logging the parser could not determine is
not reported as unlogged. The device may well be logging; we simply did not capture it,
and a finding that sends someone to "fix" a correct configuration costs more credibility
than the finding was worth.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from netsecops.firewall.intervals import IPV4_MAX, describe_ipv4
from netsecops.firewall.model import ANY_PROTOCOL, ResolvedRule


class RuleIssue(StrEnum):
    ANY_ANY_ANY = "any_any_any"
    BROAD_SOURCE = "broad_source"
    BROAD_DESTINATION = "broad_destination"
    BROAD_SERVICE = "broad_service"
    NO_LOGGING = "no_logging"
    NO_PROFILES = "no_profiles"
    DISABLED = "disabled"
    NO_RECENT_HITS = "no_recent_hits"
    NEVER_HIT = "never_hit"
    EXPIRED_SCHEDULE = "expired_schedule"
    INSECURE_SERVICE = "insecure_service"
    UNRESOLVED_OBJECTS = "unresolved_objects"


ISSUE_SEVERITY: dict[RuleIssue, str] = {
    RuleIssue.ANY_ANY_ANY: "critical",
    RuleIssue.BROAD_SOURCE: "medium",
    RuleIssue.BROAD_DESTINATION: "medium",
    RuleIssue.BROAD_SERVICE: "medium",
    RuleIssue.NO_LOGGING: "high",
    RuleIssue.NO_PROFILES: "medium",
    RuleIssue.DISABLED: "info",
    RuleIssue.NO_RECENT_HITS: "low",
    RuleIssue.NEVER_HIT: "low",
    RuleIssue.EXPIRED_SCHEDULE: "low",
    RuleIssue.INSECURE_SERVICE: "high",
    RuleIssue.UNRESOLVED_OBJECTS: "medium",
}


@dataclass(frozen=True, slots=True)
class PolicyThresholds:
    """Every judgement this module makes, in one place and overridable.

    A threshold buried in a comparison is an opinion masquerading as a fact. These are
    defaults, chosen to be defensible rather than universal, and a policy can change any
    of them.
    """

    #: A source broader than a /16 on a permit rule. /16 is 65,536 addresses — beyond
    #: the point where "who can reach this" is a question anyone can answer.
    max_source_addresses: int = 65_536
    #: Destinations are held to the same standard, but the finding is separate: a broad
    #: *source* and a broad *destination* are different mistakes with different fixes.
    max_destination_addresses: int = 65_536
    #: More than 1,024 ports on a permit rule. Wide enough to allow a legitimate
    #: ephemeral range, narrow enough that "tcp/any" does not slip through.
    max_service_ports: int = 1_024
    #: Days without a hit before a rule is worth questioning. 90 covers a quarterly
    #: business process; 30 would flag every month-end job.
    unused_rule_days: int = 90
    #: Services no permit rule from an untrusted source should carry.
    insecure_ports: frozenset[tuple[int, int]] = frozenset(
        {
            (6, 23),  # telnet
            (6, 21),  # ftp control
            (6, 512),  # rexec
            (6, 513),  # rlogin
            (6, 514),  # rsh
            (6, 445),  # smb
            (6, 139),  # netbios session
            (17, 161),  # snmp
            (17, 69),  # tftp
            (6, 3389),  # rdp
            (6, 5900),  # vnc
            (6, 1433),  # mssql
            (6, 3306),  # mysql
        }
    )


DEFAULT_THRESHOLDS = PolicyThresholds()

#: Port → the name an operator will recognise in a finding.
PORT_NAMES: dict[tuple[int, int], str] = {
    (6, 23): "Telnet",
    (6, 21): "FTP",
    (6, 512): "rexec",
    (6, 513): "rlogin",
    (6, 514): "rsh",
    (6, 445): "SMB",
    (6, 139): "NetBIOS",
    (17, 161): "SNMP",
    (17, 69): "TFTP",
    (6, 3389): "RDP",
    (6, 5900): "VNC",
    (6, 1433): "Microsoft SQL",
    (6, 3306): "MySQL",
}


@dataclass(frozen=True, slots=True)
class RuleFinding:
    issue: RuleIssue
    rule_order: int
    rule_name: str
    message: str
    #: The threshold this tripped, so the number is arguable rather than mysterious.
    threshold: str | None = None

    @property
    def severity(self) -> str:
        return ISSUE_SEVERITY[self.issue]


@dataclass(slots=True)
class PolicyReport:
    findings: list[RuleFinding] = field(default_factory=list)
    rules_examined: int = 0

    def by_issue(self, issue: RuleIssue) -> list[RuleFinding]:
        return [f for f in self.findings if f.issue is issue]

    @property
    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.issue.value] = counts.get(finding.issue.value, 0) + 1
        return counts


def _service_port_count(rule: ResolvedRule) -> int:
    if rule.services.is_any:
        return 65_536
    return sum(ports.size for ports in rule.services.by_protocol.values())


def _insecure_services(rule: ResolvedRule, thresholds: PolicyThresholds) -> list[str]:
    """Which dangerous services a rule permits.

    `service any` is deliberately *not* reported here. It permits every dangerous port,
    but the finding for that is `BROAD_SERVICE` or `ANY_ANY_ANY`; listing thirteen
    protocol names as well would bury the real problem under its own symptoms.
    """
    if rule.services.is_any:
        return []

    found: list[str] = []
    for protocol, port in sorted(thresholds.insecure_ports):
        ports = rule.services.by_protocol.get(protocol)
        if ports is not None and ports.covers_value(port):
            found.append(PORT_NAMES.get((protocol, port), f"proto {protocol}/{port}"))
    return found


def _days_since(timestamp: str | None) -> int | None:
    if not timestamp:
        return None
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return (datetime.now(UTC) - parsed).days


def examine(
    rules: Sequence[ResolvedRule], *, thresholds: PolicyThresholds = DEFAULT_THRESHOLDS
) -> PolicyReport:
    """Find what is wrong with each rule in its own right (FR-FW-02)."""
    report = PolicyReport(rules_examined=len(rules))

    def add(
        issue: RuleIssue, rule: ResolvedRule, message: str, threshold: str | None = None
    ) -> None:
        report.findings.append(
            RuleFinding(
                issue=issue,
                rule_order=rule.order,
                rule_name=rule.name,
                message=message,
                threshold=threshold,
            )
        )

    for rule in rules:
        if not rule.enabled:
            # Reported, but at Info. A disabled rule is not an exposure; it is clutter,
            # and occasionally a rollback somebody forgot to finish.
            add(
                RuleIssue.DISABLED,
                rule,
                "This rule is disabled. It has no effect and may be a change that was "
                "never completed or never reverted.",
            )
            continue

        if rule.unresolved:
            add(
                RuleIssue.UNRESOLVED_OBJECTS,
                rule,
                f"This rule references {len(rule.unresolved)} object(s) the collection "
                f"did not capture: {', '.join(rule.unresolved[:5])}. Its real scope "
                "could not be determined, so it is excluded from overlap analysis.",
            )

        if not rule.permits:
            # The checks below are about what a rule *allows*. A deny rule that is
            # broad, unlogged or names Telnet is usually doing its job.
            continue

        source_any = rule.source.is_any
        destination_any = rule.destination.is_any
        service_any = rule.services.is_any

        if source_any and destination_any and service_any:
            add(
                RuleIssue.ANY_ANY_ANY,
                rule,
                "This rule permits any source to reach any destination on any service. "
                "It makes every rule below it unreachable and every rule above it the "
                "only control that applies.",
            )
            # Everything else about this rule is a restatement of the same fact.
            continue

        if not source_any and rule.source.v4.size > thresholds.max_source_addresses:
            add(
                RuleIssue.BROAD_SOURCE,
                rule,
                f"The source covers {rule.source.v4.size:,} addresses "
                f"({describe_ipv4(rule.source.v4)}).",
                threshold=f"max_source_addresses={thresholds.max_source_addresses:,}",
            )
        elif source_any:
            add(
                RuleIssue.BROAD_SOURCE,
                rule,
                "The source is `any`, so this rule is reachable from everywhere the "
                "firewall can see.",
                threshold="source = any",
            )

        if not destination_any and (
            rule.destination.v4.size > thresholds.max_destination_addresses
        ):
            add(
                RuleIssue.BROAD_DESTINATION,
                rule,
                f"The destination covers {rule.destination.v4.size:,} addresses "
                f"({describe_ipv4(rule.destination.v4)}).",
                threshold=f"max_destination_addresses={thresholds.max_destination_addresses:,}",
            )
        elif destination_any:
            add(
                RuleIssue.BROAD_DESTINATION,
                rule,
                "The destination is `any`, so this rule permits reaching anything "
                "behind the firewall.",
                threshold="destination = any",
            )

        ports = _service_port_count(rule)
        if service_any:
            add(
                RuleIssue.BROAD_SERVICE,
                rule,
                "The service is `any`, so every protocol and port is permitted.",
                threshold="service = any",
            )
        elif ports > thresholds.max_service_ports:
            add(
                RuleIssue.BROAD_SERVICE,
                rule,
                f"The rule permits {ports:,} ports ({rule.services.describe()}).",
                threshold=f"max_service_ports={thresholds.max_service_ports:,}",
            )

        # Logging: only when the parser actually determined it.
        if rule.logging_known and not rule.logs:
            add(
                RuleIssue.NO_LOGGING,
                rule,
                "This rule permits traffic and records nothing. Traffic it allows will "
                "not appear in any log, so an incident involving it cannot be "
                "reconstructed.",
            )

        if rule.profiles is not None and not rule.has_profiles:
            add(
                RuleIssue.NO_PROFILES,
                rule,
                "This rule permits traffic without any security profile (IPS, "
                "anti-virus, URL or DNS filtering), so the traffic is passed "
                "uninspected.",
            )

        insecure = _insecure_services(rule, thresholds)
        if insecure:
            add(
                RuleIssue.INSECURE_SERVICE,
                rule,
                f"This rule permits {', '.join(insecure)}"
                + (
                    " from any source." if source_any else f" from {describe_ipv4(rule.source.v4)}."
                ),
            )

        if rule.hit_count == 0:
            add(
                RuleIssue.NEVER_HIT,
                rule,
                "This rule has never matched any traffic since its counters were last "
                "cleared. It may be obsolete, or it may be shadowed by a rule above it.",
            )
        else:
            idle_days = _days_since(rule.last_hit)
            if idle_days is not None and idle_days > thresholds.unused_rule_days:
                add(
                    RuleIssue.NO_RECENT_HITS,
                    rule,
                    f"This rule has not matched traffic for {idle_days} days.",
                    threshold=f"unused_rule_days={thresholds.unused_rule_days}",
                )

    return report


def find_cleanup_rule(rules: Sequence[ResolvedRule]) -> ResolvedRule | None:
    """The final catch-all deny, if there is one.

    Its absence is a finding in its own right: a rulebase whose last rule is not an
    explicit deny relies on the vendor's implicit default, which differs between
    platforms and is not visible to anyone reading the configuration.
    """
    for rule in reversed(list(rules)):
        if not rule.enabled:
            continue
        if (
            not rule.permits
            and rule.source.is_any
            and rule.destination.is_any
            and rule.services.is_any
        ):
            return rule
        # Only the last enabled rule can be the cleanup rule.
        return None
    return None


def find_stealth_rule(rules: Sequence[ResolvedRule], firewall_addresses: Sequence[int]) -> bool:
    """Whether an early rule denies traffic addressed to the firewall itself.

    A Check Point convention worth generalising: the management plane should be
    protected by the rulebase, near the top, rather than by whatever happens to be
    further down.
    """
    if not firewall_addresses:
        return False

    for rule in list(rules)[:10]:
        if not rule.enabled or rule.permits:
            continue
        if any(rule.destination.v4.covers_value(address) for address in firewall_addresses):
            return True
    return False


def summarise(report: PolicyReport) -> dict[str, object]:
    return {
        "rules_examined": report.rules_examined,
        "counts": report.counts,
        "total": len(report.findings),
    }


__all__ = [
    "ANY_PROTOCOL",
    "DEFAULT_THRESHOLDS",
    "IPV4_MAX",
    "ISSUE_SEVERITY",
    "PORT_NAMES",
    "PolicyReport",
    "PolicyThresholds",
    "RuleFinding",
    "RuleIssue",
    "examine",
    "find_cleanup_rule",
    "find_stealth_rule",
    "summarise",
]
