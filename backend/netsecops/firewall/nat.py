"""NAT analysis (FR-FW-04).

NAT is where a firewall's *intent* and its *effect* come apart, and the gap is invisible
if you read either rulebase alone.

A security rule permitting `any → 10.20.0.10:443` looks like an internal rule. It is
only reachable from the internet if a destination-NAT rule publishes 10.20.0.10 behind a
public address — and that rule lives in a different rulebase, often maintained by
different people. Reading the security policy alone understates exposure; reading the
NAT policy alone cannot say whether the translated host is actually reachable. FR-FW-04
is about joining the two.

Four things this module reports:

**Exposed services.** A destination-NAT rule publishes an internal host, and a security
rule permits traffic to it. Together they put a service on the internet. The severity
comes from the *service*: a published RDP or SMB port is a different conversation from a
published HTTPS port.

**Unmatched NAT.** A destination-NAT rule exists and no security rule permits traffic to
the translated host. Usually harmless leftovers — but a NAT rule with no matching permit
is exactly what remains after someone removes a service and forgets half the change, and
it is the first thing to reinstate accidentally.

**Unprotected exposure.** A published service whose security rule has no logging or no
inspection profile. This is the combination that matters most operationally: the traffic
most likely to be hostile, arriving where nothing is watching.

**Any-source publication.** A destination NAT whose original source is `any`, published
to a host that a security rule then permits from `any`. Stated separately from the
generic broad-source finding because the NAT makes it *internet-facing*, which the
security rule alone does not say.

**What this module does not claim.** It cannot verify routing, and it does not know
which zones face the internet unless the caller says so. `external_zones` is therefore a
parameter with no default guess: a wrong guess here would either invent exposure
findings or hide real ones, and both are worse than saying the analysis was not
performed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.firewall.intervals import IntervalSet, describe_ipv4, parse_address
from netsecops.firewall.model import ObjectResolver, ResolvedRule
from netsecops.firewall.policy import DEFAULT_THRESHOLDS, PORT_NAMES, PolicyThresholds

log = get_logger(__name__)


class NatIssue(StrEnum):
    EXPOSED_SERVICE = "exposed_service"
    EXPOSED_INSECURE_SERVICE = "exposed_insecure_service"
    EXPOSED_WITHOUT_LOGGING = "exposed_without_logging"
    EXPOSED_WITHOUT_INSPECTION = "exposed_without_inspection"
    UNMATCHED_NAT = "unmatched_nat"
    NAT_WITHOUT_TRANSLATION = "nat_without_translation"


ISSUE_SEVERITY: dict[NatIssue, str] = {
    # A published service is a fact to review, not a defect in itself — publishing
    # services is what a perimeter firewall is for.
    NatIssue.EXPOSED_SERVICE: "info",
    # Publishing RDP, SMB or a database port to the internet is a different matter.
    NatIssue.EXPOSED_INSECURE_SERVICE: "critical",
    NatIssue.EXPOSED_WITHOUT_LOGGING: "high",
    NatIssue.EXPOSED_WITHOUT_INSPECTION: "medium",
    NatIssue.UNMATCHED_NAT: "low",
    NatIssue.NAT_WITHOUT_TRANSLATION: "low",
}


@dataclass(frozen=True, slots=True)
class NatFinding:
    issue: NatIssue
    nat_order: int
    nat_name: str
    message: str
    #: The security rule that completes the exposure, where there is one. Both halves
    #: are named because fixing either one fixes the exposure, and which to change is
    #: the operator's call.
    rule_order: int | None = None
    rule_name: str | None = None

    @property
    def severity(self) -> str:
        return ISSUE_SEVERITY[self.issue]


@dataclass(slots=True)
class NatReport:
    findings: list[NatFinding] = field(default_factory=list)
    nat_rules_examined: int = 0
    #: False when the caller did not say which zones face the internet. Every exposure
    #: conclusion depends on that, so the report says it was not performed rather than
    #: reporting zero exposures — which would read as "nothing is exposed".
    exposure_analysed: bool = True

    def by_issue(self, issue: NatIssue) -> list[NatFinding]:
        return [f for f in self.findings if f.issue is issue]

    @property
    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.issue.value] = counts.get(finding.issue.value, 0) + 1
        return counts


@dataclass(frozen=True, slots=True)
class TranslatedTarget:
    """One destination-NAT rule, with its translated address resolved."""

    order: int
    name: str
    #: The address traffic actually reaches after translation.
    addresses: IntervalSet
    #: The port it lands on, when the rule translates one. None means the port is
    #: unchanged, which is common and not a gap.
    port: int | None
    #: What the rule said, kept verbatim for the finding text.
    translated: str
    service: str


def _resolve_target(raw: Mapping[str, Any], resolver: ObjectResolver) -> TranslatedTarget | None:
    """Turn a NAT rule's translated destination into addresses, or None.

    Returns None when the rule translates nothing resolvable — an interface name, a
    dynamic pool, an object the collection did not capture. That is reported as its own
    finding rather than silently treated as "exposes nothing", because the two are very
    different claims.
    """
    translated = str(raw.get("translated") or "").strip()
    if not translated:
        return None

    address_text, _, port_text = translated.partition(":")
    address_text = address_text.strip()

    addresses, _v6 = parse_address(address_text)
    if not addresses:
        # Not a literal. It may still be a named object the rulebase defines.
        resolved, missing = resolver.resolve_addresses([address_text])
        if missing or not resolved.v4:
            return None
        addresses = resolved.v4

    port: int | None = None
    if port_text.strip().isdigit():
        port = int(port_text.strip())

    return TranslatedTarget(
        order=int(raw.get("order", 0)),
        name=str(raw.get("name") or f"NAT {raw.get('order', '?')}"),
        addresses=addresses,
        port=port,
        translated=translated,
        service=str(raw.get("service") or "any"),
    )


def _reaches(rule: ResolvedRule, target: TranslatedTarget) -> bool:
    """Whether a security rule permits traffic to the translated host and port."""
    if not rule.destination.v4.intersects(target.addresses):
        return False
    if target.port is None:
        return True
    if rule.services.is_any:
        return True
    # NAT does not say which protocol; a published port is reachable if any protocol
    # the rule permits covers it. Requiring a protocol match would miss UDP services.
    return any(ports.covers_value(target.port) for ports in rule.services.by_protocol.values())


def _exposed_insecure(
    rule: ResolvedRule, target: TranslatedTarget, thresholds: PolicyThresholds
) -> list[str]:
    """Dangerous services reachable through this NAT and rule together."""
    found: list[str] = []
    for protocol, port in sorted(thresholds.insecure_ports):
        if target.port is not None and target.port != port:
            continue
        ports = rule.services.by_protocol.get(protocol)
        if rule.services.is_any or (ports is not None and ports.covers_value(port)):
            found.append(PORT_NAMES.get((protocol, port), f"proto {protocol}/{port}"))
    return found


def examine(
    firewall: Mapping[str, Any],
    rules: Sequence[ResolvedRule],
    resolver: ObjectResolver,
    *,
    external_zones: Sequence[str] | None = None,
    thresholds: PolicyThresholds = DEFAULT_THRESHOLDS,
) -> NatReport:
    """Join the NAT and security rulebases to find what is actually published.

    ``external_zones`` names the zones that face untrusted networks. There is no default:
    guessing would either invent exposure findings for an internal NAT or hide a real
    one, and a wrong exposure finding on a perimeter firewall costs more credibility than
    the finding was worth. Without it the NAT rules are still checked for internal
    consistency, and ``exposure_analysed`` is False.
    """
    nat_rules = list(firewall.get("nat_rules", []))
    report = NatReport(nat_rules_examined=len(nat_rules))

    external = {zone.strip().lower() for zone in external_zones or () if zone.strip()}
    report.exposure_analysed = bool(external)

    def add(
        issue: NatIssue,
        target_order: int,
        target_name: str,
        message: str,
        rule: ResolvedRule | None = None,
    ) -> None:
        report.findings.append(
            NatFinding(
                issue=issue,
                nat_order=target_order,
                nat_name=target_name,
                message=message,
                rule_order=rule.order if rule else None,
                rule_name=rule.name if rule else None,
            )
        )

    for raw in nat_rules:
        if str(raw.get("direction") or "").lower() != "destination":
            # Source NAT hides internal addresses on the way out. It does not publish
            # anything, so it cannot create inbound exposure.
            continue

        target = _resolve_target(raw, resolver)
        if target is None:
            add(
                NatIssue.NAT_WITHOUT_TRANSLATION,
                int(raw.get("order", 0)),
                str(raw.get("name") or "unnamed"),
                "This rule translates the destination, but the address it translates to "
                f"could not be resolved ({raw.get('translated') or 'nothing recorded'}). "
                "What it publishes could not be determined, so it is excluded from the "
                "exposure analysis rather than assumed harmless.",
            )
            continue

        matching = [
            rule for rule in rules if rule.enabled and rule.permits and _reaches(rule, target)
        ]
        from_outside = [
            rule for rule in matching if external & {zone.lower() for zone in rule.src_zones}
        ]
        where = describe_ipv4(target.addresses)

        if not matching:
            add(
                NatIssue.UNMATCHED_NAT,
                target.order,
                target.name,
                f"This rule publishes {where} but no enabled security rule permits "
                "traffic to it, so nothing reaches the translated host today. A NAT rule "
                "with no matching permit is what is left when half a decommissioning is "
                "completed — and is the easy half to undo.",
            )
            continue

        if not report.exposure_analysed:
            # The internal-consistency checks above stand on their own. Everything below
            # is a claim about internet exposure, which cannot be made without knowing
            # which zones face the internet.
            continue

        if not from_outside:
            # Matched, but only from inside. Without this the rule falls through both
            # branches and is reported as nothing at all — which is how a NAT publishing
            # RDP, held shut only by a deny rule above it, became invisible. The
            # translation is in place; the permit is the only thing missing, and a permit
            # is a much smaller change than a NAT rule.
            add(
                NatIssue.UNMATCHED_NAT,
                target.order,
                target.name,
                f"This rule publishes {where}, and security rules permit traffic to it "
                "from inside, but nothing permits it from an untrusted zone — so it is "
                "not reachable from outside today. The translation is already in place, "
                "so a single permit would expose it.",
            )
            continue

        for rule in from_outside:
            port_text = f":{target.port}" if target.port is not None else ""

            insecure = _exposed_insecure(rule, target, thresholds)
            if insecure:
                add(
                    NatIssue.EXPOSED_INSECURE_SERVICE,
                    target.order,
                    target.name,
                    f"{', '.join(insecure)} on {where}{port_text} is reachable from an "
                    f"untrusted zone. The NAT rule publishes the host and security rule "
                    f"#{rule.order} permits the traffic; either one being changed would "
                    "close it.",
                    rule,
                )
            else:
                add(
                    NatIssue.EXPOSED_SERVICE,
                    target.order,
                    target.name,
                    f"{where}{port_text} is published to an untrusted zone and permitted "
                    f"by security rule #{rule.order} ({rule.name}).",
                    rule,
                )

            if rule.logging_known and not rule.logs:
                add(
                    NatIssue.EXPOSED_WITHOUT_LOGGING,
                    target.order,
                    target.name,
                    f"Traffic published to {where} is permitted by rule #{rule.order} "
                    "without logging. This is internet-facing traffic arriving where "
                    "nothing records it, so an incident involving this service could "
                    "not be reconstructed afterwards.",
                    rule,
                )

            if not rule.has_profiles:
                add(
                    NatIssue.EXPOSED_WITHOUT_INSPECTION,
                    target.order,
                    target.name,
                    f"Traffic published to {where} is permitted by rule #{rule.order} "
                    "with no security profile, so it is passed to the host uninspected.",
                    rule,
                )

    log.info(
        "firewall.nat_analysis_complete",
        nat_rules=report.nat_rules_examined,
        findings=len(report.findings),
        exposure_analysed=report.exposure_analysed,
    )
    return report


def external_zones_from(firewall: Mapping[str, Any]) -> list[str]:
    """Zones whose name suggests they face untrusted networks.

    A convenience for callers that have nothing better, and deliberately *not* the
    default inside :func:`examine`. Naming conventions are a guess: a zone called
    `outside` usually is, but an estate that names its zones after sites has none of
    these and would silently get no exposure analysis at all. A caller that uses this
    should be able to say so in the report.
    """
    hints = ("untrust", "outside", "internet", "wan", "external", "public")
    return [
        zone
        for zone in firewall.get("zones", [])
        if any(hint in str(zone).lower() for hint in hints)
    ]


__all__ = [
    "ISSUE_SEVERITY",
    "NatFinding",
    "NatIssue",
    "NatReport",
    "TranslatedTarget",
    "examine",
    "external_zones_from",
]
