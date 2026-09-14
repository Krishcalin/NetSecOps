"""Firewall rulebase normalisation and analysis (SRS §5, FR-FW).

Four modules, in the order the data moves through them:

``intervals``  integer interval-set algebra — the primitive everything rests on.
``model``      resolves a rulebase's object names into comparable address and service
               sets, expanding nested groups once and caching the result.
``analysis``   how rules relate to each other: shadowing, redundancy, correlation,
               generalisation (FR-FW-03), plus the FR-FW-06 rule query.
``policy``     what is wrong with a rule on its own terms (FR-FW-02).
``nat``        what the NAT and security rulebases publish *together* (FR-FW-04) —
               exposure is invisible in either one alone.
``hygiene``    the state of the object catalogue behind the rules (FR-FW-05).

All of it is vendor-neutral and works on the NCM, so a Palo Alto, a FortiGate and a
Check Point rulebase are analysed by the same code (C-6). The vendor-specific work is
turning a configuration into the NCM, which belongs in ``parsers/``.
"""

from netsecops.firewall.analysis import (
    AnalysisResult,
    QueryResult,
    Relationship,
    RuleRelationship,
    analyse,
    first_match,
)
from netsecops.firewall.hygiene import HygieneIssue, HygieneReport
from netsecops.firewall.hygiene import examine as examine_hygiene
from netsecops.firewall.intervals import IntervalSet, parse_address, parse_port_range
from netsecops.firewall.model import (
    AddressSet,
    ObjectResolver,
    ResolvedRule,
    ServiceSet,
    resolve_rulebase,
)
from netsecops.firewall.nat import NatFinding, NatIssue, NatReport, external_zones_from
from netsecops.firewall.nat import examine as examine_nat
from netsecops.firewall.policy import PolicyReport, PolicyThresholds, RuleIssue
from netsecops.firewall.policy import examine as examine_policy

__all__ = [
    "AddressSet",
    "AnalysisResult",
    "HygieneIssue",
    "HygieneReport",
    "IntervalSet",
    "NatFinding",
    "NatIssue",
    "NatReport",
    "ObjectResolver",
    "PolicyReport",
    "PolicyThresholds",
    "QueryResult",
    "Relationship",
    "ResolvedRule",
    "RuleIssue",
    "RuleRelationship",
    "ServiceSet",
    "analyse",
    "examine_hygiene",
    "examine_nat",
    "examine_policy",
    "external_zones_from",
    "first_match",
    "parse_address",
    "parse_port_range",
    "resolve_rulebase",
]
