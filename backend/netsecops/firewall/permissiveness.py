"""How much traffic a rule admits, as a 0-100 score (FR-FW-07).

The analysis already resolves every rule to the exact integer sets it covers — that is
how shadowing and redundancy are decided. Those same sets answer a question operators
ask constantly and had no way to ask here: *which of these rules is the widest?* A
rulebase of four hundred rules has no natural reading order, and "sort by severity" only
ranks the rules something was already found wrong with.

Four decisions shape this, and each of them is about not overstating what is known.

**Only permit rules are scored.** A deny rule matching everything is the implicit-deny
catch-all — the single best rule in most rulebases. Scoring it 100 would put the
healthiest line at the top of a "worst rules" list, so denies score `None`, which is a
different thing from 0 and is rendered differently.

**The scale is logarithmic, because operators think in prefix bits.** A /32 scores 0, a
/24 scores 25, a /16 50, a /8 75, and 0.0.0.0/0 scores 100 — the score is simply the
proportion of the address space's bits the rule leaves wild. A linear fraction-of-space
scale would score every prefix longer than /8 as approximately zero and be useless
across the range where real rules actually sit.

**IPv4 and IPv6 are scored separately and the broader one wins.** They are different
spaces; adding their sizes lets 2**128 swamp anything v4 can express. A rule pinned to
one v4 host but unrestricted in v6 is wide open, and taking the maximum is what says so.

**A rule naming objects the rulebase never defined scores as a lower bound.** Unresolved
names resolve to nothing, so the covered set is smaller than the real one and every
component is understated. The score is still returned — refusing to score is its own
kind of unhelpful — but `understated` is set and the caller is expected to show it. A
score presented as a measurement when it is a floor is exactly the failure this codebase
keeps finding.

What this deliberately does **not** fold in: whether the rule logs, has a profile,
names an application or a user, or has ever been hit. Those are real hygiene problems
and the analysis reports them separately as issues. Mixing them into a breadth number
produces a score that cannot be explained from the rule you are looking at, and an
unexplainable score gets ignored after the first time it surprises someone.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import log2

from netsecops.firewall.intervals import IPV4_MAX, IPV6_MAX, IntervalSet
from netsecops.firewall.model import ResolvedRule, ServiceSet

#: Protocol numbers are a byte, ports are two. `service any` covers the whole plane, and
#: `tcp/any` covers one protocol's worth of it — a real difference the score should show.
_PROTOCOL_BITS = 8
_PORT_BITS = 16
_SERVICE_BITS = _PROTOCOL_BITS + _PORT_BITS

#: Band edges. Conventions for colouring and sorting, not measurements — named once here
#: so the UI, the CSV export and any future report agree on where the lines sit.
BANDS: tuple[tuple[int, str], ...] = (
    (75, "critical"),
    (50, "high"),
    (25, "moderate"),
    (0, "low"),
)


def band_for(score: int) -> str:
    for floor, name in BANDS:
        if score >= floor:
            return name
    return "low"


def _breadth(size: int, total_bits: int) -> float:
    """What proportion of a space's bits a set of this size leaves wild, as 0-100.

    `size` is a count of integers, so a set covering 2**n of them leaves n bits wild.
    An empty set scores 0 — it admits nothing — and so does a single address, which is
    the intended reading: a host-specific rule is as narrow as a rule can be.
    """
    if size <= 1:
        return 0.0
    return min(100.0, log2(size) / total_bits * 100.0)


def _address_breadth(v4: IntervalSet, v6: IntervalSet) -> float:
    """The broader of the two families.

    Summing them would let the v6 space swamp every v4 distinction; ignoring v6 would
    score a rule that is `host → any-v6` as narrow, which is the more dangerous mistake.
    """
    return max(
        _breadth(v4.size, IPV4_MAX.bit_length()),
        _breadth(v6.size, IPV6_MAX.bit_length()),
    )


def _service_breadth(services: ServiceSet) -> float:
    if services.is_any:
        return 100.0
    covered = sum(ports.size for ports in services.by_protocol.values())
    return _breadth(covered, _SERVICE_BITS)


@dataclass(frozen=True, slots=True)
class Permissiveness:
    """A rule's breadth, with the parts it was built from.

    The components travel with the score on purpose. "73" tells an operator nothing they
    can act on; "source any, destination 10.0.0.0/8, service tcp/any" tells them which
    field to narrow, and lets them disagree with the weighting on the evidence rather
    than on faith.
    """

    score: int
    band: str
    source: int
    destination: int
    service: int
    #: True when the rule referenced object names the rulebase never defined. The sets
    #: are then smaller than the real ones and every number above is a floor.
    understated: bool = False


def score_rule(rule: ResolvedRule) -> Permissiveness | None:
    """Score one rule, or `None` if scoring it would mean something misleading.

    Returns `None` for deny rules — see the module docstring. Disabled rules *are*
    scored: the breadth is a property of what the rule says, and an operator reviewing a
    disabled any-any-any before re-enabling it wants the number. Callers that are
    summarising live exposure filter on `enabled` themselves.
    """
    if not rule.permits:
        return None

    source = _address_breadth(rule.source.v4, rule.source.v6)
    destination = _address_breadth(rule.destination.v4, rule.destination.v6)
    service = _service_breadth(rule.services)

    # An unweighted mean. Any weighting here would be a claim about which field's
    # breadth is more dangerous, and that depends entirely on the rule's direction --
    # a wide source is the problem on an inbound rule and a wide destination on an
    # outbound one. The zone-aware version of that judgement belongs with the path
    # analysis, which knows which way the traffic goes; this number does not pretend to.
    combined = (source + destination + service) / 3

    return Permissiveness(
        score=round(combined),
        band=band_for(round(combined)),
        source=round(source),
        destination=round(destination),
        service=round(service),
        understated=bool(rule.unresolved),
    )
