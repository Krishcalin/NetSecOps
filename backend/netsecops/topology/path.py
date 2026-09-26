"""Walking a path across the graph (FR-TOPO-03, FR-TOPO-04, FR-TOPO-05).

The question an operator actually asks is not "which rule matches on this firewall" —
that is FR-FW-06 and it has existed since Phase 4 — but "can this host reach that one,
and what decides". Answering it means finding the devices in between and asking each of
them, which is what this does.

**The result has two axes, and keeping them apart is the whole point.** Routing says how
far the path could be traced; policy says what the firewalls along it decided. They fail
independently, and a single verdict has to lie about one of them:

    Every firewall I found permits this, but I lost the path at 10.20.0.0/16
    because 10.20.0.1 belongs to no device in the inventory.

That sentence is honest and actionable — it says what to onboard. Collapsed to "allowed"
it becomes a claim the product cannot support, and somebody will open a firewall on the
strength of it. So a policy verdict of `allowed` is only ever produced alongside routing
`routed`: anything less becomes `partially-allowed`, which reads as the invitation to
look further that it is.

**A block is definitive; a permit is not.** If a device on the path denies the packet, it
dies there and nothing beyond matters — so `blocked` stands even when the rest of the
path is unknown. A permit only tells you about the devices actually consulted, and an
unknown remainder may hold another firewall. The asymmetry is deliberate and it is the
reason the two axes combine the way they do below.

**Nothing here sends a packet.** Every hop is a lookup in a stored table and every verdict
is `first_match` over a stored rulebase — the same offline simulation the rule query
already performs, run once per device on the path.
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.firewall.analysis import RangeOutcome, first_match, first_match_over_range
from netsecops.firewall.intervals import IntervalSet
from netsecops.firewall.model import PROTOCOL_NUMBERS, ResolvedRule, resolve_rulebase
from netsecops.ncm.models import Route
from netsecops.topology.graph import DeviceNode, TopologyGraph
from netsecops.topology.translation import Translation, touches, translate

log = get_logger(__name__)

#: A path longer than this is a routing loop rather than a long path. Real management
#: estates are a handful of hops deep; the cap exists so a mutual pair of default routes
#: terminates with a diagnosis instead of running until something else stops it.
MAX_HOPS = 32


class RoutingConfidence(StrEnum):
    """How far the path could be traced (FR-TOPO-04)."""

    #: A device on the path has a table we can read and no route to the destination.
    UNREACHABLE = "unreachable"
    #: Source and destination sit on the same attached subnet: nothing routes between
    #: them, so no firewall is in the way and no rulebase was consulted.
    SAME_ZONE = "same-zone"
    #: Traced end to end, every hop on a device in the inventory.
    ROUTED = "routed"
    #: Traced as far as the managed estate goes and then left it. The next hop is a real
    #: address that belongs to no device here.
    PARTIALLY_ROUTED = "partially-routed"
    #: Something in the way of an answer: a table never collected, a truncated table, a
    #: routing loop, or a source no device serves.
    UNKNOWN = "unknown"


class PolicyVerdict(StrEnum):
    """What the devices on the path decided (FR-TOPO-04)."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"
    #: Every firewall consulted permitted it, but the path was not traced all the way,
    #: so there may be another one. Never collapse this to `allowed`.
    PARTIALLY_ALLOWED = "partially-allowed"
    #: No path to evaluate policy over.
    NOT_ROUTED = "not-routed"


@dataclass(slots=True)
class Hop:
    """One device the packet passes through, and what it decided."""

    device_id: uuid.UUID
    hostname: str
    platform: str | None = None
    #: The route this device chose, as `destination via next-hop`.
    matched_route: str | None = None
    next_hop: str | None = None
    egress_interface: str | None = None
    #: The interface the packet arrived on. Not exposed on the wire — it exists so the
    #: walk can pick the access list bound inbound here, which on IOS and NX-OS is keyed
    #: by interface name and not by zone, because those platforms have no zones.
    ingress_interface: str | None = None
    ingress_zone: str | None = None
    egress_zone: str | None = None

    #: None where the device carries no rulebase — a router is a hop, not a decision.
    #: That is different from a firewall that permitted the packet, and the UI must not
    #: render them the same.
    action: str | None = None
    rule_name: str | None = None
    rule_order: int | None = None
    #: Caveats from the rule query, carried through rather than dropped: matching is over
    #: addresses, protocol and port only, so App-ID and User-ID narrowing is not simulated.
    limitations: tuple[str, ...] = ()
    #: What this device's NAT did to the packet — "destination 203.0.113.10 →
    #: 10.20.0.10" — or None where nothing was translated. Every hop after this one was
    #: traced with the rewritten addresses, so this is where the reader finds out that
    #: the question changed mid-path.
    translation: str | None = None


@dataclass(slots=True)
class PathResult:
    """The answer, on both axes."""

    source: str
    destination: str
    protocol: str
    port: int

    routing: RoutingConfidence
    policy: PolicyVerdict

    hops: list[Hop] = field(default_factory=list)
    #: Where the trace stopped, when it did not finish. Names the prefix and next hop so
    #: the answer is actionable rather than merely hedged (FR-TOPO-05).
    stopped_at_prefix: str | None = None
    stopped_at_next_hop: str | None = None
    stopped_at_device: str | None = None
    #: Plain-language reasons, shown beside the verdict. A caveat that lives only in a
    #: log is a caveat nobody reads.
    notes: list[str] = field(default_factory=list)
    #: Devices where the packet could have taken more than one equal-cost route. The
    #: trace follows one; a real router picks per flow by a hash this cannot see, so the
    #: others are paths this answer does not describe.
    branched_at: list[str] = field(default_factory=list)
    #: Translations the walk *followed*: "edge-fw: destination 203.0.113.10 →
    #: 10.20.0.10". Informational, and deliberately not a caveat any more. The hops
    #: after one of these were asked about the rewritten addresses, which is the
    #: correct question — so a followed translation no longer weakens the verdict.
    translated_at: list[str] = field(default_factory=list)
    #: NAT that may apply here and could not be followed — a pool chosen per session,
    #: an object nothing defines, a form no parser reads. This one *does* weaken every
    #: hop after it, because those hops were asked about addresses the packet may no
    #: longer have been carrying, and it downgrades the policy verdict accordingly.
    #:
    #: Split from `translated_at` when translation became real. While the two were one
    #: list, every path through any NAT device reported `partially-allowed` — which is
    #: right for "we could not tell" and wrong for "we followed it".
    translation_unknown_at: list[str] = field(default_factory=list)

    @property
    def devices_traversed(self) -> int:
        return len(self.hops)

    @property
    def blocked_by(self) -> Hop | None:
        return next((hop for hop in self.hops if hop.action == "deny"), None)


def _address(value: str, label: str) -> int:
    try:
        return int(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ValidationProblem(
            f"'{value}' is not an IP address. A path query needs a literal {label} "
            "address — names are not resolved, so that what was analysed is what was asked."
        ) from None


@dataclass(frozen=True, slots=True)
class Endpoint:
    """One side of a query: a single host, or a whole subnet.

    A subnet is the form a segmentation review actually asks in — "can anything in the
    user VLAN reach anything in the card-data environment" — and asking it host by host
    is both 65,536 queries and the wrong question, because it answers whether one
    arbitrary pair gets through rather than whether the boundary holds.

    `representative` is what the *routing* walk uses. Routing is decided by longest-prefix
    match on the destination, so every address in a range that no route subdivides takes
    the same path; `splits` is where that assumption is checked rather than assumed.
    """

    text: str
    addresses: Any
    representative: int
    is_range: bool

    @property
    def size(self) -> int:
        return int(self.addresses.size)


def _endpoint(value: str, label: str) -> Endpoint:
    """Parse one side of a query, accepting a host or a CIDR range."""
    text = (value or "").strip()
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValidationProblem(
            f"'{value}' is not an IP address or CIDR range. A path query needs a literal "
            f"{label} — names are not resolved, so that what was analysed is what was asked."
        ) from None

    if network.version != 4:
        raise ValidationProblem(
            f"'{value}' is IPv6. Path analysis reasons over IPv4 forwarding tables only, "
            "and answering for a protocol whose tables are not collected would be a guess."
        )

    low, high = int(network.network_address), int(network.broadcast_address)
    return Endpoint(
        text=text,
        addresses=IntervalSet.of((low, high)),
        representative=low,
        is_range=low != high,
    )


def _protocol_number(protocol: str) -> int:
    text = (protocol or "").strip().lower()
    if text.isdigit():
        return int(text)
    number = PROTOCOL_NUMBERS.get(text)
    if number is None:
        raise ValidationProblem(
            f"'{protocol}' is not a protocol this can simulate. "
            f"Use one of: {', '.join(sorted(PROTOCOL_NUMBERS))}, or a protocol number."
        )
    return number


def _unnormalised_nat_rules(node: DeviceNode) -> int:
    """NAT rules on this device that carry no normalised fields at all.

    This used to be the whole of the NAT story: a count, and a caveat on every path
    through any firewall that does NAT. The parsers now emit a normalised form
    (`NatRule.original_source` and friends) and `translation.translate` follows it, so
    what is left here is the residue — a rule from a snapshot taken before that, or a
    configuration form no parser recognised.

    It is still counted, because a device whose NAT nobody could read must not look
    like a device with no NAT.
    """
    rules = node.firewall.get("nat_rules") if node.firewall else None
    if not isinstance(rules, list):
        return 0
    return sum(
        1
        for rule in rules
        if isinstance(rule, dict)
        and not rule.get("translated_source")
        and not rule.get("translated_destination")
        and not rule.get("translation_unreadable")
    )


def _translate_at(
    node: DeviceNode,
    source: int,
    destination: int,
    port: int,
    dst_endpoint: Endpoint,
) -> Translation | None:
    """This device's NAT applied to the packet, or None if nothing is to be said.

    A ranged destination is deliberately not translated. NAT rewrites addresses one at
    a time, and a range that a rule covers only part of does not become one other
    range — so following the translation for a range would produce a single path for
    traffic that takes several. The range case is reported rather than translated.
    """
    if not node.firewall:
        return None

    if dst_endpoint.is_range:
        # Probing the range's representative address would only find a rule that
        # happens to match that one address, and miss a rule matching any other
        # address in the range — which is most of them. The question here is whether
        # the rules touch the range *at all*, so it is asked that way.
        if not touches(node.firewall, dst_endpoint.addresses):
            return None
        return Translation(
            applied=False,
            reason=(
                f"{node.hostname} translates addresses inside the range asked about, "
                "and a range does not translate to one other range. Ask about a "
                "single address to follow the translation."
            ),
        )

    result = translate(
        node.firewall,
        source=source,
        destination=destination,
        port=port,
        interface_addresses=node.interface_addresses,
    )
    return result if (result.applied or result.unreadable) else None


#: Platforms whose rulebase matches the *translated* address rather than the original.
#: ASA from 8.3 onwards changed this, and it is the one place where evaluating with the
#: pre-NAT address — which is what PAN-OS does and what this walk does — gives an answer
#: the device would not.
_POST_NAT_MATCHING = ("asa", "ftd")


def _note_nat_semantics(result: PathResult, node: DeviceNode) -> None:
    platform = (node.platform or "").lower()
    if not any(family in platform for family in _POST_NAT_MATCHING):
        return
    note = (
        f"{node.hostname} is an ASA-family device, whose access lists match the "
        "translated address rather than the original. This walk evaluated its rulebase "
        "against the address as it arrived, so the policy verdict at that hop may "
        "differ from what the device does."
    )
    if note not in result.notes:
        result.notes.append(note)


def _describe(route: Route) -> str:
    if route.next_hop:
        return f"{route.destination} via {route.next_hop}"
    if route.interface:
        return f"{route.destination} via {route.interface}"
    return route.destination


@dataclass(frozen=True, slots=True)
class _Query:
    """The packet, as the rulebase is asked about it."""

    source: int
    destination: int
    protocol: int
    port: int
    src_range: Any = None
    dst_range: Any = None


@dataclass(frozen=True, slots=True)
class _Verdict:
    """What one ordered rulebase said.

    `action` None means the list was consulted and its answer could not be established —
    distinct from a permit, and it must not be combined as one.
    """

    action: str | None = None
    rule_name: str | None = None
    rule_order: int | None = None
    limitations: tuple[str, ...] = ()


#: Conservative precedence when several access lists apply to one hop. A deny anywhere
#: drops the packet, so it wins outright. An unevaluable list beats a permit, because it
#: might have denied — claiming `allow` on the strength of the list we could read would
#: be a permit the data does not support.
_PRECEDENCE: Final[dict[str | None, int]] = {"deny": 3, "mixed": 2, None: 1, "allow": 0}


def _governing_rulebases(node: DeviceNode, hop: Hop, contexts: set[str]) -> set[str] | None:
    """Which of this device's access lists are enforced on this hop.

    Matching is against the interface name *and* the zone, because the two platforms
    write the binding differently and both names are available here: IOS and NX-OS bind
    `ip access-group` under a physical interface and have no zones at all, while an ASA
    binds `access-group … interface inside`, naming the nameif — which is what the graph
    records as that interface's zone.

    Returns None when nothing matched, which is the caller's signal to report the
    decision as unknown rather than to pick one.
    """
    bindings = node.firewall.get("rulebase_bindings") or {}
    if not bindings:
        return None

    ingress = {name for name in (hop.ingress_interface, hop.ingress_zone) if name}
    egress = {name for name in (hop.egress_interface, hop.egress_zone) if name}

    governing: set[str] = set()
    for name in contexts:
        for binding in bindings.get(name, []):
            interface = binding.get("interface")
            direction = str(binding.get("direction") or "in").lower()
            # An ASA `access-group NAME global` has no interface and applies everywhere,
            # and so does a binding line the parser could not read — the safe reading of
            # "bound to something we could not identify" is that it is in force.
            if (
                interface is None
                or (direction == "in" and interface in ingress)
                or (direction == "out" and interface in egress)
            ):
                governing.add(name)
                break

    return governing or None


def _ask(node: DeviceNode, hop: Hop, rules: list[ResolvedRule], query: _Query) -> _Verdict:
    """One first-match evaluation over one ordered rulebase."""
    if query.src_range is not None and query.dst_range is not None:
        ranged = first_match_over_range(
            rules,
            source=query.src_range,
            destination=query.dst_range,
            protocol=query.protocol,
            port=query.port,
            src_zone=hop.ingress_zone,
            dst_zone=hop.egress_zone,
        )
        if ranged.outcome is RangeOutcome.MIXED:
            return _Verdict(
                action="mixed",
                rule_name=", ".join(rule.name for rule in ranged.split_by[:3]),
                limitations=tuple(ranged.notes),
            )
        if ranged.outcome is RangeOutcome.NO_MATCH:
            return _Verdict(action="deny", rule_name="(implicit deny)")

        decided = ranged.decided_by
        if decided is None:
            # Unreachable as the verdict is constructed, and left as a gap rather than
            # an assumed permit: a uniform outcome with no deciding rule would mean the
            # range analysis contradicted itself, and inventing an action here would
            # bury that behind a confident answer.
            return _Verdict(
                limitations=(
                    f"{node.hostname} returned a uniform verdict with no deciding rule, "
                    "so its decision is unknown and is not counted as a permit.",
                )
            )
        return _Verdict(action=decided.action, rule_name=decided.name, rule_order=decided.order)

    result = first_match(
        rules,
        source=query.source,
        destination=query.destination,
        protocol=query.protocol,
        port=query.port,
        src_zone=hop.ingress_zone,
        dst_zone=hop.egress_zone,
    )
    if result.matched is None:
        # No rule matched. Every platform here ends its policy with an implicit deny, so
        # the packet is dropped — and saying so is more useful than "no rule matched",
        # which reads as though the question went unanswered.
        return _Verdict(
            action="deny", rule_name="(implicit deny)", limitations=tuple(result.limitations)
        )

    return _Verdict(
        action=result.matched.action,
        rule_name=result.matched.name,
        rule_order=result.matched.order,
        limitations=tuple(result.limitations),
    )


def _combine(
    node: DeviceNode, hop: Hop, groups: list[list[ResolvedRule]], query: _Query
) -> _Verdict:
    """The device's answer, across every access list enforced on this hop.

    With one list — every platform that has a single ordered policy, and the ordinary
    Cisco case — this is that list's verdict unchanged.
    """
    verdicts = [_ask(node, hop, group, query) for group in groups if group]
    if not verdicts:
        return _Verdict()
    if len(verdicts) == 1:
        return verdicts[0]

    strongest = max(verdicts, key=lambda verdict: _PRECEDENCE.get(verdict.action, 1))
    # Caveats from the lists that did not decide still apply to the packet, so they are
    # carried rather than discarded with the verdicts they came from.
    merged = tuple(dict.fromkeys(note for verdict in verdicts for note in verdict.limitations))
    return _Verdict(
        action=strongest.action,
        rule_name=strongest.rule_name,
        rule_order=strongest.rule_order,
        limitations=merged,
    )


def _record(hop: Hop, verdict: _Verdict) -> None:
    hop.action = verdict.action
    hop.rule_name = verdict.rule_name
    hop.rule_order = verdict.rule_order
    # Extended, not replaced. The NAT step runs before this one and may already have
    # put a caveat on the hop; assigning here silently dropped it, which is the exact
    # failure this field exists to prevent.
    hop.limitations = (*hop.limitations, *verdict.limitations)


def _evaluate(
    node: DeviceNode,
    hop: Hop,
    *,
    source: int,
    destination: int,
    protocol: int,
    port: int,
    src_range: Any = None,
    dst_range: Any = None,
) -> None:
    """Ask one device's rulebase about the packet, and record what it said.

    A device with no rulebase leaves `action` None rather than defaulting to permit. A
    router forwards without an opinion, and rendering that as "allowed" would count it as
    a control that was checked — the same mistake as reporting an unevaluated check as a
    pass.

    Where either side of the query is a range, the rulebase is asked about the range
    rather than about one address in it. A rule that permits most of a subnet and denies
    one host inside it produces no single action, and picking a representative address
    would answer confidently for whichever host the query happened to name.
    """
    if not node.has_rulebase:
        return

    try:
        rules, _ = resolve_rulebase(node.firewall)
    except Exception as exc:  # a malformed stored rulebase must not abort the path
        log.warning("topology.rulebase_unreadable", device=node.hostname, error=str(exc))
        hop.limitations = (
            *hop.limitations,
            f"{node.hostname} carries a rulebase this could not resolve, so its decision "
            "is unknown and is not counted as a permit.",
        )
        return

    # Rules in an ACL bound to no interface filter nothing. They are frequently vty or
    # SNMP filters, and they end in `deny any` — so evaluating them here reported the
    # path blocked at a switch that forwards the traffic without looking at it. A false
    # `blocked` is the dangerous direction: it says a control is already in place.
    #
    # `ncm.acls` records the binding and the walker never sees it, so the parsers mark
    # the rules themselves. A platform with no such concept leaves this None and nothing
    # is filtered out.
    detached = [rule for rule in rules if rule.applied is False]
    rules = [rule for rule in rules if rule.applied is not False]

    if detached and not rules:
        # Every rulebase on the device is unbound, which is not the same as a device
        # with no rulebase: somebody wrote a policy here and did not apply it. Saying so
        # is worth more than silently reporting no decision.
        hop.limitations = (
            *hop.limitations,
            f"{node.hostname} carries {len(detached)} rule(s), all in access lists bound "
            "to no interface, so none of them filters this traffic. It was treated as "
            "forwarding without an opinion.",
        )
        return

    if not rules:
        return

    # A packet crossing an ASA, an IOS router or a Nexus is not tested against every
    # access list the device holds. It is tested against the one bound inbound on the
    # interface it arrived on, and the one bound outbound on the interface it leaves by.
    # The NCM records that on `SecurityRule.rulebase` and the hygiene analysis honours
    # it; evaluating them as one ordered list did not. On a three-interface ASA the
    # first list in the file decided every path, and since each ends in `deny ip any
    # any`, every path came back blocked by a rule governing the opposite direction.
    contexts = {rule.rulebase for rule in rules if rule.rulebase is not None}
    groups: list[list[ResolvedRule]] = [rules]

    if len(contexts) > 1:
        governing = _governing_rulebases(node, hop, contexts)
        if governing is None:
            # Either the snapshot predates the bindings, or none of them names this
            # hop's interfaces. No confident verdict from an arbitrary choice: a false
            # `blocked` says a control is already in place and somebody stops looking.
            hop.limitations = (
                *hop.limitations,
                f"{node.hostname} carries {len(contexts)} access lists and none of them "
                "is bound to the interface this packet arrives on or leaves by, so "
                "which one governs this hop could not be determined. Its decision is "
                "unknown and is not counted as a permit.",
            )
            return

        # One group per governing list, never concatenated. They are separate
        # first-match evaluations and a deny in either drops the packet — merging them
        # would let the first list's trailing deny shadow the second list's permit,
        # which is exactly the defect this replaced.
        groups = [[rule for rule in rules if rule.rulebase == name] for name in sorted(governing)]

    query = _Query(source, destination, protocol, port, src_range, dst_range)
    _record(hop, _combine(node, hop, groups, query))


def walk(
    graph: TopologyGraph,
    *,
    source: str,
    destination: str,
    protocol: str = "tcp",
    port: int = 443,
) -> PathResult:
    """Trace a packet across the estate and report both axes (FR-TOPO-03).

    `source` and `destination` may each be a host or a CIDR range. A range is the form a
    segmentation review asks in, and it changes what the policy axis can honestly say: a
    rulebase that permits most of a range and denies one address inside it has no single
    verdict, and `partially-allowed` is what that is.
    """
    src_endpoint = _endpoint(source, "source")
    dst_endpoint = _endpoint(destination, "destination")
    src = src_endpoint.representative
    dst = dst_endpoint.representative
    proto = _protocol_number(protocol)

    result = PathResult(
        source=source,
        destination=destination,
        protocol=protocol,
        port=port,
        routing=RoutingConfidence.UNKNOWN,
        policy=PolicyVerdict.NOT_ROUTED,
    )

    start = graph.device_serving(src)
    if start is None:
        result.notes.append(
            f"No device in the inventory is attached to a subnet containing {source}, so "
            "the path has no starting point. Onboard the device that serves that subnet, "
            "or start the query from an address inside the managed estate."
        )
        return _finalise(result)

    # Same attached subnet: the two hosts talk directly and nothing routes between them.
    # Reporting a firewall verdict here would be wrong in the dangerous direction — it
    # would imply a control sits in a path that has none.
    if start.serves(dst) and _same_connected_subnet(start, src, dst):
        result.routing = RoutingConfidence.SAME_ZONE
        result.policy = PolicyVerdict.NOT_ROUTED
        result.notes.append(
            f"{source} and {destination} are on the same subnet attached to "
            f"{start.hostname}, so traffic between them is not routed and no rulebase "
            "applies. A host firewall or a switch ACL could still block it; neither is "
            "visible from a configuration assessment."
        )
        return result

    current = start
    arrived_from = src
    visited: set[uuid.UUID] = set()

    for _ in range(MAX_HOPS):
        if current.device_id in visited:
            result.routing = RoutingConfidence.UNKNOWN
            result.stopped_at_device = current.hostname
            result.notes.append(
                f"The path returns to {current.hostname}, which is a routing loop rather "
                "than a route to the destination. The tables disagree with each other."
            )
            return _finalise(result)
        visited.add(current.device_id)

        hop = Hop(
            device_id=current.device_id,
            hostname=current.hostname,
            platform=current.platform,
            ingress_interface=current.interface_containing(arrived_from),
            ingress_zone=current.zone_containing(arrived_from),
        )

        # ── NAT, before the route lookup ──────────────────────────────────
        #
        # Destination translation has to be applied here or the whole point is lost:
        # a packet addressed to a public VIP is rewritten to an internal address and
        # *then* routed, so looking the public address up in the inside table finds
        # nothing and reports "unreachable" about a service that works.
        #
        # The rulebase below is still evaluated against the addresses as they arrived.
        # That is PAN-OS's model — security rules match the pre-NAT address and the
        # post-NAT zone — and it is the majority platform here. ASA from 8.3 matches
        # its ACLs on the translated address instead, so at an ASA hop the policy
        # verdict may differ; `_note_nat_semantics` says so rather than leaving it.
        pre_nat_destination = dst
        if (translation := _translate_at(current, src, dst, port, dst_endpoint)) is not None:
            if translation.unreadable:
                hop.limitations = (*hop.limitations, translation.reason or "")
                result.translation_unknown_at.append(f"{current.hostname}: {translation.reason}")
            elif translation.applied:
                hop.translation = translation.detail
                result.translated_at.append(f"{current.hostname}: {translation.detail}")
                _note_nat_semantics(result, current)
                if translation.destination is not None:
                    dst = translation.destination
                if translation.source is not None:
                    src = translation.source
                if translation.port is not None:
                    port = translation.port

        # Arrived: the destination is on a subnet this device is directly attached to.
        if current.serves(dst):
            # The interface as well as the zone: an outbound access list is bound by
            # interface name on IOS and NX-OS, and the last hop is exactly where an
            # outbound list on the destination's own segment is enforced.
            hop.egress_interface = current.interface_containing(dst)
            hop.egress_zone = current.zone_containing(dst)
            hop.matched_route = "connected"
            _evaluate(
                current,
                hop,
                source=src,
                destination=pre_nat_destination,
                protocol=proto,
                port=port,
                src_range=src_endpoint.addresses,
                dst_range=dst_endpoint.addresses,
            )
            result.hops.append(hop)
            result.routing = RoutingConfidence.ROUTED
            return _finalise(result)

        route = current.lookup(dst)
        if route is None:
            result.hops.append(hop)
            result.stopped_at_device = current.hostname
            other_vrfs = current.other_vrfs_matching(dst)
            if not current.routes_known:
                result.routing = RoutingConfidence.UNKNOWN
                result.notes.append(
                    f"{current.hostname} was collected before forwarding tables were "
                    "parsed, so its routes are unknown rather than absent. Re-collect it "
                    "to complete this path."
                )
            elif other_vrfs:
                # The global table has no route, but a VRF does. Which VRF a packet is in
                # is decided by the interface it arrives on, and no parser records that
                # binding — so this is a limit of what is modelled, not a property of the
                # network, and must not be reported as unreachable.
                result.routing = RoutingConfidence.UNKNOWN
                result.notes.append(
                    f"{current.hostname} has no route to {destination} in its global "
                    f"table, but VRF {', '.join(other_vrfs)} does. Which VRF carries this "
                    "traffic depends on the interface it arrives on, which is not "
                    "collected — so the path cannot be resolved rather than being absent."
                )
            elif current.routes_truncated:
                result.routing = RoutingConfidence.UNKNOWN
                result.notes.append(
                    f"{current.hostname}'s routing table was larger than is stored, so "
                    "the absence of a route here may be an artefact of truncation."
                )
            else:
                result.routing = RoutingConfidence.UNREACHABLE
                result.notes.append(
                    f"{current.hostname} has no route to {destination}. The packet is "
                    "dropped there, so no firewall beyond it is consulted."
                )
            return _finalise(result)

        # A range that one of this device's prefixes cuts across does not take one path,
        # so a single trace cannot describe it. Checked per hop rather than once, because
        # a range can be whole on the first device and subdivided three hops later.
        if dst_endpoint.is_range:
            subdividing = current.routes_subdividing(
                int(dst_endpoint.addresses.intervals[0][0]),
                int(dst_endpoint.addresses.intervals[-1][1]),
            )
            if subdividing:
                result.hops.append(hop)
                result.routing = RoutingConfidence.UNKNOWN
                result.stopped_at_device = current.hostname
                result.notes.append(
                    f"{current.hostname} routes {destination} through more than one "
                    f"prefix ({', '.join(subdividing)}), so different parts of that range "
                    "take different paths. Narrow the query to one of those prefixes to "
                    "get a single answer."
                )
                return _finalise(result)

        # More than one route ties for best. A router chooses per flow by hashing the
        # header, and nothing in a configuration says which way this flow goes — so the
        # trace continues down one of them and the result has to say the others exist.
        # Silently following the first is how a permit gets reported for a path the
        # packet may never take, while an equal-cost sibling crosses a firewall that
        # denies it.
        alternatives = current.equal_cost_next_hops(dst)
        if alternatives:
            chosen = route.next_hop
            others = [hop_address for hop_address in alternatives if hop_address != chosen]
            result.branched_at.append(
                f"{current.hostname} has {len(alternatives)} equal-cost routes to "
                f"{route.destination} (via {', '.join(alternatives)}); this trace follows "
                f"{chosen}."
            )
            log.info(
                "topology.equal_cost_paths",
                device=current.hostname,
                destination=route.destination,
                followed=chosen,
                alternatives=others,
            )

        hop.matched_route = _describe(route)
        hop.next_hop = route.next_hop
        hop.egress_interface = route.interface
        hop.egress_zone = current.zone_for(route.interface)
        _evaluate(
            current,
            hop,
            source=src,
            destination=pre_nat_destination,
            protocol=proto,
            port=port,
            src_range=src_endpoint.addresses,
            dst_range=dst_endpoint.addresses,
        )
        result.hops.append(hop)

        # A rule that denies ends the path here, definitively. Continuing to trace would
        # produce hops the packet never reaches.
        if hop.action == "deny":
            result.routing = RoutingConfidence.ROUTED if route.next_hop else result.routing
            break

        adjacency = graph.adjacency(current, route)
        if adjacency.next_device_id is None:
            # The edge of the managed estate. This is the answer FR-TOPO-05 exists for,
            # and the input to the missing-device report.
            result.routing = RoutingConfidence.PARTIALLY_ROUTED
            result.stopped_at_prefix = route.destination
            result.stopped_at_next_hop = route.next_hop
            result.stopped_at_device = current.hostname
            result.notes.append(
                f"The path leaves the managed estate at {current.hostname}: it routes "
                f"{route.destination} via {route.next_hop or route.interface}, which "
                "belongs to no device in the inventory. Anything beyond that point — "
                "including further firewalls — is not visible here."
            )
            return _finalise(result)

        # A device carrying NAT rules none of which this could read at all. The
        # per-packet cases are handled at the top of the loop; this catches a device
        # whose parser has no normalised NAT — every rule skipped, nothing said — which
        # would otherwise be indistinguishable from a device with no NAT.
        if (unread := _unnormalised_nat_rules(current)) and not hop.translation:
            result.translation_unknown_at.append(
                f"{current.hostname} carries {unread} NAT rule(s) in a form this cannot "
                "read, so whether they rewrite this traffic is unknown. If any of them "
                "does, the devices after it were asked about the original addresses "
                "rather than the ones the packet actually carried."
            )

        arrived_from = _address(route.next_hop, "next hop") if route.next_hop else arrived_from
        current = graph.nodes[adjacency.next_device_id]
    else:
        result.routing = RoutingConfidence.UNKNOWN
        result.notes.append(
            f"The path exceeded {MAX_HOPS} hops without reaching {destination}, which "
            "means the tables form a loop rather than a route."
        )

    return _finalise(result)


def _finalise(result: PathResult) -> PathResult:
    """Derive the policy axis from the hops and the routing axis (FR-TOPO-04).

    This is where the two axes are combined, and the combination is the product's honesty
    about its own coverage. The rule that matters: `allowed` requires `routed`. Anything
    less becomes `partially-allowed`, because a permit only speaks for the devices that
    were actually consulted and an untraced remainder may hold another firewall.
    """
    consulted = [hop for hop in result.hops if hop.action is not None]

    if any(hop.action == "deny" for hop in consulted):
        # Definitive: the packet dies at the first denial, so what lies beyond is moot.
        result.policy = PolicyVerdict.BLOCKED
        blocker = result.blocked_by
        if blocker:
            result.notes.append(
                f"{blocker.hostname} denies this traffic"
                + (f" at rule '{blocker.rule_name}'" if blocker.rule_name else "")
                + ". Devices beyond it were not evaluated, because the packet does not "
                "reach them."
            )
        return result

    if result.routing is RoutingConfidence.UNREACHABLE:
        result.policy = PolicyVerdict.NOT_ROUTED
        return result

    if not consulted:
        # Traced, and nothing on the way had a rulebase to consult.
        result.policy = (
            PolicyVerdict.PARTIALLY_ALLOWED
            if result.routing is not RoutingConfidence.ROUTED
            else PolicyVerdict.ALLOWED
        )
        if result.routing is RoutingConfidence.ROUTED:
            result.notes.append(
                "No device on this path carries a firewall rulebase, so nothing "
                "inspected the traffic. 'Allowed' here means unfiltered, not permitted."
            )
        return result

    if any(hop.action == "mixed" for hop in consulted):
        # A range whose answer is not uniform. Not `allowed`, because part of it is not;
        # not `blocked`, because part of it is not either. `partially-allowed` already
        # carries "this does not settle the question", which is exactly the state.
        result.policy = PolicyVerdict.PARTIALLY_ALLOWED
        splitters = [hop for hop in consulted if hop.action == "mixed"]
        result.notes.append(
            "This query covers a range, and "
            + ", ".join(f"{hop.hostname} ({hop.rule_name})" for hop in splitters)
            + " treats part of it differently from the rest. Narrow the range to the "
            "prefixes those rules name to get a verdict that holds for all of it."
        )
        return result

    if result.routing is RoutingConfidence.ROUTED:
        # Traced end to end, and every device consulted permits it. Two things can still
        # stop that being a plain `allowed`, and they can both hold at once — so both are
        # reported, rather than whichever happened to be checked first. Each says the
        # same thing in a different way: the permit is real for the devices actually
        # consulted about the addresses actually asked, and something about the trace
        # makes that a narrower claim than "this traffic gets through".
        if result.branched_at:
            # Only one of several equal-cost paths was followed. The firewalls on the
            # others were never consulted.
            result.notes.append(
                "This path was traced end to end, but the packet could take more than "
                "one route: "
                + " ".join(result.branched_at)
                + " A router picks between equal-cost paths per flow, so a firewall on "
                "a path not followed here could still deny this traffic."
            )

        if result.translated_at:
            # A translation the walk *followed*. Stated, because the reader asked
            # about one address and the later hops were evaluated about another — but
            # not a caveat, because those later hops were asked the right question.
            result.notes.append(
                "Addresses were rewritten along this path and the trace followed the "
                "rewrite: " + " ".join(result.translated_at) + " Hops after each of "
                "those were evaluated against the translated addresses."
            )

        if result.translation_unknown_at:
            # NAT that may apply and could not be followed. This is the one that still
            # weakens the answer: the hops after it were asked about addresses the
            # packet may no longer have been carrying.
            result.notes.append(
                "The path continues past a device whose NAT could not be followed: "
                + " ".join(result.translation_unknown_at)
            )

        # Note what is *not* here: `translated_at`. While a followed translation and an
        # unreadable one shared a list, every path through an internet edge came back
        # `partially-allowed` — correct for "we could not tell", wrong for "we followed
        # it", and a caveat that fires on nearly every path teaches a reader to ignore
        # the caveat.
        result.policy = (
            PolicyVerdict.PARTIALLY_ALLOWED
            if result.branched_at or result.translation_unknown_at
            else PolicyVerdict.ALLOWED
        )
        return result

    result.policy = PolicyVerdict.PARTIALLY_ALLOWED
    result.notes.append(
        f"{len(consulted)} device(s) on the traced part of this path permit the traffic, "
        "but the path was not followed to the destination — so this is not a statement "
        "that the traffic gets through."
    )
    return result


def _same_connected_subnet(node: DeviceNode, left: int, right: int) -> bool:
    """Whether both addresses fall in one of this device's attached subnets."""
    for route in node.routes:
        if route.protocol != "connected":
            continue
        try:
            network = ipaddress.ip_network(route.destination, strict=False)
        except ValueError:
            continue
        low, high = int(network.network_address), int(network.broadcast_address)
        if low <= left <= high and low <= right <= high:
            return True
    return False


__all__ = [
    "MAX_HOPS",
    "Hop",
    "PathResult",
    "PolicyVerdict",
    "RoutingConfidence",
    "walk",
]
