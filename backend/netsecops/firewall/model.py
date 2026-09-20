"""Resolving a rulebase into comparable sets (FR-FW-01, FR-FW-03, FR-FW-05).

The NCM stores a security rule the way the device writes it: `src: ["DMZ-Servers"]`,
`services: ["web-ports"]`. Those are names. Deciding whether two rules overlap requires
the *addresses and ports behind the names*, with groups expanded — including nested
groups, which every vendor allows and every large rulebase uses.

This module does that expansion once per rulebase and caches it. The alternative —
resolving names inside the comparison loop — would repeat the same group walk millions
of times and is the difference between the analysis finishing in seconds and not
finishing at all.

**Unresolvable names are recorded, never guessed.** A rule referencing an object the
collection did not capture becomes a rule with an empty address set, and the name is
kept in ``unresolved``. Treating it as `any` would invent permissions the device does
not grant; treating it as nothing silently hides a rule. Reporting it is the only
honest option, and the object-hygiene checks surface it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from netsecops.firewall.intervals import (
    ANY_IPV4,
    ANY_IPV6,
    ANY_PORT,
    EMPTY_INTERVALS,
    IPV4_MAX,
    IPV6_MAX,
    IntervalSet,
    parse_address,
    parse_port_range,
)

#: How deep a nested group may go before we stop and call it a loop. Vendors permit
#: nesting; none permit cycles, but a malformed export can contain one and an
#: unbounded walk would hang the analysis rather than failing it.
MAX_GROUP_DEPTH = 16

#: Protocol numbers the analyser reasons about by name. Anything else is compared by
#: its numeric value, so an unusual protocol is handled rather than dropped.
PROTOCOL_NUMBERS: dict[str, int] = {
    "icmp": 1,
    "igmp": 2,
    "tcp": 6,
    "udp": 17,
    "gre": 47,
    "esp": 50,
    "ah": 51,
    "icmpv6": 58,
    "sctp": 132,
}

ANY_PROTOCOL = -1


@dataclass(frozen=True, slots=True)
class ServiceSet:
    """The protocol/port space a rule covers.

    A dict of protocol number to the ports permitted on it. `ANY_PROTOCOL` is a distinct
    key rather than "every protocol enumerated", because `service any` and `tcp 1-65535`
    are different rules and conflating them would report false redundancies.
    """

    by_protocol: Mapping[int, IntervalSet] = field(default_factory=dict)

    @property
    def is_any(self) -> bool:
        return ANY_PROTOCOL in self.by_protocol

    def __bool__(self) -> bool:
        return bool(self.by_protocol)

    def intersects(self, other: ServiceSet) -> bool:
        if self.is_any or other.is_any:
            return bool(self.by_protocol) and bool(other.by_protocol)

        # Iterate the smaller map: protocol counts are tiny, but this loop runs on every
        # candidate pair that survived the address prefilter.
        mine, theirs = (
            (self.by_protocol, other.by_protocol)
            if len(self.by_protocol) <= len(other.by_protocol)
            else (other.by_protocol, self.by_protocol)
        )
        for protocol, ports in mine.items():
            counterpart = theirs.get(protocol)
            if counterpart is not None and ports.intersects(counterpart):
                return True
        return False

    def contains(self, other: ServiceSet) -> bool:
        """True if every protocol/port `other` permits is also permitted here."""
        if not other.by_protocol:
            return True
        if self.is_any:
            return True
        if other.is_any:
            return False

        for protocol, ports in other.by_protocol.items():
            counterpart = self.by_protocol.get(protocol)
            if counterpart is None or not counterpart.contains_set(ports):
                return False
        return True

    def describe(self, limit: int = 3) -> str:
        if self.is_any:
            return "any"
        names = {number: name for name, number in PROTOCOL_NUMBERS.items()}
        parts = []
        for protocol, ports in list(self.by_protocol.items())[:limit]:
            label = names.get(protocol, f"proto-{protocol}")
            if ports == ANY_PORT:
                parts.append(f"{label}/any")
            else:
                rendered = ",".join(
                    str(lo) if lo == hi else f"{lo}-{hi}" for lo, hi in ports.intervals[:3]
                )
                parts.append(f"{label}/{rendered}")
        if len(self.by_protocol) > limit:
            parts.append(f"and {len(self.by_protocol) - limit} more")
        return ", ".join(parts) if parts else "nothing"


ANY_SERVICE = ServiceSet({ANY_PROTOCOL: ANY_PORT})


@dataclass(frozen=True, slots=True)
class AddressSet:
    """Addresses a rule covers, kept per family.

    IPv4 and IPv6 are separate spaces. Merging them into one integer line would make a
    v4 rule and a v6 rule appear to overlap whenever their numeric ranges happened to
    coincide, which is a false positive nobody could interpret.
    """

    v4: IntervalSet = EMPTY_INTERVALS
    v6: IntervalSet = EMPTY_INTERVALS

    def __bool__(self) -> bool:
        return bool(self.v4) or bool(self.v6)

    @property
    def is_any(self) -> bool:
        return self.v4 == ANY_IPV4 or self.v6 == ANY_IPV6

    @property
    def size(self) -> int:
        return self.v4.size + self.v6.size

    def intersects(self, other: AddressSet) -> bool:
        return self.v4.intersects(other.v4) or self.v6.intersects(other.v6)

    def contains(self, other: AddressSet) -> bool:
        return self.v4.contains_set(other.v4) and self.v6.contains_set(other.v6)

    def union(self, other: AddressSet) -> AddressSet:
        return AddressSet(v4=self.v4.union(other.v4), v6=self.v6.union(other.v6))

    def negated(self) -> AddressSet:
        """Everything this set does not cover, in both families.

        Check Point rules can negate a source or destination. Each family is
        complemented against its own maximum — complementing v6 against the IPv4 bound
        would silently truncate the result to the first four billion addresses.
        """
        return AddressSet(
            v4=self.v4.complement(IPV4_MAX),
            v6=self.v6.complement(IPV6_MAX),
        )


ANY_ADDRESS = AddressSet(v4=ANY_IPV4, v6=ANY_IPV6)
EMPTY_ADDRESS = AddressSet()


@dataclass(slots=True)
class ResolvedRule:
    """One security rule with every name expanded to the set it stands for."""

    order: int
    name: str
    enabled: bool
    action: str
    src_zones: frozenset[str]
    dst_zones: frozenset[str]
    source: AddressSet
    destination: AddressSet
    services: ServiceSet
    applications: frozenset[str]
    users: frozenset[str]
    log_start: bool | None
    log_end: bool | None
    profiles: Mapping[str, str]
    schedule: str | None
    hit_count: int | None
    last_hit: str | None
    #: Object names the rulebase referenced but did not define.
    unresolved: tuple[str, ...] = ()
    #: The named ACL or policy this rule is evaluated in; None on platforms with a
    #: single ordered policy. Rules in different contexts are never compared, because
    #: they are never applied to the same packet.
    rulebase: str | None = None
    #: False where the rulebase is bound to no interface and so filters nothing. `None`
    #: where the platform has no such concept. See `SecurityRule.applied`.
    #:
    #: Read by the path walk only. Hygiene analysis deliberately still reports on an
    #: unapplied rule: a rulebase somebody wrote and never bound is worth surfacing, and
    #: is a different observation from what happens to a packet.
    applied: bool | None = None

    @property
    def permits(self) -> bool:
        """Whether this rule allows traffic. Vendors spell denial four ways."""
        return self.action.lower() in {"allow", "permit", "accept"}

    @property
    def logs(self) -> bool:
        """Whether the rule records anything at all.

        `None` means the parser could not tell, which must not read as False — a rule
        reported as unlogged when logging was simply not captured sends someone to
        change a firewall for no reason.
        """
        return bool(self.log_start) or bool(self.log_end)

    @property
    def logging_known(self) -> bool:
        return self.log_start is not None or self.log_end is not None

    @property
    def usage_known(self) -> bool:
        """Whether this rule's traffic counters were captured at all.

        The same rule as `logging_known`, for the field where getting it wrong is most
        expensive. `hit_count is None` means no counter reached this rule — the platform
        does not report them, or the collection did not capture them — and it must never
        read as zero.

        Zero and unknown look identical on a cleanup report and mean opposite things:
        one is a rule nothing has matched, the other a rule nobody has watched. Removing
        a rule on the strength of the second is how a firewall change takes production
        down, which is not hypothetical — it is the reported failure mode of the market
        leader's unused-rule analysis.
        """
        return self.hit_count is not None

    @property
    def has_profiles(self) -> bool:
        return any(value for value in self.profiles.values())

    def zones_intersect(self, other: ResolvedRule) -> bool:
        """Zones gate everything: rules in disjoint zone pairs cannot overlap.

        An empty zone set means the rule is zone-agnostic (FortiOS interface-less
        policies, Check Point rules), which matches anything.
        """
        if self.src_zones and other.src_zones and self.src_zones.isdisjoint(other.src_zones):
            return False
        return not (
            self.dst_zones and other.dst_zones and self.dst_zones.isdisjoint(other.dst_zones)
        )

    def zones_contain(self, other: ResolvedRule) -> bool:
        src_ok = not self.src_zones or (other.src_zones and other.src_zones <= self.src_zones)
        dst_ok = not self.dst_zones or (other.dst_zones and other.dst_zones <= self.dst_zones)
        return bool(src_ok and dst_ok)

    def describe(self) -> str:
        from netsecops.firewall.intervals import describe_ipv4

        return (
            f"#{self.order} {self.name or '(unnamed)'}: "
            f"{describe_ipv4(self.source.v4)} → {describe_ipv4(self.destination.v4)} "
            f"[{self.services.describe()}] {self.action}"
        )


class ObjectResolver:
    """Expands address and service object names into sets, with nested groups.

    Every lookup is memoised. A group referenced by two hundred rules is walked once,
    which is the difference between resolution being a rounding error and being the
    dominant cost.
    """

    def __init__(self, firewall: Mapping[str, Any]) -> None:
        self._addresses = {
            o["name"]: o for o in firewall.get("address_objects", []) if o.get("name")
        }
        self._address_groups = {
            o["name"]: o for o in firewall.get("address_groups", []) if o.get("name")
        }
        self._services = {
            o["name"]: o for o in firewall.get("service_objects", []) if o.get("name")
        }
        self._service_groups = {
            o["name"]: o for o in firewall.get("service_groups", []) if o.get("name")
        }

        self._address_cache: dict[str, AddressSet] = {}
        self._service_cache: dict[str, ServiceSet] = {}
        self.unresolved: set[str] = set()
        #: Names that were referenced at least once, for the unused-object check.
        self.referenced: set[str] = set()

    # ── addresses ───────────────────────────────────────────────────────

    def resolve_addresses(self, names: Sequence[str]) -> tuple[AddressSet, tuple[str, ...]]:
        combined = EMPTY_ADDRESS
        missing: list[str] = []

        for name in names:
            resolved = self._resolve_address(name, depth=0)
            if resolved is None:
                missing.append(name)
                continue
            if resolved.is_any:
                # `any` swallows everything else; stop early rather than unioning the
                # rest into a set that is already the whole space.
                return ANY_ADDRESS, tuple(missing)
            combined = combined.union(resolved)

        return combined, tuple(missing)

    def _resolve_address(self, name: str, *, depth: int) -> AddressSet | None:
        if depth > MAX_GROUP_DEPTH:
            self.unresolved.add(f"{name} (nested beyond {MAX_GROUP_DEPTH} levels)")
            return None

        cached = self._address_cache.get(name)
        if cached is not None:
            self.referenced.add(name)
            return cached

        token = name.strip().lower()
        if token in {"any", "all", "*"}:
            return ANY_ADDRESS

        # A literal address written inline, which every vendor permits alongside objects.
        v4, v6 = parse_address(name)
        if v4 or v6:
            resolved = AddressSet(v4=v4, v6=v6)
            self._address_cache[name] = resolved
            return resolved

        self.referenced.add(name)

        obj = self._addresses.get(name)
        if obj is not None:
            v4, v6 = parse_address(str(obj.get("value") or ""))
            if not v4 and not v6:
                # The object exists and its value could not be read — a vendor spelling
                # this does not know, or an empty definition. Returning the empty set
                # here made every rule referencing it match *nothing*, silently and with
                # no entry in `unresolved`: the rule was still analysed, still ordered,
                # and could never fire. That is how a whole platform's rulebase can be
                # inert without a single error. Refusing it instead puts the object on
                # the rule's `unresolved` list, which is reported and takes the rule out
                # of overlap analysis.
                self.unresolved.add(f"{name} (value not understood)")
                return None
            resolved = AddressSet(v4=v4, v6=v6)
            self._address_cache[name] = resolved
            return resolved

        group = self._address_groups.get(name)
        if group is not None:
            combined = EMPTY_ADDRESS
            members = list(group.get("members", []))
            for member in members:
                member_set = self._resolve_address(str(member), depth=depth + 1)
                if member_set is None:
                    continue
                combined = combined.union(member_set)
            if members and combined is EMPTY_ADDRESS:
                # Same reasoning as an object: a group with members, none of which could
                # be read, is not an empty group. An empty group is a real thing to
                # write and resolves to nothing legitimately — so the distinction is
                # whether there were members at all.
                self.unresolved.add(f"{name} (no member could be read)")
                return None
            self._address_cache[name] = combined
            return combined

        self.unresolved.add(name)
        return None

    # ── services ────────────────────────────────────────────────────────

    def resolve_services(self, names: Sequence[str]) -> tuple[ServiceSet, tuple[str, ...]]:
        by_protocol: dict[int, IntervalSet] = {}
        missing: list[str] = []

        for name in names:
            resolved = self._resolve_service(name, depth=0)
            if resolved is None:
                missing.append(name)
                continue
            if resolved.is_any:
                return ANY_SERVICE, tuple(missing)
            for protocol, ports in resolved.by_protocol.items():
                existing = by_protocol.get(protocol)
                by_protocol[protocol] = ports if existing is None else existing.union(ports)

        return ServiceSet(by_protocol), tuple(missing)

    def _resolve_service(self, name: str, *, depth: int) -> ServiceSet | None:
        if depth > MAX_GROUP_DEPTH:
            self.unresolved.add(f"{name} (nested beyond {MAX_GROUP_DEPTH} levels)")
            return None

        cached = self._service_cache.get(name)
        if cached is not None:
            self.referenced.add(name)
            return cached

        token = name.strip().lower()
        if token in {"any", "all", "*", "application-default", "ip", "ipv4"}:
            # `application-default` is PAN-OS for "whatever ports the App-ID expects".
            # It is narrower than `any` in practice, but the rulebase alone does not say
            # how much narrower, so treating it as any is the conservative reading —
            # it can only over-report overlap, never hide it.
            #
            # `ip` is Cisco for "every protocol" in an access-list entry. The parsers
            # normalise it to `any` before it gets here; it is accepted anyway because
            # the failure mode when it is not is silent — the service lands in
            # `unresolved`, the rule stops matching, and the rulebase quietly behaves as
            # though the entry were not there.
            return ANY_SERVICE

        self.referenced.add(name)

        obj = self._services.get(name)
        if obj is not None:
            resolved = _service_from_object(obj)
            self._service_cache[name] = resolved
            return resolved

        group = self._service_groups.get(name)
        if group is not None:
            by_protocol: dict[int, IntervalSet] = {}
            for member in group.get("members", []):
                member_set = self._resolve_service(str(member), depth=depth + 1)
                if member_set is None:
                    continue
                if member_set.is_any:
                    self._service_cache[name] = ANY_SERVICE
                    return ANY_SERVICE
                for protocol, ports in member_set.by_protocol.items():
                    existing = by_protocol.get(protocol)
                    by_protocol[protocol] = ports if existing is None else existing.union(ports)
            resolved = ServiceSet(by_protocol)
            self._service_cache[name] = resolved
            return resolved

        # A literal like `tcp/443` or `tcp-8080`, common in FortiOS and inline configs.
        literal = _service_from_literal(name)
        if literal is not None:
            self._service_cache[name] = literal
            return literal

        self.unresolved.add(name)
        return None

    # ── hygiene support (FR-FW-05) ──────────────────────────────────────

    def defined_names(self) -> set[str]:
        return (
            set(self._addresses)
            | set(self._address_groups)
            | set(self._services)
            | set(self._service_groups)
        )

    def group_members(self, name: str) -> list[str]:
        group = self._address_groups.get(name) or self._service_groups.get(name)
        return [str(m) for m in group.get("members", [])] if group else []

    def address_values(self) -> dict[str, str]:
        """Object name → literal value, for duplicate detection."""
        return {
            name: str(obj.get("value") or "")
            for name, obj in self._addresses.items()
            if obj.get("value")
        }


def _service_from_object(obj: Mapping[str, Any]) -> ServiceSet:
    """Build a ServiceSet from an NCM service object.

    The NCM stores these loosely — `value` carries whatever the vendor wrote — so this
    accepts the several shapes seen in practice rather than one canonical form.
    """
    value = str(obj.get("value") or "").strip().lower()
    declared = str(obj.get("type") or "").strip().lower()

    if value in {"any", "all"}:
        return ANY_SERVICE

    protocol = PROTOCOL_NUMBERS.get(declared)
    ports = value

    if "/" in value:
        head, _, tail = value.partition("/")
        if head in PROTOCOL_NUMBERS:
            protocol, ports = PROTOCOL_NUMBERS[head], tail
    elif value.startswith(("tcp-", "udp-")):
        protocol, ports = PROTOCOL_NUMBERS[value[:3]], value[4:]

    if protocol is None:
        protocol = PROTOCOL_NUMBERS.get("tcp", 6) if ports else ANY_PROTOCOL

    port_set = parse_port_range(ports) if ports else ANY_PORT
    return ServiceSet({protocol: port_set}) if port_set else ServiceSet({})


def _service_from_literal(name: str) -> ServiceSet | None:
    token = name.strip().lower()
    for separator in ("/", "-", ":"):
        head, sep, tail = token.partition(separator)
        if sep and head in PROTOCOL_NUMBERS:
            ports = parse_port_range(tail)
            return ServiceSet({PROTOCOL_NUMBERS[head]: ports}) if ports else None
    if token in PROTOCOL_NUMBERS:
        return ServiceSet({PROTOCOL_NUMBERS[token]: ANY_PORT})
    return None


def resolve_rulebase(firewall: Mapping[str, Any]) -> tuple[list[ResolvedRule], ObjectResolver]:
    """Expand every rule in an NCM firewall block into comparable sets."""
    resolver = ObjectResolver(firewall)
    rules: list[ResolvedRule] = []

    for index, raw in enumerate(firewall.get("security_rules", [])):
        source, missing_src = resolver.resolve_addresses(raw.get("src") or ["any"])
        destination, missing_dst = resolver.resolve_addresses(raw.get("dst") or ["any"])
        services, missing_svc = resolver.resolve_services(raw.get("services") or ["any"])

        # Check Point rules can mean "anything *except* these addresses". The flag has
        # to be applied here rather than in the parser, because it inverts the resolved
        # set and the parser only ever sees object names. An unapplied negation would
        # make the rule read as its exact opposite.
        if raw.get("src_negate"):
            source = source.negated()
        if raw.get("dst_negate"):
            destination = destination.negated()

        rules.append(
            ResolvedRule(
                order=int(raw.get("order", index)),
                name=str(raw.get("name") or f"rule-{index + 1}"),
                enabled=bool(raw.get("enabled", True)),
                action=str(raw.get("action") or "allow"),
                src_zones=frozenset(raw.get("src_zones") or ()),
                dst_zones=frozenset(raw.get("dst_zones") or ()),
                source=source,
                destination=destination,
                services=services,
                applications=frozenset(raw.get("applications") or ()),
                users=frozenset(raw.get("users") or ()),
                log_start=raw.get("log_start"),
                log_end=raw.get("log_end"),
                profiles=raw.get("profiles") or {},
                schedule=raw.get("schedule"),
                hit_count=raw.get("hit_count"),
                last_hit=raw.get("last_hit"),
                unresolved=tuple(missing_src + missing_dst + missing_svc),
                rulebase=raw.get("rulebase"),
                applied=raw.get("applied"),
            )
        )

    return rules, resolver


__all__ = [
    "ANY_ADDRESS",
    "ANY_PROTOCOL",
    "ANY_SERVICE",
    "EMPTY_ADDRESS",
    "MAX_GROUP_DEPTH",
    "PROTOCOL_NUMBERS",
    "AddressSet",
    "ObjectResolver",
    "ResolvedRule",
    "ServiceSet",
    "resolve_rulebase",
]
