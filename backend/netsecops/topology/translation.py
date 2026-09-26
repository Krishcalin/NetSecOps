"""Following a NAT translation across a hop (FR-TOPO-03).

Until now the path walk reported only that a device *carried* NAT rules, and said so on
every hop it crossed. That is honest but nearly useless: "an address may have changed
here" is the caveat that makes the rest of the answer unverifiable, and it appeared on
every path through any firewall that does NAT, which is most of them.

Following the translation is what makes a destination-NAT path answerable at all. Ask
whether the internet can reach `203.0.113.10:443` and the truth is that the edge
firewall rewrites that to `10.20.0.10` and routes it inward — so a walk that does not
translate looks up `203.0.113.10` in the *inside* routing table, finds nothing, and
reports "unreachable" about a service that works.

**Why this could not be done before.** The four parsers emitted a `NatRule.original`
that meant something different on each platform: PAN-OS put the rule's *source* members
there whatever it translated, FortiOS put a VIP's *external* address, Check Point joined
object names into one string, and ASA set it to nothing at all. A matcher over that
field would have been wrong differently on every platform, and a wrong path verdict is
somebody opening a firewall. The normalised fields on `NatRule` are the prerequisite,
and this module is built only on them.

**What it refuses to do.** A rule whose translation the parser could not read — a pool
chosen per session, an `interface` keyword whose address is not in the rule, an object
name nothing defines — does not silently fail to match. It stops the translation and
says why, because a hop where NAT might have applied and could not be read is a weaker
answer than a hop where NAT plainly did not apply, and the two must never look alike.

Order is first-match, as every platform evaluates NAT: the first rule whose match
conditions the packet satisfies is applied and the rest are not consulted.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from netsecops.core.logging import get_logger
from netsecops.firewall.intervals import IntervalSet, parse_address

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Translation:
    """What one hop did to the packet.

    `applied` False with a `reason` is a rule that matched but could not be followed;
    `applied` False with no reason means no rule matched, which is the ordinary case and
    is not worth reporting. The two are distinguished because only the first weakens
    every conclusion downstream of this hop.
    """

    applied: bool
    rule_name: str | None = None
    #: The packet after translation. Unchanged fields hold their original values.
    destination: int | None = None
    source: int | None = None
    port: int | None = None
    #: Human-readable, for the hop record: "destination 203.0.113.10 → 10.20.0.10".
    detail: str | None = None
    #: Set when a rule matched and could not be followed. Everything after this hop is
    #: computed from an address that may be wrong.
    reason: str | None = None

    @property
    def unreadable(self) -> bool:
        return self.reason is not None


NO_TRANSLATION = Translation(applied=False)


@dataclass(slots=True)
class _Resolver:
    """Object names to address sets, for the platforms that express NAT in names.

    Check Point NAT is written entirely against the object database and ASA object NAT
    names the enclosing `object network`. A literal address is returned as itself, so
    the same lookup serves PAN-OS and FortiOS, which write literals.
    """

    objects: dict[str, str] = field(default_factory=dict)
    interface_addresses: set[int] = field(default_factory=set)

    def resolve(self, token: str) -> IntervalSet | None:
        """The addresses a token stands for, or None if nothing here defines it."""
        literal = _parse_literal(token)
        if literal is not None:
            return literal

        value = self.objects.get(token)
        if value is None:
            return None
        return _parse_literal(value)


def _parse_literal(token: str) -> IntervalSet | None:
    # A token that is not an address is the normal case here — most NAT rules name
    # objects — so this returns None rather than raising. Narrow on purpose: an
    # unexpected failure inside the parser should surface, not be read as "not a
    # literal" and quietly turn into an unresolvable name.
    try:
        v4, _v6 = parse_address(token.strip())
    except (ValueError, TypeError):
        return None
    return v4 if v4.size else None


def _single_address(token: str, resolver: _Resolver) -> int | None:
    """The one address a translation target names, or None if it is not exactly one.

    A translation has to produce a single address to be followable. A rule translating
    to a range is a pool, and which address a given session gets is not something a
    stored configuration can answer.
    """
    resolved = resolver.resolve(token)
    if resolved is None or resolved.size != 1:
        return None
    return resolved.intervals[0][0]


def _object_index(firewall: dict[str, Any]) -> dict[str, str]:
    """Object name → its value, flattened from the firewall block.

    Groups are deliberately not expanded. A NAT rule translating to a group is not
    followable anyway — it names more than one address — so the only thing expansion
    would change is turning "could not resolve" into "resolved to a pool", and both
    stop the translation.
    """
    index: dict[str, str] = {}
    for key in ("address_objects", "service_objects"):
        for entry in firewall.get(key) or []:
            if isinstance(entry, dict):
                name, value = entry.get("name"), entry.get("value")
                if isinstance(name, str) and isinstance(value, str):
                    index[name] = value
    return index


def _matches(tokens: list[str], address: int, resolver: _Resolver) -> bool | None:
    """Whether `address` is in the set these tokens name.

    An empty token list is "any" and matches everything, which is how every platform
    treats an omitted match condition. None means at least one token could not be
    resolved, so the answer is unknown — never False, which would silently skip a rule
    that may well apply.
    """
    if not tokens:
        return True

    unresolved = False
    for token in tokens:
        resolved = resolver.resolve(token)
        if resolved is None:
            unresolved = True
            continue
        if resolved.covers_value(address):
            return True
    return None if unresolved else False


def translate(
    firewall: dict[str, Any],
    *,
    source: int,
    destination: int,
    port: int,
    interface_addresses: set[int] | None = None,
) -> Translation:
    """Apply this device's NAT to a packet, first matching rule wins.

    Returns `NO_TRANSLATION` when no rule matches, which is the common case and says
    nothing about the packet. A rule that matches but cannot be followed returns a
    Translation carrying `reason`, and the caller is expected to surface it: the walk
    continues from an address that may be wrong, and every verdict after that hop
    inherits the doubt.
    """
    rules = firewall.get("nat_rules")
    if not isinstance(rules, list) or not rules:
        return NO_TRANSLATION

    resolver = _Resolver(
        objects=_object_index(firewall),
        interface_addresses=interface_addresses or set(),
    )

    for raw in rules:
        if not isinstance(raw, dict):
            continue

        original_source = _strings(raw.get("original_source"))
        original_destination = _strings(raw.get("original_destination"))
        translated_source = _strings(raw.get("translated_source"))
        translated_destination = _strings(raw.get("translated_destination"))
        unreadable = raw.get("translation_unreadable")

        # A rule that translates nothing this can follow, and was not flagged, is a
        # rule from a parser that has not been normalised. Skipping it is right: it
        # carries no normalised fields at all, so there is nothing to match on.
        if not (translated_source or translated_destination or unreadable):
            continue

        src_hit = _matches(original_source, source, resolver)
        dst_hit = _matches(original_destination, destination, resolver)

        if src_hit is False or dst_hit is False:
            continue

        name = raw.get("name") or raw.get("raw") or f"NAT rule {raw.get('order', '?')}"

        if src_hit is None or dst_hit is None:
            # The rule may apply and nothing here can tell. Stopping is the honest
            # outcome: continuing past it would compute the rest of the path from an
            # address this may have been about to change.
            return Translation(
                applied=False,
                rule_name=str(name),
                reason=(
                    f"{name} matches on object names this snapshot does not define, so "
                    "whether it applies to this packet could not be determined"
                ),
            )

        if unreadable:
            return Translation(
                applied=False,
                rule_name=str(name),
                reason=f"{name} applies, and {unreadable}",
            )

        new_destination = destination
        new_source = source
        new_port = port
        changes: list[str] = []

        if translated_destination:
            resolved = _single_address(translated_destination[0], resolver)
            if resolved is None:
                return Translation(
                    applied=False,
                    rule_name=str(name),
                    reason=(
                        f"{name} translates the destination to "
                        f"{translated_destination[0]}, which is not a single address "
                        "this can follow"
                    ),
                )
            changes.append(f"destination {_render(destination)} → {_render(resolved)}")
            new_destination = resolved

        if translated_source:
            resolved = _single_address(translated_source[0], resolver)
            if resolved is None:
                return Translation(
                    applied=False,
                    rule_name=str(name),
                    reason=(
                        f"{name} translates the source to {translated_source[0]}, "
                        "which is not a single address this can follow"
                    ),
                )
            changes.append(f"source {_render(source)} → {_render(resolved)}")
            new_source = resolved

        translated_port = raw.get("translated_port")
        if isinstance(translated_port, int) and translated_port != port:
            changes.append(f"port {port} → {translated_port}")
            new_port = translated_port

        if not changes:
            continue

        return Translation(
            applied=True,
            rule_name=str(name),
            destination=new_destination,
            source=new_source,
            port=new_port,
            detail=", ".join(changes),
        )

    return NO_TRANSLATION


def touches(firewall: dict[str, Any], addresses: IntervalSet) -> bool:
    """Whether any NAT rule here matches on an address inside this set.

    Asked when the query names a *range*, where following a translation is refused —
    the range still has to be told that NAT applies somewhere inside it, and probing
    one representative address would miss every rule matching any of the others.

    An unreadable rule counts as touching: it may well be about this range, and
    treating "could not read it" as "does not apply" is the silent failure.
    """
    rules = firewall.get("nat_rules")
    if not isinstance(rules, list):
        return False

    resolver = _Resolver(objects=_object_index(firewall))
    for raw in rules:
        if not isinstance(raw, dict):
            continue
        if not (
            raw.get("translated_source")
            or raw.get("translated_destination")
            or raw.get("translation_unreadable")
        ):
            continue

        tokens = _strings(raw.get("original_destination"))
        if not tokens:
            # Matches any destination, so it certainly touches this range.
            return True
        for token in tokens:
            resolved = resolver.resolve(token)
            if resolved is None or resolved.intersects(addresses):
                return True
    return False


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item.strip()]


def _render(address: int) -> str:
    return str(ipaddress.IPv4Address(address))


__all__ = ["NO_TRANSLATION", "Translation", "touches", "translate"]
