"""What discovery is allowed to look at (FR-DISC-01).

    Users SHALL be able to define discovery scopes as IP ranges/CIDRs/lists with
    exclusions.

Straightforward until you consider what a typo does. `10.0.0.0/8` is one character away
from `10.0.0.0/18` and sixteen million addresses away from what the operator meant. A
scope that quietly expands to sixteen million probes against a customer's production
network is the single worst thing this package could do â€” worse than a missed device,
because it is active, it is attributable, and it does not stop when someone notices.

So three properties hold here, and none is optional:

**A ceiling, checked before enumeration.** :data:`MAX_SCOPE_HOSTS` is counted from the
network sizes without expanding anything, so an over-large scope is refused in constant
time rather than by running out of memory somewhere inside a generator.

**Exclusions are subtracted, not filtered.** Excluding `10.0.5.0/24` from `10.0.0.0/16`
removes it from the address space before anything iterates, so an excluded host is never
enumerated, never counted against the ceiling, and cannot be reached by an off-by-one in
a later loop. Filtering at probe time would leave the excluded addresses one missing
`continue` away from being contacted.

**Enumeration is lazy.** :meth:`Scope.hosts` yields. A /16 inside the ceiling is 65,534
addresses; materialising that as a list before the first probe delays the run and buys
nothing.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Final

from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.discovery.probes import DEFAULT_TCP_PORTS, normalise_ports

log = get_logger(__name__)

IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

#: The most addresses one scope may cover.
#:
#: 65,536 is a /16, which is the largest block anyone plausibly runs a flat management
#: network on. Above that the operator is either scanning the estate â€” which this is not
#: for â€” or has mistyped a prefix length. Both deserve a refusal rather than a best
#: effort, and the error says which of the two it thinks happened.
MAX_SCOPE_HOSTS: Final[int] = 65_536


def parse_target(text: str) -> list[IpNetwork]:
    """Read one scope entry: a CIDR, a hyphenated range, or a single address.

    Returns networks rather than addresses so that exclusion can be done as set
    arithmetic. A hyphenated range like `10.0.0.10-10.0.0.20` becomes the minimal set of
    CIDRs covering it, which is what makes `address_exclude` able to subtract from it.
    """
    entry = (text or "").strip()
    if not entry:
        raise ValidationProblem("A discovery target cannot be blank.")

    if "-" in entry:
        start_text, _, end_text = entry.partition("-")
        try:
            start = ipaddress.ip_address(start_text.strip())
            end = ipaddress.ip_address(end_text.strip())
        except ValueError:
            raise ValidationProblem(
                f"'{entry}' is not a valid address range. Use `10.0.0.10-10.0.0.20`."
            ) from None
        if start.version != end.version:
            raise ValidationProblem(f"'{entry}' mixes IPv4 and IPv6.")
        if int(end) < int(start):
            raise ValidationProblem(f"'{entry}' ends before it begins.")
        return list(ipaddress.summarize_address_range(start, end))

    try:
        # strict=False so `10.0.0.5/24` is read as the /24 containing it rather than
        # rejected. Operators write that constantly and mean the network.
        return [ipaddress.ip_network(entry, strict=False)]
    except ValueError:
        raise ValidationProblem(f"'{entry}' is not an IP address, CIDR block or range.") from None


@dataclass(slots=True)
class Scope:
    """One discovery scope: what to probe, what to leave alone, and how.

    Built through :func:`build_scope`, which is where validation happens. Constructing
    one directly skips the ceiling check.
    """

    name: str
    networks: list[IpNetwork] = field(default_factory=list)
    exclusions: list[IpNetwork] = field(default_factory=list)
    tcp_ports: tuple[int, ...] = DEFAULT_TCP_PORTS
    snmp_configured: bool = False
    #: FR-DISC-04: a scope may be trusted to onboard what it finds, but only if someone
    #: says so. The default is a review queue.
    auto_onboard: bool = False

    @property
    def included(self) -> list[IpNetwork]:
        """The networks that remain once exclusions are subtracted.

        Computed rather than stored: the subtraction is the security-relevant step and
        recomputing it costs nothing next to the probing it gates.
        """
        remaining: list[IpNetwork] = list(self.networks)

        for excluded in self.exclusions:
            next_round: list[IpNetwork] = []
            for network in remaining:
                if not _overlaps(network, excluded):
                    next_round.append(network)
                    continue
                if _contains(excluded, network):
                    # The exclusion swallows this network whole; nothing survives.
                    continue
                next_round.extend(_subtract(network, excluded))
            remaining = next_round

        return sorted(remaining, key=lambda net: (net.version, int(net.network_address)))

    @property
    def size(self) -> int:
        """How many addresses this scope covers, without enumerating any of them."""
        return sum(_usable(network) for network in self.included)

    def hosts(self) -> Iterator[IpAddress]:
        """Every address in the scope, lazily, exclusions already removed."""
        for network in self.included:
            # A /31 and /32 have no "hosts" by `hosts()`'s definition, but a /32 is
            # exactly how an operator names one device, so it is yielded explicitly.
            if network.prefixlen == network.max_prefixlen:
                yield network.network_address
                continue
            yield from network.hosts()

    def covers(self, address: str | IpAddress) -> bool:
        """Whether an address is in scope. Exclusions win."""
        parsed = ipaddress.ip_address(address) if isinstance(address, str) else address
        return any(parsed in network for network in self.included)


def build_scope(
    name: str,
    targets: Sequence[str],
    *,
    exclusions: Sequence[str] = (),
    tcp_ports: Sequence[int] | None = None,
    snmp_configured: bool = False,
    auto_onboard: bool = False,
    max_hosts: int = MAX_SCOPE_HOSTS,
) -> Scope:
    """Validate and assemble a scope (FR-DISC-01).

    The ceiling is checked here, after exclusions are applied, so that a legitimately
    large block with most of it excluded is allowed â€” `10.0.0.0/8` minus everything but
    a /24 is 254 addresses and there is no reason to refuse it.
    """
    if not targets:
        raise ValidationProblem("A discovery scope needs at least one target.")

    networks: list[IpNetwork] = []
    for entry in targets:
        networks.extend(parse_target(entry))

    excluded: list[IpNetwork] = []
    for entry in exclusions:
        excluded.extend(parse_target(entry))

    scope = Scope(
        name=name,
        networks=networks,
        exclusions=excluded,
        tcp_ports=normalise_ports(tuple(tcp_ports) if tcp_ports is not None else None),
        snmp_configured=snmp_configured,
        auto_onboard=auto_onboard,
    )

    size = scope.size
    if size > max_hosts:
        raise ValidationProblem(
            f"Scope '{name}' covers {size:,} addresses, over the {max_hosts:,} limit. "
            "Discovery sends probes to every address in scope, so this is usually a "
            "mistyped prefix length â€” check the CIDR, or narrow it with exclusions."
        )
    if size == 0:
        # Not an error worth raising, but worth saying: a scope whose exclusions cancel
        # its targets will run, find nothing, and look like an estate with no devices.
        log.warning("discovery.scope_empty", scope=name)

    log.info("discovery.scope_built", scope=name, addresses=size, ports=len(scope.tcp_ports))
    return scope


# A v4 and a v6 network never overlap and neither contains the other, and the stdlib
# raises rather than saying so. Each helper below checks the family first and returns a
# plain False across families, which is what every caller wants — a scope holding both
# families is ordinary, not an error. The isinstance pairs, rather than a `.version`
# comparison, are also what lets the type checker narrow the union, so these need no
# suppressions to type-check.


def _overlaps(left: IpNetwork, right: IpNetwork) -> bool:
    if isinstance(left, ipaddress.IPv4Network) and isinstance(right, ipaddress.IPv4Network):
        return left.overlaps(right)
    if isinstance(left, ipaddress.IPv6Network) and isinstance(right, ipaddress.IPv6Network):
        return left.overlaps(right)
    return False


def _contains(outer: IpNetwork, inner: IpNetwork) -> bool:
    if isinstance(outer, ipaddress.IPv4Network) and isinstance(inner, ipaddress.IPv4Network):
        return outer.supernet_of(inner)
    if isinstance(outer, ipaddress.IPv6Network) and isinstance(inner, ipaddress.IPv6Network):
        return outer.supernet_of(inner)
    return False


def _subtract(network: IpNetwork, excluded: IpNetwork) -> list[IpNetwork]:
    """`network` minus `excluded`, as the minimal set of covering networks."""
    if isinstance(network, ipaddress.IPv4Network) and isinstance(excluded, ipaddress.IPv4Network):
        return list(network.address_exclude(excluded))
    if isinstance(network, ipaddress.IPv6Network) and isinstance(excluded, ipaddress.IPv6Network):
        return list(network.address_exclude(excluded))
    return [network]


def _usable(network: IpNetwork) -> int:
    """Addresses a probe would actually be sent to.

    A /31 is a point-to-point link with two usable addresses and a /32 is one host;
    anything larger loses its network and broadcast addresses. Counting those would make
    the ceiling reject scopes marginally smaller than it claims to.
    """
    if network.prefixlen >= network.max_prefixlen - 1:
        return int(network.num_addresses)
    return int(network.num_addresses) - 2


__all__ = [
    "MAX_SCOPE_HOSTS",
    "Scope",
    "build_scope",
    "parse_target",
]
