"""Cisco ACE parsing, shared by the IOS and NX-OS parsers (FR-PARSE-02, FR-FW-01).

An IOS or NX-OS access list *is* the device's security policy, and until this existed
neither reached the rulebase analysis: `_parse_acls` recorded the action, a `log` flag
and the raw line, and nothing else. The Al-Shaer relationship analysis, the per-rule
hygiene checks and the NAT join all ran on four platforms and were blind to the two that
make up a third of the check library.

**The wildcard mask is the hazard this module exists to contain.** IOS writes
`10.1.1.0 0.0.0.255`, and the second token is an *inverted* netmask — a /24. Reading it
as a netmask gives 10.1.1.0/8, and reading it as an address gives nonsense. Both produce
a rule whose scope is wrong by orders of magnitude and whose analysis is silently
confident. So the conversion is explicit, and it refuses the case it cannot express:

**Discontiguous masks are refused, never approximated.** `0.0.0.254` matches every even
final octet, which no CIDR prefix can describe. Rather than round it to something that
looks similar, the address is returned as unresolvable, the rule is flagged, and the
analysis excludes it — the same path the resolver already uses for an object the
collection never captured. An approximate rulebase produces exact-looking findings.

NX-OS mostly writes prefixes (`10.1.1.0/24`), which need no conversion; both dialects
share everything else, which is why this is one module rather than two.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from ciscoconfparse2 import CiscoConfParse

from netsecops.ncm.models import AclBinding, NormalisedConfig

#: Port names IOS and NX-OS accept in place of a number. Not exhaustive by design: an
#: unrecognised name is refused rather than guessed, because guessing a port number
#: silently changes which traffic a rule is understood to permit.
PORT_NAMES: dict[str, int] = {
    "ftp-data": 20,
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "time": 37,
    "nameserver": 42,
    "whois": 43,
    "tacacs": 49,
    "domain": 53,
    "bootps": 67,
    "bootpc": 68,
    "tftp": 69,
    "gopher": 70,
    "finger": 79,
    "www": 80,
    "http": 80,
    "kerberos": 88,
    "pop2": 109,
    "pop3": 110,
    "sunrpc": 111,
    "ident": 113,
    "nntp": 119,
    "ntp": 123,
    "netbios-ns": 137,
    "netbios-dgm": 138,
    "netbios-ss": 139,
    "snmp": 161,
    "snmptrap": 162,
    "bgp": 179,
    "irc": 194,
    "ldap": 389,
    "https": 443,
    "microsoft-ds": 445,
    "isakmp": 500,
    "exec": 512,
    "biff": 512,
    "login": 513,
    "who": 513,
    "cmd": 514,
    "syslog": 514,
    "lpd": 515,
    "talk": 517,
    "rip": 520,
    "uucp": 540,
    "klogin": 543,
    "kshell": 544,
    "ldaps": 636,
    "ldp": 646,
    "msdp": 639,
    "rsync": 873,
    "pim-auto-rp": 496,
    "mysql": 3306,
    "rdp": 3389,
    "nfs": 2049,
    "sqlnet": 1521,
    "drip": 3949,
    "pcanywhere-status": 5632,
    "pcanywhere-data": 5631,
    "citrix-ica": 1494,
}

#: Tokens that end the address/port grammar and carry no addressing meaning of their own.
#: `established` and the TCP flag words narrow *which* packets match without narrowing
#: the address or port space, so they are recorded and then ignored for scope purposes —
#: treating the rule as covering the whole port range can only over-report an overlap,
#: never hide one.
TRAILING_FLAGS = frozenset(
    {
        "log",
        "log-input",
        "established",
        "fragments",
        "dscp",
        "precedence",
        "tos",
        "time-range",
        "reflect",
        "evaluate",
        "ttl",
        "option",
        "packet-length",
        "urg",
        "ack",
        "psh",
        "rst",
        "syn",
        "fin",
        "match-all",
        "match-any",
    }
)

#: The port comparison operators. `neq` is deliberately absent — see `read_ports`.
PORT_OPERATORS = frozenset({"eq", "lt", "gt", "range", "neq"})

#: Sentinel emitted where a token was understood to exist but could not be expressed.
#: It resolves to nothing, lands in the rule's `unresolved` list and takes the rule out
#: of overlap analysis with a Medium finding — the existing path for "we saw something
#: here and could not read it", which is the honest outcome.
UNREADABLE = "cisco-acl-unreadable"


@dataclass(slots=True)
class ParsedAce:
    """One access-list entry, normalised to the shapes the resolver understands."""

    action: str
    protocol: str
    source: str
    destination: str
    services: list[str] = field(default_factory=list)
    log: bool = False
    sequence: int | None = None
    #: Flag words seen after the addressing, kept so a rule can explain itself.
    flags: list[str] = field(default_factory=list)
    #: True when some part of the entry could not be expressed and the rule must not be
    #: treated as fully understood.
    partial: bool = False


def wildcard_to_cidr(address: str, wildcard: str) -> str | None:
    """`10.1.1.0 0.0.0.255` → `10.1.1.0/24`, or None if it cannot be expressed.

    Returns None for a discontiguous mask such as `0.0.0.254`. That is not a parse
    failure to be worked around — no CIDR prefix describes "every even address", and any
    value returned here would be a different rule from the one on the device.
    """
    try:
        host = ipaddress.IPv4Address(address)
        mask = ipaddress.IPv4Address(wildcard)
    except ipaddress.AddressValueError:
        return None

    # A wildcard is the bitwise complement of a netmask, so invert and let ipaddress
    # decide whether the result is a legal prefix. It rejects discontiguous masks, which
    # is precisely the check wanted here.
    netmask = int(mask) ^ 0xFFFFFFFF
    try:
        network = ipaddress.IPv4Network(
            (int(host), str(ipaddress.IPv4Address(netmask))), strict=False
        )
    except (ValueError, ipaddress.NetmaskValueError):
        return None

    return str(network)


def _read_address(tokens: list[str], index: int) -> tuple[str, int]:
    """Consume one address specification, returning the token and the next index.

    The forms differ in width — `any` is one token, `host X` two, `X W.W.W.W` two,
    `object-group G` two — and getting the width wrong shifts everything after it, so
    the destination silently becomes a port operator and the rule is read as a different
    rule entirely. Each form is therefore matched explicitly rather than by counting.
    """
    if index >= len(tokens):
        return UNREADABLE, index

    word = tokens[index]

    if word == "any":
        return "any", index + 1

    if word == "host" and index + 1 < len(tokens):
        return tokens[index + 1], index + 2

    if word in {"object-group", "addrgroup", "group-object"} and index + 1 < len(tokens):
        # Resolved by name against the NCM's address groups, exactly as a PAN-OS or
        # FortiOS object is. Unknown names land in `unresolved` on their own.
        return tokens[index + 1], index + 2

    if "/" in word:
        # NX-OS prefix form, already what the resolver wants.
        return word, index + 1

    # `A.B.C.D W.W.W.W` — the wildcard form, and the reason this module exists.
    if index + 1 < len(tokens) and _is_ipv4(word) and _is_ipv4(tokens[index + 1]):
        cidr = wildcard_to_cidr(word, tokens[index + 1])
        return (cidr or UNREADABLE), index + 2

    if _is_ipv4(word):
        # A bare address with no mask is a host on both platforms.
        return word, index + 1

    return UNREADABLE, index + 1


def _is_ipv4(word: str) -> bool:
    try:
        ipaddress.IPv4Address(word)
    except ipaddress.AddressValueError:
        return False
    return True


def _port_number(word: str) -> int | None:
    if word.isdigit():
        value = int(word)
        return value if 0 <= value <= 65535 else None
    return PORT_NAMES.get(word)


def read_ports(tokens: list[str], index: int, protocol: str) -> tuple[list[str], int, bool]:
    """Consume a port operator if one is present.

    Returns the service tokens, the next index, and whether anything was refused.

    `neq` is refused rather than expressed. "Every port except 22" is representable as
    an interval set, but not as the `tcp/…` literal this emits, and writing `tcp/1-21`
    plus `tcp/23-65535` would make the rule *look* precise while quietly dropping the
    distinction between a rule that names two ranges and one that excludes a port. The
    rule is marked partial instead, which excludes it from overlap analysis.
    """
    if index >= len(tokens) or tokens[index] not in PORT_OPERATORS:
        return [], index, False

    operator = tokens[index]
    cursor = index + 1

    if operator == "range":
        if cursor + 1 >= len(tokens):
            return [], cursor, True
        low, high = _port_number(tokens[cursor]), _port_number(tokens[cursor + 1])
        if low is None or high is None or low > high:
            return [], cursor + 2, True
        return [f"{protocol}/{low}-{high}"], cursor + 2, False

    if operator == "neq":
        # Consume the operand so the destination is not misread as a port, then refuse.
        return [], cursor + 1, True

    if operator in {"lt", "gt"}:
        if cursor >= len(tokens):
            return [], cursor, True
        value = _port_number(tokens[cursor])
        cursor += 1
        if value is None:
            return [], cursor, True
        # `lt 1` and `gt 65535` name an empty port space. That is a rule matching
        # nothing, which is a real thing to write by mistake — but it is not something
        # this can express as a range, so it is refused rather than widened to `any`.
        if operator == "lt":
            return (
                ([f"{protocol}/1-{value - 1}"], cursor, False) if value > 1 else ([], cursor, True)
            )
        return (
            ([f"{protocol}/{value + 1}-65535"], cursor, False)
            if value < 65535
            else ([], cursor, True)
        )

    # `eq` accepts several ports on one line: `eq www 443 8080`.
    ports: list[str] = []
    while cursor < len(tokens):
        value = _port_number(tokens[cursor])
        if value is None:
            break
        ports.append(f"{protocol}/{value}")
        cursor += 1

    return (ports, cursor, False) if ports else ([], cursor, True)


#: `10 permit tcp ...` — NX-OS and named IOS ACLs number their entries.
_SEQUENCE = re.compile(r"^(\d+)\s+(.*)$")


def parse_ace(text: str) -> ParsedAce | None:
    """Parse one access-list entry. Returns None for anything that is not one.

    Remarks, `ip access-list` headers and blank lines are not entries and yield None
    rather than a half-built rule.
    """
    stripped = text.strip()
    if not stripped:
        return None

    sequence: int | None = None
    if match := _SEQUENCE.match(stripped):
        sequence, stripped = int(match.group(1)), match.group(2)

    tokens = stripped.split()
    if not tokens or tokens[0] not in {"permit", "deny"}:
        return None

    action, cursor = tokens[0], 1
    partial = False

    # A standard ACL has no protocol and no destination: `permit 10.1.1.0 0.0.0.255`.
    # Detected by the token after the action not being a protocol word, which is what
    # separates the two grammars.
    protocol_token = tokens[cursor] if cursor < len(tokens) else ""
    standard = protocol_token in {"any", "host"} or _is_ipv4(protocol_token)

    if standard:
        source, cursor = _read_address(tokens, cursor)
        ace = ParsedAce(
            action=action,
            protocol="ip",
            source=source,
            destination="any",
            services=["any"],
            sequence=sequence,
        )
    else:
        protocol = protocol_token
        cursor += 1

        source, cursor = _read_address(tokens, cursor)
        source_ports, cursor, src_refused = read_ports(tokens, cursor, protocol)
        destination, cursor = _read_address(tokens, cursor)
        destination_ports, cursor, dst_refused = read_ports(tokens, cursor, protocol)
        partial = src_refused or dst_refused

        # Destination ports describe the service; a source port constrains the client
        # side and is not what "service" means in the normalised model. Recording it as
        # the service would make a rule permitting `udp any eq 53 any` look like a rule
        # to port 53 rather than one *from* it, inverting the direction of the finding.
        services = destination_ports or ([protocol] if protocol != "ip" else ["any"])
        if source_ports and not destination_ports:
            # Source-port-only rules exist and are rare. The port space cannot be stated
            # in the service field without lying about direction, so the rule keeps the
            # protocol and is marked partial.
            partial = True

        ace = ParsedAce(
            action=action,
            protocol=protocol,
            source=source,
            destination=destination,
            services=services,
            sequence=sequence,
        )

    ace.flags = [word for word in tokens[cursor:] if word in TRAILING_FLAGS]
    ace.log = any(flag.startswith("log") for flag in ace.flags)
    ace.partial = partial or UNREADABLE in {ace.source, ace.destination}
    return ace


def record_bindings(
    ncm: NormalisedConfig, applied: Mapping[str, list[AclBinding]], *, raw: Mapping[str, list[str]]
) -> None:
    """Attach ACL bindings to the ACLs, the rulebase index and the rules themselves.

    Three places, because three different consumers ask three different questions and
    none of them can see the others' data:

    * `Acl.bindings` — for anything reading the ACL as a configuration object.
    * `Firewall.rulebase_bindings` — for the path walk, which reads the firewall block
      and never sees `ncm.acls`. Without it the walk cannot tell which of a device's
      access lists governs a hop, and it was evaluating all of them as one ordered list:
      on a three-interface ASA the first list in the file decided every path.
    * `SecurityRule.applied` — the cheap question, "does this rule filter anything at
      all", asked before the expensive one. An access list bound to nothing is usually a
      vty or SNMP filter and still ends in `deny any`.
    """
    for acl in ncm.acls:
        if lines := raw.get(acl.name):
            acl.applied_to = lines
        if bindings := applied.get(acl.name):
            acl.bindings = list(bindings)

    ncm.firewall.rulebase_bindings = {name: list(items) for name, items in applied.items()}

    for rule in ncm.firewall.security_rules:
        if rule.rulebase is not None:
            rule.applied = rule.rulebase in applied


def interface_bindings(
    parse: CiscoConfParse, pattern: str
) -> tuple[dict[str, list[AclBinding]], dict[str, list[str]]]:
    """Read `ip access-group NAME {in|out}` from under each interface.

    The IOS and NX-OS shape: the binding lives inside the interface block, so the
    interface is the parent and the ACL name is in the child line. `pattern` differs
    only in that NX-OS also accepts `ip port access-group`.
    """
    applied: dict[str, list[AclBinding]] = {}
    raw: dict[str, list[str]] = {}
    compiled = re.compile(pattern)

    for obj in parse.find_objects(r"^interface\s"):
        name_match = re.match(r"^interface\s+(\S+)", obj.text)
        interface = name_match.group(1) if name_match else ""
        for child in obj.children:
            match = compiled.match(child.text)
            if not match:
                continue
            acl_name, direction = match.group(1), match.group(2)
            applied.setdefault(acl_name, []).append(
                AclBinding(interface=interface, direction=direction)
            )
            raw.setdefault(acl_name, []).append(f"{interface} {direction}")

    return applied, raw


__all__ = [
    "PORT_NAMES",
    "UNREADABLE",
    "ParsedAce",
    "interface_bindings",
    "parse_ace",
    "read_ports",
    "record_bindings",
    "wildcard_to_cidr",
]
