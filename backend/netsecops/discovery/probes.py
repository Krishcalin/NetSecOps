"""What discovery may send to a host (FR-DISC-02, SRS §1.2).

FR-DISC-02 is an allow-list written as a requirement:

    Discovery SHALL perform only: ICMP echo, TCP connect to 22/443 (configurable
    list), SSH banner grab, HTTPS server certificate & header retrieval, and
    optional SNMP sysDescr/sysObjectID GET. No port sweeps beyond the configured
    list; no service exploitation.

This module is that sentence, enforced. It is deliberately built the same way as
:mod:`netsecops.adapters.readonly`: a guard that runs *before* anything reaches the
wire, with no path around it, because a promise about what NetSecOps does not send is
worth exactly what its enforcement is worth.

**Why a guard rather than a code review.** The probe types are few and obvious today. The
pressure that breaks this is incremental: a UDP probe to identify a printer, a second TCP
port because one customer runs SSH on 2222, a banner grab that reads "just a little
further" to disambiguate two platforms. Each is individually reasonable and the sum is a
port scanner. A guard makes each of those a deliberate edit to an allow-list with a test
attached, rather than a line in a pull request nobody reads as a policy change.

**What the guard cannot see.** It authorises a probe; it does not send one. A caller
that opens its own socket bypasses everything here, which is why the transport is
expected to take an authorised probe rather than a host and port — the same reason
adapters hold a guarded session rather than a transport.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger

log = get_logger(__name__)


class ProbeViolationError(ValidationProblem):
    """A probe was requested that FR-DISC-02 does not permit.

    Raised, never returned as a flag. This is the discovery equivalent of
    :class:`~netsecops.core.errors.ReadOnlyViolationError`: it means the platform tried
    to do something it guarantees it does not do, so it aborts the run rather than
    skipping the host and carrying on quietly.
    """


class ProbeKind(StrEnum):
    """The complete set of things discovery may do to a host.

    Adding a member here is a change to what the product sends to customer networks. It
    needs an SRS amendment, not a commit — ``test_discovery_probes.py`` asserts this
    enum's exact contents so that adding one without noticing is impossible.
    """

    #: A single ICMP echo request.
    ICMP_ECHO = "icmp_echo"
    #: A TCP connect to a port on the configured list. Connect only — the handshake
    #: completes and the socket closes.
    TCP_CONNECT = "tcp_connect"
    #: Read the SSH identification string the server volunteers on connect. No
    #: authentication is attempted and no key exchange is begun.
    SSH_BANNER = "ssh_banner"
    #: TLS handshake to retrieve the server certificate and response headers. No
    #: credentials, no request body beyond a HEAD.
    HTTPS_CERTIFICATE = "https_certificate"
    #: SNMP GET of sysDescr and sysObjectID only, and only where a community or v3
    #: credential was configured for the scope. Never SET (SRS §8).
    SNMP_SYSDESCR = "snmp_sysdescr"


#: The default TCP ports FR-DISC-02 names. Configurable per scope, within `PORT_CEILING`.
DEFAULT_TCP_PORTS: Final[tuple[int, ...]] = (22, 443)

#: The most TCP ports a scope may name.
#:
#: FR-DISC-02 says "no port sweeps beyond the configured list", which constrains what is
#: probed but not how long the list may be — a scope naming a thousand ports honours the
#: letter of the requirement and violates its intent, since the result is a port scan
#: assembled out of individually-permitted probes. Eight is comfortably more than the two
#: the requirement names and nowhere near enough to sweep with.
PORT_CEILING: Final[int] = 8

#: The only OIDs the SNMP probe may request (FR-DISC-02).
#:
#: sysDescr and sysObjectID identify a device. Everything else in the MIB is inventory
#: or telemetry, which is collection's job and requires an onboarded device with
#: approved credentials — not a probe against a host nobody has agreed to assess yet.
PERMITTED_OIDS: Final[tuple[str, ...]] = (
    "1.3.6.1.2.1.1.1.0",  # sysDescr.0
    "1.3.6.1.2.1.1.2.0",  # sysObjectID.0
)

#: How many bytes the SSH banner probe may read.
#:
#: An SSH identification string is at most 255 bytes by RFC 4253. Reading further would
#: begin consuming the key-exchange packet, which is no longer "the banner the server
#: volunteered" and starts to look like protocol interaction.
SSH_BANNER_LIMIT: Final[int] = 255


@dataclass(frozen=True, slots=True)
class Probe:
    """One authorised probe against one host.

    Construction does not authorise: :func:`authorise` does, and it returns this. The
    transport takes a ``Probe``, so there is no signature by which a caller can ask it
    to contact a host the guard never saw.
    """

    kind: ProbeKind
    host: str
    port: int | None = None
    oids: tuple[str, ...] = field(default_factory=tuple)

    def describe(self) -> str:
        """For the audit record. Every probe is logged (FR-AUD-01)."""
        target = f"{self.host}:{self.port}" if self.port else self.host
        return f"{self.kind.value} {target}"


def normalise_ports(ports: tuple[int, ...] | list[int] | None) -> tuple[int, ...]:
    """Validate a scope's TCP port list.

    Rejects rather than truncates. A scope that named nine ports meant to probe nine,
    and silently probing the first eight would leave the operator believing a host was
    checked on a port it never was.
    """
    if ports is None:
        return DEFAULT_TCP_PORTS

    unique = tuple(sorted(set(ports)))
    if not unique:
        return DEFAULT_TCP_PORTS

    for port in unique:
        if not 1 <= port <= 65535:
            raise ProbeViolationError(f"{port} is not a TCP port number.")

    if len(unique) > PORT_CEILING:
        raise ProbeViolationError(
            f"A discovery scope may name at most {PORT_CEILING} TCP ports; this one names "
            f"{len(unique)}. Discovery performs reachability checks, not port sweeps "
            "(FR-DISC-02) — a list this long is a scan assembled out of permitted probes."
        )

    return unique


def authorise(
    kind: ProbeKind | str,
    host: str,
    *,
    port: int | None = None,
    allowed_ports: tuple[int, ...] = DEFAULT_TCP_PORTS,
    snmp_configured: bool = False,
    oids: tuple[str, ...] | None = None,
) -> Probe:
    """Authorise one probe, or raise.

    Every argument is checked against FR-DISC-02 rather than trusted, including the
    ones a caller "obviously" got right: the guard's value is that it holds when the
    caller is wrong.
    """
    try:
        probe_kind = ProbeKind(kind)
    except ValueError:
        raise ProbeViolationError(
            f"'{kind}' is not a discovery probe. Permitted: "
            f"{', '.join(sorted(k.value for k in ProbeKind))} (FR-DISC-02)."
        ) from None

    address = _valid_host(host)

    if probe_kind in (ProbeKind.ICMP_ECHO,):
        if port is not None:
            raise ProbeViolationError("An ICMP echo has no port.")
        return Probe(kind=probe_kind, host=address)

    if probe_kind is ProbeKind.SNMP_SYSDESCR:
        if not snmp_configured:
            # FR-DISC-02 calls SNMP "optional": it runs only where the operator supplied
            # a community or v3 credential for the scope. Probing without one would be
            # guessing at `public`, which is a credential attempt, not a probe.
            raise ProbeViolationError(
                "SNMP discovery needs a credential configured on the scope. NetSecOps "
                "does not try default communities (SRS §1.2: no brute-forcing)."
            )
        requested = tuple(oids) if oids else PERMITTED_OIDS
        for oid in requested:
            if oid not in PERMITTED_OIDS:
                raise ProbeViolationError(
                    f"SNMP discovery may read only sysDescr and sysObjectID; '{oid}' is "
                    "neither (FR-DISC-02)."
                )
        return Probe(kind=probe_kind, host=address, port=161, oids=requested)

    # Everything remaining is TCP and needs a port from the scope's list.
    if port is None:
        raise ProbeViolationError(f"{probe_kind.value} needs a TCP port.")
    if port not in allowed_ports:
        raise ProbeViolationError(
            f"Port {port} is not on this scope's list ({', '.join(map(str, allowed_ports))}). "
            "Discovery probes only the configured ports — anything else is a sweep "
            "(FR-DISC-02)."
        )

    return Probe(kind=probe_kind, host=address, port=port)


def _valid_host(host: str) -> str:
    """A probe target must be one literal address.

    Hostnames are refused on purpose. A name resolves at send time to something the
    guard never inspected, and an operator reading the audit log needs to see the
    address that was actually contacted rather than the label it was contacted by.
    """
    text = (host or "").strip()
    if not text:
        raise ProbeViolationError("A probe needs a target address.")

    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        raise ProbeViolationError(
            f"'{text}' is not an IP address. Discovery probes literal addresses so that "
            "what was contacted is what was authorised."
        ) from None

    return str(parsed)


__all__ = [
    "DEFAULT_TCP_PORTS",
    "PERMITTED_OIDS",
    "PORT_CEILING",
    "SSH_BANNER_LIMIT",
    "Probe",
    "ProbeKind",
    "ProbeViolationError",
    "authorise",
    "normalise_ports",
]
