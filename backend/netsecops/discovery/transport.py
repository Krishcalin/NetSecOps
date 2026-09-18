"""Sending the probes FR-DISC-02 permits.

:mod:`netsecops.discovery.probes` decides what discovery *may* send and returns a
:class:`~netsecops.discovery.probes.Probe`. Nothing until now sent one: scopes, the
allow-list, the fingerprinter and the review queue were four parts with no wire between
them. This is the wire.

**The rule this module exists to keep.** A socket is opened here and nowhere else in
discovery, every socket call takes an already-authorised ``Probe``, and the only way to
obtain one is :func:`~netsecops.discovery.probes.authorise`. Combined with
:class:`HostProber` holding the pacer, that makes "every probe was permitted and paced"
a property of the call graph rather than of everyone's care.

**Each probe reads exactly as far as its name.** A TCP connect completes the handshake
and closes. A banner read stops at the newline or 255 bytes, whichever comes first, and
never sends a byte — which is what keeps it a banner grab rather than the beginning of
an SSH session. The HTTPS probe completes the handshake, takes the certificate, sends
one HEAD and reads headers only. None of them authenticates and none retries: a probe
that retries on refusal is knocking.

**Failure is information, not an error.** Almost every address in a scope will refuse or
time out, because that is what an unused address does. So these functions return what
happened rather than raising, and only a genuine programming fault — an unauthorised
probe reaching the wire — is allowed to escape. The one exception is
:class:`~netsecops.discovery.probes.ProbeViolationError`, which propagates on purpose:
it means the platform tried to send something it guarantees it does not send, and that
aborts the run rather than being counted as a host that did not answer.

**ICMP needs a capability the container may not have.** Raw and ping sockets both
require privileges Docker withholds by default (``CAP_NET_RAW``, or a
``net.ipv4.ping_group_range`` that includes the runtime user). When it is missing,
discovery does not pretend the hosts are down — it records that echo was unavailable and
falls back to TCP for liveness, which is the honest degradation. Silently treating "we
could not ask" as "nothing answered" would hand back an empty estate that reads exactly
like a quiet network.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import ssl
import struct
import warnings
from dataclasses import dataclass, field
from typing import Final

from netsecops.core.logging import get_logger
from netsecops.discovery.fingerprint import Evidence, Signal, read_text
from netsecops.discovery.pacing import HostPacer
from netsecops.discovery.probes import (
    SSH_BANNER_LIMIT,
    Probe,
    ProbeKind,
    authorise,
)

log = get_logger(__name__)

#: Per-probe timeout, in seconds.
#:
#: Short on purpose, and much shorter than a device session's. A scope is mostly unused
#: addresses; at a 15-second connect timeout a /24 of silence costs an hour of wall clock
#: whatever the rate limit says. Three seconds is beyond any management network's round
#: trip and cheap to spend on every dead address.
DEFAULT_PROBE_TIMEOUT: Final[float] = 3.0

#: The most header bytes the HTTPS probe reads.
#:
#: FR-DISC-02 permits "HTTPS server certificate & header retrieval". Headers, not bodies:
#: a login page can be megabytes and none of it is more identifying than the `Server:`
#: line. Eight kilobytes holds any realistic header block and bounds what an adversarial
#: host can make discovery allocate.
HTTP_HEADER_LIMIT: Final[int] = 8192

#: ICMP echo request, type 8 code 0 (RFC 792); the reply is type 0.
_ICMP_ECHO_REQUEST: Final[int] = 8
_ICMP_ECHO_REPLY: Final[int] = 0

#: Carried in the echo payload and checked in the reply, so a stray datagram from some
#: other pinger on the box is not read as this host answering.
_ICMP_MAGIC: Final[bytes] = b"netsecops-discovery"

#: Which read an open port earns.
#:
#: The follow-up is chosen by port rather than inferred from the connect, because the
#: alternative is to attempt both on everything: reading for a banner on 443 and speaking
#: TLS to 22 each cost a full timeout, on every responding host in the scope.
#:
#: Adding an entry here does **not** widen what discovery probes — the scope's port list
#: governs that, and :func:`~netsecops.discovery.probes.authorise` enforces it. It only
#: decides which of the permitted reads to attempt on a port that is already open and
#: already connected to. The alternates matter: an appliance whose web UI is on 8443 is
#: ordinary, and without an entry its certificate is never read, so the host is found and
#: never identified.
DEFAULT_FOLLOW_UP: Final[dict[int, ProbeKind]] = {
    22: ProbeKind.SSH_BANNER,
    2222: ProbeKind.SSH_BANNER,
    443: ProbeKind.HTTPS_CERTIFICATE,
    4443: ProbeKind.HTTPS_CERTIFICATE,
    8443: ProbeKind.HTTPS_CERTIFICATE,
}


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    """What one probe did."""

    probe: Probe
    responded: bool
    #: Whatever the host volunteered: a banner line, a certificate subject, a header
    #: block. Kept verbatim — the review queue shows a person the raw string, because
    #: "Cisco, 70%" is not something anybody can check.
    payload: str | None = None
    #: Why it did not respond, for the run log. Not shown per-address in the UI: a scope
    #: is mostly silence and "connection refused" ×250 is noise.
    detail: str | None = None


@dataclass(slots=True)
class HostResult:
    """Everything one address gave up, ready for the fingerprinter."""

    address: str
    responded: bool = False
    open_ports: tuple[int, ...] = ()
    evidence: list[Evidence] = field(default_factory=list)
    #: From the TLS certificate's common name, where it looks like a host name rather
    #: than a vendor's boilerplate. A guess, and labelled as one by being separate from
    #: the fingerprint's vendor and platform.
    hostname: str | None = None
    probes_sent: int = 0
    #: Non-fatal notes: echo unavailable, a TLS handshake that failed after connecting.
    notes: tuple[str, ...] = ()


class IcmpUnavailableError(RuntimeError):
    """The process may not open an ICMP socket.

    Not a probe failure and not fatal. Raised once by :func:`icmp_capability`, recorded
    on the run, and then ICMP is skipped for its duration.
    """


def icmp_capability() -> str | None:
    """Whether this process can send an echo request. ``None`` means it can.

    Checked once per run rather than per host: the answer cannot change mid-run, and
    finding out by failing 65,000 times would bury it.
    """
    for kind in (socket.SOCK_DGRAM, socket.SOCK_RAW):
        try:
            sock = socket.socket(socket.AF_INET, kind, socket.IPPROTO_ICMP)
        except (PermissionError, OSError):
            continue
        sock.close()
        return None

    return (
        "This process may not open an ICMP socket, so echo requests were not sent and "
        "liveness was decided by TCP connect alone. A device that is up but has none of "
        "the scope's TCP ports open will have been missed. Grant the container "
        "CAP_NET_RAW, or set net.ipv4.ping_group_range to include its user."
    )


def _checksum(payload: bytes) -> int:
    """The internet checksum (RFC 1071) over an ICMP message."""
    if len(payload) % 2:
        payload += b"\x00"
    total = 0
    for index in range(0, len(payload), 2):
        total += (payload[index] << 8) + payload[index + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_echo_request(identifier: int, sequence: int) -> bytes:
    """Assemble one ICMP echo request.

    Separated from the socket work so the encoding is testable without a capability CI
    does not have. The checksum is computed over a header with a zero checksum field and
    then written back into it, which is the step that is easy to get subtly wrong and
    impossible to notice: a bad checksum is silently dropped by the far end, so the
    symptom is an estate that appears empty.
    """
    header = struct.pack("!BBHHH", _ICMP_ECHO_REQUEST, 0, 0, identifier & 0xFFFF, sequence & 0xFFFF)
    payload = _ICMP_MAGIC
    checksum = _checksum(header + payload)
    header = struct.pack(
        "!BBHHH", _ICMP_ECHO_REQUEST, 0, checksum, identifier & 0xFFFF, sequence & 0xFFFF
    )
    return header + payload


def is_echo_reply(datagram: bytes) -> bool:
    """Whether a received datagram is a reply to one of ours.

    Handles both socket flavours. A ping socket (``SOCK_DGRAM``) hands over the ICMP
    message alone; a raw socket includes the IP header, whose length is the low nibble of
    the first byte in 32-bit words. Reading the type at a fixed offset would work on
    exactly one of the two and fail silently on the other.
    """
    if len(datagram) < 8:
        return False

    for body in _icmp_bodies(datagram):
        if len(body) < 8:
            continue
        if body[0] == _ICMP_ECHO_REPLY and _ICMP_MAGIC in body[8:]:
            return True
    return False


def _icmp_bodies(datagram: bytes) -> list[bytes]:
    """The candidate ICMP messages inside a datagram, raw-socket IP header or not."""
    candidates = [datagram]
    if datagram[0] >> 4 == 4:
        header_length = (datagram[0] & 0x0F) * 4
        if 20 <= header_length < len(datagram):
            candidates.append(datagram[header_length:])
    return candidates


async def send_icmp_echo(probe: Probe, *, timeout: float = DEFAULT_PROBE_TIMEOUT) -> ProbeOutcome:
    """One echo request, one reply, no retry (FR-DISC-02)."""
    if probe.kind is not ProbeKind.ICMP_ECHO:
        raise ValueError("send_icmp_echo was handed a probe of another kind.")

    loop = asyncio.get_running_loop()
    sock: socket.socket | None = None
    try:
        for kind in (socket.SOCK_DGRAM, socket.SOCK_RAW):
            with contextlib.suppress(PermissionError, OSError):
                sock = socket.socket(socket.AF_INET, kind, socket.IPPROTO_ICMP)
                break
        if sock is None:
            raise IcmpUnavailableError(probe.host)

        sock.setblocking(False)
        # Connected, so the kernel delivers only this peer's replies to this socket and
        # a concurrent probe of another address cannot be credited to this one.
        sock.connect((probe.host, 0))

        identifier = os.getpid() & 0xFFFF
        request = build_echo_request(identifier, sequence=1)

        async with asyncio.timeout(timeout):
            await loop.sock_sendall(sock, request)
            while True:
                datagram = await loop.sock_recv(sock, 1024)
                if is_echo_reply(datagram):
                    return ProbeOutcome(probe=probe, responded=True)

    except TimeoutError:
        return ProbeOutcome(probe=probe, responded=False, detail="No echo reply.")
    except IcmpUnavailableError:
        raise
    except OSError as exc:
        return ProbeOutcome(probe=probe, responded=False, detail=str(exc))
    finally:
        if sock is not None:
            sock.close()


async def send_tcp_connect(probe: Probe, *, timeout: float = DEFAULT_PROBE_TIMEOUT) -> ProbeOutcome:
    """Complete a TCP handshake and close it. Nothing is sent on the connection."""
    if probe.kind is not ProbeKind.TCP_CONNECT or probe.port is None:
        raise ValueError("send_tcp_connect was handed a probe of another kind.")

    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(probe.host, probe.port)
        await _close(writer)
        del reader
        return ProbeOutcome(probe=probe, responded=True)
    except TimeoutError:
        return ProbeOutcome(probe=probe, responded=False, detail="Connect timed out.")
    except OSError as exc:
        return ProbeOutcome(probe=probe, responded=False, detail=str(exc))


async def send_ssh_banner(probe: Probe, *, timeout: float = DEFAULT_PROBE_TIMEOUT) -> ProbeOutcome:
    """Read the identification string an SSH server volunteers on connect.

    Not a single byte is written. RFC 4253 has the server speak first, so the banner is
    obtainable without beginning a key exchange — which matters, because starting one
    would put this on the wrong side of the line between reading what a host announces
    and interacting with the service. It also means no authentication attempt appears in
    the device's log, so a discovery sweep does not read as a credential-stuffing run to
    whoever reviews it.
    """
    if probe.kind is not ProbeKind.SSH_BANNER or probe.port is None:
        raise ValueError("send_ssh_banner was handed a probe of another kind.")

    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(probe.host, probe.port)

        # The connect and the read are timed separately, and that is the whole point of
        # the split. A host that accepts the connection and then says nothing has still
        # answered — it is a device — and timing them together would discard the
        # successful connect along with the absent banner, reporting a live host as
        # silent. Plenty of hardened SSH services do exactly this.
        try:
            async with asyncio.timeout(timeout):
                # `readuntil` would raise once the limit is passed without giving back
                # what it read; a bounded read returns whatever arrived, which is what a
                # banner grab wants from a server that never sends a newline.
                raw = await reader.read(SSH_BANNER_LIMIT)
        except TimeoutError:
            return ProbeOutcome(
                probe=probe, responded=True, detail="Connected, but sent no banner."
            )

        banner = raw.decode("utf-8", errors="replace").strip()
        if not banner:
            return ProbeOutcome(probe=probe, responded=True, detail="Connected, no banner sent.")
        return ProbeOutcome(probe=probe, responded=True, payload=banner)

    except TimeoutError:
        return ProbeOutcome(probe=probe, responded=False, detail="Connect timed out.")
    except OSError as exc:
        return ProbeOutcome(probe=probe, responded=False, detail=str(exc))
    finally:
        if writer is not None:
            await _close(writer)


def _discovery_tls_context() -> ssl.SSLContext:
    """A context that completes a handshake with anything.

    Verification is off, and that is correct here rather than a shortcut. The probe's
    purpose is to read the certificate of a host nobody has identified yet; a management
    appliance ships a self-signed certificate for an address, and verifying it would fail
    on precisely the devices discovery exists to find. Nothing is sent over this
    connection but a HEAD, no credential crosses it, and nothing collected through it is
    trusted — it becomes weighted evidence for a human to review. Collection, which does
    carry credentials, verifies: see ``verify_device_tls``.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Appliances that have not been touched in a decade still answer TLS 1.0, and a
    # discovery probe that cannot talk to them reports them as absent — which is the
    # worst possible outcome, since an appliance nobody has touched in a decade is
    # exactly what an assessment needs to find. Python deprecates naming TLS 1.0 and the
    # warning is correct for a client carrying data; this connection carries a HEAD.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with contextlib.suppress(ValueError):
            context.minimum_version = ssl.TLSVersion.TLSv1
    with contextlib.suppress(ssl.SSLError, ValueError):
        context.set_ciphers("DEFAULT@SECLEVEL=1")
    return context


def _certificate_subject(ssl_object: ssl.SSLObject | None) -> tuple[str | None, str | None]:
    """The certificate's subject as text, and its common name.

    ``getpeercert()`` returns an empty dict whenever the peer was not verified, which is
    always here — so the parsed form is unavailable by construction and the DER has to be
    decoded instead. Missing that is how this probe ends up contributing no TLS signal
    ever, silently, with no error anywhere.
    """
    if ssl_object is None:
        return None, None

    der = ssl_object.getpeercert(binary_form=True)
    if not der:
        return None, None

    try:
        from cryptography import x509

        certificate = x509.load_der_x509_certificate(der)
        subject = certificate.subject.rfc4514_string()
        common_names = certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        common_name = str(common_names[0].value) if common_names else None
        # The issuer is worth as much as the subject on an appliance, whose certificate
        # is usually self-issued with the vendor's name in both.
        issuer = certificate.issuer.rfc4514_string()
        return f"{subject} (issuer: {issuer})", common_name
    except Exception as exc:
        # Broad on purpose. A certificate is attacker-influenced input from a host nobody
        # has identified, and every parse failure means the same thing here: no TLS
        # signal from this address. Letting one escape would turn an unparseable
        # certificate into a failed run.
        log.debug("discovery.certificate_unreadable", error=str(exc))
        return None, None


async def send_https_certificate(
    probe: Probe, *, timeout: float = DEFAULT_PROBE_TIMEOUT
) -> ProbeOutcome:
    """Retrieve the server certificate and response headers (FR-DISC-02).

    One HEAD, headers only, no body. HTTP/1.0 so the connection closes on its own rather
    than needing a keep-alive dance with a host whose behaviour is unknown.
    """
    if probe.kind is not ProbeKind.HTTPS_CERTIFICATE or probe.port is None:
        raise ValueError("send_https_certificate was handed a probe of another kind.")

    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(
                probe.host, probe.port, ssl=_discovery_tls_context()
            )
            subject, common_name = _certificate_subject(writer.get_extra_info("ssl_object"))

            request = f"HEAD / HTTP/1.0\r\nHost: {probe.host}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode("ascii"))
            await writer.drain()
            raw = await reader.read(HTTP_HEADER_LIMIT)

        headers = raw.decode("utf-8", errors="replace").strip()
        parts = [text for text in (subject, headers) if text]
        return ProbeOutcome(
            probe=probe,
            responded=True,
            payload="\n".join(parts) or None,
            detail=common_name,
        )

    except TimeoutError:
        return ProbeOutcome(probe=probe, responded=False, detail="TLS handshake timed out.")
    except (OSError, ssl.SSLError) as exc:
        return ProbeOutcome(probe=probe, responded=False, detail=str(exc))
    finally:
        if writer is not None:
            await _close(writer)


async def _close(writer: asyncio.StreamWriter) -> None:
    """Close a stream without letting the teardown fail a probe.

    A host that has already gone away raises on close, and on some platforms an SSL
    stream raises during ``wait_closed`` regardless. Neither says anything about whether
    the probe succeeded, and letting either propagate would turn a host that answered
    into a host that errored.
    """
    with contextlib.suppress(Exception):
        writer.close()
    with contextlib.suppress(Exception):
        await writer.wait_closed()


class HostProber:
    """Probes one host at a time, paced (FR-DISC-02, FR-DISC-05).

    The pacer is held here rather than passed per call, because this is the object every
    probe goes through: there is no method that contacts a host without first taking a
    slot. That is the same reasoning as the read-only guard owning the session rather
    than being consulted by it — a control that callers have to remember to use is a
    convention, not a control.

    One host's probes run in sequence, never together. The pacer's unit is hosts, so
    firing a host's eight connects concurrently would multiply the packet rate by the
    port count while the configured number stayed put.
    """

    def __init__(
        self,
        pacer: HostPacer,
        *,
        tcp_ports: tuple[int, ...],
        snmp_configured: bool = False,
        snmp_community: str | None = None,
        timeout: float = DEFAULT_PROBE_TIMEOUT,
        icmp_available: bool = True,
        follow_up: dict[int, ProbeKind] | None = None,
    ) -> None:
        self.pacer = pacer
        self.tcp_ports = tcp_ports
        # Both, and the community is what actually gates the probe. The flag says the
        # operator intends SNMP; the community is the only thing that makes it possible,
        # and there is deliberately no default — `public` is a credential, and trying it
        # is a credential guess whatever its reputation.
        self.snmp_configured = snmp_configured
        self.snmp_community = snmp_community
        self.timeout = timeout
        self.icmp_available = icmp_available
        self.follow_up = DEFAULT_FOLLOW_UP if follow_up is None else follow_up
        #: Seconds this prober spent waiting on the limiter, so a run can report whether
        #: the rate it was given was the binding constraint.
        self.paced_seconds = 0.0

    async def probe(self, address: str) -> HostResult:
        """Everything the scope permits against one address, in order."""
        self.paced_seconds += await self.pacer.acquire()

        result = HostResult(address=address)
        notes: list[str] = []

        if self.icmp_available:
            try:
                echo = await send_icmp_echo(
                    authorise(ProbeKind.ICMP_ECHO, address), timeout=self.timeout
                )
                result.probes_sent += 1
                result.responded |= echo.responded
            except IcmpUnavailableError:
                # The capability went away mid-run, which should not happen; carry on
                # with TCP rather than abandoning the scope.
                self.icmp_available = False
                notes.append("ICMP became unavailable during the run.")

        for port in self.tcp_ports:
            connect = await send_tcp_connect(
                authorise(ProbeKind.TCP_CONNECT, address, port=port, allowed_ports=self.tcp_ports),
                timeout=self.timeout,
            )
            result.probes_sent += 1
            if not connect.responded:
                continue

            result.responded = True
            result.open_ports = (*result.open_ports, port)

            match self.follow_up.get(port):
                case ProbeKind.SSH_BANNER:
                    await self._read_banner(address, port, result)
                case ProbeKind.HTTPS_CERTIFICATE:
                    await self._read_certificate(address, port, result)
                case _:
                    # An open port the map has no read for. It still counts towards
                    # liveness — the host answered — it just contributes no evidence.
                    pass

        # SNMP last, and only with a credential. It is the strongest fingerprint signal
        # there is — sysObjectID names the exact hardware model — so a host that answers
        # it usually needs no human at all (FR-DISC-02, FR-DISC-03).
        if self.snmp_configured and self.snmp_community:
            await self._read_snmp(address, result, notes)

        result.notes = tuple(notes)
        return result

    async def _read_banner(self, address: str, port: int, result: HostResult) -> None:
        outcome = await send_ssh_banner(
            authorise(ProbeKind.SSH_BANNER, address, port=port, allowed_ports=self.tcp_ports),
            timeout=self.timeout,
        )
        result.probes_sent += 1
        if outcome.payload:
            result.evidence.append(read_text(Signal.SSH_BANNER, outcome.payload))

    async def _read_snmp(self, address: str, result: HostResult, notes: list[str]) -> None:
        """GET sysDescr and sysObjectID (FR-DISC-02).

        `authorise` is consulted exactly as it is for every other probe — it is what
        refuses any OID beyond those two, and refuses the probe entirely when no
        credential is configured. Calling the SNMP module directly would route around the
        one control that keeps discovery inside its allow-list.

        A non-answer is not a failure. Most hosts do not run SNMP, or do not accept this
        community, and recording that as an error would fill every run's notes with noise
        about the ordinary case.
        """
        from netsecops.discovery.snmp import SnmpError, get_system_facts

        authorise(ProbeKind.SNMP_SYSDESCR, address, snmp_configured=self.snmp_configured)
        result.probes_sent += 1

        try:
            facts = await get_system_facts(address, self.snmp_community or "", timeout=self.timeout)
        except SnmpError:
            return

        result.responded |= not facts.empty
        if facts.sys_object_id:
            result.evidence.append(read_text(Signal.SNMP_SYSOBJECTID, facts.sys_object_id))
        if facts.sys_descr:
            result.evidence.append(read_text(Signal.SNMP_SYSDESCR, facts.sys_descr))

    async def _read_certificate(self, address: str, port: int, result: HostResult) -> None:
        outcome = await send_https_certificate(
            authorise(
                ProbeKind.HTTPS_CERTIFICATE, address, port=port, allowed_ports=self.tcp_ports
            ),
            timeout=self.timeout,
        )
        result.probes_sent += 1
        if not outcome.payload:
            return

        subject, _, headers = outcome.payload.partition("\n")
        if subject:
            result.evidence.append(read_text(Signal.TLS_SUBJECT, subject))
        if headers:
            result.evidence.append(read_text(Signal.HTTP_HEADER, headers))

        # The certificate's common name is a hostname candidate, not an identity. Vendors
        # ship certificates whose CN is the model or a wildcard, so anything without a dot
        # in it is at least as likely to be boilerplate as a name.
        candidate = (outcome.detail or "").strip()
        if candidate and "." in candidate and not candidate.startswith("*"):
            result.hostname = candidate


__all__ = [
    "DEFAULT_FOLLOW_UP",
    "DEFAULT_PROBE_TIMEOUT",
    "HTTP_HEADER_LIMIT",
    "HostProber",
    "HostResult",
    "IcmpUnavailableError",
    "ProbeOutcome",
    "build_echo_request",
    "icmp_capability",
    "is_echo_reply",
    "send_https_certificate",
    "send_icmp_echo",
    "send_ssh_banner",
    "send_tcp_connect",
]
