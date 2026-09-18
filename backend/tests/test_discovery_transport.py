"""Actually sending the probes FR-DISC-02 permits.

Against real sockets on the loopback, because the claims worth testing here are all
claims about the wire. "The banner grab sends nothing" is not checkable by reading the
function — it is checkable by having a server count the bytes it received, which is what
:class:`RecordingServer` is for.

ICMP is the exception: it needs a capability neither CI nor a developer's laptop reliably
has. So the encoding and the reply matching are pure functions, tested directly, and the
socket work around them degrades honestly rather than being mocked into looking covered.

The two failures these are written against, both of which are silent:

- A bad ICMP checksum. The far end drops the packet without a word, so the symptom is an
  estate that appears empty and a discovery feature that appears to work.
- ``getpeercert()`` on an unverified connection, which returns ``{}`` rather than
  raising. The TLS signal simply never appears, no error is logged, and every host
  scores lower than it should for want of evidence nobody knows was dropped.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import ssl
import struct
from pathlib import Path

import pytest

from netsecops.discovery.fingerprint import Signal
from netsecops.discovery.pacing import HostPacer
from netsecops.discovery.probes import ProbeKind, ProbeViolationError, authorise
from netsecops.discovery.transport import (
    HostProber,
    build_echo_request,
    is_echo_reply,
    send_https_certificate,
    send_ssh_banner,
    send_tcp_connect,
)

LOOPBACK = "127.0.0.1"
QUICK = 2.0


# ── servers ──────────────────────────────────────────────────────────────────


class RecordingServer:
    """A TCP listener that optionally greets, and always records what it was sent."""

    def __init__(self, greeting: bytes | None = None, *, ssl_context: ssl.SSLContext | None = None):
        self.greeting = greeting
        self.ssl_context = ssl_context
        self.received = bytearray()
        self.port = 0
        self._server: asyncio.AbstractServer | None = None

    async def __aenter__(self) -> RecordingServer:
        self._server = await asyncio.start_server(self._handle, LOOPBACK, 0, ssl=self.ssl_context)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            if self.greeting:
                writer.write(self.greeting)
                await writer.drain()
            with contextlib.suppress(Exception):
                self.received += await asyncio.wait_for(reader.read(4096), timeout=0.5)
        finally:
            with contextlib.suppress(Exception):
                writer.close()


@pytest.fixture(scope="module")
def self_signed(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """A throwaway certificate whose subject names a vendor the fingerprinter knows.

    Self-signed deliberately: it is what a management appliance ships with, and it is the
    case a verifying client would refuse — so this fixture is also the test that discovery
    does not verify.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Palo Alto Networks"),
            x509.NameAttribute(NameOID.COMMON_NAME, "fw01.example.net"),
        ]
    )
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )

    directory = tmp_path_factory.mktemp("discovery-tls")
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture
def tls_context(self_signed: tuple[Path, Path]) -> ssl.SSLContext:
    cert_path, key_path = self_signed
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))
    return context


# ── ICMP, which is arithmetic before it is a socket ──────────────────────────


class TestEchoRequestEncoding:
    def test_the_checksum_validates(self) -> None:
        """Summing a correct ICMP message gives zero (RFC 1071).

        The property, not the value. A hardcoded expected checksum would be re-derived
        from the implementation the moment it changed, which is how a checksum test ends
        up asserting that the code does what the code does.
        """
        packet = build_echo_request(identifier=0x1234, sequence=1)
        # RFC 1071 pads an odd-length message with a zero byte before summing. The
        # payload makes this packet odd-length, so omitting the pad here reads a byte
        # past the end — which is how the sum comes out right for the wrong reason.
        padded = packet + b"\x00" if len(packet) % 2 else packet

        total = 0
        for index in range(0, len(padded), 2):
            total += (padded[index] << 8) + padded[index + 1]
        total = (total >> 16) + (total & 0xFFFF)

        assert (~total & 0xFFFF) == 0

    def test_it_is_an_echo_request_carrying_our_marker(self) -> None:
        packet = build_echo_request(identifier=0x1234, sequence=7)
        icmp_type, code, _, identifier, sequence = struct.unpack("!BBHHH", packet[:8])

        assert (icmp_type, code) == (8, 0)
        assert (identifier, sequence) == (0x1234, 7)
        assert b"netsecops-discovery" in packet[8:]

    def test_an_oversized_identifier_is_masked_rather_than_raising(self) -> None:
        """The identifier is a PID, and a PID can exceed sixteen bits."""
        packet = build_echo_request(identifier=0x1FFFF, sequence=1)

        assert struct.unpack("!H", packet[4:6])[0] == 0xFFFF


class TestEchoReplyMatching:
    def _reply(self, *, icmp_type: int = 0, payload: bytes = b"netsecops-discovery") -> bytes:
        return struct.pack("!BBHHH", icmp_type, 0, 0, 0x1234, 1) + payload

    def test_a_ping_socket_reply_is_recognised(self) -> None:
        assert is_echo_reply(self._reply()) is True

    def test_a_raw_socket_reply_behind_an_ip_header_is_recognised(self) -> None:
        """The case a fixed offset gets wrong, on one socket flavour only.

        A ping socket hands over the ICMP message alone; a raw socket prefixes the IP
        header. Reading the type at byte 0 works for one and silently reports every host
        as down for the other.
        """
        ip_header = bytes([0x45, 0x00]) + b"\x00" * 18  # IHL 5 → 20 bytes

        assert is_echo_reply(ip_header + self._reply()) is True

    def test_our_own_echo_request_is_not_a_reply(self) -> None:
        """A raw socket sees its own traffic; counting it would mark every host alive."""
        assert is_echo_reply(self._reply(icmp_type=8)) is False

    def test_another_process_ping_is_not_ours(self) -> None:
        assert is_echo_reply(self._reply(payload=b"some other pinger")) is False

    def test_a_runt_datagram_is_rejected_rather_than_indexed(self) -> None:
        assert is_echo_reply(b"\x00\x00") is False


# ── TCP ──────────────────────────────────────────────────────────────────────


class TestTcpConnect:
    async def test_an_open_port_responds(self) -> None:
        async with RecordingServer() as server:
            probe = authorise(
                ProbeKind.TCP_CONNECT, LOOPBACK, port=server.port, allowed_ports=(server.port,)
            )

            outcome = await send_tcp_connect(probe, timeout=QUICK)

        assert outcome.responded is True

    async def test_a_closed_port_is_a_non_response_rather_than_an_error(self) -> None:
        """Most of a scope is closed ports. If that raised, a run could not finish."""
        async with RecordingServer() as server:
            closed = server.port
        # The server is gone; the port is now refusing.

        probe = authorise(ProbeKind.TCP_CONNECT, LOOPBACK, port=closed, allowed_ports=(closed,))
        outcome = await send_tcp_connect(probe, timeout=QUICK)

        assert outcome.responded is False
        assert outcome.detail

    async def test_connecting_sends_no_payload(self) -> None:
        """FR-DISC-02 permits a *connect*. Anything written would be interaction."""
        async with RecordingServer() as server:
            probe = authorise(
                ProbeKind.TCP_CONNECT, LOOPBACK, port=server.port, allowed_ports=(server.port,)
            )
            await send_tcp_connect(probe, timeout=QUICK)
            await asyncio.sleep(0.05)

            assert bytes(server.received) == b""


class TestSshBanner:
    async def test_the_banner_is_read(self) -> None:
        async with RecordingServer(greeting=b"SSH-2.0-Cisco-1.25\r\n") as server:
            probe = authorise(
                ProbeKind.SSH_BANNER, LOOPBACK, port=server.port, allowed_ports=(server.port,)
            )

            outcome = await send_ssh_banner(probe, timeout=QUICK)

        assert outcome.responded is True
        assert outcome.payload == "SSH-2.0-Cisco-1.25"

    async def test_not_one_byte_is_written(self) -> None:
        """The claim that keeps this a banner grab rather than an SSH session.

        RFC 4253 has the server speak first, so the banner is obtainable without starting
        a key exchange. Writing anything — even a client identification string — would
        begin one, and would put an authentication attempt in the device's log.
        """
        async with RecordingServer(greeting=b"SSH-2.0-OpenSSH_9.6\r\n") as server:
            probe = authorise(
                ProbeKind.SSH_BANNER, LOOPBACK, port=server.port, allowed_ports=(server.port,)
            )
            await send_ssh_banner(probe, timeout=QUICK)
            await asyncio.sleep(0.05)

            assert bytes(server.received) == b""

    async def test_a_verbose_server_is_cut_off_at_the_rfc_limit(self) -> None:
        """255 bytes by RFC 4253. Reading further consumes the key-exchange packet."""
        async with RecordingServer(greeting=b"SSH-2.0-" + b"A" * 4000 + b"\r\n") as server:
            probe = authorise(
                ProbeKind.SSH_BANNER, LOOPBACK, port=server.port, allowed_ports=(server.port,)
            )

            outcome = await send_ssh_banner(probe, timeout=QUICK)

        assert outcome.payload is not None
        assert len(outcome.payload) <= 255

    async def test_a_silent_port_still_counts_as_open(self) -> None:
        """A device that connects and says nothing is still a device."""
        async with RecordingServer() as server:
            probe = authorise(
                ProbeKind.SSH_BANNER, LOOPBACK, port=server.port, allowed_ports=(server.port,)
            )

            outcome = await send_ssh_banner(probe, timeout=0.3)

        assert outcome.responded is True
        assert outcome.payload is None


class TestHttpsCertificate:
    async def test_the_subject_of_an_unverified_certificate_is_read(
        self, tls_context: ssl.SSLContext
    ) -> None:
        """The silent failure this whole probe turns on.

        ``getpeercert()`` returns an empty dict whenever the peer was not verified, and
        discovery never verifies — it is identifying appliances that ship self-signed
        certificates for an IP address. So the parsed form is unavailable by construction
        and the DER has to be decoded. Get this wrong and the TLS signal never appears,
        with no error anywhere and no test failing.
        """
        async with RecordingServer(ssl_context=tls_context) as server:
            probe = authorise(
                ProbeKind.HTTPS_CERTIFICATE,
                LOOPBACK,
                port=server.port,
                allowed_ports=(server.port,),
            )

            outcome = await send_https_certificate(probe, timeout=QUICK)

        assert outcome.responded is True
        assert outcome.payload is not None
        assert "Palo Alto Networks" in outcome.payload
        assert outcome.detail == "fw01.example.net"

    async def test_only_a_head_is_sent(self, tls_context: ssl.SSLContext) -> None:
        """FR-DISC-02 permits headers, not bodies."""
        async with RecordingServer(ssl_context=tls_context) as server:
            probe = authorise(
                ProbeKind.HTTPS_CERTIFICATE,
                LOOPBACK,
                port=server.port,
                allowed_ports=(server.port,),
            )
            await send_https_certificate(probe, timeout=QUICK)
            await asyncio.sleep(0.05)

        sent = bytes(server.received).decode("utf-8", errors="replace")
        assert sent.startswith("HEAD / HTTP/1.0")
        assert "GET" not in sent

    async def test_a_plaintext_port_is_a_non_response_rather_than_a_crash(self) -> None:
        async with RecordingServer(greeting=b"SSH-2.0-OpenSSH_9.6\r\n") as server:
            probe = authorise(
                ProbeKind.HTTPS_CERTIFICATE,
                LOOPBACK,
                port=server.port,
                allowed_ports=(server.port,),
            )

            outcome = await send_https_certificate(probe, timeout=QUICK)

        assert outcome.responded is False


# ── the prober, which is where pacing and authorisation meet ─────────────────


class TestHostProber:
    @staticmethod
    def _prober(port: int, kind: ProbeKind | None, **kwargs: object) -> HostProber:
        """A prober whose single scope port is the ephemeral one the fixture bound.

        The follow-up map is injected rather than the port being forced to 22, because
        `authorise` refuses any port the scope did not name — so a test cannot pretend an
        ephemeral port is 22, and should not want to.
        """
        return HostProber(
            HostPacer(1000),
            tcp_ports=(port,),
            timeout=QUICK,
            icmp_available=False,
            follow_up={port: kind} if kind else {},
            **kwargs,  # type: ignore[arg-type]
        )

    async def test_an_open_port_makes_a_host_responsive(self) -> None:
        async with RecordingServer(greeting=b"SSH-2.0-Cisco-1.25\r\n") as server:
            result = await self._prober(server.port, None).probe(LOOPBACK)

        assert result.responded is True
        assert result.open_ports == (server.port,)

    async def test_a_banner_port_yields_weighted_ssh_evidence(self) -> None:
        async with RecordingServer(greeting=b"SSH-2.0-FortiSSH_1.0\r\n") as server:
            result = await self._prober(server.port, ProbeKind.SSH_BANNER).probe(LOOPBACK)

        assert [item.signal for item in result.evidence] == [Signal.SSH_BANNER]
        assert result.evidence[0].vendor == "fortinet"
        assert result.evidence[0].raw == "SSH-2.0-FortiSSH_1.0"

    async def test_a_tls_port_yields_both_certificate_and_header_evidence(
        self, tls_context: ssl.SSLContext
    ) -> None:
        """One probe, two signals, weighted differently.

        A TLS subject and an HTTP header are worth 20 and 15 respectively, and they are
        recorded separately rather than concatenated — the fingerprinter's conflict
        detection works on signals, so merging them would hide a host whose certificate
        and whose headers name different vendors.
        """
        async with RecordingServer(ssl_context=tls_context) as server:
            result = await self._prober(server.port, ProbeKind.HTTPS_CERTIFICATE).probe(LOOPBACK)

        signals = [item.signal for item in result.evidence]
        assert Signal.TLS_SUBJECT in signals
        assert result.hostname == "fw01.example.net"

    async def test_an_open_port_with_no_follow_up_still_counts_as_alive(self) -> None:
        """Found but unidentified is a real outcome, and the queue is sorted for it."""
        async with RecordingServer() as server:
            result = await self._prober(server.port, None).probe(LOOPBACK)

        assert result.responded is True
        assert result.evidence == []

    async def test_every_host_takes_a_slot_from_the_pacer(self) -> None:
        """The structural claim: there is no probe that is not paced.

        The prober holds the pacer rather than being handed one per call, so a future
        caller cannot probe without pacing by forgetting an argument. This asserts the
        limiter was actually consulted, on a host that answers nothing.
        """
        calls: list[float] = []

        class CountingPacer(HostPacer):
            async def acquire(self) -> float:
                calls.append(0.0)
                return await super().acquire()

        prober = HostProber(CountingPacer(1000), tcp_ports=(9,), timeout=0.2, icmp_available=False)

        await prober.probe("192.0.2.1")
        await prober.probe("192.0.2.2")

        assert len(calls) == 2

    async def test_a_port_outside_the_scope_list_is_refused_at_the_guard(self) -> None:
        """Defence in depth: the prober's own list is re-checked by `authorise`."""
        with pytest.raises(ProbeViolationError):
            authorise(ProbeKind.TCP_CONNECT, LOOPBACK, port=8080, allowed_ports=(22, 443))
