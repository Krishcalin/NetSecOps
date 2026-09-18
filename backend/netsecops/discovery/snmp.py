"""A minimal SNMPv2c GET, for discovery fingerprinting (FR-DISC-02).

sysObjectID is the strongest fingerprint signal there is — it names the exact hardware
model from a vendor-assigned tree, where an SSH banner says "Cisco" at best and a TLS
certificate usually says nothing. Without it more discovered hosts need a human.

**Hand-rolled rather than a dependency**, because what is needed is two OIDs from one
request and the encoding for that is about a hundred lines. `pysnmp` is a large library
carrying an async engine, a MIB compiler and a transport stack, none of which this uses,
and this product is deliberately careful about what it ships.

**v2c only, and v3 is refused rather than degraded.** SNMPv3's User Security Model needs
a username, an authentication protocol and key, and a privacy protocol and key —
per-device credentials that by definition nobody has for a host they have not yet
identified. A "v3 attempt" against an unknown host is therefore either a guess or a
failure, and guessing is what FR-DISC-02 rules out.

**No community is ever guessed.** `public` is a credential, and trying it is a credential
guess whatever its reputation. The probe runs only where an operator has supplied one,
which is why the scope carries a credential reference rather than a boolean.
"""

from __future__ import annotations

import asyncio
import secrets
import socket
from dataclasses import dataclass
from typing import Final

from netsecops.core.logging import get_logger

log = get_logger(__name__)

SNMP_PORT: Final[int] = 161

#: The only two OIDs this may request (FR-DISC-02), as dotted strings.
SYS_DESCR: Final[str] = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID: Final[str] = "1.3.6.1.2.1.1.2.0"

#: Longest response accepted. A GET for two scalars is a few hundred bytes; anything
#: larger is not an answer to this question and will not be parsed.
MAX_RESPONSE: Final[int] = 4096

# ── BER tags ────────────────────────────────────────────────────────────
_INTEGER: Final[int] = 0x02
_OCTET_STRING: Final[int] = 0x04
_NULL: Final[int] = 0x05
_OID: Final[int] = 0x06
_SEQUENCE: Final[int] = 0x30
_GET_REQUEST: Final[int] = 0xA0
_GET_RESPONSE: Final[int] = 0xA2


class SnmpError(RuntimeError):
    """The probe could not be completed, with a reason fit for a run's notes."""


@dataclass(frozen=True, slots=True)
class SnmpFacts:
    """What one successful GET yielded."""

    sys_descr: str | None = None
    sys_object_id: str | None = None

    @property
    def empty(self) -> bool:
        return not (self.sys_descr or self.sys_object_id)


# ═══════════════════════════════ encoding ════════════════════════════════════


def _length(value: int) -> bytes:
    """BER length: short form below 128, long form above.

    The boundary is the classic off-by-one here. A 127-byte payload takes one length
    byte and a 128-byte one takes three, and getting that wrong produces a packet the
    agent silently drops — presenting as a device that does not speak SNMP.
    """
    if value < 0x80:
        return bytes([value])
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _length(len(payload)) + payload


def _integer(value: int) -> bytes:
    if value == 0:
        return _tlv(_INTEGER, b"\x00")
    raw = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
    return _tlv(_INTEGER, raw)


def encode_oid(oid: str) -> bytes:
    """Encode a dotted OID.

    The first two arcs are packed into one byte as ``40 * a + b``, which is the part a
    naive encoder omits; the result is a syntactically valid packet that asks for the
    wrong object.
    """
    parts = [int(p) for p in oid.split(".")]
    if len(parts) < 2:
        raise SnmpError(f"{oid!r} is not a usable OID.")

    body = bytearray([40 * parts[0] + parts[1]])
    for arc in parts[2:]:
        if arc < 0x80:
            body.append(arc)
            continue
        chunks = []
        while arc:
            chunks.append(arc & 0x7F)
            arc >>= 7
        chunks.reverse()
        for index, chunk in enumerate(chunks):
            body.append(chunk | (0x80 if index < len(chunks) - 1 else 0))

    return _tlv(_OID, bytes(body))


def build_get(community: str, oids: tuple[str, ...], request_id: int) -> bytes:
    """One SNMPv2c GET request."""
    varbinds = b"".join(_tlv(_SEQUENCE, encode_oid(oid) + _tlv(_NULL, b"")) for oid in oids)
    pdu = _tlv(
        _GET_REQUEST,
        _integer(request_id) + _integer(0) + _integer(0) + _tlv(_SEQUENCE, varbinds),
    )
    # version 1 is SNMPv2c. 0 would be v1, whose error handling differs.
    return _tlv(_SEQUENCE, _integer(1) + _tlv(_OCTET_STRING, community.encode()) + pdu)


# ═══════════════════════════════ decoding ════════════════════════════════════


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Return ``(tag, value, next_offset)``."""
    if offset + 2 > len(data):
        raise SnmpError("Truncated SNMP response.")

    tag = data[offset]
    first = data[offset + 1]
    offset += 2

    if first < 0x80:
        size = first
    else:
        count = first & 0x7F
        if count == 0 or offset + count > len(data):
            raise SnmpError("Malformed SNMP length.")
        size = int.from_bytes(data[offset : offset + count], "big")
        offset += count

    if offset + size > len(data):
        raise SnmpError("SNMP response shorter than its declared length.")
    return tag, data[offset : offset + size], offset + size


def decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    arcs = [str(raw[0] // 40), str(raw[0] % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(str(value))
            value = 0
    return ".".join(arcs)


def parse_response(data: bytes) -> dict[str, object]:
    """Pull the varbinds out of a GET response, as ``{oid: value}``."""
    tag, message, _ = _read_tlv(data, 0)
    if tag != _SEQUENCE:
        raise SnmpError("Response is not an SNMP message.")

    _, _version, offset = _read_tlv(message, 0)
    _, _community, offset = _read_tlv(message, offset)
    tag, pdu, _ = _read_tlv(message, offset)
    if tag != _GET_RESPONSE:
        raise SnmpError(f"Expected a GET response, got tag 0x{tag:02x}.")

    _, _request_id, offset = _read_tlv(pdu, 0)
    _, error_status, offset = _read_tlv(pdu, offset)
    _, _error_index, offset = _read_tlv(pdu, offset)
    if error_status and int.from_bytes(error_status, "big"):
        raise SnmpError(f"Agent returned error-status {int.from_bytes(error_status, 'big')}.")

    _, varbinds, _ = _read_tlv(pdu, offset)

    found: dict[str, object] = {}
    cursor = 0
    while cursor < len(varbinds):
        _, binding, cursor = _read_tlv(varbinds, cursor)
        _, oid_bytes, inner = _read_tlv(binding, 0)
        value_tag, value, _ = _read_tlv(binding, inner)

        oid = decode_oid(oid_bytes)
        if value_tag == _OCTET_STRING:
            found[oid] = value.decode(errors="replace")
        elif value_tag == _OID:
            found[oid] = decode_oid(value)
        elif value_tag == _INTEGER:
            found[oid] = int.from_bytes(value, "big")
        # Anything else — noSuchObject, endOfMibView — is left out rather than guessed at.
    return found


# ═══════════════════════════════ the probe ═══════════════════════════════════


async def get_system_facts(
    address: str, community: str, *, timeout: float = 2.0, port: int = SNMP_PORT
) -> SnmpFacts:
    """GET sysDescr and sysObjectID from one host.

    One datagram, one reply, no retry. Discovery is paced and a retry would double the
    packet rate the limiter was configured for; a host that does not answer is recorded
    as not answering, which is the honest result for a single-shot probe.
    """
    request = build_get(community, (SYS_DESCR, SYS_OBJECT_ID), secrets.randbelow(0x7FFFFFFF))

    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_sendto(sock, request, (address, port))
        data = await asyncio.wait_for(loop.sock_recv(sock, MAX_RESPONSE), timeout=timeout)
    except (TimeoutError, OSError) as exc:
        raise SnmpError(f"No SNMP response from {address}: {exc}") from exc
    finally:
        sock.close()

    values = parse_response(data)
    descr = values.get(SYS_DESCR)
    obj = values.get(SYS_OBJECT_ID)
    return SnmpFacts(
        sys_descr=str(descr) if descr is not None else None,
        sys_object_id=str(obj) if obj is not None else None,
    )


__all__ = [
    "MAX_RESPONSE",
    "SNMP_PORT",
    "SYS_DESCR",
    "SYS_OBJECT_ID",
    "SnmpError",
    "SnmpFacts",
    "build_get",
    "decode_oid",
    "encode_oid",
    "get_system_facts",
    "parse_response",
]
