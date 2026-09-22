"""SNMPv2c BER encoding and decoding — GET, GETNEXT and GETBULK only.

**Hand-rolled rather than a dependency**, for the reason the discovery probe gave when it
first needed one: what is needed is a handful of OIDs and the encoding for that is a few
hundred lines. `pysnmp` carries an async engine, a MIB compiler and a transport stack,
none of which this uses, and this product is deliberately careful about what it ships.

**There is no SET.** Not "SET is rejected" — there is no function here that can build
one, and the tag is not among the constants. A read-only guarantee enforced by a check is
worth its check; a guarantee enforced by the absence of an encoder is worth rather more.
`test_snmp_readonly.py` asserts the tag never appears in anything this module produces.

**v2c only.** v3's User Security Model needs a username, an auth protocol and key and a
privacy protocol and key. Those are per-device credentials the vault can hold, but the
key derivation and message authentication are a different and much larger piece of work,
and half of it — encoding without authenticating — would be worse than not offering it.
So v3 is refused explicitly rather than silently downgraded to v2c, which would send a
community string where an operator asked for authenticated privacy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

SNMP_PORT: Final[int] = 161

#: Longest response accepted from one datagram. GETBULK replies are bounded by the
#: agent's own message size, commonly 1472 bytes on Ethernet; 8 KiB is generous for that
#: and still refuses to read an unbounded stream into memory.
MAX_RESPONSE: Final[int] = 8192

# ── BER tags ────────────────────────────────────────────────────────────
INTEGER: Final[int] = 0x02
OCTET_STRING: Final[int] = 0x04
NULL: Final[int] = 0x05
OID_TAG: Final[int] = 0x06
SEQUENCE: Final[int] = 0x30

#: Application types. IpAddress is the one that matters for a route table: the next hop
#: and mask arrive as four raw bytes, not as a string.
IP_ADDRESS: Final[int] = 0x40
COUNTER32: Final[int] = 0x41
GAUGE32: Final[int] = 0x42
TIME_TICKS: Final[int] = 0x43
COUNTER64: Final[int] = 0x46

#: Exception markers a v2c agent returns in place of a value. Each means something
#: different and none of them means "zero", so they are surfaced rather than coerced.
NO_SUCH_OBJECT: Final[int] = 0x80
NO_SUCH_INSTANCE: Final[int] = 0x81
END_OF_MIB_VIEW: Final[int] = 0x82

# ── PDU tags. Note what is absent: 0xA3 is SET, and nothing here builds one. ──
GET_REQUEST: Final[int] = 0xA0
GET_NEXT_REQUEST: Final[int] = 0xA1
GET_RESPONSE: Final[int] = 0xA2
GET_BULK_REQUEST: Final[int] = 0xA5


class SnmpError(RuntimeError):
    """The exchange could not be completed, with a reason fit for a run's notes."""


@dataclass(frozen=True, slots=True)
class VarBind:
    """One returned binding, with its tag preserved.

    The tag is kept because a walk cannot terminate correctly without it: `endOfMibView`
    is a *tag*, not a value, and a decoder that returned only values would leave the
    caller unable to tell the end of the table from an empty string.
    """

    oid: str
    tag: int
    value: object

    @property
    def is_end_of_mib(self) -> bool:
        return self.tag == END_OF_MIB_VIEW

    @property
    def is_absent(self) -> bool:
        """No such object or instance — the agent answered, and has nothing there."""
        return self.tag in (NO_SUCH_OBJECT, NO_SUCH_INSTANCE)


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
        return _tlv(INTEGER, b"\x00")
    raw = value.to_bytes((value.bit_length() + 8) // 8, "big", signed=True)
    return _tlv(INTEGER, raw)


def encode_oid(oid: str) -> bytes:
    """Encode a dotted OID.

    The first two arcs are packed into one byte as ``40 * a + b``, which is the part a
    naive encoder omits; the result is a syntactically valid packet that asks for the
    wrong object.
    """
    try:
        parts = [int(p) for p in oid.split(".")]
    except ValueError:
        raise SnmpError(f"{oid!r} is not a usable OID.") from None
    if len(parts) < 2 or any(part < 0 for part in parts):
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

    return _tlv(OID_TAG, bytes(body))


def _message(community: str, pdu: bytes) -> bytes:
    # version 1 is SNMPv2c. 0 would be v1, whose error handling differs.
    return _tlv(SEQUENCE, _integer(1) + _tlv(OCTET_STRING, community.encode()) + pdu)


def _varbinds(oids: tuple[str, ...]) -> bytes:
    return b"".join(_tlv(SEQUENCE, encode_oid(oid) + _tlv(NULL, b"")) for oid in oids)


def build_get(community: str, oids: tuple[str, ...], request_id: int) -> bytes:
    """One SNMPv2c GET request."""
    pdu = _tlv(
        GET_REQUEST,
        _integer(request_id) + _integer(0) + _integer(0) + _tlv(SEQUENCE, _varbinds(oids)),
    )
    return _message(community, pdu)


def build_getnext(community: str, oids: tuple[str, ...], request_id: int) -> bytes:
    """One SNMPv2c GETNEXT — the fallback when an agent refuses GETBULK."""
    pdu = _tlv(
        GET_NEXT_REQUEST,
        _integer(request_id) + _integer(0) + _integer(0) + _tlv(SEQUENCE, _varbinds(oids)),
    )
    return _message(community, pdu)


def build_getbulk(
    community: str, oids: tuple[str, ...], request_id: int, *, max_repetitions: int = 25
) -> bytes:
    """One SNMPv2c GETBULK request.

    GETBULK reuses the error-status and error-index fields as *non-repeaters* and
    *max-repetitions*. Walking a table one GETNEXT at a time costs one round trip per
    row, so a device with two thousand routes would take two thousand datagrams and
    several minutes; this takes roughly one per twenty-five rows.

    ``max_repetitions`` is capped rather than trusted. A large value asks the agent to
    assemble a reply it will then fragment or truncate, and a truncated reply read as a
    complete one is how a walk silently loses the end of a table.
    """
    if not 1 <= max_repetitions <= 50:
        raise SnmpError("max-repetitions must be between 1 and 50.")
    pdu = _tlv(
        GET_BULK_REQUEST,
        _integer(request_id)
        + _integer(0)  # non-repeaters: none of the requested OIDs is a scalar
        + _integer(max_repetitions)
        + _tlv(SEQUENCE, _varbinds(oids)),
    )
    return _message(community, pdu)


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


def _decode_value(tag: int, raw: bytes) -> object:
    match tag:
        case _ if tag == OCTET_STRING:
            return raw.decode(errors="replace")
        case _ if tag == OID_TAG:
            return decode_oid(raw)
        case _ if tag in (INTEGER, COUNTER32, GAUGE32, TIME_TICKS, COUNTER64):
            return int.from_bytes(raw, "big")
        case _ if tag == IP_ADDRESS:
            # Four raw bytes. Rendering it as a string here keeps the dotted form in one
            # place rather than in every caller that touches an address.
            return ".".join(str(byte) for byte in raw) if len(raw) == 4 else None
        case _:
            # Exception markers and anything unrecognised keep their tag and carry no
            # value, rather than being coerced into one the agent did not send.
            return None


def parse_varbinds(data: bytes) -> list[VarBind]:
    """Decode a response into its bindings, tags preserved.

    Raises on a non-response or an agent-reported error, because both mean the answer to
    the question asked is unknown — which is not the same as the answer being empty, and
    a walk that conflated them would report a device with routes as having none.
    """
    tag, message, _ = _read_tlv(data, 0)
    if tag != SEQUENCE:
        raise SnmpError("Response is not an SNMP message.")

    _, _version, offset = _read_tlv(message, 0)
    _, _community, offset = _read_tlv(message, offset)
    tag, pdu, _ = _read_tlv(message, offset)
    if tag != GET_RESPONSE:
        raise SnmpError(f"Expected a GET response, got tag 0x{tag:02x}.")

    _, _request_id, offset = _read_tlv(pdu, 0)
    _, error_status, offset = _read_tlv(pdu, offset)
    _, _error_index, offset = _read_tlv(pdu, offset)
    status = int.from_bytes(error_status, "big") if error_status else 0
    if status:
        raise SnmpError(f"Agent returned error-status {status}.")

    _, varbinds, _ = _read_tlv(pdu, offset)

    found: list[VarBind] = []
    cursor = 0
    while cursor < len(varbinds):
        _, binding, cursor = _read_tlv(varbinds, cursor)
        _, oid_bytes, inner = _read_tlv(binding, 0)
        value_tag, value, _ = _read_tlv(binding, inner)
        found.append(
            VarBind(oid=decode_oid(oid_bytes), tag=value_tag, value=_decode_value(value_tag, value))
        )
    return found


def parse_response(data: bytes) -> dict[str, object]:
    """``{oid: value}`` for callers that only want scalars.

    Bindings carrying an exception marker are omitted: `noSuchObject` is the agent saying
    it has nothing there, and putting ``None`` in the map would make that indistinguishable
    from a value that was genuinely null.
    """
    return {
        binding.oid: binding.value
        for binding in parse_varbinds(data)
        if not binding.is_absent and not binding.is_end_of_mib and binding.value is not None
    }


__all__ = [
    "END_OF_MIB_VIEW",
    "GET_BULK_REQUEST",
    "GET_NEXT_REQUEST",
    "GET_REQUEST",
    "GET_RESPONSE",
    "IP_ADDRESS",
    "MAX_RESPONSE",
    "SNMP_PORT",
    "SnmpError",
    "VarBind",
    "build_get",
    "build_getbulk",
    "build_getnext",
    "decode_oid",
    "encode_oid",
    "parse_response",
    "parse_varbinds",
]
