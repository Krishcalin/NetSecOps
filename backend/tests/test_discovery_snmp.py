"""SNMPv2c GET for discovery fingerprinting (FR-DISC-02).

A hand-rolled BER codec fails silently: a mis-encoded packet is dropped by the agent
without a reply, which is indistinguishable from a host that does not speak SNMP. So
these assert the *bytes*, against values worked out from the encoding rules rather than
from a run of this code.

The round-trip tests are deliberately not the only ones. Encode and decode can agree with
each other and both be wrong; the byte-level assertions are what pin them to the wire
format.
"""

from __future__ import annotations

import pytest

from netsecops.discovery.snmp import (
    SYS_DESCR,
    SYS_OBJECT_ID,
    SnmpError,
    build_get,
    decode_oid,
    encode_oid,
    parse_response,
)


class TestOidEncoding:
    def test_the_first_two_arcs_pack_into_one_byte(self) -> None:
        """`40 * a + b`, which a naive encoder omits.

        The result is a syntactically valid packet asking for the wrong object, so the
        agent answers — with something else — and the fingerprint is quietly wrong.
        """
        # 1.3.6.1 -> 0x2b 0x06 0x01, where 0x2b == 43 == 40*1 + 3.
        assert encode_oid("1.3.6.1")[2:] == bytes([0x2B, 0x06, 0x01])

    def test_an_arc_over_127_uses_continuation_bytes(self) -> None:
        # Cisco's enterprise tree is 1.3.6.1.4.1.9, but model OIDs run far past 127 and a
        # single-byte encoder truncates them into a different vendor's space.
        encoded = encode_oid("1.3.6.1.4.1.9.1.1745")
        assert encoded[-2:] == bytes([0x8D, 0x51])  # 1745 == 0b1101_1010001

    def test_it_round_trips(self) -> None:
        for oid in ("1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.9.1.1745", "1.3.6.1.4.1.2636.1.1.1.2.29"):
            assert decode_oid(encode_oid(oid)[2:]) == oid

    def test_a_single_arc_is_refused(self) -> None:
        with pytest.raises(SnmpError):
            encode_oid("1")


class TestRequestEncoding:
    def test_it_is_a_v2c_get_with_the_community(self) -> None:
        packet = build_get("s3cret", (SYS_DESCR,), 1234)

        assert packet[0] == 0x30  # SEQUENCE
        # version INTEGER 1 == v2c. 0 would be v1, whose error handling differs.
        assert packet[2:5] == bytes([0x02, 0x01, 0x01])
        assert b"s3cret" in packet

    def test_the_pdu_is_a_get_request(self) -> None:
        assert bytes([0xA0]) in build_get("public", (SYS_DESCR,), 1)

    def test_both_oids_are_present(self) -> None:
        packet = build_get("public", (SYS_DESCR, SYS_OBJECT_ID), 1)
        assert encode_oid(SYS_DESCR) in packet
        assert encode_oid(SYS_OBJECT_ID) in packet

    def test_a_long_payload_uses_the_long_form_length(self) -> None:
        """The 127/128 boundary, where a short-form length silently truncates.

        The agent then drops the datagram and the host looks like it does not run SNMP.
        """
        packet = build_get("c" * 200, (SYS_DESCR, SYS_OBJECT_ID), 1)
        assert packet[1] & 0x80, "outer length should be long-form for a >127-byte body"


def _response(community: bytes, varbinds: bytes, *, error: int = 0) -> bytes:
    """Assemble a GET response the way an agent would."""
    from netsecops.snmp.codec import _tlv

    pdu = _tlv(
        0xA2,
        bytes([0x02, 0x01, 0x01])
        + bytes([0x02, 0x01, error])
        + bytes([0x02, 0x01, 0x00])
        + _tlv(0x30, varbinds),
    )
    return _tlv(0x30, bytes([0x02, 0x01, 0x01]) + _tlv(0x04, community) + pdu)


class TestResponseDecoding:
    def test_it_reads_a_string_and_an_oid(self) -> None:
        from netsecops.snmp.codec import _tlv

        descr = b"Cisco IOS Software, C2960X Software"
        model = encode_oid("1.3.6.1.4.1.9.1.1745")

        varbinds = _tlv(0x30, encode_oid(SYS_DESCR) + _tlv(0x04, descr)) + _tlv(
            0x30, encode_oid(SYS_OBJECT_ID) + model
        )
        values = parse_response(_response(b"public", varbinds))

        assert values[SYS_DESCR] == descr.decode()
        assert values[SYS_OBJECT_ID] == "1.3.6.1.4.1.9.1.1745"

    def test_an_agent_error_is_raised_not_ignored(self) -> None:
        # A non-zero error-status means the varbinds are meaningless. Reading them anyway
        # produces a fingerprint from a failed request.
        with pytest.raises(SnmpError):
            parse_response(_response(b"public", b"", error=2))

    def test_a_truncated_response_is_refused(self) -> None:
        from netsecops.snmp.codec import _tlv

        full = _response(b"public", _tlv(0x30, encode_oid(SYS_DESCR) + _tlv(0x04, b"abc")))
        with pytest.raises(SnmpError):
            parse_response(full[:-4])

    def test_a_non_snmp_payload_is_refused(self) -> None:
        # UDP/161 attracts all sorts of traffic; whatever comes back must not be parsed
        # hopefully into a fingerprint.
        with pytest.raises(SnmpError):
            parse_response(b"\x04\x03abc")

    def test_an_unhandled_value_type_is_left_out_rather_than_guessed(self) -> None:
        from netsecops.snmp.codec import _tlv

        # noSuchObject (0x81) — the agent saying it has no such OID.
        varbinds = _tlv(0x30, encode_oid(SYS_DESCR) + _tlv(0x81, b""))
        assert parse_response(_response(b"public", varbinds)) == {}
