"""No SNMP request NetSecOps builds can be a SET (SRS §8).

This file is written late and should have been written first. Both
`netsecops/snmp/__init__.py` and `codec.py` have asserted, in prose, that
"``test_snmp_readonly.py`` asserts that the tag never appears in an encoded packet".
No such file existed. Nothing had ever been deleted — it was never written, and the
claim had been sitting in a package docstring describing a guarantee nobody checked.

The guarantee itself did hold, which is the uncomfortable part: the codec defines
`0xA0`, `0xA1`, `0xA2` and `0xA5` and no `0xA3`, and there is no SET builder to call.
The property was real and the assurance was imaginary, and from outside they looked
identical.

**What is asserted, and why not the literal claim.** "The tag never appears in an
encoded packet" is the wrong test: `0xA3` is an ordinary byte and can legitimately
occur inside a request id, a community string or an OID arc, so a substring search
would fail on a valid GET whenever the random request id happened to contain it. What
matters is the byte in the *PDU tag position*, so the packet is decoded to reach it.

The second test is the one with a future: it fails when somebody adds a builder, which
is how a SET would actually arrive.
"""

from __future__ import annotations

import pytest

from netsecops.snmp import codec

#: SNMPv2c SET-REQUEST. Deliberately written here and nowhere in the source tree.
SET_REQUEST = 0xA3

REQUESTS = {
    "get": codec.build_get("public", ("1.3.6.1.2.1.1.1.0",), 1),
    "getnext": codec.build_getnext("public", ("1.3.6.1.2.1.1.1.0",), 2),
    "getbulk": codec.build_getbulk("public", ("1.3.6.1.2.1.4.24.4",), 3, max_repetitions=10),
}


def read_tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    """Return ``(tag, value_offset, value_length)`` for the TLV at ``offset``."""
    tag = data[offset]
    length = data[offset + 1]
    offset += 2

    # Long form: the low seven bits give how many bytes carry the real length.
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count

    return tag, offset, length


def pdu_tag(packet: bytes) -> int:
    """The PDU tag of an SNMPv2c message: SEQUENCE { version, community, PDU }."""
    _, body, _ = read_tlv(packet, 0)

    _, version_value, version_length = read_tlv(packet, body)
    after_version = version_value + version_length

    _, community_value, community_length = read_tlv(packet, after_version)
    after_community = community_value + community_length

    return packet[after_community]


@pytest.mark.parametrize("name", sorted(REQUESTS))
def test_every_request_this_codec_builds_is_a_read(name: str) -> None:
    """Checked in the tag position rather than by searching the packet.

    A substring search for `0xA3` would pass here and fail intermittently in the field,
    when a request id or an OID arc happened to contain that byte.
    """
    tag = pdu_tag(REQUESTS[name])

    assert tag != SET_REQUEST
    assert tag in {codec.GET_REQUEST, codec.GET_NEXT_REQUEST, codec.GET_BULK_REQUEST}


def test_the_codec_exposes_no_way_to_build_anything_else() -> None:
    """The test that will still be doing work in a year.

    A SET does not arrive by an existing builder changing its tag — it arrives as a new
    function somebody adds for a reason that sounds good at the time. This enumerates
    the builders rather than trusting that none was added, so widening the codec's
    write surface cannot be done quietly: it fails here and names the new function.
    """
    builders = {name for name in dir(codec) if name.startswith("build_")}

    assert builders == {"build_get", "build_getnext", "build_getbulk"}


def test_no_set_tag_is_defined_anywhere_in_the_codec() -> None:
    """`0xA3` should not be reachable as a constant, under any name.

    Encoding a SET needs the tag. Not having a name for it is a small barrier, but it
    is the difference between a typo producing a write and a typo failing to compile.
    """
    constants = {
        name: value
        for name, value in vars(codec).items()
        if isinstance(value, int) and name.isupper()
    }

    assert SET_REQUEST not in constants.values(), (
        f"the SET-REQUEST tag is defined in codec as: "
        f"{[name for name, value in constants.items() if value == SET_REQUEST]}"
    )
