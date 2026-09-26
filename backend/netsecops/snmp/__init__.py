"""SNMP, read-only.

The BER codec lived under ``discovery`` while discovery was its only caller. It was
moved here when collection also began speaking SNMP, so that collection would not have
to import from discovery and invert the layering. Collection no longer does — the route
walk that needed it has been removed, because the devices it existed for answer a route
command instead — so discovery is once again the only caller. The codec stays here
rather than moving back: it is a protocol, not a discovery detail, and moving it twice
would churn every import for no gain.

Nothing in this package can encode a SET (SRS §8). ``codec`` exposes no PDU builder for
one, and ``test_snmp_readonly.py`` asserts that the tag never appears in an encoded
packet.
"""

from netsecops.snmp.codec import (
    SNMP_PORT,
    SnmpError,
    VarBind,
    build_get,
    build_getbulk,
    build_getnext,
    decode_oid,
    encode_oid,
    parse_response,
    parse_varbinds,
)

__all__ = [
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
