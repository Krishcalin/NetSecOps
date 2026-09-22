"""SNMP, read-only.

The BER codec lived under ``discovery`` while discovery was its only caller. Collection
now walks route tables from onboarded devices (SRS §8: "SNMP v2c/v3 GET only
(discovery/fingerprint & optional inventory), never SET"), and collection importing from
discovery would invert the layering — so the protocol lives here and both call in.

Nothing in this package can encode a SET. ``codec`` exposes no PDU builder for one, and
``test_snmp_readonly.py`` asserts that the tag never appears in an encoded packet.
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
from netsecops.snmp.routes import (
    IP_CIDR_ROUTE_TABLE,
    RouteWalk,
    parse_route_index,
    walk_routes,
)

__all__ = [
    "IP_CIDR_ROUTE_TABLE",
    "SNMP_PORT",
    "RouteWalk",
    "SnmpError",
    "VarBind",
    "build_get",
    "build_getbulk",
    "build_getnext",
    "decode_oid",
    "encode_oid",
    "parse_response",
    "parse_route_index",
    "parse_varbinds",
    "walk_routes",
]
