"""The SNMP route walk (FR-TOPO-01, SRS §8).

Tested against a fake agent that *encodes real responses* rather than a mocked decoder,
for the same reason the read-only suite runs a fake SSH device: a test that asserts on
what the parser was handed proves nothing about what the agent would actually send. The
agent here walks its MIB in numeric OID order, answers GETBULK and GETNEXT, and returns
`endOfMibView` at the end — so a codec defect surfaces here rather than in the field.

The cases that matter are the ones where a wrong answer looks like a clean one: an empty
table versus an unreachable agent, a reject route counted as forwarding, a truncated walk
reported as complete.
"""

from __future__ import annotations

import pytest

from netsecops.snmp.codec import (
    END_OF_MIB_VIEW,
    GET_BULK_REQUEST,
    GET_RESPONSE,
    INTEGER,
    IP_ADDRESS,
    OCTET_STRING,
    SEQUENCE,
    SnmpError,
    _integer,
    _length,
    _read_tlv,
    _tlv,
    build_getbulk,
    decode_oid,
    encode_oid,
    parse_varbinds,
)
from netsecops.snmp.routes import (
    IF_DESCR,
    IP_CIDR_ROUTE_IF_INDEX,
    IP_CIDR_ROUTE_PROTO,
    IP_CIDR_ROUTE_TYPE,
    parse_route_index,
    walk_routes,
)


def oid_key(oid: str) -> list[int]:
    """Numeric ordering. String ordering puts `.10` before `.9` and breaks every walk."""
    return [int(arc) for arc in oid.split(".")]


class FakeAgent:
    """An SNMP agent over a dict, speaking real BER.

    `max_repetitions` is honoured, `endOfMibView` is returned past the end, and the
    community is checked — all three are things a real agent does that a stub would not,
    and each has a corresponding way for the walk to be wrong.
    """

    def __init__(
        self,
        mib: dict[str, tuple[int, object]],
        *,
        community: str = "public",
        refuse_bulk: bool = False,
        stall: bool = False,
    ) -> None:
        self.mib = dict(sorted(mib.items(), key=lambda item: oid_key(item[0])))
        self.community = community
        self.refuse_bulk = refuse_bulk
        self.stall = stall
        self.requests = 0

    async def exchange(self, request: bytes) -> bytes:
        self.requests += 1
        kind, community, request_id, oids, repetitions = self._decode(request)

        if community != self.community:
            raise SnmpError("wrong community")
        if kind == GET_BULK_REQUEST and self.refuse_bulk:
            return self._error(request_id, status=5)  # genErr

        start = oids[0]
        count = repetitions if kind == GET_BULK_REQUEST else 1
        ordered = list(self.mib.items())

        bindings: list[tuple[str, int, object]] = []
        cursor = start
        for _ in range(count):
            # A stalling agent answers with the OID it was asked from instead of the one
            # after it, so the walk is handed a row it already has and never moves on.
            key = oid_key(cursor)
            nxt = next(
                (
                    item
                    for item in ordered
                    if (oid_key(item[0]) >= key if self.stall else oid_key(item[0]) > key)
                ),
                None,
            )
            if nxt is None:
                bindings.append((cursor, END_OF_MIB_VIEW, None))
                break
            oid, (tag, value) = nxt
            bindings.append((oid, tag, value))
            # A stalling agent repeats the same binding forever: the walk must notice
            # rather than spin until its packet budget runs out.
            cursor = start if self.stall else oid

        return self._response(request_id, bindings)

    # ── wire format ─────────────────────────────────────────────────────
    def _decode(self, request: bytes) -> tuple[int, str, int, list[str], int]:
        _, message, _ = _read_tlv(request, 0)
        _, _version, offset = _read_tlv(message, 0)
        _, community, offset = _read_tlv(message, offset)
        kind, pdu, _ = _read_tlv(message, offset)

        _, rid, offset = _read_tlv(pdu, 0)
        _, _a, offset = _read_tlv(pdu, offset)
        _, repetitions, offset = _read_tlv(pdu, offset)
        _, varbinds, _ = _read_tlv(pdu, offset)

        oids: list[str] = []
        cursor = 0
        while cursor < len(varbinds):
            _, binding, cursor = _read_tlv(varbinds, cursor)
            _, oid_bytes, _ = _read_tlv(binding, 0)
            oids.append(decode_oid(oid_bytes))

        return (
            kind,
            community.decode(),
            int.from_bytes(rid, "big"),
            oids,
            int.from_bytes(repetitions, "big"),
        )

    def _encode_value(self, tag: int, value: object) -> bytes:
        if tag == OCTET_STRING:
            return _tlv(OCTET_STRING, str(value).encode())
        if tag == INTEGER:
            return _integer(int(value))  # type: ignore[arg-type]
        if tag == IP_ADDRESS:
            return _tlv(IP_ADDRESS, bytes(int(p) for p in str(value).split(".")))
        return bytes([tag]) + _length(0)

    def _response(self, request_id: int, bindings: list[tuple[str, int, object]]) -> bytes:
        varbinds = b"".join(
            _tlv(SEQUENCE, encode_oid(oid) + self._encode_value(tag, value))
            for oid, tag, value in bindings
        )
        pdu = _tlv(
            GET_RESPONSE,
            _integer(request_id) + _integer(0) + _integer(0) + _tlv(SEQUENCE, varbinds),
        )
        return _tlv(SEQUENCE, _integer(1) + _tlv(OCTET_STRING, self.community.encode()) + pdu)

    def _error(self, request_id: int, *, status: int) -> bytes:
        pdu = _tlv(
            GET_RESPONSE,
            _integer(request_id) + _integer(status) + _integer(0) + _tlv(SEQUENCE, b""),
        )
        return _tlv(SEQUENCE, _integer(1) + _tlv(OCTET_STRING, self.community.encode()) + pdu)


def route_mib(
    rows: list[tuple[str, str, str, int, int, int]],
    interfaces: dict[int, str] | None = None,
) -> dict[str, tuple[int, object]]:
    """Build a MIB from ``(dest, mask, next_hop, if_index, type, proto)`` rows."""
    mib: dict[str, tuple[int, object]] = {}
    for dest, mask, next_hop, if_index, route_type, proto in rows:
        index = f"{dest}.{mask}.0.{next_hop}"
        mib[f"{IP_CIDR_ROUTE_IF_INDEX}.{index}"] = (INTEGER, if_index)
        mib[f"{IP_CIDR_ROUTE_TYPE}.{index}"] = (INTEGER, route_type)
        mib[f"{IP_CIDR_ROUTE_PROTO}.{index}"] = (INTEGER, proto)
    for number, name in (interfaces or {}).items():
        mib[f"{IF_DESCR}.{number}"] = (OCTET_STRING, name)
    return mib


ESTATE = route_mib(
    [
        # default route, learned by BGP, via 10.0.0.1 on the first interface
        ("0.0.0.0", "0.0.0.0", "10.0.0.1", 1, 4, 14),
        # a connected /24
        ("10.10.10.0", "255.255.255.0", "0.0.0.0", 2, 3, 2),
        # an OSPF route two hops away
        ("10.20.0.0", "255.255.0.0", "10.0.0.9", 1, 4, 13),
        # a configured black hole
        ("192.168.99.0", "255.255.255.0", "0.0.0.0", 1, 2, 3),
    ],
    interfaces={1: "GigabitEthernet0/0", 2: "Vlan10"},
)


# ════════════════════════════ the codec ═══════════════════════════════════


class TestTheCodec:
    def test_oid_round_trips_including_the_packed_first_arcs(self) -> None:
        for oid in ("1.3.6.1.2.1.4.24.4.1.7", "1.3.6.1.2.1.2.2.1.2.1", "1.3.6.1.4.1.9.1.1745"):
            _, body, _ = _read_tlv(encode_oid(oid), 0)
            assert decode_oid(body) == oid

    def test_an_arc_over_127_uses_multibyte_encoding(self) -> None:
        # 1745 is a real Cisco sysObjectID arc. A single-byte encoder silently truncates
        # it and asks for a different object.
        _, body, _ = _read_tlv(encode_oid("1.3.6.1.4.1.9.1.1745"), 0)
        assert decode_oid(body) == "1.3.6.1.4.1.9.1.1745"

    def test_length_boundary_at_128(self) -> None:
        assert _length(127) == bytes([127])
        assert _length(128) == bytes([0x81, 128])

    def test_a_malformed_oid_is_refused(self) -> None:
        with pytest.raises(SnmpError):
            encode_oid("not-an-oid")

    def test_getbulk_caps_max_repetitions(self) -> None:
        with pytest.raises(SnmpError):
            build_getbulk("public", ("1.3.6.1",), 1, max_repetitions=5000)

    def test_there_is_no_set_pdu(self) -> None:
        """The read-only guarantee, as an absence rather than a check (SRS §8)."""
        import netsecops.snmp.codec as codec

        builders = [name for name in dir(codec) if name.startswith("build_")]
        assert sorted(builders) == ["build_get", "build_getbulk", "build_getnext"]

        # 0xA3 is SetRequest. It must not appear in any packet this module can produce.
        for packet in (
            codec.build_get("c", ("1.3.6.1",), 1),
            codec.build_getnext("c", ("1.3.6.1",), 1),
            codec.build_getbulk("c", ("1.3.6.1",), 1),
        ):
            assert 0xA3 not in packet

    def test_an_agent_error_raises_rather_than_returning_empty(self) -> None:
        """An error and an empty table must never decode to the same thing."""
        agent = FakeAgent({})
        with pytest.raises(SnmpError, match="error-status 5"):
            parse_varbinds(agent._error(1, status=5))

    def test_end_of_mib_keeps_its_tag(self) -> None:
        agent = FakeAgent({})
        bindings = parse_varbinds(agent._response(1, [("1.3.6.1", END_OF_MIB_VIEW, None)]))
        assert bindings[0].is_end_of_mib


# ════════════════════════════ the index ═══════════════════════════════════


class TestTheRouteIndex:
    def test_destination_mask_and_next_hop_come_out_of_the_oid(self) -> None:
        parsed = parse_route_index(
            f"{IP_CIDR_ROUTE_PROTO}.10.20.0.0.255.255.0.0.0.10.0.0.9",
            column=IP_CIDR_ROUTE_PROTO,
        )
        assert parsed == ("10.20.0.0", "255.255.0.0", "10.0.0.9")

    def test_a_row_of_the_wrong_shape_is_skipped_not_part_parsed(self) -> None:
        assert (
            parse_route_index(f"{IP_CIDR_ROUTE_PROTO}.10.20.0.0", column=IP_CIDR_ROUTE_PROTO)
            is None
        )

    def test_an_oid_outside_the_column_is_refused(self) -> None:
        assert parse_route_index(f"{IF_DESCR}.1", column=IP_CIDR_ROUTE_PROTO) is None


# ════════════════════════════ the walk ════════════════════════════════════


@pytest.mark.asyncio
class TestTheWalk:
    async def test_reads_a_whole_table_with_protocols_and_interfaces(self) -> None:
        walk = await walk_routes(FakeAgent(ESTATE), "public")

        assert walk.table_present
        assert not walk.truncated
        by_destination = {route.destination: route for route in walk.routes}

        assert set(by_destination) == {"0.0.0.0/0", "10.10.10.0/24", "10.20.0.0/16"}
        assert by_destination["0.0.0.0/0"].next_hop == "10.0.0.1"
        assert by_destination["0.0.0.0/0"].protocol == "bgp"
        assert by_destination["0.0.0.0/0"].interface == "GigabitEthernet0/0"
        assert by_destination["10.20.0.0/16"].protocol == "ospf"
        assert by_destination["10.10.10.0/24"].interface == "Vlan10"

    async def test_a_connected_route_reports_no_next_hop_rather_than_0_0_0_0(self) -> None:
        walk = await walk_routes(FakeAgent(ESTATE), "public")
        connected = next(r for r in walk.routes if r.destination == "10.10.10.0/24")

        assert connected.next_hop is None
        assert connected.protocol == "connected"

    async def test_a_reject_route_is_excluded_and_counted(self) -> None:
        """A black hole and a missing route are different answers to a path question."""
        walk = await walk_routes(FakeAgent(ESTATE), "public")

        assert "192.168.99.0/24" not in {route.destination for route in walk.routes}
        assert walk.rejected == 1

    async def test_an_empty_table_is_not_a_failure(self) -> None:
        walk = await walk_routes(FakeAgent({}), "public")

        assert walk.table_present is True
        assert walk.routes == ()
        assert walk.note is None

    async def test_an_unreachable_agent_is_not_an_empty_table(self) -> None:
        """The distinction this whole result type exists for."""
        walk = await walk_routes(FakeAgent(ESTATE, community="other"), "public")

        assert walk.table_present is False
        assert walk.routes == ()
        assert walk.note is not None

    async def test_it_falls_back_to_getnext_when_the_agent_refuses_getbulk(self) -> None:
        agent = FakeAgent(ESTATE, refuse_bulk=True)
        walk = await walk_routes(agent, "public")

        assert len(walk.routes) == 3

    async def test_a_stalling_agent_is_refused_rather_than_walked_forever(self) -> None:
        walk = await walk_routes(FakeAgent(ESTATE, stall=True), "public", max_packets=50)

        assert walk.routes == ()
        assert walk.note is not None
        # And it stopped immediately rather than burning the whole packet budget.
        assert walk.packets < 5

    async def test_truncation_is_reported_not_silent(self) -> None:
        walk = await walk_routes(FakeAgent(ESTATE), "public", max_routes=2)

        assert walk.truncated is True
        assert len(walk.routes) <= 2

    async def test_a_packet_budget_bounds_the_walk(self) -> None:
        agent = FakeAgent(ESTATE)
        walk = await walk_routes(agent, "public", max_packets=1)

        assert walk.truncated is True
        assert agent.requests <= 1

    async def test_interfaces_can_be_skipped_without_losing_the_routes(self) -> None:
        walk = await walk_routes(FakeAgent(ESTATE), "public", with_interfaces=False)

        assert len(walk.routes) == 3
        assert all(route.interface is None for route in walk.routes)

    async def test_a_non_contiguous_mask_is_dropped_rather_than_coerced(self) -> None:
        mib = route_mib([("10.0.0.0", "255.0.255.0", "10.0.0.1", 1, 4, 13)])
        walk = await walk_routes(FakeAgent(mib), "public")

        # It cannot be written in CIDR, and inventing a prefix would match addresses the
        # device does not route.
        assert walk.routes == ()
        assert walk.table_present is True
