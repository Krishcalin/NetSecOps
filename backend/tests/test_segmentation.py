"""Declared segmentation, checked against what the estate does (FR-TOPO-07).

This is the part of the product somebody signs, so the tests are mostly about the one
way it could be catastrophically wrong: **reporting a pass for something nobody
checked.**

A segmentation matrix is read as evidence of isolation. Every other failure mode here
is recoverable — a wrong red gets investigated, a missing row gets noticed — but a
green cell over a path that could not be traced is an assertion nobody will question
until the thing it claimed to prevent has happened. So `unverified` has its own status,
its own count, and a test for each way of arriving at it.

The second theme is that the evaluation is *path-centric*. A rule-centric check would
search each rulebase for a matching rule, which is wrong in both directions: a permit
on one firewall means nothing if a second denies the same traffic downstream, and a
permit assembled across two devices belongs to no single rule for a search to find.
`test_a_permit_assembled_across_two_devices_is_still_a_violation` is that assertion.
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ValidationProblem
from netsecops.core.rbac import Role
from netsecops.db.models import User
from netsecops.db.models.segmentation import SegmentationExpectation
from netsecops.ncm.models import Route
from netsecops.services.segmentation import CellStatus, SegmentationService
from netsecops.topology.graph import DeviceNode, build_graph
from tests.conftest import make_user

SEG = "/api/v1/segmentation"


def connected(prefix: str, interface: str) -> Route:
    return Route(destination=prefix, interface=interface, protocol="connected")


def static(prefix: str, via: str, interface: str | None = None) -> Route:
    return Route(destination=prefix, next_hop=via, interface=interface, protocol="static")


def permit_all() -> dict[str, Any]:
    return {"security_rules": [{"order": 1, "name": "permit-any", "action": "allow"}]}


def deny_to(prefix: str) -> dict[str, Any]:
    return {
        "security_rules": [
            {"order": 1, "name": "block", "action": "deny", "dst": [prefix]},
            {"order": 2, "name": "permit-rest", "action": "allow"},
        ]
    }


def node(
    hostname: str,
    *,
    routes: list[Route],
    addresses: dict[str, str],
    firewall: dict[str, Any] | None = None,
) -> DeviceNode:
    built = DeviceNode(
        device_id=uuid.uuid5(uuid.NAMESPACE_DNS, hostname),
        hostname=hostname,
        platform="cisco_asa" if firewall else "cisco_ios",
        ncm_version="1.1",
        routes=routes,
        has_rulebase=bool(firewall),
        firewall=firewall or {},
    )
    for interface, address in addresses.items():
        parsed = ipaddress.ip_interface(address)
        built.interface_addresses.add(int(parsed.ip))
        built.interface_networks.append((interface, parsed.network))
    return built


def two_tier(*, edge_firewall: dict[str, Any], core_firewall: dict[str, Any] | None = None):
    """prod 10.10.0.0/24 ── edge ── core ── cde 10.20.0.0/24."""
    edge = node(
        "edge-fw",
        addresses={"prod": "10.10.0.1/24", "up": "10.0.0.1/30"},
        routes=[
            connected("10.10.0.0/24", "prod"),
            connected("10.0.0.0/30", "up"),
            static("10.20.0.0/24", "10.0.0.2", "up"),
        ],
        firewall=edge_firewall,
    )
    core = node(
        "core-fw",
        addresses={"down": "10.0.0.2/30", "cde": "10.20.0.1/24"},
        routes=[connected("10.0.0.0/30", "down"), connected("10.20.0.0/24", "cde")],
        firewall=core_firewall,
    )
    return build_graph([edge, core])


@pytest.fixture
async def policy(session: AsyncSession):
    """Two zones and one rule: production must not reach the card environment."""
    service = SegmentationService(session)
    prod = await service.create_zone(name="Production", prefixes=["10.10.0.0/24"])
    cde = await service.create_zone(name="Cardholder data", prefixes=["10.20.0.0/24"])
    rule = await service.create_rule(
        source_zone_id=prod.id,
        destination_zone_id=cde.id,
        expectation=SegmentationExpectation.DENIED,
        justification="PCI DSS 1.2.1 — the CDE is not reachable from the general estate.",
    )
    await session.flush()
    return {"service": service, "prod": prod, "cde": cde, "rule": rule}


# ───────────────────── the property that matters most ─────────────────────


class TestUnverifiedIsNeverAPass:
    """A green cell over a path nobody could trace is the one unrecoverable failure.

    Every other mistake gets investigated. This one is an assertion of isolation that
    nobody questions until the thing it claimed to prevent has happened.
    """

    async def test_a_source_no_device_serves_is_unverified_not_upheld(
        self, session: AsyncSession, policy
    ) -> None:
        """Nothing in the inventory is attached to production, so the walk has no
        starting point. That says nothing about whether the traffic is blocked."""
        graph = build_graph(
            [
                node(
                    "lonely",
                    addresses={"lan": "192.168.0.1/24"},
                    routes=[connected("192.168.0.0/24", "lan")],
                )
            ]
        )

        result = await policy["service"].evaluate(graph)

        assert [cell.status for cell in result.cells] == [CellStatus.UNVERIFIED]
        assert result.upheld == 0
        assert result.unverified == 1

    async def test_a_device_with_no_route_data_is_unverified(
        self, session: AsyncSession, policy
    ) -> None:
        """A snapshot predating route parsing has no routes because nobody parsed any,
        not because there are none. Reading that as "unreachable, therefore separated"
        would turn a collection gap into a compliance pass."""
        edge = node(
            "edge-fw",
            addresses={"prod": "10.10.0.1/24", "up": "10.0.0.1/30"},
            routes=[],
            firewall=permit_all(),
        )
        edge.ncm_version = "1.0"

        result = await policy["service"].evaluate(build_graph([edge]))

        assert result.cells[0].status is CellStatus.UNVERIFIED
        assert result.unverified == 1

    async def test_the_summary_states_how_many_were_unverified(
        self, session: AsyncSession, policy
    ) -> None:
        """Said at the top, not only per cell. A reader scanning for red would take the
        absence of it as a pass."""
        result = await policy["service"].evaluate(build_graph([]))

        assert any("not passes" in note for note in result.limitations)

    async def test_an_empty_policy_says_so_rather_than_reporting_compliance(
        self, session: AsyncSession
    ) -> None:
        """Zero violations out of zero rules is not a clean estate."""
        result = await SegmentationService(session).evaluate(build_graph([]))

        assert result.cells == []
        assert any("not a clean one" in note for note in result.limitations)


# ─────────────────────────── the evaluation ───────────────────────────


class TestADeniedPairIsChecked:
    async def test_a_firewall_blocking_it_upholds_the_rule(
        self, session: AsyncSession, policy
    ) -> None:
        graph = two_tier(edge_firewall=deny_to("10.20.0.0/24"))

        result = await policy["service"].evaluate(graph)

        assert result.cells[0].status is CellStatus.UPHELD
        assert "denied" in result.cells[0].detail

    async def test_a_permit_assembled_across_two_devices_is_still_a_violation(
        self, session: AsyncSession, policy
    ) -> None:
        """The reason this is path-centric. No single rule permits production to reach
        the CDE — each firewall has its own unremarkable permit — and yet the packet
        gets there. A search of the rulebases finds nothing to flag."""
        graph = two_tier(edge_firewall=permit_all(), core_firewall=permit_all())

        result = await policy["service"].evaluate(graph)

        assert result.cells[0].status is CellStatus.VIOLATED
        assert "edge-fw" in result.cells[0].detail
        assert "core-fw" in result.cells[0].detail

    async def test_no_route_between_them_upholds_it_but_says_it_is_not_a_control(
        self, session: AsyncSession, policy
    ) -> None:
        """Separation by routing gap satisfies the intent and is worth distinguishing
        from a firewall denying it: no control is enforcing it, and the separation
        disappears the day somebody adds a static route."""
        isolated = node(
            "edge-fw",
            addresses={"prod": "10.10.0.1/24"},
            routes=[connected("10.10.0.0/24", "prod")],
            firewall=permit_all(),
        )

        result = await policy["service"].evaluate(build_graph([isolated]))

        assert result.cells[0].status is CellStatus.UPHELD
        assert "routing gap rather than a policy control" in result.cells[0].detail

    async def test_a_partial_permit_does_not_uphold_a_denial(
        self, session: AsyncSession, policy
    ) -> None:
        """`partially-allowed` means the permit speaks for the devices consulted and
        the path was not traced to the end. That is not proof of isolation."""
        # The core is missing from the inventory, so the path leaves the estate.
        edge = node(
            "edge-fw",
            addresses={"prod": "10.10.0.1/24", "up": "10.0.0.1/30"},
            routes=[
                connected("10.10.0.0/24", "prod"),
                connected("10.0.0.0/30", "up"),
                static("10.20.0.0/24", "10.0.0.2", "up"),
            ],
            firewall=permit_all(),
        )

        result = await policy["service"].evaluate(build_graph([edge]))

        assert result.cells[0].status is CellStatus.UNVERIFIED
        assert "not evidence of separation" in result.cells[0].detail


class TestAnAllowedPairIsChecked:
    @pytest.fixture
    async def allow_policy(self, session: AsyncSession):
        service = SegmentationService(session)
        web = await service.create_zone(name="Web", prefixes=["10.10.0.0/24"])
        db = await service.create_zone(name="Database", prefixes=["10.20.0.0/24"])
        await service.create_rule(
            source_zone_id=web.id,
            destination_zone_id=db.id,
            expectation=SegmentationExpectation.ALLOWED,
            justification="The web tier reads the application database over TLS.",
        )
        await session.flush()
        return service

    async def test_a_firewall_blocking_required_traffic_is_a_violation(
        self, session: AsyncSession, allow_policy
    ) -> None:
        """The direction people forget. An outage is a policy violation too, and it is
        the one nobody writes a matrix row for until it has happened twice."""
        graph = two_tier(edge_firewall=deny_to("10.20.0.0/24"))

        result = await allow_policy.evaluate(graph)

        assert result.cells[0].status is CellStatus.VIOLATED
        assert "requires it to be permitted" in result.cells[0].detail

    async def test_a_clean_path_upholds_it(self, session: AsyncSession, allow_policy) -> None:
        graph = two_tier(edge_firewall=permit_all(), core_firewall=permit_all())

        result = await allow_policy.evaluate(graph)

        assert result.cells[0].status is CellStatus.UPHELD

    async def test_no_route_at_all_violates_a_required_permit(
        self, session: AsyncSession, allow_policy
    ) -> None:
        isolated = node(
            "edge-fw",
            addresses={"prod": "10.10.0.1/24"},
            routes=[connected("10.10.0.0/24", "prod")],
            firewall=permit_all(),
        )

        result = await allow_policy.evaluate(build_graph([isolated]))

        assert result.cells[0].status is CellStatus.VIOLATED
        assert "cannot flow at all" in result.cells[0].detail


class TestTheWholeZoneIsChecked:
    async def test_the_range_is_walked_not_one_representative_address(
        self, session: AsyncSession, policy
    ) -> None:
        """Walking one address proves nothing about the other 254 while looking just as
        authoritative. The walk evaluates the range, so a rulebase treating part of it
        differently is visible."""
        graph = two_tier(edge_firewall=permit_all(), core_firewall=permit_all())

        result = await policy["service"].evaluate(graph)

        assert result.cells[0].walked == ["10.10.0.0/24 → 10.20.0.0/24"]

    @pytest.mark.parametrize(
        "prefixes",
        [
            # Both orderings, because the whole claim is that *position* does not
            # decide the cell. With only one ordering the test passes just as well
            # against an implementation that takes the last pair it walked — which is
            # exactly what the first version of this test did.
            ["10.20.0.0/24", "10.30.0.0/24"],
            ["10.30.0.0/24", "10.20.0.0/24"],
        ],
        ids=["violating-pair-last", "violating-pair-first"],
    )
    async def test_the_worst_prefix_pair_decides_the_cell(
        self, session: AsyncSession, prefixes: list[str]
    ) -> None:
        """A zone is a list of CIDRs, and the interesting combination is the one that
        behaves differently. Averaging it away — or letting whichever was walked last
        win — is how a matrix comes to show green over a hole."""
        service = SegmentationService(session)
        prod = await service.create_zone(name="Prod", prefixes=["10.10.0.0/24"])
        # Two destination prefixes: one the edge blocks, one it does not.
        cde = await service.create_zone(name="CDE", prefixes=prefixes)
        await service.create_rule(
            source_zone_id=prod.id,
            destination_zone_id=cde.id,
            expectation=SegmentationExpectation.DENIED,
            justification="Neither card network is reachable from production.",
        )
        await session.flush()

        edge = node(
            "edge-fw",
            addresses={"prod": "10.10.0.1/24", "up": "10.0.0.1/30"},
            routes=[
                connected("10.10.0.0/24", "prod"),
                connected("10.0.0.0/30", "up"),
                static("10.20.0.0/24", "10.0.0.2", "up"),
                static("10.30.0.0/24", "10.0.0.2", "up"),
            ],
            firewall=deny_to("10.20.0.0/24"),
        )
        core = node(
            "core-fw",
            addresses={"down": "10.0.0.2/30", "cde": "10.20.0.1/24", "other": "10.30.0.1/24"},
            routes=[
                connected("10.0.0.0/30", "down"),
                connected("10.20.0.0/24", "cde"),
                connected("10.30.0.0/24", "other"),
            ],
            firewall=permit_all(),
        )

        result = await service.evaluate(build_graph([edge, core]))

        # One pair is blocked and the other is not. The cell is a violation.
        assert result.cells[0].status is CellStatus.VIOLATED
        assert len(result.cells[0].walked) == 2


# ─────────────────────────── the policy itself ───────────────────────────


class TestDeclaringThePolicy:
    async def test_a_zone_with_an_unreadable_prefix_is_refused(self, session: AsyncSession) -> None:
        """Not stored and reported later as an unverifiable row: refused at the point
        somebody can still fix the typo."""
        with pytest.raises(ValidationProblem, match="not an address"):
            await SegmentationService(session).create_zone(
                name="Typo", prefixes=["10.10.0.0/24", "10.20.0.0/2x"]
            )

    async def test_a_zone_with_no_prefixes_is_refused(self, session: AsyncSession) -> None:
        with pytest.raises(ValidationProblem, match="at least one address range"):
            await SegmentationService(session).create_zone(name="Empty", prefixes=[])

    async def test_a_zone_cannot_be_segmented_from_itself(self, session: AsyncSession) -> None:
        """Intra-zone traffic crosses no boundary, so there is nothing to evaluate and
        the row would always read unverified."""
        service = SegmentationService(session)
        zone = await service.create_zone(name="Solo", prefixes=["10.10.0.0/24"])

        with pytest.raises(ValidationProblem, match="cannot be segmented from itself"):
            await service.create_rule(
                source_zone_id=zone.id,
                destination_zone_id=zone.id,
                expectation=SegmentationExpectation.DENIED,
                justification="This should never be stored, whatever it says here.",
            )


class TestTheApi:
    @pytest.fixture
    async def author(self, session: AsyncSession, authenticate) -> User:
        user = await make_user(session, username="seg_author", roles={Role.SECURITY_ANALYST})
        await session.commit()
        authenticate(user)
        return user

    async def test_a_zone_and_a_rule_round_trip(self, client: AsyncClient, author: User) -> None:
        prod = (
            await client.post(f"{SEG}/zones", json={"name": "Prod", "prefixes": ["10.10.0.0/24"]})
        ).json()
        cde = (
            await client.post(f"{SEG}/zones", json={"name": "CDE", "prefixes": ["10.20.0.0/24"]})
        ).json()

        created = await client.post(
            f"{SEG}/rules",
            json={
                "source_zone_id": prod["id"],
                "destination_zone_id": cde["id"],
                "expectation": "denied",
                "justification": "PCI DSS 1.2.1 — the CDE is not reachable from production.",
            },
        )

        assert created.status_code == 201
        listed = (await client.get(f"{SEG}/rules")).json()
        assert [r["expectation"] for r in listed] == ["denied"]

    async def test_a_justification_is_required(self, client: AsyncClient, author: User) -> None:
        """A matrix cell nobody can explain is one nobody dares change."""
        prod = (
            await client.post(f"{SEG}/zones", json={"name": "P", "prefixes": ["10.10.0.0/24"]})
        ).json()
        cde = (
            await client.post(f"{SEG}/zones", json={"name": "C", "prefixes": ["10.20.0.0/24"]})
        ).json()

        response = await client.post(
            f"{SEG}/rules",
            json={
                "source_zone_id": prod["id"],
                "destination_zone_id": cde["id"],
                "expectation": "denied",
                "justification": "too short",
            },
        )

        assert response.status_code == 422

    async def test_an_unknown_expectation_is_refused(
        self, client: AsyncClient, author: User
    ) -> None:
        """Only `allowed` and `denied`. A "these services only" form reads well and
        evaluates badly, so it is refused rather than silently approximated."""
        prod = (
            await client.post(f"{SEG}/zones", json={"name": "P2", "prefixes": ["10.10.0.0/24"]})
        ).json()
        cde = (
            await client.post(f"{SEG}/zones", json={"name": "C2", "prefixes": ["10.20.0.0/24"]})
        ).json()

        response = await client.post(
            f"{SEG}/rules",
            json={
                "source_zone_id": prod["id"],
                "destination_zone_id": cde["id"],
                "expectation": "allowed_services_only",
                "justification": "Long enough justification to satisfy validation here.",
            },
        )

        assert response.status_code == 422

    async def test_the_matrix_is_readable_on_an_empty_estate(
        self, client: AsyncClient, author: User
    ) -> None:
        body = (await client.get(f"{SEG}/matrix")).json()

        assert body["cells"] == []
        assert any("not a clean one" in note for note in body["limitations"])

    async def test_withdrawing_a_rule_removes_it_from_the_matrix(
        self, client: AsyncClient, author: User
    ) -> None:
        prod = (
            await client.post(f"{SEG}/zones", json={"name": "P3", "prefixes": ["10.10.0.0/24"]})
        ).json()
        cde = (
            await client.post(f"{SEG}/zones", json={"name": "C3", "prefixes": ["10.20.0.0/24"]})
        ).json()
        rule = (
            await client.post(
                f"{SEG}/rules",
                json={
                    "source_zone_id": prod["id"],
                    "destination_zone_id": cde["id"],
                    "expectation": "denied",
                    "justification": "Withdrawn in this test, long enough to validate.",
                },
            )
        ).json()

        assert (await client.delete(f"{SEG}/rules/{rule['id']}")).status_code == 204
        assert (await client.get(f"{SEG}/rules")).json() == []
