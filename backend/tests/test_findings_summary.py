"""Finding counts by facet (FR-FIND-03).

The console drew a severity distribution by asking for one `limit=1` page per
severity and reading the totals off the envelopes — five round trips for one bar, and
five chances for the bands to come from five different moments. This is the one
request that replaces them.

Two properties are worth more than the arithmetic.

**The summary counts the same population as the list.** Same Device Group scoping,
same `active_only` default. A strip that totalled the estate above a table scoped to
the reader invites them to compare the two and conclude the product is broken.

**Every severity is present, including the empty ones.** A client drawing five bands
should not have to know the vocabulary and fill in the gaps, which is how a band
quietly goes missing.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import User
from netsecops.db.models.collection import Finding, FindingSeverity, FindingStatus
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.services.inventory import InventoryService
from tests.conftest import make_user

SUMMARY = "/api/v1/findings/summary"
LIST = "/api/v1/findings"


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user: User = await make_user(session, username="summary_actor", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
async def signed_in(session: AsyncSession, authenticate):
    user = await make_user(session, username="summary_reader", roles={Role.SECURITY_ANALYST})
    await session.commit()
    authenticate(user)
    return user


async def add_device(session: AsyncSession, actor: Principal, hostname: str, ip: str) -> Any:
    return await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=actor,
        hostname=hostname,
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )


def finding(device_id: uuid.UUID, severity: str, status: str, n: int) -> Finding:
    return Finding(
        org_id=1,
        device_id=device_id,
        kind="check",
        fingerprint=f"{severity}-{status}-{n}",
        title=f"{severity} finding {n}",
        severity=severity,
        status=status,
    )


@pytest.fixture
async def estate(session: AsyncSession, actor: Principal):
    """Two devices: five open findings across three severities, plus two resolved."""
    one = await add_device(session, actor, "sum-a", "10.70.0.1")
    two = await add_device(session, actor, "sum-b", "10.70.0.2")

    session.add_all(
        [
            finding(one.id, FindingSeverity.CRITICAL.value, FindingStatus.OPEN.value, 1),
            finding(one.id, FindingSeverity.HIGH.value, FindingStatus.NEW.value, 2),
            finding(one.id, FindingSeverity.HIGH.value, FindingStatus.REOPENED.value, 3),
            finding(two.id, FindingSeverity.LOW.value, FindingStatus.OPEN.value, 4),
            finding(two.id, FindingSeverity.LOW.value, FindingStatus.OPEN.value, 5),
            # Not active, so excluded by default — and the count that proves it.
            finding(two.id, FindingSeverity.CRITICAL.value, FindingStatus.RESOLVED.value, 6),
            finding(two.id, FindingSeverity.MEDIUM.value, FindingStatus.FALSE_POSITIVE.value, 7),
        ]
    )
    await session.commit()
    return {"one": one, "two": two}


class TestTheCounts:
    async def test_it_counts_open_findings_by_severity(
        self, client: AsyncClient, estate, signed_in
    ) -> None:
        body = (await client.get(SUMMARY)).json()

        assert body["total"] == 5
        assert body["by_severity"]["critical"] == 1
        assert body["by_severity"]["high"] == 2
        assert body["by_severity"]["low"] == 2

    async def test_every_severity_has_a_key_even_at_nought(
        self, client: AsyncClient, estate, signed_in
    ) -> None:
        """A client drawing five bands should not have to know the vocabulary. A
        missing key is a band that silently disappears from the bar."""
        body = (await client.get(SUMMARY)).json()

        assert set(body["by_severity"]) >= {s.value for s in FindingSeverity}
        assert body["by_severity"]["medium"] == 0
        assert body["by_severity"]["info"] == 0

    async def test_resolved_findings_are_excluded_by_default(
        self, client: AsyncClient, estate, signed_in
    ) -> None:
        """Matching the list's default. The dashboard's tiles link to
        `/findings?severity=…`, and a tile whose destination shows a different figure
        is worse than no tile."""
        body = (await client.get(SUMMARY)).json()

        assert body["total"] == 5
        assert "resolved" not in body["by_status"]
        assert "false_positive" not in body["by_status"]

    async def test_active_only_false_counts_the_whole_lifecycle(
        self, client: AsyncClient, estate, signed_in
    ) -> None:
        body = (await client.get(f"{SUMMARY}?active_only=false")).json()

        assert body["total"] == 7
        assert body["by_status"]["resolved"] == 1
        assert body["by_severity"]["medium"] == 1

    async def test_it_counts_devices_carrying_a_finding_not_the_estate(
        self, client: AsyncClient, estate, signed_in
    ) -> None:
        """A device with nothing open is not in here, and neither is one nobody has
        assessed — which is why this is not a coverage figure and is not named one."""
        body = (await client.get(SUMMARY)).json()

        assert body["devices_affected"] == 2

    async def test_the_lifecycle_split_sums_to_the_total(
        self, client: AsyncClient, estate, signed_in
    ) -> None:
        body = (await client.get(SUMMARY)).json()

        assert sum(body["by_status"].values()) == body["total"]
        assert sum(body["by_severity"].values()) == body["total"]


class TestItAgreesWithTheListItSummarises:
    """The property that makes the strip trustworthy above the table.

    Two endpoints counting the same thing differently is the failure nobody reports as
    a bug: the reader assumes they misread one of them.
    """

    async def test_each_severity_matches_the_filtered_list(
        self, client: AsyncClient, estate, signed_in
    ) -> None:
        body = (await client.get(SUMMARY)).json()

        for severity in ("critical", "high", "medium", "low", "info"):
            listed = (await client.get(f"{LIST}?severity={severity}&limit=1")).json()
            assert body["by_severity"][severity] == listed["meta"]["total"], severity

    async def test_the_total_matches_the_unfiltered_list(
        self, client: AsyncClient, estate, signed_in
    ) -> None:
        body = (await client.get(SUMMARY)).json()
        listed = (await client.get(f"{LIST}?limit=1")).json()

        assert body["total"] == listed["meta"]["total"]


class TestScope:
    async def test_it_counts_only_devices_the_reader_may_see(
        self, client: AsyncClient, session: AsyncSession, estate, authenticate
    ) -> None:
        """Same Device Group narrowing as the list. A summary over the whole estate
        shown to somebody scoped to part of it leaks the shape of the rest."""
        narrow = await make_user(session, username="summary_narrow", roles={Role.SECURITY_ANALYST})
        await session.commit()
        # Scoped to a group with nothing in it: every finding above belongs to a device
        # outside it, so the honest answer is nought rather than the estate's five.
        authenticate(narrow, scope=Scope(device_group_ids=frozenset({uuid.uuid4()})))

        body = (await client.get(SUMMARY)).json()

        assert body["total"] == 0
        assert body["devices_affected"] == 0
        # And the vocabulary is still complete, so the bar renders empty rather than
        # not at all.
        assert set(body["by_severity"]) >= {s.value for s in FindingSeverity}


class TestItIsOneRequest:
    async def test_the_route_is_not_swallowed_by_the_detail_path(
        self, client: AsyncClient, signed_in
    ) -> None:
        """`/findings/{finding_id}` is declared in the same router. Below it, this
        path would bind `summary` as an id and answer 422 for a route that exists."""
        response = await client.get(SUMMARY)

        assert response.status_code == 200, response.text
