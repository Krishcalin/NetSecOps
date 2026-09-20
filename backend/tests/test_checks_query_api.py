"""Drafting a check, and asking its language as a question (FR-CHK-06).

The check library is written in JMESPath over the NCM, and until now that language was
only reachable as a *saved control*. Two consequences, and both are friction in the same
place — the moment somebody is working out what a check should say:

* **Preview needed a check that already existed.** Its docstring says an operator should
  be able to iterate "without leaving a trail of findings that were never real", and it
  does avoid findings — but the check itself had to be created first, so the trail moved
  from findings into the library.
* **There was no way to ask "where does this hold".** A check answers pass or fail for
  one device. Finding out which devices an expression is even true of meant writing a
  check, assigning it to a policy, running an assessment and reading the results.

The tests below are mostly about what these must *not* do: write anything, or quietly
answer for a smaller estate than the one asked about.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.collection import Snapshot
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.db.models.policy import CustomCheck
from netsecops.services.inventory import InventoryService
from tests.conftest import make_user

PREVIEW = "/api/v1/checks/preview"
QUERY = "/api/v1/checks/query"

DRAFT: dict[str, Any] = {
    "id": "draft-aaa-new-model",
    "title": "AAA is enabled",
    "description": "A draft, not saved anywhere.",
    "rationale": "Checking the draft runs before it is part of the library.",
    "severity": "high",
    "applicability": {"vendors": ["cisco"], "platforms": ["cisco_ios"]},
    "logic": {"type": "ncm", "expression": "aaa.new_model", "assert": {"equals": True}},
    "remediation": "Configure `aaa new-model`.",
}


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="checks_query_actor", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
async def signed_in(session: AsyncSession, authenticate):
    user = await make_user(session, username="checks_query_api", roles={Role.SECURITY_ANALYST})
    await session.commit()
    authenticate(user)
    return user


async def add_device(
    session: AsyncSession,
    actor: Principal,
    *,
    ip: str,
    hostname: str,
    aaa: bool | None = True,
    snapshot: bool = True,
):
    device = await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=actor,
        hostname=hostname,
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )
    if snapshot:
        ncm: dict[str, Any] = {
            "ncm_version": "1.1",
            "device": {"vendor": "cisco", "platform": "cisco_ios", "hostname": hostname},
            "aaa": {} if aaa is None else {"new_model": aaa},
        }
        session.add(
            Snapshot(
                org_id=device.org_id,
                device_id=device.id,
                ncm=ncm,
                config_redacted="hostname " + hostname,
                config_hash=hostname,
                normalized_hash=hostname,
                parser_platform="cisco_ios",
            )
        )
    await session.flush()
    return device


@pytest.fixture
async def estate(session: AsyncSession, actor: Principal, signed_in):
    compliant = await add_device(session, actor, ip="10.30.0.1", hostname="sw-aaa-on", aaa=True)
    lacking = await add_device(session, actor, ip="10.30.0.2", hostname="sw-aaa-off", aaa=False)
    # Onboarded, never collected — the device a query must not silently drop.
    uncollected = await add_device(
        session, actor, ip="10.30.0.3", hostname="sw-never-read", snapshot=False
    )
    await session.commit()
    return {"compliant": compliant, "lacking": lacking, "uncollected": uncollected}


class TestDraftPreview:
    async def test_a_draft_runs_without_being_saved(self, client: AsyncClient, estate) -> None:
        response = await client.post(
            PREVIEW,
            json={"definition": DRAFT, "device_id": str(estate["compliant"].id)},
        )

        assert response.status_code == 200
        assert response.json()["outcome"] == "pass"

    async def test_the_same_draft_fails_where_it_should(self, client: AsyncClient, estate) -> None:
        response = await client.post(
            PREVIEW,
            json={"definition": DRAFT, "device_id": str(estate["lacking"].id)},
        )

        assert response.json()["outcome"] == "fail"

    async def test_nothing_is_written(
        self, client: AsyncClient, session: AsyncSession, estate
    ) -> None:
        """The whole point. A dry run that saves the check is not a dry run.

        Previewing by id required the check to exist first, so tuning one left a trail of
        half-finished checks in the library — the cost the dry run was introduced to
        avoid, relocated rather than removed.
        """
        before = (await session.execute(select(func.count()).select_from(CustomCheck))).scalar_one()

        await client.post(
            PREVIEW, json={"definition": DRAFT, "device_id": str(estate["compliant"].id)}
        )

        after = (await session.execute(select(func.count()).select_from(CustomCheck))).scalar_one()
        assert after == before

    async def test_an_invalid_definition_is_refused_not_crashed(
        self, client: AsyncClient, estate
    ) -> None:
        """Rejected by the same schema the loader uses, so a draft that previews can save."""
        response = await client.post(
            PREVIEW,
            json={
                "definition": {"id": "broken", "logic": {"type": "ncm"}},
                "device_id": str(estate["compliant"].id),
            },
        )

        assert response.status_code in (400, 422)
        assert response.status_code != 500

    async def test_a_device_with_no_snapshot_is_refused_with_a_reason(
        self, client: AsyncClient, estate
    ) -> None:
        response = await client.post(
            PREVIEW,
            json={"definition": DRAFT, "device_id": str(estate["uncollected"].id)},
        )

        assert response.status_code in (400, 422)
        assert "snapshot" in response.text.lower()


class TestEstateQuery:
    async def test_it_answers_for_every_device(self, client: AsyncClient, estate) -> None:
        response = await client.post(QUERY, json={"expression": "aaa.new_model"})

        assert response.status_code == 200
        body = response.json()
        by_host = {row["hostname"]: row for row in body["rows"]}
        assert by_host["sw-aaa-on"]["value"] is True
        assert by_host["sw-aaa-off"]["value"] is False

    async def test_a_device_that_could_not_be_asked_is_reported_not_dropped(
        self, client: AsyncClient, estate
    ) -> None:
        """The distinction the whole endpoint turns on.

        "No device has X" and "no device I could read has X" are different claims, and
        only one of them is true of an estate holding a device nobody has collected from.
        Dropping it would silently narrow the question.
        """
        body = (await client.post(QUERY, json={"expression": "aaa.new_model"})).json()
        by_host = {row["hostname"]: row for row in body["rows"]}

        assert "sw-never-read" in by_host
        assert by_host["sw-never-read"]["not_evaluated"] is not None
        assert body["devices_not_evaluated"] == 1

    async def test_matching_only_keeps_the_devices_it_could_not_ask(
        self, client: AsyncClient, estate
    ) -> None:
        """They are not matches, but they are not evidence of absence either."""
        body = (
            await client.post(QUERY, json={"expression": "aaa.new_model", "matching_only": True})
        ).json()
        hosts = {row["hostname"] for row in body["rows"]}

        assert "sw-aaa-on" in hosts
        assert "sw-aaa-off" not in hosts, "false is not a match"
        assert "sw-never-read" in hosts, "an unreadable device was filtered out as a non-match"

    async def test_a_bad_expression_is_refused_rather_than_raising(
        self, client: AsyncClient, estate
    ) -> None:
        response = await client.post(QUERY, json={"expression": "aaa..new_model["})

        assert response.status_code in (400, 422)
        assert response.status_code != 500

    async def test_the_platform_filter_narrows_the_estate(
        self, client: AsyncClient, estate
    ) -> None:
        body = (
            await client.post(QUERY, json={"expression": "aaa.new_model", "platforms": ["panos"]})
        ).json()

        assert body["rows"] == []

    async def test_the_expression_is_the_one_checks_are_written_in(
        self, client: AsyncClient, estate
    ) -> None:
        """One language for both, which is the point of building this at all.

        The expression that finds the devices you care about is the predicate you paste
        into a check — so a query and a check must agree about what it selects.
        """
        query = (await client.post(QUERY, json={"expression": DRAFT["logic"]["expression"]})).json()
        preview = (
            await client.post(
                PREVIEW, json={"definition": DRAFT, "device_id": str(estate["lacking"].id)}
            )
        ).json()

        by_host = {row["hostname"]: row for row in query["rows"]}
        assert by_host["sw-aaa-off"]["value"] is False
        assert preview["outcome"] == "fail"


class TestRouteOrdering:
    """`/checks/preview` and `/checks/query` are literal siblings of `/checks/{check_id}`.

    FastAPI matches in registration order. A check id is a plain string, so a
    parameterised route declared first would swallow both and answer 404 — which reads as
    "that endpoint does not exist" rather than as a routing mistake. The same trap is
    recorded for `/vulnerabilities/{cve_id}` and `/devices/pending-review`.
    """

    async def test_the_literal_routes_are_not_shadowed(self, client: AsyncClient, estate) -> None:
        preview = await client.post(
            PREVIEW, json={"definition": DRAFT, "device_id": str(estate["compliant"].id)}
        )
        query = await client.post(QUERY, json={"expression": "device.vendor"})

        assert preview.status_code == 200
        assert query.status_code == 200
