"""AAA posture and correlation endpoints (FR-AAA-05, FR-AAA-06).

The split between the reads and the write is the thing worth testing here. Loading a
dashboard must not write findings: if it did, the act of looking at the estate would
change its finding history, two people opening the page at once would race each other to
open and resolve the same rows, and a screenshot taken on Tuesday would not be
reproducible on Wednesday.

The rest is about the response carrying its own caveats. Every panel on this page can
reach zero because nobody collected the data, and a UI cannot render that honestly
unless the API tells it — which means ``None`` where the answer is unknown, and a
populated ``limitations`` list where the page is blind.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import Device, User
from netsecops.db.models.collection import Finding, FindingKind, Snapshot
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.services.inventory import InventoryService
from tests.conftest import make_user

POSTURE = "/api/v1/aaa/posture"
CORRELATION = "/api/v1/aaa/correlation"
ASSESS = "/api/v1/aaa/assess"


@pytest.fixture
async def analyst_user(session: AsyncSession) -> User:
    return await make_user(session, username="aaa_api_analyst", roles={Role.SECURITY_ANALYST})


@pytest.fixture
async def principal(analyst_user: User) -> Principal:
    return Principal(
        id=analyst_user.id,
        username=analyst_user.username,
        roles=analyst_user.role_set,
        scope=Scope.all(),
    )


async def add(
    session: AsyncSession,
    principal: Principal,
    *,
    ip: str,
    hostname: str,
    platform: str = "cisco_ios",
    device_class: DeviceClass = DeviceClass.SWITCH,
    vendor: Vendor = Vendor.CISCO,
) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=principal,
        hostname=hostname,
        vendor=vendor,
        platform=platform,
        device_class=device_class,
    )


async def snap(session: AsyncSession, device: Device, ncm: dict[str, Any]) -> Snapshot:
    digest = sha256(f"{device.id}{ncm}".encode()).hexdigest()
    row = Snapshot(
        org_id=device.org_id,
        device_id=device.id,
        ncm=ncm,
        config_redacted="",
        config_hash=digest,
        normalized_hash=digest,
    )
    session.add(row)
    await session.flush()
    return row


@pytest.fixture
async def estate(session: AsyncSession, principal: Principal, analyst_user: User, authenticate):
    """One ISE with an orphan and a weak protocol set, one switch with no AAA at all."""
    ise = await add(
        session,
        principal,
        ip="10.100.0.50",
        hostname="ise-01",
        platform="cisco_ise",
        device_class=DeviceClass.AAA_SERVER,
    )
    switch = await add(session, principal, ip="198.51.100.1", hostname="sw-a")

    await snap(
        session,
        ise,
        {
            "device": {},
            "aaa_server": {
                "product": "ise",
                "clients": [
                    {"name": "ghost-sw", "address": "10.88.0.1", "secret_configured": True}
                ],
                "allowed_protocols": ["EAP-TLS", "MS-CHAPv1"],
                "admin_mfa_enabled": False,
            },
            "certificates": [
                {
                    "name": "campus-eap",
                    "not_after": (datetime.now(UTC) + timedelta(days=12)).isoformat(),
                    "usage": ["EAP Authentication"],
                },
                {"name": "pxgrid", "not_after": "unknown"},
            ],
        },
    )
    await snap(session, switch, {"device": {}, "aaa": {"servers": []}})
    authenticate(analyst_user)
    return {"ise": ise, "switch": switch}


# ══════════════════════════ the posture read ════════════════════════════════


class TestPostureRead:
    async def test_the_four_panels_fr_aaa_06_asks_for_are_present(
        self, client: AsyncClient, estate: dict[str, Device]
    ) -> None:
        response = await client.get(POSTURE)
        assert response.status_code == 200
        body = response.json()

        # Coverage: one device assessable, using no central auth.
        assert body["coverage_percentage"] == 0
        assert body["devices_total"] == 2
        # Protocols, weak first.
        assert body["accepted_protocols"][0] == {
            "name": "MS-CHAPv1",
            "weak": True,
            "servers": ["ise-01"],
        }
        # Orphaned clients, via the correlation.
        assert [c["name"] for c in body["correlation"]["orphaned_clients"]] == ["ghost-sw"]
        # And the certificate expiry timeline.
        assert body["certificates"]["expiring_soon"] == 1
        assert body["certificates"]["undated"] == 1

    async def test_unknown_coverage_is_null_rather_than_zero(
        self,
        client: AsyncClient,
        session: AsyncSession,
        principal: Principal,
        analyst_user,
        authenticate,
    ) -> None:
        """The UI cannot render "unknown" honestly if the API has already collapsed it
        into a number. 0% sends someone to roll out TACACS+; null sends them to find out
        why nothing has been collected."""
        await add(session, principal, ip="198.51.100.9", hostname="sw-uncollected")
        authenticate(analyst_user)

        body = (await client.get(POSTURE)).json()

        assert body["coverage_percentage"] is None
        assert body["devices_not_evaluated"] == 1

    async def test_the_limitations_travel_with_the_data(
        self, client: AsyncClient, estate: dict[str, Device]
    ) -> None:
        """A footnote in documentation is not a caveat anyone reading the dashboard will
        see. The undated certificate and the masked ISE secret both have to surface."""
        body = (await client.get(POSTURE)).json()
        limitations = " ".join(body["limitations"])

        assert "could not interpret" in limitations
        assert "masked value" in limitations

    async def test_a_certificate_entry_names_its_device_and_usage(
        self, client: AsyncClient, estate: dict[str, Device]
    ) -> None:
        body = (await client.get(POSTURE)).json()
        entry = body["certificates"]["entries"][0]

        assert entry["name"] == "campus-eap"
        assert entry["device"] == "ise-01"
        assert entry["usage"] == ["EAP Authentication"]
        assert entry["days_remaining"] == 11

    async def test_the_horizons_are_stated_rather_than_assumed_by_the_ui(
        self, client: AsyncClient, estate: dict[str, Device]
    ) -> None:
        """The UI labels a column "expiring soon". If the threshold lived only in the
        frontend, changing it on the backend would relabel the column wrongly."""
        certificates = (await client.get(POSTURE)).json()["certificates"]

        assert certificates["soon_days"] == 30
        assert certificates["horizon_days"] == 90


class TestCorrelationRead:
    async def test_the_correlation_is_available_on_its_own(
        self, client: AsyncClient, estate: dict[str, Device]
    ) -> None:
        body = (await client.get(CORRELATION)).json()

        assert body["servers_examined"] == 1
        assert body["registration_analysed"] is True
        assert [c["name"] for c in body["orphaned_clients"]] == ["ghost-sw"]

    async def test_the_shared_secret_is_never_in_the_response(
        self, client: AsyncClient, estate: dict[str, Device]
    ) -> None:
        """C-2. The ISE client has a secret configured; only its existence may travel,
        and here not even a fingerprint, because ISE masks the value."""
        response = await client.get(CORRELATION)

        assert response.status_code == 200
        assert "secret_configured" not in response.text
        assert body_has_no_secret(response.text)
        # It is counted as unknowable rather than counted as unique.
        assert response.json()["secrets_not_exposable"] == 1


def body_has_no_secret(text: str) -> bool:
    return all(token not in text for token in ("shared_secret", "radiusSharedSecret", "********"))


# ═══════════════════════ reads do not write ═════════════════════════════════


class TestReadsDoNotWrite:
    async def test_loading_the_dashboard_writes_no_findings(
        self, client: AsyncClient, session: AsyncSession, estate: dict[str, Device]
    ) -> None:
        """The property this endpoint split exists for. A dashboard that wrote findings
        would mean the act of looking changed the history, and two operators refreshing
        it would race each other."""
        await client.get(POSTURE)
        await client.get(CORRELATION)

        rows = (
            (await session.execute(select(Finding).where(Finding.kind == FindingKind.AAA.value)))
            .scalars()
            .all()
        )
        assert list(rows) == []

    async def test_assessing_writes_them(
        self, client: AsyncClient, session: AsyncSession, estate: dict[str, Device]
    ) -> None:
        response = await client.post(ASSESS)
        assert response.status_code == 200

        rows = (
            (await session.execute(select(Finding).where(Finding.kind == FindingKind.AAA.value)))
            .scalars()
            .all()
        )
        assert len(rows) >= 1
        # The orphan lands on the server that named it, not on a device that does not
        # exist — there is no row for the ghost to attach to.
        orphan = next(row for row in rows if "ghost-sw" in row.title)
        assert orphan.device_id == estate["ise"].id

    async def test_assessing_returns_the_same_report_the_read_returns(
        self, client: AsyncClient, estate: dict[str, Device]
    ) -> None:
        """So a caller can act on the outcome without a second round trip, and so the
        two endpoints cannot drift into disagreeing about the same estate."""
        read = (await client.get(CORRELATION)).json()
        written = (await client.post(ASSESS)).json()

        assert read["orphaned_clients"] == written["orphaned_clients"]
        assert read["servers_examined"] == written["servers_examined"]


class TestEmptyEstate:
    async def test_an_estate_with_nothing_in_it_answers_rather_than_erroring(
        self, client: AsyncClient, analyst_user: User, authenticate
    ) -> None:
        authenticate(analyst_user)

        response = await client.get(POSTURE)

        assert response.status_code == 200
        body = response.json()
        assert body["devices_total"] == 0
        assert body["coverage_percentage"] is None
        assert body["certificates"]["entries"] == []
        assert body["correlation"]["registration_analysed"] is False
