"""Audit log HTTP endpoint tests (FR-AUD-01, FR-AUD-02).

These exist because the service-layer tests missed a real defect: they only ever wrote
records with ``ip_address=None``, so nothing exercised reading an INET column back
through the response model. asyncpg returns those as ``ipaddress`` objects, which the
schema rejected. The container caught it; these tests keep it caught.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Role
from netsecops.db.models.audit import AuditAction, AuditOutcome
from netsecops.services.audit import AuditService
from tests.conftest import make_user


@pytest.fixture
async def auditor_client(client: AsyncClient, session: AsyncSession, authenticate):
    authenticate(await make_user(session, username="audit_reader", roles={Role.AUDITOR}))
    return client


class TestListing:
    async def test_records_with_an_ip_address_serialise(
        self, auditor_client: AsyncClient, session: AsyncSession
    ) -> None:
        """Regression: INET round-trips as an ipaddress object, not a string."""
        await AuditService(session).record(
            AuditAction.LOGIN_SUCCESS,
            actor_username="alice",
            ip_address="192.0.2.10",
        )
        await session.flush()

        response = await auditor_client.get("/api/v1/audit-log")

        assert response.status_code == 200, response.text
        entry = response.json()["data"][0]
        assert entry["ip_address"] == "192.0.2.10"
        assert isinstance(entry["ip_address"], str)

    async def test_ipv6_address_serialises(
        self, auditor_client: AsyncClient, session: AsyncSession
    ) -> None:
        await AuditService(session).record(AuditAction.LOGIN_SUCCESS, ip_address="2001:db8::1")
        await session.flush()

        response = await auditor_client.get("/api/v1/audit-log")
        assert response.status_code == 200
        assert response.json()["data"][0]["ip_address"] == "2001:db8::1"

    async def test_null_ip_is_preserved(
        self, auditor_client: AsyncClient, session: AsyncSession
    ) -> None:
        await AuditService(session).record(AuditAction.LOGOUT)
        await session.flush()

        response = await auditor_client.get("/api/v1/audit-log")
        assert response.json()["data"][0]["ip_address"] is None

    async def test_full_record_round_trips(
        self, auditor_client: AsyncClient, session: AsyncSession
    ) -> None:
        """Every column the endpoint exposes must survive the round trip."""
        device_id = uuid.uuid4()
        await AuditService(session).record(
            AuditAction.DEVICE_COMMAND,
            actor_username="collector",
            object_type="device",
            object_id=device_id,
            details={"adapter": "cisco_iosxe"},
            command_text="show running-config",
            device_id=device_id,
            ip_address="198.51.100.7",
            user_agent="netsecops-worker/0.1.0",
        )
        await session.flush()

        entry = (await auditor_client.get("/api/v1/audit-log")).json()["data"][0]

        assert entry["action"] == "device.command"
        assert entry["command_text"] == "show running-config"
        assert entry["device_id"] == str(device_id)
        assert entry["object_type"] == "device"
        assert entry["details"] == {"adapter": "cisco_iosxe"}
        assert entry["hash"] and entry["prev_hash"]

    async def test_newest_first(self, auditor_client: AsyncClient, session: AsyncSession) -> None:
        service = AuditService(session)
        for name in ("first", "second", "third"):
            await service.record(AuditAction.LOGIN_SUCCESS, actor_username=name)
        await session.flush()

        data = (await auditor_client.get("/api/v1/audit-log")).json()["data"]
        assert [e["actor_username"] for e in data] == ["third", "second", "first"]

    async def test_pagination_meta(
        self, auditor_client: AsyncClient, session: AsyncSession
    ) -> None:
        service = AuditService(session)
        for i in range(7):
            await service.record(AuditAction.LOGIN_SUCCESS, actor_username=f"u{i}")
        await session.flush()

        body = (await auditor_client.get("/api/v1/audit-log?limit=3&offset=2")).json()

        assert body["meta"] == {"total": 7, "limit": 3, "offset": 2}
        assert len(body["data"]) == 3


class TestFiltering:
    async def test_filter_by_action(
        self, auditor_client: AsyncClient, session: AsyncSession
    ) -> None:
        service = AuditService(session)
        await service.record(AuditAction.LOGIN_SUCCESS, actor_username="a")
        await service.record(AuditAction.LOGIN_FAILURE, outcome=AuditOutcome.FAILURE)
        await session.flush()

        body = (await auditor_client.get("/api/v1/audit-log?action=login.failure")).json()

        assert body["meta"]["total"] == 1
        assert body["data"][0]["action"] == "login.failure"

    async def test_filter_by_outcome(
        self, auditor_client: AsyncClient, session: AsyncSession
    ) -> None:
        service = AuditService(session)
        await service.record(AuditAction.LOGIN_SUCCESS)
        await service.record(AuditAction.ROLE_GRANTED, outcome=AuditOutcome.DENIED)
        await session.flush()

        body = (await auditor_client.get("/api/v1/audit-log?outcome=denied")).json()
        assert body["meta"]["total"] == 1

    async def test_unmatched_filter_returns_empty(
        self, auditor_client: AsyncClient, session: AsyncSession
    ) -> None:
        await AuditService(session).record(AuditAction.LOGIN_SUCCESS)
        await session.flush()

        body = (await auditor_client.get("/api/v1/audit-log?action=nope.nothing")).json()
        assert body["data"] == [] and body["meta"]["total"] == 0


class TestVerification:
    async def test_verify_reports_a_clean_chain(
        self, auditor_client: AsyncClient, session: AsyncSession
    ) -> None:
        service = AuditService(session)
        for i in range(4):
            await service.record(AuditAction.LOGIN_SUCCESS, actor_username=f"u{i}")
        await session.flush()

        body = (await auditor_client.get("/api/v1/audit-log/verify")).json()

        assert body["valid"] is True
        assert body["total"] == 4
        assert body["first_invalid_id"] is None


class TestExport:
    async def test_csv_export(self, auditor_client: AsyncClient, session: AsyncSession) -> None:
        await AuditService(session).record(
            AuditAction.LOGIN_SUCCESS, actor_username="alice", ip_address="192.0.2.10"
        )
        await session.flush()

        response = await auditor_client.get("/api/v1/audit-log/export")

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        assert "attachment" in response.headers["content-disposition"]

        lines = response.text.strip().splitlines()
        assert lines[0].startswith("id,ts,actor_username,action")
        assert "alice" in lines[1]
