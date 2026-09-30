"""Disaster-recovery sets: the record and the HA-fact resolver that suggests them.

The engine change that collapses a set into one node is a separate slice with its own
tests. These cover the data layer and the suggestion resolver: the invariants a set must
hold (exactly one primary, a device in at most one set), and that a suggestion is
derived from a real HA fact and never invented.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ConflictError, NotFoundError, ValidationProblem
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import User
from netsecops.db.models.audit import AuditAction, AuditLog
from netsecops.db.models.dr import DrRole
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.schemas.dr import DrMemberInput
from netsecops.services.dr import DrService
from netsecops.services.inventory import InventoryService
from tests.conftest import make_user

DR = "/api/v1/dr-sets"


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="dr_actor", roles={Role.SUPER_ADMIN})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def make_device(
    session: AsyncSession,
    actor: Principal,
    *,
    ip: str,
    hostname: str,
    ha: dict | None = None,
):
    device = await InventoryService(session).create_device(
        mgmt_ip=ip,
        actor=actor,
        hostname=hostname,
        vendor=Vendor.PALOALTO,
        platform="panos",
        device_class=DeviceClass.FIREWALL,
    )
    if ha is not None:
        device.facts = {"ha": ha}
        await session.flush()
    return device


def members(primary: uuid.UUID, standby: uuid.UUID) -> list[DrMemberInput]:
    return [
        DrMemberInput(device_id=primary, role=DrRole.PRIMARY),
        DrMemberInput(device_id=standby, role=DrRole.STANDBY),
    ]


class TestMigrationShape:
    @pytest.mark.parametrize(
        ("table", "index"),
        [
            ("dr_sets", "ix_dr_sets_org_id"),
            ("dr_set_members", "ix_dr_set_members_org_id"),
        ],
    )
    async def test_the_org_id_index_the_orm_declares_actually_exists(
        self, session: AsyncSession, table: str, index: str
    ) -> None:
        """OrgMixin declares index=True on org_id (DATA-04). Both tables must carry the
        index or the ORM and the database disagree — an autogenerate diff that fails the
        C-5 check, and an unindexed tenancy column on a table every scoped query filters.
        """
        rows = (
            await session.execute(
                text("SELECT indexname FROM pg_indexes WHERE tablename = :t"),
                {"t": table},
            )
        ).scalars().all()

        assert index in rows, f"{table} is missing {index}"


class TestTheRecordAndItsInvariants:
    async def test_a_set_reads_back_with_the_primary_first(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        a = await make_device(session, actor, ip="10.0.0.1", hostname="fw-a")
        b = await make_device(session, actor, ip="10.0.0.2", hostname="fw-b")

        created = await DrService(session).create_set(name="edge", members=members(a.id, b.id))

        assert [m.role for m in created.members] == ["primary", "standby"]
        assert created.members[0].device_id == a.id
        assert created.members[0].hostname == "fw-a"

        fetched = await DrService(session).get_set(created.id)
        assert {m.device_id for m in fetched.members} == {a.id, b.id}

    async def test_exactly_one_primary_is_required(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        a = await make_device(session, actor, ip="10.0.0.1", hostname="fw-a")
        b = await make_device(session, actor, ip="10.0.0.2", hostname="fw-b")

        with pytest.raises(ValidationProblem):
            await DrService(session).create_set(
                name="two-primaries",
                members=[
                    DrMemberInput(device_id=a.id, role=DrRole.PRIMARY),
                    DrMemberInput(device_id=b.id, role=DrRole.PRIMARY),
                ],
            )

    async def test_a_device_belongs_to_at_most_one_set(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        a = await make_device(session, actor, ip="10.0.0.1", hostname="fw-a")
        b = await make_device(session, actor, ip="10.0.0.2", hostname="fw-b")
        c = await make_device(session, actor, ip="10.0.0.3", hostname="fw-c")

        await DrService(session).create_set(name="first", members=members(a.id, b.id))

        with pytest.raises(ConflictError):
            await DrService(session).create_set(name="second", members=members(a.id, c.id))

    async def test_an_unknown_device_is_refused(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        a = await make_device(session, actor, ip="10.0.0.1", hostname="fw-a")

        with pytest.raises(NotFoundError):
            await DrService(session).create_set(
                name="ghost", members=members(a.id, uuid.uuid4())
            )

    async def test_a_duplicate_name_is_refused(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        a = await make_device(session, actor, ip="10.0.0.1", hostname="fw-a")
        b = await make_device(session, actor, ip="10.0.0.2", hostname="fw-b")
        c = await make_device(session, actor, ip="10.0.0.3", hostname="fw-c")
        d = await make_device(session, actor, ip="10.0.0.4", hostname="fw-d")

        await DrService(session).create_set(name="dup", members=members(a.id, b.id))
        with pytest.raises(ConflictError):
            await DrService(session).create_set(name="dup", members=members(c.id, d.id))

    async def test_delete_removes_the_set(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        a = await make_device(session, actor, ip="10.0.0.1", hostname="fw-a")
        b = await make_device(session, actor, ip="10.0.0.2", hostname="fw-b")
        created = await DrService(session).create_set(name="gone", members=members(a.id, b.id))

        await DrService(session).delete_set(created.id)

        assert await DrService(session).list_sets() == []


class TestSuggestionsFromHaFacts:
    async def test_an_ha_peer_is_resolved_to_a_suggestion(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        await make_device(
            session,
            actor,
            ip="10.0.0.1",
            hostname="fw-a",
            ha={"enabled": True, "role": "active", "peer": "fw-b"},
        )
        b = await make_device(session, actor, ip="10.0.0.2", hostname="fw-b")

        suggestions = await DrService(session).suggestions()

        assert len(suggestions) == 1
        roles = {m.hostname: m.role for m in suggestions[0].members}
        assert roles == {"fw-a": "primary", "fw-b": "standby"}
        assert b.hostname in suggestions[0].reason

    async def test_a_device_already_in_a_set_is_not_suggested(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        a = await make_device(
            session,
            actor,
            ip="10.0.0.1",
            hostname="fw-a",
            ha={"enabled": True, "role": "active", "peer": "fw-b"},
        )
        b = await make_device(session, actor, ip="10.0.0.2", hostname="fw-b")
        await DrService(session).create_set(name="already", members=members(a.id, b.id))

        assert await DrService(session).suggestions() == []

    async def test_an_unresolvable_peer_yields_no_suggestion(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        await make_device(
            session,
            actor,
            ip="10.0.0.1",
            hostname="fw-a",
            ha={"enabled": True, "role": "active", "peer": "not-in-inventory"},
        )

        assert await DrService(session).suggestions() == []


class TestTheApi:
    async def test_create_list_and_audit(
        self,
        client: AsyncClient,
        session: AsyncSession,
        actor: Principal,
        super_admin: User,
        authenticate,
    ) -> None:
        a = await make_device(session, actor, ip="10.1.0.1", hostname="api-a")
        b = await make_device(session, actor, ip="10.1.0.2", hostname="api-b")
        authenticate(super_admin)

        created = await client.post(
            DR,
            json={
                "name": "api-set",
                "members": [
                    {"device_id": str(a.id), "role": "primary"},
                    {"device_id": str(b.id), "role": "standby"},
                ],
            },
        )
        assert created.status_code == 201, created.text
        listed = (await client.get(DR)).json()
        assert [s["name"] for s in listed] == ["api-set"]

        entries = (await session.execute(select(AuditLog))).scalars().all()
        assert any(e.action == AuditAction.DR_SET_CREATED.value for e in entries)

    async def test_write_requires_device_write(
        self,
        client: AsyncClient,
        session: AsyncSession,
        actor: Principal,
        auditor: User,
        authenticate,
    ) -> None:
        a = await make_device(session, actor, ip="10.2.0.1", hostname="ro-a")
        b = await make_device(session, actor, ip="10.2.0.2", hostname="ro-b")
        authenticate(auditor)

        response = await client.post(
            DR,
            json={
                "name": "denied",
                "members": [
                    {"device_id": str(a.id), "role": "primary"},
                    {"device_id": str(b.id), "role": "standby"},
                ],
            },
        )
        assert response.status_code == 403

    async def test_suggestions_endpoint(
        self,
        client: AsyncClient,
        session: AsyncSession,
        actor: Principal,
        super_admin: User,
        authenticate,
    ) -> None:
        await make_device(
            session,
            actor,
            ip="10.3.0.1",
            hostname="sug-a",
            ha={"enabled": True, "role": "active", "peer": "sug-b"},
        )
        await make_device(session, actor, ip="10.3.0.2", hostname="sug-b")
        authenticate(super_admin)

        body = (await client.get(f"{DR}/suggestions")).json()
        assert len(body) == 1
        assert {m["hostname"] for m in body[0]["members"]} == {"sug-a", "sug-b"}
