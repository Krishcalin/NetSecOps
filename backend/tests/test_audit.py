"""Audit log and hash-chain tests (FR-AUD-01, FR-AUD-02)."""

from __future__ import annotations

import uuid
from itertools import pairwise

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.db.models.audit import GENESIS_HASH, AuditAction, AuditLog, AuditOutcome
from netsecops.services.audit import AuditService


class TestChainConstruction:
    async def test_first_record_links_to_genesis(self, session: AsyncSession) -> None:
        entry = await AuditService(session).record(
            AuditAction.LOGIN_SUCCESS, actor_username="alice"
        )
        assert entry.prev_hash == GENESIS_HASH
        assert entry.verify()

    async def test_records_link_in_sequence(self, session: AsyncSession) -> None:
        service = AuditService(session)
        entries = [
            await service.record(AuditAction.LOGIN_SUCCESS, actor_username=f"u{i}")
            for i in range(5)
        ]

        for previous, current in pairwise(entries):
            assert current.prev_hash == previous.hash

    async def test_chain_verifies_clean(self, session: AsyncSession) -> None:
        service = AuditService(session)
        for i in range(10):
            await service.record(AuditAction.USER_CREATED, object_id=f"user-{i}")

        result = await service.verify_chain()
        assert result.valid
        assert result.total == 10

    async def test_empty_chain_is_valid(self, session: AsyncSession) -> None:
        result = await AuditService(session).verify_chain()
        assert result.valid and result.total == 0

    async def test_hash_covers_every_recorded_field(self, session: AsyncSession) -> None:
        entry = await AuditService(session).record(
            AuditAction.DEVICE_COMMAND,
            command_text="show running-config",
            device_id=uuid.uuid4(),
            details={"adapter": "cisco_iosxe"},
        )
        original = entry.hash

        # Mutating any covered field must change the computed hash.
        entry.command_text = "configure terminal"
        assert entry.compute_hash() != original
        assert not entry.verify()


class TestTamperDetection:
    async def test_altered_details_break_verification(self, session: AsyncSession) -> None:
        service = AuditService(session)
        for i in range(3):
            await service.record(AuditAction.LOGIN_SUCCESS, actor_username=f"u{i}")
        await session.flush()

        target = (
            await session.execute(select(AuditLog).order_by(AuditLog.id).limit(1))
        ).scalar_one()

        # Bypass the ORM and the append-only trigger to simulate direct database tampering.
        await session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_reject_update"))
        await session.execute(
            text("UPDATE audit_log SET actor_username = 'mallory' WHERE id = :id"),
            {"id": target.id},
        )
        await session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_reject_update"))
        session.expunge_all()

        result = await AuditService(session).verify_chain()
        assert not result.valid
        assert result.first_invalid_id == target.id
        assert result.reason is not None and "hash" in result.reason.lower()

    async def test_deleted_record_breaks_linkage(self, session: AsyncSession) -> None:
        service = AuditService(session)
        for i in range(4):
            await service.record(AuditAction.LOGIN_SUCCESS, actor_username=f"u{i}")
        await session.flush()

        ids = list(
            (await session.execute(select(AuditLog.id).order_by(AuditLog.id))).scalars().all()
        )

        await session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_reject_delete"))
        await session.execute(text("DELETE FROM audit_log WHERE id = :id"), {"id": ids[1]})
        await session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_reject_delete"))
        session.expunge_all()

        result = await AuditService(session).verify_chain()
        assert not result.valid
        assert result.first_invalid_id == ids[2]
        assert result.reason is not None and "linkage" in result.reason.lower()


class TestAppendOnlyEnforcement:
    """The migration's triggers must refuse mutation outright.

    Each attempt runs inside a savepoint: the trigger aborts the transaction it fires
    in, and without a savepoint that would tear down the fixture's outer transaction
    along with it.
    """

    @pytest.mark.parametrize(
        ("statement", "params"),
        [
            ("UPDATE audit_log SET action = 'tampered' WHERE id = :id", True),
            ("DELETE FROM audit_log WHERE id = :id", True),
            ("TRUNCATE audit_log", False),
        ],
        ids=["update", "delete", "truncate"],
    )
    async def test_mutation_is_rejected(
        self, session: AsyncSession, statement: str, params: bool
    ) -> None:
        entry = await AuditService(session).record(AuditAction.LOGIN_SUCCESS)
        await session.flush()

        savepoint = await session.begin_nested()
        with pytest.raises(DBAPIError, match="append-only"):
            await session.execute(text(statement), {"id": entry.id} if params else {})
        await savepoint.rollback()

    async def test_insert_is_still_allowed(self, session: AsyncSession) -> None:
        """The guard must block mutation without blocking the log itself."""
        service = AuditService(session)
        await service.record(AuditAction.LOGIN_SUCCESS)
        await service.record(AuditAction.LOGOUT)
        assert await service.count() == 2


class TestSecretScrubbing:
    """C-2 — secrets must not reach the audit table, even if a caller passes them."""

    async def test_password_in_details_is_redacted(self, session: AsyncSession) -> None:
        entry = await AuditService(session).record(
            AuditAction.CREDENTIAL_CREATED,
            details={"name": "core-switch-ro", "password": "hunter2", "type": "ssh_password"},
        )
        assert entry.details is not None
        assert entry.details["password"] == "***REDACTED***"
        assert entry.details["name"] == "core-switch-ro"

    async def test_sensitive_subtree_is_redacted_wholesale(self, session: AsyncSession) -> None:
        """A key that is itself secret-bearing takes its whole subtree with it."""
        entry = await AuditService(session).record(
            AuditAction.CREDENTIAL_TESTED,
            details={"device": {"host": "10.0.0.1", "credential": {"api_key": "abc123"}}},
        )
        assert entry.details is not None
        assert entry.details["device"]["credential"] == "***REDACTED***"
        assert entry.details["device"]["host"] == "10.0.0.1"

    async def test_secret_nested_under_innocuous_keys_is_redacted(
        self, session: AsyncSession
    ) -> None:
        entry = await AuditService(session).record(
            AuditAction.DEVICE_COMMAND,
            details={"adapter": {"transport": {"api_key": "abc123", "host": "10.0.0.1"}}},
        )
        assert entry.details is not None
        assert entry.details["adapter"]["transport"]["api_key"] == "***REDACTED***"
        assert entry.details["adapter"]["transport"]["host"] == "10.0.0.1"

    async def test_secret_inside_a_list_is_redacted(self, session: AsyncSession) -> None:
        entry = await AuditService(session).record(
            AuditAction.DEVICE_COMMAND,
            details={"servers": [{"host": "10.0.0.1", "shared_secret": "tacacs-key"}]},
        )
        assert entry.details is not None
        assert entry.details["servers"][0]["shared_secret"] == "***REDACTED***"
        assert entry.details["servers"][0]["host"] == "10.0.0.1"

    async def test_community_string_in_free_text_is_redacted(self, session: AsyncSession) -> None:
        entry = await AuditService(session).record(
            AuditAction.DEVICE_COMMAND,
            details={"note": "snmp-server community S3cr3tRO RO"},
        )
        assert entry.details is not None
        assert "S3cr3tRO" not in entry.details["note"]


class TestRecordFields:
    async def test_outcome_and_object_are_persisted(self, session: AsyncSession) -> None:
        object_id = uuid.uuid4()
        entry = await AuditService(session).record(
            AuditAction.ROLE_GRANTED,
            outcome=AuditOutcome.DENIED,
            object_type="user",
            object_id=object_id,
        )
        assert entry.outcome == AuditOutcome.DENIED.value
        assert entry.object_type == "user"
        assert entry.object_id == str(object_id)

    async def test_device_command_is_recorded_verbatim(self, session: AsyncSession) -> None:
        """FR-AUD-01 / SRS §8.1 item 8 — customers must see exactly what was executed."""
        entry = await AuditService(session).record(
            AuditAction.DEVICE_COMMAND,
            command_text="show running-config all",
            device_id=uuid.uuid4(),
        )
        assert entry.command_text == "show running-config all"

    async def test_count(self, session: AsyncSession) -> None:
        service = AuditService(session)
        for _ in range(3):
            await service.record(AuditAction.LOGIN_SUCCESS)
        assert await service.count() == 3
