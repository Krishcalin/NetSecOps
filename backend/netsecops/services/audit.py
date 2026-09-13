"""Audit service — writes and verifies the tamper-evident chain (FR-AUD-01, FR-AUD-02).

Chain integrity depends on appends being serialised: two concurrent writers that both
read the same tail would produce two records claiming the same ``prev_hash``, forking the
chain. A PostgreSQL transaction-scoped advisory lock serialises the read-tail/append pair
without locking the table for readers.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.logging import correlation_id, get_logger
from netsecops.core.logging import scrub_secrets as _scrub_processor
from netsecops.db.models.audit import (
    GENESIS_HASH,
    AuditAction,
    AuditLog,
    AuditOutcome,
)

log = get_logger(__name__)

#: Arbitrary but stable key for the advisory lock guarding audit appends.
_AUDIT_LOCK_KEY = 0x4E53_4F41  # "NSOA"


def _scrub(details: dict[str, Any] | None) -> dict[str, Any] | None:
    """Apply the same secret scrubbing used for logs before persisting details (C-2)."""
    if details is None:
        return None
    return dict(_scrub_processor(None, "", dict(details)))


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """Result of replaying the audit chain."""

    total: int
    valid: bool
    first_invalid_id: int | None = None
    reason: str | None = None


class AuditService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record(
        self,
        action: AuditAction,
        *,
        outcome: AuditOutcome = AuditOutcome.SUCCESS,
        actor_id: uuid.UUID | None = None,
        actor_username: str | None = None,
        token_id: uuid.UUID | None = None,
        object_type: str | None = None,
        object_id: str | uuid.UUID | None = None,
        details: dict[str, Any] | None = None,
        command_text: str | None = None,
        device_id: uuid.UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        org_id: int = 1,
    ) -> AuditLog:
        """Append one record, linking it to the current chain tail."""
        # Serialise appends for the remainder of this transaction.
        await self.session.execute(select(func.pg_advisory_xact_lock(_AUDIT_LOCK_KEY)))

        prev_hash = await self._tail_hash(org_id)

        entry = AuditLog(
            org_id=org_id,
            ts=datetime.now(UTC),
            actor_id=actor_id,
            actor_username=actor_username,
            token_id=token_id,
            action=action.value,
            outcome=outcome.value,
            object_type=object_type,
            object_id=str(object_id) if object_id is not None else None,
            details=_scrub(details),
            command_text=command_text,
            device_id=device_id,
            ip_address=ip_address,
            user_agent=user_agent,
            correlation_id=correlation_id.get(),
            prev_hash=prev_hash,
        )
        entry.hash = entry.compute_hash()

        self.session.add(entry)
        await self.session.flush()

        log.info(
            "audit.recorded",
            action=action.value,
            outcome=outcome.value,
            actor=actor_username,
            object_type=object_type,
            object_id=str(object_id) if object_id is not None else None,
        )
        return entry

    async def _tail_hash(self, org_id: int) -> str:
        result = await self.session.execute(
            select(AuditLog.hash)
            .where(AuditLog.org_id == org_id)
            .order_by(AuditLog.id.desc())
            .limit(1)
        )
        return result.scalar_one_or_none() or GENESIS_HASH

    async def verify_chain(self, org_id: int = 1, *, batch_size: int = 1000) -> ChainVerification:
        """Replay the chain, confirming every record's hash and linkage (FR-AUD-02).

        Streams in batches so verifying a multi-million-row log does not need to hold the
        whole table in memory.
        """
        expected_prev = GENESIS_HASH
        total = 0
        last_id = 0

        while True:
            rows: Sequence[AuditLog] = (
                (
                    await self.session.execute(
                        select(AuditLog)
                        .where(AuditLog.org_id == org_id, AuditLog.id > last_id)
                        .order_by(AuditLog.id.asc())
                        .limit(batch_size)
                    )
                )
                .scalars()
                .all()
            )
            if not rows:
                break

            for entry in rows:
                total += 1
                last_id = entry.id

                if entry.prev_hash != expected_prev:
                    return ChainVerification(
                        total=total,
                        valid=False,
                        first_invalid_id=entry.id,
                        reason=(
                            "Broken linkage: record references a predecessor hash that does "
                            "not match the previous record. A record was altered or removed."
                        ),
                    )
                if not entry.verify():
                    return ChainVerification(
                        total=total,
                        valid=False,
                        first_invalid_id=entry.id,
                        reason="Record contents do not match its stored hash.",
                    )
                expected_prev = entry.hash

        return ChainVerification(total=total, valid=True)

    async def count(self, org_id: int = 1) -> int:
        result = await self.session.execute(
            select(func.count()).select_from(AuditLog).where(AuditLog.org_id == org_id)
        )
        return int(result.scalar_one())
