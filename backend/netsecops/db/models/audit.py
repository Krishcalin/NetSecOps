"""Append-only, tamper-evident audit log (FR-AUD-01, FR-AUD-02).

Each row carries the hash of its predecessor, so altering or deleting any historical
record breaks every hash that follows it and is detectable by replaying the chain
(``netsecops-cli verify-audit-chain``).

FR-AUD-01 also requires recording every command sent to a device — the ``command_text``
column exists for that from Phase 1 onward. The device *response* is deliberately not
stored here: it routinely contains secrets, and lives encrypted in ``artifacts`` instead.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import DateTime, Index, String, Text, func
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from netsecops.db.base import Base, BigIntPrimaryKeyMixin, OrgMixin

#: Chain anchor — the ``prev_hash`` of the very first record.
GENESIS_HASH = "0" * 64


class AuditAction(StrEnum):
    """Auditable actions (FR-AUD-01). Extended as later phases add capability."""

    # Authentication
    LOGIN_SUCCESS = "login.success"
    LOGIN_FAILURE = "login.failure"
    LOGIN_LOCKED = "login.locked"
    LOGOUT = "logout"
    TOKEN_REFRESH = "token.refresh"  # noqa: S105
    TOKEN_REUSE_DETECTED = "token.reuse_detected"  # noqa: S105
    MFA_ENROLLED = "mfa.enrolled"
    MFA_CONFIRMED = "mfa.confirmed"
    MFA_DISABLED = "mfa.disabled"
    MFA_CHALLENGE_FAILED = "mfa.challenge_failed"
    PASSWORD_CHANGED = "password.changed"  # noqa: S105
    PASSWORD_RESET = "password.reset"  # noqa: S105

    # User & role administration
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    USER_DELETED = "user.deleted"
    USER_ACTIVATED = "user.activated"
    USER_DEACTIVATED = "user.deactivated"
    ROLE_GRANTED = "role.granted"
    ROLE_REVOKED = "role.revoked"
    SCOPE_CHANGED = "scope.changed"
    API_TOKEN_CREATED = "api_token.created"  # noqa: S105
    API_TOKEN_REVOKED = "api_token.revoked"  # noqa: S105
    API_TOKEN_USED = "api_token.used"  # noqa: S105

    # Credentials (Phase 1)
    CREDENTIAL_CREATED = "credential.created"
    CREDENTIAL_UPDATED = "credential.updated"
    CREDENTIAL_DELETED = "credential.deleted"
    CREDENTIAL_USED = "credential.used"
    CREDENTIAL_TESTED = "credential.tested"

    # Inventory & assessment (Phases 1-3)
    DEVICE_CREATED = "device.created"
    DEVICE_UPDATED = "device.updated"
    DEVICE_DELETED = "device.deleted"
    JOB_STARTED = "job.started"
    JOB_CANCELLED = "job.cancelled"
    JOB_COMPLETED = "job.completed"

    # Schedules (FR-JOB-02). Separate from job events: a schedule decides that something
    # will touch the estate repeatedly and unattended, which is a different decision from
    # running it once, and the audit trail should be able to answer "who set this up"
    # without inferring it from the first job it produced.
    SCHEDULE_CREATED = "schedule.created"
    SCHEDULE_UPDATED = "schedule.updated"
    SCHEDULE_DELETED = "schedule.deleted"

    # Baselines (Phase 2). Pinning decides what "drift" means for a device, so it is an
    # operator decision worth naming separately rather than folding into device.updated.
    BASELINE_PINNED = "baseline.pinned"
    BASELINE_CLEARED = "baseline.cleared"

    #: Every command or API call issued to a device (FR-AUD-01, SRS §8.1 item 8).
    DEVICE_COMMAND = "device.command"
    READONLY_VIOLATION = "device.readonly_violation"

    # Results
    FINDING_STATUS_CHANGED = "finding.status_changed"
    EXCEPTION_CREATED = "exception.created"
    EXCEPTION_EXPIRED = "exception.expired"

    # Platform
    SETTINGS_CHANGED = "settings.changed"
    REPORT_GENERATED = "report.generated"
    REPORT_DOWNLOADED = "report.downloaded"
    CONFIG_VIEWED_UNREDACTED = "config.viewed_unredacted"  # SEC-09
    FEED_SYNCED = "feed.synced"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"


class AuditLog(Base, BigIntPrimaryKeyMixin, OrgMixin):
    """One immutable audit record.

    There is no ``updated_at``: rows are never modified. A database-level rule enforcing
    append-only is applied by the migration.
    """

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_ts", "ts"),
        Index("ix_audit_log_actor_ts", "actor_id", "ts"),
        Index("ix_audit_log_action_ts", "action", "ts"),
        Index("ix_audit_log_object", "object_type", "object_id"),
    )

    # Indexed via __table_args__ above, not index=True, to avoid a duplicate definition.
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    # ── Actor ───────────────────────────────────────────────────────────────
    actor_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
    actor_username: Mapped[str | None] = mapped_column(String(150))
    #: Set instead of actor_id when the caller authenticated with an API token.
    token_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))

    # ── What happened ───────────────────────────────────────────────────────
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False, default=AuditOutcome.SUCCESS)
    object_type: Mapped[str | None] = mapped_column(String(50))
    object_id: Mapped[str | None] = mapped_column(String(255))
    #: Structured context. Scrubbed of secrets before insertion (C-2).
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    #: The exact command / API call sent to a device (FR-AUD-01). Never the response.
    command_text: Mapped[str | None] = mapped_column(Text)
    device_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))

    # ── Request context ─────────────────────────────────────────────────────
    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str | None] = mapped_column(String(64), index=True)

    # ── Tamper-evidence (FR-AUD-02) ─────────────────────────────────────────
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    def canonical_payload(self) -> str:
        """Deterministic serialisation of the fields the hash covers.

        Sorted keys and a fixed separator make the digest reproducible across processes
        and Python versions, which is what makes offline verification possible.
        """
        payload = {
            "ts": self.ts.isoformat() if self.ts else None,
            "org_id": self.org_id,
            "actor_id": str(self.actor_id) if self.actor_id else None,
            "actor_username": self.actor_username,
            "token_id": str(self.token_id) if self.token_id else None,
            "action": self.action,
            "outcome": self.outcome,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "details": self.details,
            "command_text": self.command_text,
            "device_id": str(self.device_id) if self.device_id else None,
            "ip_address": str(self.ip_address) if self.ip_address else None,
            "user_agent": self.user_agent,
            "correlation_id": self.correlation_id,
            "prev_hash": self.prev_hash,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)

    def compute_hash(self) -> str:
        return hashlib.sha256(self.canonical_payload().encode("utf-8")).hexdigest()

    def verify(self) -> bool:
        return self.hash == self.compute_hash()


class Setting(Base, OrgMixin):
    """Key/value platform settings (FR-ADM-01)."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(150), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
