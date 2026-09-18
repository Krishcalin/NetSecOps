"""Job engine tables (FR-JOB-01…06)."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netsecops.db.base import Base, OrgMixin, TimestampMixin, UUIDPrimaryKeyMixin


class JobType(StrEnum):
    """FR-JOB-01 — the scopes a run may take."""

    COLLECT = "collect"
    COLLECT_AND_ASSESS = "collect_and_assess"
    ASSESS_ONLY = "assess_only"
    VULN_REMATCH = "vuln_rematch"
    CREDENTIAL_TEST = "credential_test"
    DISCOVERY = "discovery"
    #: Pull vulnerability feeds from their publishers (FR-VUL-07). Like DISCOVERY, this
    #: targets no devices — it touches no customer equipment at all.
    FEED_SYNC = "feed_sync"
    #: Push findings and audit records to a SIEM (FR-INT-02). Also device-less, and the
    #: only job type whose traffic leaves the estate rather than staying inside it.
    SIEM_FORWARD = "siem_forward"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    SUCCEEDED = "succeeded"
    #: Finished, but at least one device failed.
    PARTIAL = "partial"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        return self in {
            JobStatus.CANCELLED,
            JobStatus.SUCCEEDED,
            JobStatus.PARTIAL,
            JobStatus.FAILED,
        }


class DeviceJobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class ErrorClass(StrEnum):
    """FR-COL-07 — failures are classified, because the remedy differs by class.

    "Unreachable" is a network problem, "authz denied" is a device-account problem, and
    "readonly violation" is a NetSecOps defect. Lumping them together would make the
    job history useless for triage.
    """

    UNREACHABLE = "unreachable"
    AUTH_FAILED = "auth_failed"
    AUTHZ_DENIED = "authz_denied"
    TIMEOUT = "timeout"
    PARSER_ERROR = "parser_error"
    UNSUPPORTED_VERSION = "unsupported_version"
    HOST_KEY_CHANGED = "host_key_changed"
    READONLY_VIOLATION = "readonly_violation"
    INTERNAL_ERROR = "internal_error"


class Job(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    __tablename__ = "jobs"
    __table_args__ = (
        Index("ix_jobs_status_created", "status", "created_at"),
        Index("ix_jobs_schedule", "schedule_id"),
    )

    job_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=JobStatus.QUEUED, index=True
    )

    #: How the target set was expressed: device ids, group ids, tags or a saved filter.
    #: Kept alongside the resolved job_devices so a re-run can re-resolve the scope.
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("schedules.id", ondelete="SET NULL")
    )

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    #: Counters maintained as devices complete, so the UI need not aggregate per poll.
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text)

    #: Set when a cancel is requested; workers check it between devices (FR-JOB-03).
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    #: Idempotency key from the caller, so a retried POST cannot start a second run.
    idempotency_key: Mapped[str | None] = mapped_column(String(128), unique=True)

    #: The correlation id of the request that created the job, carried into every
    #: device session so a finding traces back to the HTTP call (NFR-LOG-01).
    correlation_id: Mapped[str | None] = mapped_column(String(64), index=True)

    devices: Mapped[list[JobDevice]] = relationship(
        back_populates="job", cascade="all, delete-orphan"
    )

    @property
    def is_cancelling(self) -> bool:
        return self.cancel_requested_at is not None and not JobStatus(self.status).is_terminal


class JobDevice(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Per-device outcome within a job (FR-JOB-04)."""

    __tablename__ = "job_devices"
    __table_args__ = (
        Index("ix_job_devices_job_status", "job_id", "status"),
        Index("ix_job_devices_device", "device_id", "created_at"),
    )

    job_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )

    status: Mapped[str] = mapped_column(String(20), nullable=False, default=DeviceJobStatus.PENDING)
    error_class: Mapped[str | None] = mapped_column(String(32))
    error_message: Mapped[str | None] = mapped_column(Text)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    retries: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )

    #: Which credential actually worked, so the fallback list can be reordered later.
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("credentials.id", ondelete="SET NULL")
    )
    #: Commands issued during this device's session — the count only; the commands
    #: themselves live in the audit log (FR-AUD-01).
    command_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )

    job: Mapped[Job] = relationship(back_populates="devices")


class Schedule(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Recurring assessment (FR-JOB-02)."""

    __tablename__ = "schedules"
    __table_args__ = (Index("ix_schedules_enabled_next", "enabled", "next_run_at"),)

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    job_type: Mapped[str] = mapped_column(String(32), nullable=False)
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    cron: Mapped[str] = mapped_column(String(100), nullable=False)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, default="UTC")

    #: Windows during which the schedule must not fire — change freezes, business hours.
    blackout: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # jobs.schedule_id and schedules.last_job_id reference each other, so one side must
    # be added after both tables exist. use_alter defers this one; a schedule always
    # exists before the job it spawns, so this is the natural side to defer.
    last_job_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("jobs.id", ondelete="SET NULL", use_alter=True, name="fk_schedules_last_job_id"),
    )

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
