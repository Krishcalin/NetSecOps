"""Collection artefacts, snapshots and findings (FR-COL-03, FR-DRIFT, SRS §5.1).

The split between these tables is deliberate:

- **artifacts** hold raw command output, encrypted, one row per command. They are the
  evidence: what the device actually said, hashed so it can be shown to have not been
  altered since.
- **snapshots** hold the *interpretation* — a configuration and the NCM parsed from it.
  Identical configurations de-duplicate to a single row (FR-DRIFT-01), so a device
  polled daily for a year that never changed costs one snapshot, not 365.
- **findings** are conclusions. Drift creates them in Phase 2; the check engine and the
  vulnerability matcher add their own kinds in Phases 3 and 6.
"""

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
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netsecops.db.base import Base, OrgMixin, TimestampMixin, UUIDPrimaryKeyMixin


class ArtifactKind(StrEnum):
    COMMAND = "command"
    API = "api"
    #: Uploaded by an operator rather than collected (FR-COL-11).
    UPLOAD = "upload"


class FindingKind(StrEnum):
    """Where a finding came from. The lifecycle is shared; the origins are not."""

    CONFIG = "config"
    VULN = "vuln"
    DRIFT = "drift"
    HOSTKEY = "hostkey"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    """FR-FIND-01 lifecycle."""

    NEW = "new"
    OPEN = "open"
    REOPENED = "reopened"
    RESOLVED = "resolved"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"

    @property
    def is_active(self) -> bool:
        return self in {FindingStatus.NEW, FindingStatus.OPEN, FindingStatus.REOPENED}


class Collection(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """One authenticated read session against a device (SRS §1.4)."""

    __tablename__ = "collections"
    __table_args__ = (Index("ix_collections_device_created", "device_id", "created_at"),)

    device_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    job_device_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("job_devices.id", ondelete="SET NULL")
    )

    adapter: Mapped[str] = mapped_column(String(64), nullable=False)
    adapter_version: Mapped[str | None] = mapped_column(String(32))

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    #: True when some commands failed. The collection is still stored and assessed,
    #: with the affected checks marked "Not evaluated — missing data" (FR-COL-08).
    partial: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    error_message: Mapped[str | None] = mapped_column(Text)

    artifacts: Mapped[list[Artifact]] = relationship(
        back_populates="collection", cascade="all, delete-orphan"
    )


class Artifact(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """Raw output of one command or API call (FR-COL-03).

    Two copies are kept, deliberately. ``response_encrypted`` is the original, sealed,
    used for hashing and diffing. ``response_redacted`` is what any UI or export shows
    (FR-COL-13) — so the ordinary path never moves a secret, and the unredacted view
    stays behind a distinct, audited permission (SEC-09).
    """

    __tablename__ = "artifacts"
    __table_args__ = (
        Index("ix_artifacts_collection_ordinal", "collection_id", "ordinal"),
        Index("ix_artifacts_sha256", "sha256"),
    )

    collection_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("collections.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default=ArtifactKind.COMMAND)

    #: The exact command or API call issued — the same text recorded in the audit log.
    request_text: Mapped[str] = mapped_column(Text, nullable=False)
    response_encrypted: Mapped[bytes] = mapped_column(nullable=False)
    response_redacted: Mapped[str] = mapped_column(Text, nullable=False)

    #: SHA-256 of the *original* response. Hashing the redacted copy would be useless:
    #: two different secrets redact to different placeholders only because the
    #: fingerprint differs, and the point of this hash is evidentiary integrity.
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    #: Position within the collection, so the command sequence is reconstructable.
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    succeeded: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )

    collection: Mapped[Collection] = relationship(back_populates="artifacts")


class Snapshot(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """A device's configuration at a point in time, plus its NCM (FR-DRIFT-01)."""

    __tablename__ = "snapshots"
    __table_args__ = (
        Index("ix_snapshots_device_created", "device_id", "created_at"),
        Index("ix_snapshots_config_hash", "device_id", "config_hash"),
        # At most one baseline per device (FR-DRIFT-03). A partial unique index is the
        # only way to say "unique among the rows where is_baseline is true".
        Index(
            "uq_snapshots_one_baseline_per_device",
            "device_id",
            unique=True,
            postgresql_where=text("is_baseline"),
        ),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    collection_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("collections.id", ondelete="SET NULL")
    )

    #: Hash of the configuration with volatile lines removed, so a timestamp that
    #: changes every poll does not read as a configuration change (FR-DRIFT-01).
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Hash of the NCM. Two configurations that differ only in comment or ordering may
    #: normalise to the same thing, which is worth knowing separately.
    normalized_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    #: The redacted configuration. The original lives in the artefact it came from.
    config_redacted: Mapped[str] = mapped_column(Text, nullable=False)
    ncm: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    ncm_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    parser_platform: Mapped[str | None] = mapped_column(String(64))
    #: How much of the configuration the parser understood, as a percentage. Surfaced
    #: so a low number is visible rather than silently degrading every check.
    parse_coverage: Mapped[int | None] = mapped_column(Integer)
    unparsed_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )

    is_baseline: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    baseline_pinned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    baseline_pinned_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    #: Set when an identical configuration was already stored; this row points at it
    #: rather than duplicating the text (FR-DRIFT-01).
    duplicate_of_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("snapshots.id", ondelete="SET NULL")
    )
    #: How many times this configuration has been seen, for a de-duplicated row.
    seen_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Finding(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """A conclusion about a device (FR-FIND-01).

    Phase 2 creates only drift findings; Phase 3 adds check results and Phase 6 adds
    vulnerability matches. The lifecycle is shared from the start so those phases
    extend this table rather than inventing parallel ones.
    """

    __tablename__ = "findings"
    __table_args__ = (
        # De-duplication key (FR-FIND-01): the same problem on the same device is one
        # finding with a last_seen and an occurrence count, not a new row per scan.
        UniqueConstraint("device_id", "fingerprint", name="uq_findings_device_fingerprint"),
        Index("ix_findings_status_severity", "status", "severity"),
        Index("ix_findings_device_kind", "device_id", "kind"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False)

    #: Stable identity for this problem on this device.
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)

    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default=FindingSeverity.MEDIUM
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False, default=FindingStatus.NEW)

    #: Filled in by later phases; declared now so the table does not need altering.
    check_id: Mapped[str | None] = mapped_column(String(100))
    cve_id: Mapped[str | None] = mapped_column(String(32))

    #: What the conclusion rests on: config excerpts, provenance, a diff.
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    remediation: Mapped[str | None] = mapped_column(Text)

    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("snapshots.id", ondelete="SET NULL")
    )

    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    occurrences: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )

    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def is_active(self) -> bool:
        return FindingStatus(self.status).is_active
