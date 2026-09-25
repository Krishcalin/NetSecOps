"""Snapshot, artefact and diff response models (FR-DRIFT-02, FR-COL-13, SEC-04).

Every field that could carry device output on the ordinary path carries the *redacted*
copy. The unredacted original has exactly one route out of the system — the artefact
raw endpoint — which is separately permissioned and separately audited (SEC-09). That
asymmetry is the point: a UI, an export or a screenshot cannot leak what the ordinary
response never contained.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SnapshotRead(BaseModel):
    """List view: metadata only, no configuration body."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    collection_id: uuid.UUID | None
    config_hash: str
    normalized_hash: str
    ncm_version: str
    parser_platform: str | None
    #: Percentage of meaningful configuration lines the parser understood. Surfaced so
    #: a degraded parse is visible rather than silently weakening every check.
    parse_coverage: int | None
    unparsed_count: int
    is_baseline: bool
    baseline_pinned_at: datetime | None
    seen_count: int
    last_seen_at: datetime | None
    created_at: datetime


class SnapshotDetail(SnapshotRead):
    """Detail view: the redacted configuration and the NCM (IF-UI-04)."""

    config_redacted: str
    ncm: dict[str, Any]


class PaginatedSnapshots(BaseModel):
    data: list[SnapshotRead]
    meta: dict[str, int]


class ArtifactRead(BaseModel):
    """One command's evidence, redacted."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    collection_id: uuid.UUID
    kind: str
    request_text: str
    #: SHA-256 of the *original* response, so integrity is checkable without exposing it.
    sha256: str
    size_bytes: int
    duration_ms: int | None
    ordinal: int
    succeeded: bool
    created_at: datetime


class ArtifactDetail(ArtifactRead):
    response: str = Field(description="The response with secrets replaced by placeholders")
    redacted: bool = True


class CollectionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    adapter: str
    adapter_version: str | None
    started_at: datetime | None
    finished_at: datetime | None
    #: True when some supplementary command failed. The snapshot is still valid; checks
    #: that needed the missing output report "Not evaluated" rather than passing.
    partial: bool
    error_message: str | None
    #: When retention removed this collection's artefacts (FR-ADM-01), or None if they
    #: are still here. Carried so an evidence view can say "removed on 3 May" instead of
    #: "this collection recorded no commands", which would read as a collector defect.
    artifacts_purged_at: datetime | None
    created_at: datetime


class SemanticChangeRead(BaseModel):
    """One NCM-level change, e.g. "management.services.telnet.enabled changed"."""

    path: str
    description: str


class DiffRead(BaseModel):
    """Text and semantic diff between two snapshots (FR-DRIFT-02).

    ``unified`` drives the unified view; ``before_lines``/``after_lines`` drive the
    side-by-side one. Both are built from the redacted configurations.
    """

    from_snapshot_id: uuid.UUID
    to_snapshot_id: uuid.UUID
    changed: bool
    added: list[str]
    removed: list[str]
    unified: str
    before_lines: list[str]
    after_lines: list[str]
    semantic: list[SemanticChangeRead]


class DriftRead(BaseModel):
    """A device's current position relative to its baseline (FR-DRIFT-03)."""

    device_id: uuid.UUID
    baseline_snapshot_id: uuid.UUID | None
    latest_snapshot_id: uuid.UUID | None
    changed: bool
    severity: str | None
    headline: str
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    semantic: list[SemanticChangeRead] = Field(default_factory=list)
    finding_id: uuid.UUID | None = None


class ConfigUploadResponse(BaseModel):
    """Result of an offline configuration upload (FR-COL-11)."""

    snapshot_id: uuid.UUID
    collection_id: uuid.UUID
    artifact_id: uuid.UUID
    #: True when this configuration was already stored; the existing snapshot is reused
    #: rather than a second identical copy being written (FR-DRIFT-01).
    deduplicated: bool
    parse_coverage: int | None
    unparsed_count: int
    drift: DriftRead


__all__ = [
    "ArtifactDetail",
    "ArtifactRead",
    "CollectionRead",
    "ConfigUploadResponse",
    "DiffRead",
    "DriftRead",
    "PaginatedSnapshots",
    "SemanticChangeRead",
    "SnapshotDetail",
    "SnapshotRead",
]
