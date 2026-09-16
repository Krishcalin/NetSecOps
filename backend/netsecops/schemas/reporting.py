"""Report API payloads (FR-RPT-02, FR-RPT-03)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field


class TemplateRead(BaseModel):
    """One report template, and whether it can actually be generated yet.

    `implemented` is part of the contract rather than a footnote: a console that
    offered all nine and failed on six would teach an operator that the feature is
    unreliable, when in fact three work exactly as specified.
    """

    id: str
    title: str
    audience: str
    description: str
    implemented: bool


class ReportRead(BaseModel):
    """A report's identity and provenance — not its content."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    template: str
    title: str
    status: str
    scope_device_id: uuid.UUID | None = None
    scope_group_id: uuid.UUID | None = None
    compare_to_id: uuid.UUID | None = None
    #: SHA-256 of the frozen content. Null until the report is ready.
    content_hash: str | None = None
    generated_at: datetime | None = None
    expires_at: datetime | None = None
    error_message: str | None = None
    created_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def retention_expired(self) -> bool:
        """Past its retention date — and still here, deliberately.

        Nothing deletes a report. An auditor who asks for March's evidence cannot be
        told that a background job removed it, so retention is *reported* and acted on
        by a person. This flag is what makes that decision visible rather than silent;
        a report with no `expires_at` is never expired.
        """
        if self.expires_at is None:
            return False
        return self.expires_at < datetime.now(UTC)


class ReportDetail(ReportRead):
    """A report with its frozen content.

    The content is whatever was true when the report was generated, and is never
    recomputed — a finding resolved since does not disappear from it.
    """

    parameters: dict[str, Any] = Field(default_factory=dict)
    content: dict[str, Any] = Field(default_factory=dict)


class ReportCreate(BaseModel):
    template: str
    title: str | None = Field(default=None, max_length=300)
    #: At most one scope. Both omitted means the whole estate — but the single-device
    #: templates refuse that rather than silently widening: a "device detail" report
    #: over the estate answers a different question under the same title.
    scope_device_id: uuid.UUID | None = None
    scope_group_id: uuid.UUID | None = None
    #: Required by the trend template, ignored by the others.
    compare_to_id: uuid.UUID | None = None
    #: Required by the group-compliance template, ignored by the others. A compliance
    #: report with no framework is just a list of checks.
    framework: str | None = Field(default=None, max_length=60)


class PaginatedReports(BaseModel):
    data: list[ReportRead]
    meta: dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "PaginatedReports",
    "ReportCreate",
    "ReportDetail",
    "ReportRead",
    "TemplateRead",
]
