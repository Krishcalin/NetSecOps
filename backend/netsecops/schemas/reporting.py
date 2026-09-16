"""Report API payloads (FR-RPT-02, FR-RPT-03)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


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
    #: At most one scope. Both omitted means the whole estate.
    scope_device_id: uuid.UUID | None = None
    scope_group_id: uuid.UUID | None = None
    #: Required by the trend template, ignored by the others.
    compare_to_id: uuid.UUID | None = None


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
