"""Job and schedule request/response models (SEC-04)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from netsecops.db.models.jobs import JobType


class JobScopeInput(BaseModel):
    """How to express the target set (FR-JOB-01)."""

    device_ids: list[uuid.UUID] = Field(default_factory=list)
    group_ids: list[uuid.UUID] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    include_archived: bool = Field(
        default=False, description="Archived devices are excluded unless this is set"
    )

    @model_validator(mode="after")
    def _require_a_target(self) -> JobScopeInput:
        if not (self.device_ids or self.group_ids or self.tags):
            raise ValueError("Specify at least one of device_ids, group_ids or tags.")
        return self


class JobCreate(BaseModel):
    job_type: JobType
    scope: JobScopeInput
    idempotency_key: str | None = Field(
        default=None,
        max_length=128,
        description="Supply to make a retried request return the original job rather "
        "than starting a second run",
    )


class JobDeviceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    status: str
    #: FR-COL-07 classification, so a failure is triageable without reading logs.
    error_class: str | None
    error_message: str | None
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: int | None
    retries: int
    credential_id: uuid.UUID | None
    command_count: int


class JobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    job_type: str
    status: str
    scope: dict[str, Any]
    stats: dict[str, Any]
    requested_by_id: uuid.UUID | None
    schedule_id: uuid.UUID | None
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None
    cancel_requested_at: datetime | None
    correlation_id: str | None
    created_at: datetime


class JobDetail(JobRead):
    devices: list[JobDeviceRead] = Field(default_factory=list)


class PaginatedJobs(BaseModel):
    data: list[JobRead]
    meta: dict[str, int]


class JobProgress(BaseModel):
    """The WebSocket payload (FR-COL-12). Never carries device output or secrets."""

    job_id: str
    status: str
    percent: int
    total: int
    pending: int
    running: int
    succeeded: int
    failed: int
    cancelled: int


class ScheduleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    job_type: JobType
    scope: JobScopeInput
    cron: str = Field(min_length=1, max_length=100, examples=["0 2 * * *"])
    timezone: str = Field(default="UTC", max_length=64)
    description: str | None = None
    enabled: bool = True
    blackout: dict[str, Any] | None = Field(
        default=None, description="Windows during which this schedule must not fire"
    )


class ScheduleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=150)
    cron: str | None = Field(default=None, min_length=1, max_length=100)
    timezone: str | None = Field(default=None, max_length=64)
    description: str | None = None
    enabled: bool | None = None
    blackout: dict[str, Any] | None = None


class ScheduleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    job_type: str
    scope: dict[str, Any]
    cron: str
    timezone: str
    enabled: bool
    blackout: dict[str, Any] | None
    next_run_at: datetime | None
    last_run_at: datetime | None
    last_job_id: uuid.UUID | None
    created_at: datetime


__all__ = [
    "JobCreate",
    "JobDetail",
    "JobDeviceRead",
    "JobProgress",
    "JobRead",
    "JobScopeInput",
    "PaginatedJobs",
    "ScheduleCreate",
    "ScheduleRead",
    "ScheduleUpdate",
]
