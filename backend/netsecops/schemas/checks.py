"""Check, policy, finding and exception response models (SEC-04).

Findings travel further than any other object in this system: into exports, emails,
tickets and screenshots. Everything here therefore carries only what Phase 2 already
redacted — provenance excerpts and observed values drawn from the NCM — and never the
original configuration.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from netsecops.checks.schema import Outcome, Severity
from netsecops.db.models.policy import ExceptionScope


class CheckSummary(BaseModel):
    """A check as listed in the library view."""

    id: str
    title: str
    severity: Severity
    description: str
    tags: list[str] = Field(default_factory=list)
    #: `ncm`, `regex` or `python` — shown so an operator knows which they can edit.
    logic_type: str
    vendors: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    frameworks: dict[str, list[str]] = Field(default_factory=dict)
    enabled_by_default: bool = True
    is_custom: bool = False


class CheckDetail(CheckSummary):
    rationale: str
    remediation: str
    device_classes: list[str] = Field(default_factory=list)
    references: dict[str, Any] = Field(default_factory=dict)
    version: int = 1
    #: The JMESPath expression or pattern, so a reviewer can see what it actually tests.
    expression: str | None = None


class CheckResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    snapshot_id: uuid.UUID | None
    check_id: str
    check_version: int
    outcome: Outcome
    severity: Severity
    message: str
    #: Why a check was skipped: the missing NCM path or the applicability rule.
    reason: str | None
    evidence: dict[str, Any]
    duration_ms: int
    suppressed_by_id: uuid.UUID | None
    created_at: datetime


class PolicyCheckRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    check_id: str
    enabled: bool
    severity_override: str | None
    notes: str | None


class PolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    source: str
    version: int
    enabled: bool
    is_default: bool
    frameworks: list[str]
    created_at: datetime


class PolicyDetail(PolicyRead):
    entries: list[PolicyCheckRead] = Field(default_factory=list)


class PolicyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    description: str | None = None
    check_ids: list[str] = Field(min_length=1)
    frameworks: list[str] = Field(default_factory=list)


class PolicyCheckUpdate(BaseModel):
    enabled: bool | None = None
    severity_override: Severity | None = None


class PolicyAssign(BaseModel):
    device_group_id: uuid.UUID


class CustomCheckCreate(BaseModel):
    """A check written in the UI (FR-CHK-06).

    The definition is the same document the YAML library uses, validated against the
    same schema, so the editor cannot express anything the loader would reject.
    """

    definition: dict[str, Any]


class CustomCheckRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    check_id: str
    definition: dict[str, Any]
    enabled: bool
    created_at: datetime


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    device_id: uuid.UUID
    kind: str
    check_id: str | None
    cve_id: str | None
    title: str
    description: str | None
    severity: str
    status: str
    first_seen_at: datetime | None
    last_seen_at: datetime | None
    resolved_at: datetime | None
    occurrences: int
    assignee_id: uuid.UUID | None
    due_at: datetime | None
    created_at: datetime


class FindingDetail(FindingRead):
    """FR-FIND-04 — everything needed to act on a finding without leaving the page."""

    evidence: dict[str, Any]
    remediation: str | None
    snapshot_id: uuid.UUID | None
    rationale: str | None = None
    references: dict[str, Any] = Field(default_factory=dict)


class FindingUpdate(BaseModel):
    """FR-FIND-02 — triage fields an analyst sets."""

    status: str | None = None
    assignee_id: uuid.UUID | None = None
    due_at: datetime | None = None


class PaginatedFindings(BaseModel):
    data: list[FindingRead]
    meta: dict[str, int]


class ExceptionCreate(BaseModel):
    check_id: str
    scope: ExceptionScope = ExceptionScope.DEVICE
    device_id: uuid.UUID | None = None
    device_group_id: uuid.UUID | None = None
    #: Required. An exception with no stated reason is an undocumented decision.
    justification: str = Field(min_length=10, max_length=4000)
    approver: str | None = Field(default=None, max_length=150)
    #: Required, and must be in the future (FR-CHK-07).
    expires_at: datetime


class ExceptionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    check_id: str
    scope: str
    device_id: uuid.UUID | None
    device_group_id: uuid.UUID | None
    justification: str
    approver: str | None
    expires_at: datetime
    status: str
    created_at: datetime


class RiskRead(BaseModel):
    """A device's current risk position (FR-CHK-09)."""

    device_id: uuid.UUID
    score: int | None
    #: Passes as a share of what was actually decided — Not Applicable and Not
    #: Evaluated are in neither half.
    compliance_percent: int | None
    #: How much of the policy produced a verdict at all.
    coverage_percent: int | None
    checks_evaluated: int
    checks_passed: int
    checks_failed: int
    checks_not_evaluated: int
    components: dict[str, Any] = Field(default_factory=dict)
    assessed_at: datetime | None


class FrameworkControl(BaseModel):
    control: str
    checks: list[str]
    passed: int
    failed: int
    not_evaluated: int


class ComplianceRead(BaseModel):
    """A compliance view pivoted by framework (FR-CHK-05)."""

    framework: str
    device_count: int
    compliance_percent: int | None
    controls: list[FrameworkControl] = Field(default_factory=list)


class AssessmentPreview(BaseModel):
    """The FR-CHK-06 dry run: what a check would report, without storing anything."""

    check_id: str
    outcome: Outcome
    severity: Severity
    message: str
    reason: str | None
    evidence: dict[str, Any]


__all__ = [
    "AssessmentPreview",
    "CheckDetail",
    "CheckResultRead",
    "CheckSummary",
    "ComplianceRead",
    "CustomCheckCreate",
    "CustomCheckRead",
    "ExceptionCreate",
    "ExceptionRead",
    "FindingDetail",
    "FindingRead",
    "FindingUpdate",
    "FrameworkControl",
    "PaginatedFindings",
    "PolicyAssign",
    "PolicyCheckRead",
    "PolicyCheckUpdate",
    "PolicyCreate",
    "PolicyDetail",
    "PolicyRead",
    "RiskRead",
]
