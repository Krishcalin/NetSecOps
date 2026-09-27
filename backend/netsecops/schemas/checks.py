"""Check, policy, finding and exception response models (SEC-04).

Findings travel further than any other object in this system: into exports, emails,
tickets and screenshots. Everything here therefore carries only what Phase 2 already
redacted — provenance excerpts and observed values drawn from the NCM — and never the
original configuration.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
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


class DraftPreviewRequest(BaseModel):
    """Run a check that has not been saved (FR-CHK-06).

    Preview by id can only run a check that already exists, so tuning one meant creating
    it first and editing it in place — leaving a trail of half-finished checks in the
    library, which is the thing the dry run was meant to avoid. The definition travels in
    the request instead, and nothing is written.
    """

    definition: dict[str, Any]
    device_id: uuid.UUID


class EstateQueryRequest(BaseModel):
    """One expression, asked of every device in scope.

    The same JMESPath the check library is written in, run as an ad-hoc question rather
    than as a saved control: "which devices have this set, and to what". A check answers
    pass or fail for one device; this answers "where does this hold" across the estate,
    which is the question asked while an operator is still working out what the check
    should say.
    """

    expression: str = Field(min_length=1, max_length=500)
    #: Narrow by platform, for an expression that only means something on some of them.
    platforms: list[str] = Field(default_factory=list)
    #: Return only devices where the expression selected something.
    matching_only: bool = False
    limit: int = Field(default=200, ge=1, le=1000)


class EstateQueryRow(BaseModel):
    """What one device answered."""

    device_id: uuid.UUID
    hostname: str | None = None
    platform: str | None = None
    #: What the expression selected. `null` means it selected nothing, which is a real
    #: answer and different from the device below not having been asked.
    value: Any = None
    #: Set when the device could not be asked at all — no snapshot, or one this
    #: expression could not be run against. Never silently omitted: a query for "which
    #: devices have X" that drops the devices it could not read answers a narrower
    #: question than the one asked, and reads as though it answered the whole estate.
    not_evaluated: str | None = None


class EstateQueryResponse(BaseModel):
    expression: str
    #: Devices in scope that the query considered, before `matching_only` filtering.
    devices_considered: int = 0
    #: How many could not be asked. A non-zero count here is the reader's warning that
    #: the rows below do not describe the whole estate.
    devices_not_evaluated: int = 0
    rows: list[EstateQueryRow] = Field(default_factory=list)


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


class FindingSummary(BaseModel):
    """Counts by facet, over everything the caller may see (FR-FIND-03).

    Exists because a console drawing a severity distribution otherwise asks for one
    `limit=1` page per severity and reads the totals off the envelopes — five round
    trips to render one bar, and five chances for the figures to come from five
    slightly different moments.

    **Every facet is counted over the same set**, which is the set the list endpoint
    returns under the same `active_only`. A summary computed over a different
    population from the table beneath it is worse than no summary: the reader compares
    them and one of the two is wrong.
    """

    total: int = 0
    #: Severity → count. Severities with no findings are present and zero, so a client
    #: can draw a five-band bar without inventing the missing keys.
    by_severity: dict[str, int] = Field(default_factory=dict)
    #: Lifecycle status → count. Only statuses actually present appear; unlike
    #: severity, the set is open and a zero for every unused one would be noise.
    by_status: dict[str, int] = Field(default_factory=dict)
    #: Distinct devices carrying at least one. Not the size of the estate — a device
    #: with nothing open is not in here, and neither is one nobody has assessed.
    devices_affected: int = 0


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


class TrendDay(BaseModel):
    day: date
    #: Findings first seen on this day. Exact for all time — `first_seen_at` is written
    #: once and never cleared.
    first_seen: int
    #: Resolutions that still stand. A finding resolved on this day and since reopened
    #: is not counted, because the row no longer records that it ever was: see
    #: `reopened_now` for the size of what this cannot see.
    resolved: int
    first_seen_by_severity: dict[str, int]


class FindingTrendRead(BaseModel):
    """Whether the estate is getting better (FR-FIND-05).

    **This does not include open findings by severity over time**, which the
    requirement also asks for and which this schema cannot honestly supply. A finding
    is stored as one row carrying its current status, and reopening clears
    `resolved_at`, so a retrospective open-count would show every fixed-and-returned
    problem as open throughout — wrong in exactly the estates worth charting.
    `open_by_severity` below is today's count, which is a fact rather than a
    reconstruction.
    """

    days: int
    since: date
    points: list[TrendDay]
    open_by_severity: dict[str, int]
    reopened_now: int
    #: Days from first sighting to a resolution that still stands. Median first: one
    #: finding left open for two years drags a mean somewhere no finding has been.
    median_days_to_resolve: float | None
    mean_days_to_resolve: float | None
    resolved_in_window: int
    total_first_seen: int
    total_resolved: int


class RiskPointRead(BaseModel):
    at: datetime
    score: int
    checks_evaluated: int


class RiskTrendRead(BaseModel):
    """A device's risk score as recorded, oldest first (FR-CHK-09).

    Exact history, unlike the findings trend: `risk_scores` keeps a row per computation
    rather than overwriting one, which is what the model was built for and what nothing
    has read until now.
    """

    device_id: uuid.UUID
    points: list[RiskPointRead]
    #: `improving`, `worsening`, `steady`, or `unknown` below two points. Named by the
    #: server so a report and the console cannot disagree about the same two numbers.
    direction: str


class FrameworkControl(BaseModel):
    control: str
    checks: list[str]
    passed: int
    failed: int
    not_evaluated: int


class FrameworkSummary(BaseModel):
    """One framework the check library maps to, and how many checks reach it.

    The count matters: a framework with 13 mapped checks and one with 103 support very
    different claims, and a picker that lists them identically invites the stronger
    claim to be made from the weaker mapping.
    """

    key: str
    checks: int


class FrameworkPosture(BaseModel):
    """Where one framework stands, without its control table (FR-CHK-05).

    The overview row behind the compliance page's card grid. It exists so the page can
    show every framework at once: the alternative was six full pivots on load, one per
    framework, each re-aggregating the same result rows — and a picker that showed one
    framework at a time, which meant five mappings the product has and nobody looks at.
    """

    key: str
    #: Checks in the library mapped to this framework. A framework reached by 13 checks
    #: and one reached by 103 support very different claims.
    checks: int
    #: Controls those checks map to — **the denominator is ours, not the framework's**.
    #: CIS has far more controls than a configuration read can be evidence about, and
    #: only the ones this library maps are counted.
    controls: int
    controls_failing: int
    #: Controls where nothing produced a verdict. Not passing, and deliberately not
    #: folded into either half of the percentage.
    controls_unevaluated: int
    device_count: int
    #: Share of *control* verdicts that passed, not of check runs — a check mapped to
    #: two controls contributes its result to both, because it satisfies or fails both.
    #: Not Applicable and Not Evaluated are in neither half.
    compliance_percent: int | None


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
    "FrameworkSummary",
    "PaginatedFindings",
    "PolicyAssign",
    "PolicyCheckRead",
    "PolicyCheckUpdate",
    "PolicyCreate",
    "PolicyDetail",
    "PolicyRead",
    "RiskRead",
]
