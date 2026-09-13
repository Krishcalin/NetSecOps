"""Policies, custom checks, exceptions and check results (FR-CHK-05 … FR-CHK-09).

The shipped check library is read-only and lives in YAML inside the package. This
module holds what an *installation* adds on top of it:

- **policies** — which checks run against which device groups, and with what severity.
- **custom checks** — definitions an Analyst wrote in the UI (FR-CHK-06). Stored as the
  same YAML document the library uses, so there is exactly one schema and a custom
  check cannot express anything a shipped one could not.
- **exceptions** — a suppression with a justification, an approver and an expiry
  (FR-CHK-07). The expiry is the point of the record: a permanent exception is an
  undocumented decision wearing a process.
- **check results** — every outcome of every run, including passes. Findings record
  what is wrong; results record what was *examined*, which is what a compliance
  percentage and a trend line are computed from.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
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


class ExceptionScope(StrEnum):
    """What an exception covers.

    Device scope is the common case. Group scope is for a systemic decision — "the lab
    does not need centralised logging" — and global scope for a check the organisation
    has decided never applies to it.
    """

    DEVICE = "device"
    GROUP = "group"
    GLOBAL = "global"


class ExceptionStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Policy(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """A named set of checks assigned to device groups (FR-CHK-05)."""

    __tablename__ = "policies"
    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_policies_org_name"),
        Index("ix_policies_enabled", "enabled"),
    )

    name: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    #: Where this policy came from: a shipped pack ("cis-cisco-ios-l1") or an operator.
    #: Shipped policies are reinstalled on upgrade; custom ones are never overwritten.
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="custom")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    #: True for the policy applied to devices no explicit assignment covers. At most one
    #: per organisation, enforced in the service layer rather than by a constraint
    #: because "unset it on the other one first" is friendlier than a 409.
    is_default: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )

    #: Frameworks this policy claims to implement, for the compliance view's headline.
    frameworks: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    entries: Mapped[list[PolicyCheck]] = relationship(
        back_populates="policy", cascade="all, delete-orphan", lazy="selectin"
    )
    assignments: Mapped[list[PolicyAssignment]] = relationship(
        back_populates="policy", cascade="all, delete-orphan"
    )


class PolicyCheck(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """One check's membership of a policy, with any per-policy overrides (FR-CHK-06).

    A policy that merely listed check ids could not express "run this one, but at High
    here rather than Medium" — which is the most common real customisation, because
    severity is contextual in a way the shipped library cannot know.
    """

    __tablename__ = "policy_checks"
    __table_args__ = (
        UniqueConstraint("policy_id", "check_id", name="uq_policy_checks_policy_check"),
        Index("ix_policy_checks_check", "check_id"),
    )

    policy_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False
    )
    #: The check's string id, not a foreign key: shipped checks live in YAML, not in a
    #: table, and a policy must survive a library upgrade that removes one.
    check_id: Mapped[str] = mapped_column(String(120), nullable=False)

    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    #: Null means "use the check's own severity".
    severity_override: Mapped[str | None] = mapped_column(String(16))
    notes: Mapped[str | None] = mapped_column(Text)

    policy: Mapped[Policy] = relationship(back_populates="entries")


class PolicyAssignment(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """A policy applied to a device group (FR-CHK-05)."""

    __tablename__ = "policy_assignments"
    __table_args__ = (
        UniqueConstraint("policy_id", "device_group_id", name="uq_policy_assignment"),
        Index("ix_policy_assignments_group", "device_group_id"),
    )

    policy_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False
    )
    device_group_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("device_groups.id", ondelete="CASCADE"), nullable=False
    )

    policy: Mapped[Policy] = relationship(back_populates="assignments")


class CustomCheck(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """A check an operator wrote (FR-CHK-06).

    The definition is stored as the same document the YAML library uses and validated
    against the same schema, so the UI editor, the loader and the engine cannot drift
    apart. There is deliberately no way to store Python here: a custom check runs
    declarative logic only, because accepting code from a web form would be a remote
    code-execution feature.
    """

    __tablename__ = "custom_checks"
    __table_args__ = (UniqueConstraint("org_id", "check_id", name="uq_custom_checks_org_check"),)

    check_id: Mapped[str] = mapped_column(String(120), nullable=False)
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )


class FindingException(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """A suppression with a justification and an expiry date (FR-CHK-07).

    ``expires_at`` is not optional by accident. An exception without one is a decision
    nobody revisits, and the finding it hides becomes permanently invisible — which is
    how a risk acceptance made for a two-week migration outlives the migration by five
    years.
    """

    __tablename__ = "finding_exceptions"
    __table_args__ = (
        Index("ix_exceptions_check_scope", "check_id", "scope"),
        Index("ix_exceptions_device", "device_id"),
        Index("ix_exceptions_expiry", "expires_at"),
    )

    check_id: Mapped[str] = mapped_column(String(120), nullable=False)
    scope: Mapped[str] = mapped_column(String(16), nullable=False, default=ExceptionScope.DEVICE)

    device_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE")
    )
    device_group_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("device_groups.id", ondelete="CASCADE")
    )

    #: Free text, required. "Accepted by the CAB on 12 March, ticket NET-4821" is the
    #: kind of thing an auditor asks for and nobody can reconstruct a year later.
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    approver: Mapped[str | None] = mapped_column(String(150))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    status: Mapped[str] = mapped_column(String(16), nullable=False, default=ExceptionStatus.ACTIVE)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def is_active(self) -> bool:
        """An expiry in the past deactivates the exception without a background job.

        Computing this rather than relying on a sweep means an expired exception stops
        suppressing immediately, even if the housekeeping task has not run.
        """
        if self.status != ExceptionStatus.ACTIVE.value:
            return False
        expiry = self.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        return expiry > datetime.now(UTC)


class CheckResult(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """One check's outcome against one snapshot (FR-CHK-03).

    Every outcome is stored, passes included. Findings answer "what is wrong"; these
    answer "what was looked at", and without them a compliance percentage has no
    denominator and a trend line has no baseline.
    """

    __tablename__ = "check_results"
    __table_args__ = (
        Index("ix_check_results_device_created", "device_id", "created_at"),
        Index("ix_check_results_job", "job_id"),
        Index("ix_check_results_outcome", "outcome"),
        UniqueConstraint("snapshot_id", "check_id", "job_id", name="uq_check_result_run"),
    )

    device_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("snapshots.id", ondelete="CASCADE")
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL")
    )
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("policies.id", ondelete="SET NULL")
    )

    check_id: Mapped[str] = mapped_column(String(120), nullable=False)
    #: Which version of the check produced this, so a result can be traced to the logic
    #: that made it after the check has been amended (FR-CHK-08).
    check_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    #: Why a check was skipped — the missing NCM path, or the applicability rule.
    reason: Mapped[str | None] = mapped_column(String(200))

    #: Matched values and the configuration excerpts behind them. Redacted at capture.
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    #: Set when an active exception suppressed this result's finding (FR-CHK-07). The
    #: result itself is still stored: the check ran, and hiding that would make the
    #: compliance figure a fiction.
    suppressed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("finding_exceptions.id", ondelete="SET NULL")
    )


class RiskScore(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """A device's risk score over time (FR-CHK-09).

    Stored per computation rather than overwritten, because the trend is what tells an
    operator whether things are getting better — a single current number cannot.
    """

    __tablename__ = "risk_scores"
    __table_args__ = (Index("ix_risk_scores_device_created", "device_id", "created_at"),)

    device_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("jobs.id", ondelete="SET NULL")
    )

    #: 0 is clean, 100 is as bad as this formula goes.
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    #: The inputs, so a score can be explained rather than merely asserted.
    components: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    checks_evaluated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_passed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_not_evaluated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


__all__ = [
    "CheckResult",
    "CustomCheck",
    "ExceptionScope",
    "ExceptionStatus",
    "FindingException",
    "Policy",
    "PolicyAssignment",
    "PolicyCheck",
    "RiskScore",
]
