"""Report storage (SRS §5.1, FR-RPT-02, FR-RPT-03, FR-RPT-04).

**A report is an immutable dated artefact, not a rendering of current state.** That is
the whole design, and it is the one decision here that cannot be retrofitted.

A dashboard answers "how are we now". An auditor asks "how were we on 31 March", and the
only honest answer is a record made on 31 March. So `content` is the assembled report,
frozen at generation, and nothing recomputes it afterwards. A finding resolved in April
does not retroactively disappear from March's report; a check added in May does not
appear in it either, and its absence is correct rather than a gap.

Two consequences worth stating, because both look like bugs to someone expecting a view:

* **A report can disagree with the console, and that is the point.** If they always
  agreed, one of them would be redundant.
* **`content` is denormalised on purpose.** It duplicates findings, device names and
  scores that live in other tables. Normalising it — storing ids and joining at read
  time — would make every report mutate as the estate changed, which is precisely the
  property being avoided. The duplication *is* the archive.

`content_hash` makes the artefact checkable: an auditor handed a PDF and a hash can
confirm the record was not edited after the fact. It is computed over the canonical JSON
serialisation, so it is stable across formats — the same report exported as JSON and as
CSV carries one hash, because it is one report.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from netsecops.db.base import Base, OrgMixin, TimestampMixin, UUIDPrimaryKeyMixin


class ReportTemplate(StrEnum):
    """The nine templates FR-RPT-02 names.

    Kept as an enum rather than free text so a template that was never built cannot be
    requested and silently produce an empty report — `NotFoundError` is the honest
    answer to "generate something I do not know how to assemble".
    """

    EXECUTIVE_SUMMARY = "executive_summary"
    DEVICE_DETAIL = "device_detail"
    GROUP_COMPLIANCE = "group_compliance"
    FIREWALL_RULEBASE = "firewall_rulebase"
    VULNERABILITY = "vulnerability"
    AAA_REVIEW = "aaa_review"
    DRIFT = "drift"
    EXCEPTIONS_REGISTER = "exceptions_register"
    TREND = "trend"


class ReportStatus(StrEnum):
    #: Assembling. A report is never readable in this state — a half-assembled archive
    #: is worse than none, because it looks complete.
    PENDING = "pending"
    READY = "ready"
    FAILED = "failed"


class ReportFormat(StrEnum):
    """FR-RPT-03. Every format renders the *same* frozen content, so all four of one
    report carry one `content_hash` — they are one report rendered differently, not
    four assessments."""

    JSON = "json"
    CSV = "csv"
    XLSX = "xlsx"
    PDF = "pdf"


class Report(Base, UUIDPrimaryKeyMixin, OrgMixin, TimestampMixin):
    """One generated report, frozen at the moment it was generated (FR-RPT-02)."""

    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_template_generated", "template", "generated_at"),
        Index("ix_reports_scope_device", "scope_device_id"),
        # A report that is READY must carry content, and one that FAILED must say why.
        # Enforced in the database rather than the service because the archive's value
        # rests entirely on a READY row being complete.
        CheckConstraint(
            "(status <> 'ready') OR (content_hash IS NOT NULL AND generated_at IS NOT NULL)",
            name="ck_reports_ready_is_complete",
        ),
        CheckConstraint(
            "(status <> 'failed') OR (error_message IS NOT NULL)",
            name="ck_reports_failed_says_why",
        ),
    )

    template: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default=text("'pending'")
    )

    #: What was asked for — the filters, the date window, the framework. Kept beside the
    #: output so a report can be explained, and so "generate that again" is answerable
    #: without guessing what "that" was.
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    #: Scope. All three are nullable and at most one is set; none set means the whole
    #: estate. Stored as real foreign keys so a deleted device cannot leave a report
    #: pointing at nothing — but `ondelete="SET NULL"`, because deleting a device must
    #: not delete the evidence that it was once assessed.
    scope_device_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL")
    )
    scope_group_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("device_groups.id", ondelete="SET NULL")
    )

    #: The report itself. See the module docstring: frozen, denormalised, never
    #: recomputed.
    content: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    #: SHA-256 over the canonical JSON of `content`. Lets a recipient prove the artefact
    #: they hold is the one that was generated.
    content_hash: Mapped[str | None] = mapped_column(String(64))

    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    generated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )

    #: Run-to-run comparison, attached to the NEWER report (FR-RPT-02's trend template
    #: and the auditor's "what changed since the last review"). Pointing forward from
    #: the older report would mean mutating an artefact that is supposed to be frozen.
    compare_to_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("reports.id", ondelete="SET NULL")
    )

    #: FR-RPT-04 retention. NULL means keep indefinitely, which is the default: a
    #: retention policy that deletes evidence by surprise is worse than a disk bill.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    error_message: Mapped[str | None] = mapped_column(Text)


__all__ = ["Report", "ReportFormat", "ReportStatus", "ReportTemplate"]
