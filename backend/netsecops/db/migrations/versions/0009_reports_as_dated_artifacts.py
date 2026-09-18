"""reports as dated artefacts

Phase 7's reporting storage (SRS §5.1, FR-RPT-02 … FR-RPT-04).

``content`` is JSONB holding the assembled report, and it is **denormalised on
purpose**. Storing ids and joining at read time would be the normal choice and is the
wrong one here: it would make every stored report mutate as the estate changed, so a
report generated in March would quietly rewrite itself in April and the archive would be
worth nothing. The duplication is the archive.

The two CHECK constraints are the reason this is enforced in the database rather than in
the service. A report's entire value rests on a ``ready`` row being complete — a
half-assembled one is worse than none, because it looks finished — and on a ``failed``
one saying why. Neither is a rule a future caller can be trusted to remember.

``scope_device_id`` and ``generated_by_id`` are ``ON DELETE SET NULL``, never CASCADE.
Deleting a device, or deactivating the analyst who ran the report, must not delete the
evidence that the assessment happened.

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-16
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("template", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column(
            "status", sa.String(length=16), server_default=sa.text("'pending'"), nullable=False
        ),
        sa.Column(
            "parameters",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("scope_device_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scope_group_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "content",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("generated_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("compare_to_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["scope_device_id"], ["devices.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scope_group_id"], ["device_groups.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["generated_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["compare_to_id"], ["reports.id"], ondelete="SET NULL"),
        sa.CheckConstraint(
            "(status <> 'ready') OR (content_hash IS NOT NULL AND generated_at IS NOT NULL)",
            name="ck_reports_ready_is_complete",
        ),
        sa.CheckConstraint(
            "(status <> 'failed') OR (error_message IS NOT NULL)",
            name="ck_reports_failed_says_why",
        ),
    )
    op.create_index(
        "ix_reports_template_generated", "reports", ["template", "generated_at"], unique=False
    )
    op.create_index("ix_reports_scope_device", "reports", ["scope_device_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_reports_scope_device", table_name="reports")
    op.drop_index("ix_reports_template_generated", table_name="reports")
    op.drop_table("reports")
