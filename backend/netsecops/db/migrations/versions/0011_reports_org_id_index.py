"""the org_id index migration 0009 left out

``OrgMixin`` declares ``index=True`` on ``org_id`` (DATA-04), and every table that uses
the mixin has an ``ix_<table>_org_id`` created alongside it — audit_log, users, devices,
settings and the rest. ``reports`` was added in 0009 without one, so the model and the
database disagreed.

That disagreement is not cosmetic: CI runs ``alembic check``, which autogenerates against
the live schema and fails the build if the result is non-empty (C-5). The branch could
not go green while this stood, and the check is the only thing that would ever have
noticed — an index nobody declared is invisible until the table is large enough for its
absence to hurt.

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-18
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(op.f("ix_reports_org_id"), "reports", ["org_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_reports_org_id"), table_name="reports")
