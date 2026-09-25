"""collections record when their artefacts were purged

Revision ID: 0015
Revises: 0014
Create Date: 2026-09-25

Retention for collected artefacts (FR-ADM-01). `docs/deployment.md` has described a
ninety-day artefact window since Phase 7 and based its database sizing on one; nothing
enforced it, so artefacts accumulated for the life of the deployment and the published
figure was an estimate of a system that did not exist.

Artefacts are the bulk of the schema — the raw output of every command, kept sealed and
redacted — and the collection row beside them is a few hundred bytes of metadata. So the
row stays forever and only its payloads are removed.

Nullable with no backfill, deliberately. NULL means "the artefacts are still here", which
is true of every collection written before this migration, so there is nothing to
populate. A server default would have to invent a purge date that never happened.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "collections",
        sa.Column("artifacts_purged_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Retention scans for collections old enough to purge and not yet purged. Without
    # this it is a sequential scan of every collection ever made, on a job that runs
    # nightly against the table that grows fastest.
    op.create_index(
        "ix_collections_retention",
        "collections",
        ["created_at"],
        postgresql_where=sa.text("artifacts_purged_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_collections_retention", table_name="collections")
    op.drop_column("collections", "artifacts_purged_at")
