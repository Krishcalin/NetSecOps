"""discovery runs gain an executor's record

FR-DISC-05. Until now a ``discovery_runs`` row could only ever have been written by
hand: there was no executor, so the table described a thing that never happened. Running
a scope for real needs two columns it did not have.

``job_id`` links the run to the job that executed it, and is ``ON DELETE SET NULL``
rather than CASCADE on purpose. The run is the domain record — "these addresses were
probed, on this date, and this is what answered" — while the job is operational history
that a retention policy will eventually prune. Pruning job history must not delete the
evidence that a customer's network was contacted.

``notes`` carries what a run *could not do*, which is not the same as what went wrong and
has nowhere else to live: ``error_message`` belongs to a failure, and a successful run
that could not send a single echo request has no failure to hang it from. Without this
column, a run that found nothing because it lacked CAP_NET_RAW would be indistinguishable
from a run that found nothing because the network was quiet — the same class of mistake
as reporting an unevaluated check as a pass.

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-18
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "discovery_runs",
        sa.Column("job_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_discovery_runs_job_id",
        "discovery_runs",
        "jobs",
        ["job_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_discovery_runs_job", "discovery_runs", ["job_id"])

    # NOT NULL with a server default, so the column is populated for rows written before
    # this migration and a caller that omits it gets a list rather than None. Every read
    # path treats notes as a list; a nullable column would make each one check first, and
    # the one that forgot would raise on an ordinary run.
    op.add_column(
        "discovery_runs",
        sa.Column(
            "notes",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_column("discovery_runs", "notes")
    op.drop_index("ix_discovery_runs_job", table_name="discovery_runs")
    op.drop_constraint("fk_discovery_runs_job_id", "discovery_runs", type_="foreignkey")
    op.drop_column("discovery_runs", "job_id")
