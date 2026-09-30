"""disaster-recovery sets

Revision ID: 0018
Revises: 0017
Create Date: 2026-09-29

A DR set is a primary device and its standby(s), recorded so the topology can treat the
set as one logical device. The record is here; the collapse that reads it is a separate
change in the topology service.

`dr_set_members.device_id` is the whole primary key, which is what enforces "a device is
in at most one set" in the database rather than in a service. A partial unique index on
`dr_set_id WHERE role = 'primary'` enforces "at most one primary per set"; the service
enforces "at least one", which no column constraint can express.

Both tables inherit `OrgMixin`, whose `org_id` carries `index=True` (DATA-04), so the ORM
declares `ix_dr_sets_org_id` and `ix_dr_set_members_org_id`. Both are created here — like
every other tenant-scoped table, and unlike the omission migration 0011 had to correct —
so the model and the database agree and `alembic check` stays clean (C-5).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "dr_sets",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name="pk_dr_sets"),
        sa.UniqueConstraint("org_id", "name", name="uq_dr_sets_org_id_name"),
    )
    op.create_index(op.f("ix_dr_sets_org_id"), "dr_sets", ["org_id"], unique=False)

    op.create_table(
        "dr_set_members",
        sa.Column("org_id", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("dr_set_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.PrimaryKeyConstraint("device_id", name="pk_dr_set_members"),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name="fk_dr_set_members_device_id_devices",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["dr_set_id"],
            ["dr_sets.id"],
            name="fk_dr_set_members_dr_set_id_dr_sets",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_dr_set_members_dr_set_id", "dr_set_members", ["dr_set_id"])
    op.create_index(op.f("ix_dr_set_members_org_id"), "dr_set_members", ["org_id"], unique=False)
    # At most one primary per set; any number of standbys.
    op.create_index(
        "uq_dr_set_members_one_primary",
        "dr_set_members",
        ["dr_set_id"],
        unique=True,
        postgresql_where=sa.text("role = 'primary'"),
    )


def downgrade() -> None:
    op.drop_index("uq_dr_set_members_one_primary", table_name="dr_set_members")
    op.drop_index(op.f("ix_dr_set_members_org_id"), table_name="dr_set_members")
    op.drop_index("ix_dr_set_members_dr_set_id", table_name="dr_set_members")
    op.drop_table("dr_set_members")
    op.drop_index(op.f("ix_dr_sets_org_id"), table_name="dr_sets")
    op.drop_table("dr_sets")
