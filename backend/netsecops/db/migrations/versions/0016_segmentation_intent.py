"""segmentation zones and the intent matrix

Revision ID: 0016
Revises: 0015
Create Date: 2026-09-26

FR-TOPO-07. Two tables holding what the estate is *supposed* to do, so the path engine
can be asked whether it does.

* `segmentation_zones` — a named piece of address space. Not a firewall zone: `dmz` on
  one device and `DMZ` on another may be different things and a router has no zone
  names at all, so the addresses are what gets evaluated.
* `segmentation_rules` — one ordered pair and the expectation for it. Ordered, because
  "A may reach B" says nothing about the reverse and most real segmentation is
  asymmetric.

No table for results. Verdicts are recomputed from the current graph on every request:
a stored "compliant" is a claim about an estate that has since changed, and this is the
one place where a stale pass is worse than no answer. A frozen answer belongs in the
report archive, which records when it was taken.

Three CHECK constraints, each stopping a row that could only ever evaluate to "not
verified" — a matrix full of grey cells reads as a broken tool rather than as the
unanswerable rows it would actually be. Everything the models default in Python is left
without a server default here, because `alembic check` compares the two and any
difference either way fails CI.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "segmentation_zones",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("prefixes", postgresql.ARRAY(sa.String(length=64)), nullable=False),
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
        sa.CheckConstraint("cardinality(prefixes) > 0", name="ck_segmentation_zones_has_prefixes"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("org_id", "name", name="uq_segmentation_zones_org_name"),
    )
    op.create_index(
        op.f("ix_segmentation_zones_org_id"), "segmentation_zones", ["org_id"], unique=False
    )

    op.create_table(
        "segmentation_rules",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("source_zone_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("destination_zone_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("expectation", sa.String(length=16), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
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
        sa.CheckConstraint(
            "source_zone_id <> destination_zone_id", name="ck_segmentation_rules_not_self"
        ),
        sa.ForeignKeyConstraint(
            ["destination_zone_id"], ["segmentation_zones.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["source_zone_id"], ["segmentation_zones.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "org_id",
            "source_zone_id",
            "destination_zone_id",
            "protocol",
            "port",
            name="uq_segmentation_rules_pair",
        ),
    )
    op.create_index(
        op.f("ix_segmentation_rules_org_id"), "segmentation_rules", ["org_id"], unique=False
    )
    op.create_index(
        "ix_segmentation_rules_source", "segmentation_rules", ["org_id", "source_zone_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_segmentation_rules_source", table_name="segmentation_rules")
    op.drop_index(op.f("ix_segmentation_rules_org_id"), table_name="segmentation_rules")
    op.drop_table("segmentation_rules")
    op.drop_index(op.f("ix_segmentation_zones_org_id"), table_name="segmentation_zones")
    op.drop_table("segmentation_zones")
