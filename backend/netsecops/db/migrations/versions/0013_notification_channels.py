"""notification channels, subscriptions and the delivery queue

Revision ID: 0013
Revises: 0012
Create Date: 2026-09-18

FR-INT-01. Three tables:

* `notification_channels` — where notifications go, with the secret half sealed exactly
  as `credentials` does it. A Slack or Teams incoming-webhook URL is a bearer credential,
  so it lives in `encrypted_blob`, not in `config`.
* `notification_subscriptions` — which events reach which channel.
* `notification_deliveries` — the durable queue. Durable rather than in-process because
  the notifications that matter most are raised when something is badly wrong, which is
  exactly when a process is most likely to restart.

Column defaults follow the mixins rather than being invented here: `id` from
`UUIDPrimaryKeyMixin`, `org_id` and its index from `OrgMixin`, the timestamps from
`TimestampMixin`. Everything the models default in *Python* is deliberately left without
a server default, because `alembic check` compares the two and any difference either way
fails CI — which is how this file was caught the first time.

The composite index on pending deliveries is what keeps the dispatcher's claim query off
a sequential scan once the table holds a year of sent rows.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "notification_channels",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("channel_type", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("encrypted_blob", sa.LargeBinary(), nullable=True),
        sa.Column("key_id", sa.String(length=64), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_failure_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
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
        sa.UniqueConstraint("org_id", "name", name="uq_notification_channels_org_name"),
    )
    op.create_index(
        op.f("ix_notification_channels_org_id"),
        "notification_channels",
        ["org_id"],
        unique=False,
    )

    op.create_table(
        "notification_subscriptions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("channel_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_kinds", postgresql.ARRAY(sa.String(length=48)), nullable=False),
        sa.Column("min_severity", sa.String(length=16), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
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
        sa.ForeignKeyConstraint(["channel_id"], ["notification_channels.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_notification_subscriptions_org_id"),
        "notification_subscriptions",
        ["org_id"],
        unique=False,
    )
    op.create_index(
        "ix_notification_subscriptions_channel",
        "notification_subscriptions",
        ["org_id", "channel_id"],
    )

    op.create_table(
        "notification_deliveries",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("channel_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_kind", sa.String(length=48), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=True,
        ),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
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
        sa.ForeignKeyConstraint(["channel_id"], ["notification_channels.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_notification_deliveries_org_id"),
        "notification_deliveries",
        ["org_id"],
        unique=False,
    )
    op.create_index(
        "ix_notification_deliveries_pending",
        "notification_deliveries",
        ["org_id", "status", "next_attempt_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_notification_deliveries_pending", table_name="notification_deliveries")
    op.drop_index(op.f("ix_notification_deliveries_org_id"), table_name="notification_deliveries")
    op.drop_table("notification_deliveries")
    op.drop_index("ix_notification_subscriptions_channel", table_name="notification_subscriptions")
    op.drop_index(
        op.f("ix_notification_subscriptions_org_id"), table_name="notification_subscriptions"
    )
    op.drop_table("notification_subscriptions")
    op.drop_index(op.f("ix_notification_channels_org_id"), table_name="notification_channels")
    op.drop_table("notification_channels")
