"""discovery scopes, runs and the review queue

Phase 7's discovery storage (SRS §5.1, FR-DISC-01 … FR-DISC-06).

``discovered_hosts`` is a separate table rather than a ``devices`` row in the
``pending_review`` state, and that is the safety boundary rather than a modelling
preference. A row in ``devices`` is reachable by every query that enumerates the estate,
so keeping an unapproved host out of assessment would mean each of those queries
remembering to exclude it — and one forgotten filter is NetSecOps authenticating to a
box nobody agreed it should touch. With no ``devices`` row there is nothing to forget.

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "discovery_scopes",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("targets", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("exclusions", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("tcp_ports", postgresql.ARRAY(sa.Integer()), nullable=False),
        sa.Column(
            "rate_limit_per_second", sa.Integer(), server_default=sa.text("50"), nullable=False
        ),
        sa.Column("snmp_configured", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        # Off by default. The difference between finding a device and connecting to one.
        sa.Column("auto_onboard", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_discovery_scopes")),
        sa.UniqueConstraint("org_id", "name", name="uq_discovery_scope_name"),
    )
    op.create_index(
        op.f("ix_discovery_scopes_org_id"), "discovery_scopes", ["org_id"], unique=False
    )

    op.create_table(
        "discovery_runs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("scope_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("addresses_probed", sa.Integer(), nullable=False),
        sa.Column("hosts_found", sa.Integer(), nullable=False),
        sa.Column("hosts_unidentified", sa.Integer(), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["scope_id"],
            ["discovery_scopes.id"],
            name=op.f("fk_discovery_runs_scope_id_discovery_scopes"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_discovery_runs")),
    )
    op.create_index(op.f("ix_discovery_runs_org_id"), "discovery_runs", ["org_id"], unique=False)
    op.create_index(
        "ix_discovery_runs_scope", "discovery_runs", ["org_id", "scope_id", "started_at"]
    )

    op.create_table(
        "discovered_hosts",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("address", postgresql.INET(), nullable=False),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "status", sa.String(length=16), server_default=sa.text("'pending'"), nullable=False
        ),
        sa.Column("vendor", sa.String(length=64), nullable=True),
        sa.Column("platform", sa.String(length=64), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("fingerprint", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        # Null while pending or rejected. That null is what keeps an unapproved host out
        # of the assessed estate.
        sa.Column("device_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reviewed_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_note", sa.Text(), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["discovery_runs.id"],
            name=op.f("fk_discovered_hosts_run_id_discovery_runs"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["devices.id"],
            name=op.f("fk_discovered_hosts_device_id_devices"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["reviewed_by_id"],
            ["users.id"],
            name=op.f("fk_discovered_hosts_reviewed_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_discovered_hosts")),
        sa.UniqueConstraint("org_id", "address", name="uq_discovered_host_address"),
    )
    op.create_index(
        op.f("ix_discovered_hosts_org_id"), "discovered_hosts", ["org_id"], unique=False
    )
    op.create_index("ix_discovered_hosts_status", "discovered_hosts", ["org_id", "status"])


def downgrade() -> None:
    op.drop_table("discovered_hosts")
    op.drop_table("discovery_runs")
    op.drop_table("discovery_scopes")
