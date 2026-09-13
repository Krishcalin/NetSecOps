"""clock_timestamp() for created_at and updated_at

PostgreSQL's ``now()`` is ``transaction_timestamp()``, so every row written inside one
transaction receives an identical value. That makes ``ORDER BY created_at DESC LIMIT 1``
a tie broken arbitrarily by the planner, and two places rely on that ordering meaning
"the most recent":

- ``SnapshotService.latest`` chooses the configuration drift is measured against.
- the device check-results endpoint picks the newest assessment's snapshot, and every
  result from one assessment is written in a single transaction.

Both were returning an arbitrary row. ``clock_timestamp()`` reads the wall clock at the
moment of the statement, so rows in one transaction order correctly.

Existing rows are left as they are. Back-dating them would invent an ordering that was
never observed, and the rows most affected — several snapshots of one device written in
one transaction — are indistinguishable after the fact.

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-13
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Every table carrying TimestampMixin. Listed explicitly rather than discovered from
#: metadata: a migration must describe the schema as it was at this revision, not as the
#: models happen to look whenever it is next run.
TABLES: tuple[str, ...] = (
    "api_tokens",
    "artifacts",
    "check_results",
    "collections",
    "credential_assignments",
    "credentials",
    "custom_checks",
    "device_groups",
    "devices",
    "finding_exceptions",
    "findings",
    "job_devices",
    "jobs",
    "login_attempts",
    "mfa_secrets",
    "password_history",
    "policies",
    "policy_assignments",
    "policy_checks",
    "refresh_tokens",
    "risk_scores",
    "schedules",
    "sites",
    "snapshots",
    "tags",
    "user_device_group_scopes",
    "user_roles",
    "users",
)

COLUMNS: tuple[str, ...] = ("created_at", "updated_at")


def upgrade() -> None:
    for table in TABLES:
        for column in COLUMNS:
            op.alter_column(
                table,
                column,
                server_default=sa.text("clock_timestamp()"),
                existing_type=sa.DateTime(timezone=True),
                existing_nullable=False,
            )


def downgrade() -> None:
    for table in TABLES:
        for column in COLUMNS:
            op.alter_column(
                table,
                column,
                server_default=sa.text("now()"),
                existing_type=sa.DateTime(timezone=True),
                existing_nullable=False,
            )
