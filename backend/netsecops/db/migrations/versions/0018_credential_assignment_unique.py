"""enforce credential-assignment target uniqueness

Revision ID: 0018_credential_assignment
Revises: 0017
Create Date: 2026-09-30

`uq_credential_assignment_target` spanned (credential_id, device_id, group_id), but by the
model's own invariant exactly one of device_id/group_id is set and the other is NULL. Under
Postgres' default NULLS DISTINCT two device-level rows (cred, dev, NULL) compare unequal
because of the NULL group_id, so the constraint could only ever fire for an impossible
all-non-NULL row. It never backstopped the SELECT-then-INSERT in `CredentialService.assign`,
so two concurrent assigns for the same (credential, device) both found no row and both
inserted, and the duplicate then appeared twice in the fallback list.

Replaced with two partial unique indexes, each keyed on only the target column that is
actually set, so uniqueness is enforced where it means something.

Revision id is suffixed rather than a bare "0018" because the DR-sets slice also adds a
migration off 0017 on a separate branch; distinct ids let the two merge as a normal
multi-head (resolved with `alembic merge`) instead of colliding on the same revision.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0018_credential_assignment"
down_revision: str | None = "0017"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.drop_constraint(
        "uq_credential_assignment_target", "credential_assignments", type_="unique"
    )
    op.create_index(
        "uq_credential_assignment_device",
        "credential_assignments",
        ["credential_id", "device_id"],
        unique=True,
        postgresql_where=sa.text("device_id IS NOT NULL"),
    )
    op.create_index(
        "uq_credential_assignment_group",
        "credential_assignments",
        ["credential_id", "group_id"],
        unique=True,
        postgresql_where=sa.text("group_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_credential_assignment_group", table_name="credential_assignments")
    op.drop_index("uq_credential_assignment_device", table_name="credential_assignments")
    op.create_unique_constraint(
        "uq_credential_assignment_target",
        "credential_assignments",
        ["credential_id", "device_id", "group_id"],
    )
