"""discovery scopes gain an SNMP credential

Revision ID: 0014
Revises: 0013
Create Date: 2026-09-18

FR-DISC-02's optional SNMP probe. The scope has carried a `snmp_configured` boolean since
Phase 7 and nothing could satisfy it, because the probe needs a community string and
there was nowhere to put one that was not readable by every API returning a scope.

A reference into `credentials`, so the community is sealed in the vault like every other
secret. `SET NULL` rather than `CASCADE`: deleting a credential must not delete the record
of which addresses consent was given for. The scope survives with SNMP switched off, which
shows up on the next run rather than silently.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "discovery_scopes",
        sa.Column("snmp_credential_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_discovery_scopes_snmp_credential_id_credentials",
        "discovery_scopes",
        "credentials",
        ["snmp_credential_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_discovery_scopes_snmp_credential_id_credentials",
        "discovery_scopes",
        type_="foreignkey",
    )
    op.drop_column("discovery_scopes", "snmp_credential_id")
