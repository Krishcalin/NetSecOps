"""single sign-ins in flight

Revision ID: 0017
Revises: 0016
Create Date: 2026-09-27

FR-AUTH-04. One row per sign-in between the redirect out to the identity provider and
the callback coming back, holding the PKCE verifier and the nonce that the callback has
to be checked against.

Server-side rather than a cookie, and that is forced rather than chosen. The auth
cookies are `SameSite=Strict` (SEC-02) and the callback is a top-level navigation from
the provider's origin, so a Strict cookie is not sent with it — carrying the state in
one would mean relaxing that attribute across the deployment to satisfy a single flow.

The verifier is stored sealed. For the few minutes a row lives it holds everything but
the authorization code needed to complete somebody else's sign-in, and `mfa_secrets`
already establishes that a short secret in a column gets the vault treatment.

`state` is unique because two logins sharing one would let either consume the other's
row, and the row is deleted on first use — which is what makes `state` the CSRF defence
OAuth asks it to be, rather than a value that is merely echoed back.

The index on `expires_at` is for the sweep that removes abandoned sign-ins: a browser
that never comes back leaves a row, and without the index that cleanup is a sequential
scan on a table every login writes to.

`org_id` carries `index=True` through `OrgMixin` (DATA-04), like every other tenant-scoped
table, so the model declares `ix_oidc_login_states_org_id`. It is created here rather than
in a later corrective migration (as 0011 had to do for `reports`): this is the head, so the
index can go in where it belongs instead of the model and the database disagreeing and
`alembic check` failing the build (C-5).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "oidc_login_states",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("state", sa.String(length=64), nullable=False),
        sa.Column("encrypted_verifier", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.String(length=64), nullable=False),
        sa.Column("redirect_to", sa.String(length=512), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ip_address", postgresql.INET(), nullable=True),
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
    )
    op.create_index("ix_oidc_login_states_state", "oidc_login_states", ["state"], unique=True)
    op.create_index("ix_oidc_login_states_expires_at", "oidc_login_states", ["expires_at"])
    op.create_index(
        op.f("ix_oidc_login_states_org_id"), "oidc_login_states", ["org_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_oidc_login_states_org_id"), table_name="oidc_login_states")
    op.drop_index("ix_oidc_login_states_expires_at", table_name="oidc_login_states")
    op.drop_index("ix_oidc_login_states_state", table_name="oidc_login_states")
    op.drop_table("oidc_login_states")
