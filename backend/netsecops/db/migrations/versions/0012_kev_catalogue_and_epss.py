"""the KEV catalogue, and provenance for every feed

FR-VUL-06. `vuln_cves.kev` and `vuln_cves.epss` have existed since Phase 6 with nothing
behind them: no CISA or FIRST ingestion, so `kev` was NULL on every row and the
`kev_only` filter in the API and the console could only ever return an empty list. A
control that always answers "none" reads as "your estate is clean".

`vuln_kev_entries` stores the catalogue whole rather than reducing it to that flag.
Reducing it breaks on import order — import the catalogue, then an NVD bundle carrying a
new CVE, and that CVE reads "never checked" while an entry for it sits in the same
database. With the catalogue present the flag is derivable whenever a CVE arrives, in
either order, and becomes a materialised view rather than the only copy. It is also
small: low thousands of rows against a CVE table that runs to hundreds of thousands.

`feed_syncs.source_version` records the feed's own stamp — CISA's `catalogVersion`,
EPSS's `score_date` — separately from when the import ran. Someone who uploaded a
year-old catalogue this morning has a fresh sync of stale facts, and `started_at` alone
reports only the reassuring half of that.

`kev_entries_ingested` and `epss_scores_ingested` are counted apart from
`cves_ingested` because an EPSS import updates CVE rows without creating any; folding it
in would report a scoring run as having ingested two hundred thousand CVEs.

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-18
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "vuln_kev_entries",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("org_id", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("date_added", sa.Date(), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        # Nullable on purpose: CISA's "Unknown" means not established, not "no".
        sa.Column("known_ransomware", sa.Boolean(), nullable=True),
        sa.Column("vendor_project", sa.String(length=128), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("vulnerability_name", sa.Text(), nullable=True),
        sa.Column("required_action", sa.Text(), nullable=True),
        sa.Column("catalog_version", sa.String(length=64), nullable=True),
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
        sa.UniqueConstraint("org_id", "cve_id", name="uq_vuln_kev_cve_id"),
    )
    op.create_index("ix_vuln_kev_entries_org_id", "vuln_kev_entries", ["org_id"], unique=False)

    op.add_column("feed_syncs", sa.Column("source_version", sa.String(length=64), nullable=True))
    op.add_column(
        "feed_syncs",
        sa.Column(
            "kev_entries_ingested", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
    )
    op.add_column(
        "feed_syncs",
        sa.Column(
            "epss_scores_ingested", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
    )


def downgrade() -> None:
    op.drop_column("feed_syncs", "epss_scores_ingested")
    op.drop_column("feed_syncs", "kev_entries_ingested")
    op.drop_column("feed_syncs", "source_version")
    op.drop_index("ix_vuln_kev_entries_org_id", table_name="vuln_kev_entries")
    op.drop_table("vuln_kev_entries")
