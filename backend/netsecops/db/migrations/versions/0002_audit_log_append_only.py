"""audit_log append-only enforcement

The hash chain (FR-AUD-02) makes tampering *detectable*. This migration makes it
*fail*: triggers reject UPDATE and DELETE on ``audit_log`` outright, so an application
bug or a compromised app role cannot quietly rewrite history.

The triggers belong to the table owner (``netsecops_migrate``, per SEC-06), not the
application role, so the app can never disable them. Deliberate archival — DATA-02 says
audit records are archived, never purged — is an owner-level operation: export first,
then disable the trigger, move the rows, and re-enable it.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION netsecops_audit_log_immutable()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION
                'audit_log is append-only: % is not permitted (FR-AUD-02)', TG_OP
                USING ERRCODE = 'restrict_violation';
        END;
        $$;
        """
    )

    op.execute(
        """
        CREATE TRIGGER audit_log_reject_update
            BEFORE UPDATE ON audit_log
            FOR EACH ROW EXECUTE FUNCTION netsecops_audit_log_immutable();
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_reject_delete
            BEFORE DELETE ON audit_log
            FOR EACH ROW EXECUTE FUNCTION netsecops_audit_log_immutable();
        """
    )

    # TRUNCATE bypasses row-level triggers entirely, so it needs its own statement-level
    # guard — otherwise the whole log could be erased in one statement.
    op.execute(
        """
        CREATE TRIGGER audit_log_reject_truncate
            BEFORE TRUNCATE ON audit_log
            FOR EACH STATEMENT EXECUTE FUNCTION netsecops_audit_log_immutable();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_log_reject_truncate ON audit_log;")
    op.execute("DROP TRIGGER IF EXISTS audit_log_reject_delete ON audit_log;")
    op.execute("DROP TRIGGER IF EXISTS audit_log_reject_update ON audit_log;")
    op.execute("DROP FUNCTION IF EXISTS netsecops_audit_log_immutable();")
