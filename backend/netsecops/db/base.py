"""Declarative base and shared column mixins.

DATA-03: every timestamp is ``timestamptz`` in UTC.
DATA-04: every table carries ``org_id`` (default 1) so multi-tenancy can be introduced
later without a schema rewrite, even though v1.0 is single-tenant.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Integer, MetaData, func, text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Explicit naming convention so Alembic autogenerate produces stable, diffable
# constraint names instead of database-assigned ones (C-5).
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_N_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        pk = getattr(self, "id", None)
        return f"<{type(self).__name__} id={pk}>"


class UUIDPrimaryKeyMixin:
    """UUID primary keys: ids are handed out in APIs and must not be guessable."""

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )


class BigIntPrimaryKeyMixin:
    """For append-only, high-volume tables where ordering matters (audit_log)."""

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)


class OrgMixin:
    """DATA-04 — forward-compatible tenancy column."""

    org_id: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1"), index=True
    )


class TimestampMixin:
    """DATA-03 — creation and update stamps in UTC.

    ``clock_timestamp()``, not ``now()``. PostgreSQL's ``now()`` is
    ``transaction_timestamp()``: every row written inside one transaction gets the
    *same* value, to the microsecond. That makes ``ORDER BY created_at DESC LIMIT 1``
    a tie, resolved however the planner feels, and several places depend on it meaning
    "the most recent":

    - ``SnapshotService.latest`` decides which configuration drift is measured against.
    - the device check-results endpoint picks the newest assessment's snapshot id, and
      every result in one assessment is written in a single transaction.

    Both were returning an arbitrary row. It surfaced as an intermittent test failure,
    which is the kindest way a bug like this can announce itself.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.clock_timestamp()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.clock_timestamp(),
        onupdate=func.clock_timestamp(),
    )
