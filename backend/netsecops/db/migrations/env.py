"""Alembic environment.

The database URL comes from :class:`Settings`, never from ``alembic.ini``, so migrations
and the application can never disagree about which database they are pointed at (C-5).
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from netsecops.core.config import get_settings
from netsecops.db.base import Base

# Importing the models package registers every table on Base.metadata.
import netsecops.db.models  # noqa: F401  isort:skip

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# A caller (the test harness, or `alembic -x url=...`) may have supplied the URL
# already; otherwise take it from Settings so app and migrations cannot disagree.
if not config.get_main_option("sqlalchemy.url", None):
    config.set_main_option("sqlalchemy.url", str(get_settings().database_url))


def _include_object(
    obj: object, name: str | None, type_: str, reflected: bool, compare_to: object
) -> bool:
    """Skip tables Alembic does not own (e.g. a future job-queue library's own schema)."""
    return not (type_ == "table" and name in {"procrastinate_jobs", "procrastinate_events"})


def run_migrations_offline() -> None:
    """Emit SQL to stdout without a live connection — used to review a migration."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        include_object=_include_object,
    )
    with context.begin_transaction():
        context.run_migrations()


#: Guards concurrent `alembic upgrade head` runs (SRS §9). When several API replicas
#: start at once they all attempt migrations; the lock makes the others wait and then
#: find nothing to do, instead of racing the same DDL.
MIGRATION_LOCK_KEY = 0x4E53_4F4D  # "NSOM"


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
        include_object=_include_object,
    )
    with context.begin_transaction():
        # Transaction-scoped: released automatically on commit or rollback, so a
        # crashed migration cannot leave the lock held.
        connection.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": MIGRATION_LOCK_KEY})
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
