"""Migrations must apply to a database that already has data in it (DEPLOY-02).

Every other test in this suite runs `alembic upgrade head` against an empty database, so
a fresh install is thoroughly covered and an upgrade is not covered at all. Those are
different operations and they fail differently. The classic migration defect is invisible
against no rows: a NOT NULL column added without a server default, a unique index over
data that already violates it, a backfill assuming a shape the old rows do not have. Each
passes on an empty database and fails on a customer's.

It is the one operation every deployment eventually performs and the one with no rollback
worth the name — a failed upgrade leaves a half-migrated schema at four in the morning.

**This test owns its own database.** It creates one, migrates it to an older revision,
writes rows, upgrades to head and drops it. It cannot use the shared test database
because it manipulates the schema, and two pytest processes against one database already
drop each other's tables.

**Seeded at 0009 rather than 0001.** That is the oldest revision whose tables the current
models can still describe well enough to insert through raw SQL without reimplementing
four years of schema. Revisions 0010 to 0014 are the ones that add columns to populated
tables, which is exactly the risk being tested — 0001 to 0009 build tables that did not
exist yet and cannot break data that was not there.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from tests.conftest import BACKEND_ROOT, TEST_DATABASE_URL

pytestmark = pytest.mark.migration

#: Its own database, named so a leftover is obviously this test's and safe to drop.
MIGRATION_DB = "netsecops_migration_test"

#: The revision to seed at. Everything after it alters tables that already hold rows.
SEED_REVISION = "0009"


def _url(database: str) -> str:
    return TEST_DATABASE_URL.rsplit("/", 1)[0] + f"/{database}"


def _alembic(database_url: str):
    from alembic.config import Config

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "netsecops" / "db" / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


async def upgrade_to(database_url: str, revision: str) -> None:
    """Run `alembic upgrade` off the event loop.

    The migration environment calls `asyncio.run()` itself, which cannot nest inside the
    loop a test is already running on. `conftest` avoids this by migrating from a
    synchronous fixture; here the seeding has to be async, so alembic goes to a worker
    thread where there is no running loop for it to collide with.
    """
    import asyncio

    from alembic import command

    await asyncio.to_thread(command.upgrade, _alembic(database_url), revision)


async def _recreate_database() -> None:
    import asyncpg

    admin = TEST_DATABASE_URL.replace("+asyncpg", "").rsplit("/", 1)[0] + "/postgres"
    try:
        conn = await asyncpg.connect(admin)
    except Exception as exc:  # pragma: no cover - environment, not a test failure
        pytest.skip(f"PostgreSQL is not reachable: {exc}")

    try:
        await conn.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1",
            MIGRATION_DB,
        )
        await conn.execute(f'DROP DATABASE IF EXISTS "{MIGRATION_DB}"')
        await conn.execute(f'CREATE DATABASE "{MIGRATION_DB}"')
    finally:
        await conn.close()


@pytest.fixture
async def upgraded_from_seed():
    """A database at `SEED_REVISION`, carrying rows, ready to be upgraded.

    Yields the engine and the identifiers written, so a test can assert the same rows are
    still there afterwards rather than merely that the upgrade did not raise.
    """
    await _recreate_database()
    url = _url(MIGRATION_DB)

    await upgrade_to(url, SEED_REVISION)

    engine = create_async_engine(url, poolclass=NullPool)
    now = datetime.now(UTC)
    seeded = {
        "device": uuid.uuid4(),
        "scope": uuid.uuid4(),
        "run": uuid.uuid4(),
        "feed_sync": uuid.uuid4(),
    }

    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO devices (id, org_id, mgmt_ip, hostname, vendor, device_class,"
                " criticality, status, facts, ssh_port, https_port, allow_expert,"
                " allow_sudo_read, created_at, updated_at)"
                " VALUES (:id, 1, '10.99.0.1', 'mig-sw-01', 'cisco', 'switch', 'medium',"
                " 'active', '{}', 22, 443, false, false, :ts, :ts)"
            ),
            {"id": seeded["device"], "ts": now},
        )
        await conn.execute(
            text(
                "INSERT INTO discovery_scopes (id, org_id, name, targets, exclusions,"
                " tcp_ports, snmp_configured, auto_onboard, enabled, created_at, updated_at)"
                " VALUES (:id, 1, 'mig-scope', '{10.99.0.0/24}', '{}', '{22,443}',"
                " false, false, true, :ts, :ts)"
            ),
            {"id": seeded["scope"], "ts": now},
        )
        await conn.execute(
            text(
                "INSERT INTO discovery_runs (id, org_id, scope_id, status, addresses_probed,"
                " hosts_found, hosts_unidentified, started_at, created_at)"
                " VALUES (:id, 1, :scope, 'completed', 5, 2, 1, :ts, :ts)"
            ),
            {"id": seeded["run"], "scope": seeded["scope"], "ts": now},
        )
        await conn.execute(
            text(
                "INSERT INTO feed_syncs (id, org_id, feed, mode, status, started_at,"
                " advisories_ingested, cves_ingested, eol_records_ingested, records_rejected)"
                " VALUES (:id, 1, 'nvd', 'full', 'completed', :ts, 0, 0, 0, 0)"
            ),
            {"id": seeded["feed_sync"], "ts": now},
        )

    try:
        yield engine, url, seeded
    finally:
        await engine.dispose()


class TestUpgradingAPopulatedDatabase:
    async def test_the_upgrade_completes(self, upgraded_from_seed) -> None:
        """The whole point. An empty database proves nothing about this."""
        _engine, url, _seeded = upgraded_from_seed

        await upgrade_to(url, "head")

        engine = create_async_engine(url, poolclass=NullPool)
        try:
            async with engine.connect() as conn:
                revision = (
                    await conn.execute(text("SELECT version_num FROM alembic_version"))
                ).scalar_one()
            assert revision is not None
        finally:
            await engine.dispose()

    async def test_the_rows_survive(self, upgraded_from_seed) -> None:
        """A migration that drops data is worse than one that fails, because it succeeds."""
        _engine, url, seeded = upgraded_from_seed
        await upgrade_to(url, "head")

        engine = create_async_engine(url, poolclass=NullPool)
        try:
            async with engine.connect() as conn:
                for table, key in (
                    ("devices", "device"),
                    ("discovery_scopes", "scope"),
                    ("discovery_runs", "run"),
                    ("feed_syncs", "feed_sync"),
                ):
                    found = (
                        await conn.execute(
                            # S608 is suppressed deliberately: `table` comes from the
                            # literal tuple above and never from input, and the id is
                            # still a bound parameter.
                            text(f"SELECT count(*) FROM {table} WHERE id = :id"),  # noqa: S608
                            {"id": seeded[key]},
                        )
                    ).scalar_one()
                    assert found == 1, f"{table} lost its row across the upgrade"
        finally:
            await engine.dispose()

    async def test_columns_added_to_populated_tables_are_filled(self, upgraded_from_seed) -> None:
        """The defect this test exists for.

        0010 adds `discovery_runs.notes` NOT NULL, 0012 adds two NOT NULL counters to
        `feed_syncs`, and 0014 adds `snmp_credential_id` to `discovery_scopes`. Each was
        written with a server default so pre-existing rows are filled — and that is the
        part an empty-database upgrade never demonstrates, because there are no
        pre-existing rows to fill.
        """
        _engine, url, seeded = upgraded_from_seed
        await upgrade_to(url, "head")

        engine = create_async_engine(url, poolclass=NullPool)
        try:
            async with engine.connect() as conn:
                notes = (
                    await conn.execute(
                        text("SELECT notes FROM discovery_runs WHERE id = :id"),
                        {"id": seeded["run"]},
                    )
                ).scalar_one()
                assert notes is not None, "0010 left a pre-existing row with NULL notes"

                kev, epss = (
                    await conn.execute(
                        text(
                            "SELECT kev_entries_ingested, epss_scores_ingested"
                            " FROM feed_syncs WHERE id = :id"
                        ),
                        {"id": seeded["feed_sync"]},
                    )
                ).one()
                assert kev == 0 and epss == 0, "0012 left pre-existing counters NULL"
        finally:
            await engine.dispose()

    async def test_the_audit_triggers_survive(self, upgraded_from_seed) -> None:
        """Revision 0002 makes `audit_log` append-only with triggers.

        Alembic owns those; SQLAlchemy metadata does not describe them. A later migration
        that recreated the table would take the tamper-evidence with it and nothing else
        in the suite would notice, because the ordinary fixture builds the schema from
        head where the triggers are present either way.
        """
        _engine, url, _seeded = upgraded_from_seed
        await upgrade_to(url, "head")

        engine = create_async_engine(url, poolclass=NullPool)
        try:
            async with engine.connect() as conn:
                triggers = (
                    await conn.execute(
                        text(
                            "SELECT count(*) FROM pg_trigger"
                            " WHERE tgrelid = 'audit_log'::regclass AND NOT tgisinternal"
                        )
                    )
                ).scalar_one()
            assert triggers >= 3, "the audit_log append-only triggers did not survive"
        finally:
            await engine.dispose()
