"""Shared pytest fixtures.

Tests run against a real PostgreSQL instance, not SQLite: the schema depends on JSONB,
INET and advisory locks, so a substitute engine would test something the product never
runs on. ``TEST_DATABASE_URL`` points at it (default: the compose database on 5442).

Each test gets a clean schema created from ``Base.metadata``, then dropped. That is
faster than running migrations per test; a separate test asserts that the migrations
themselves produce the same schema.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from netsecops.core.config import Environment, Settings
from netsecops.core.crypto import SecretVault, generate_master_key
from netsecops.core.rbac import Permission, Principal, Role, Scope
from netsecops.db.base import Base
from netsecops.db.models import User, UserRole

BACKEND_ROOT = Path(__file__).resolve().parent.parent

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://netsecops:netsecops@localhost:5442/netsecops_test",
)

TEST_PASSWORD = "Correct-Horse-Battery-9!"


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    return Settings(
        env=Environment.TEST,
        database_url=TEST_DATABASE_URL,  # type: ignore[arg-type]
        secret_key="test-signing-key-not-used-anywhere-real-0123456789",  # type: ignore[arg-type]
        master_key=generate_master_key(),  # type: ignore[arg-type]
        cookie_secure=False,
        metrics_enabled=True,
        log_format="console",
        # Keep Argon2 cost realistic but let lockout tests run quickly.
        lockout_max_attempts=5,
        lockout_duration_minutes=15,
    )


@pytest.fixture(scope="session")
def database_ready(test_settings: Settings) -> str:
    """Create the test database and bring its schema to head, once per session.

    This fixture is deliberately synchronous. asyncpg binds a connection to the event
    loop that created it, and pytest-asyncio gives each test its own loop, so a
    session-scoped *async* fixture would hand every test a connection from a dead loop.
    Doing the setup with its own short-lived loop sidesteps that entirely.
    """
    url = str(test_settings.database_url)
    asyncio.run(_ensure_database_exists())
    asyncio.run(_reset_schema(url))
    _run_migrations(url)
    return url


async def _ensure_database_exists() -> None:
    """Create the test database if it does not exist yet."""
    import asyncpg

    admin_url = TEST_DATABASE_URL.replace("+asyncpg", "").rsplit("/", 1)[0] + "/postgres"
    db_name = TEST_DATABASE_URL.rsplit("/", 1)[1]

    try:
        conn = await asyncpg.connect(admin_url)
    except Exception as exc:  # pragma: no cover - environment problem, not a test failure
        pytest.skip(f"PostgreSQL is not reachable for tests: {exc}")

    try:
        exists = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", db_name)
        if not exists:
            await conn.execute(f'CREATE DATABASE "{db_name}"')
    finally:
        await conn.close()


async def _reset_schema(url: str) -> None:
    """Drop everything so each run starts from a known-empty database."""
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.execute(text("DROP TABLE IF EXISTS alembic_version"))
            await conn.execute(
                text("DROP FUNCTION IF EXISTS netsecops_audit_log_immutable() CASCADE")
            )
    finally:
        await engine.dispose()


def _run_migrations(database_url: str) -> None:
    """Apply ``alembic upgrade head``, so tests run against the schema deployments get.

    This also covers objects Alembic owns that SQLAlchemy metadata does not describe,
    notably the audit_log append-only triggers from revision 0002.
    """
    from alembic import command
    from alembic.config import Config

    config = Config(str(BACKEND_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_ROOT / "netsecops" / "db" / "migrations"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")


@pytest.fixture
async def engine(database_ready: str) -> AsyncIterator[AsyncEngine]:
    """Per-test engine. NullPool keeps connections from outliving their event loop."""
    engine = create_async_engine(database_ready, poolclass=NullPool)
    yield engine
    await engine.dispose()


@pytest.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """A session whose writes are rolled back after each test.

    Everything runs inside one outer transaction that is never committed, so tests are
    isolated without paying to recreate the schema each time.
    """
    connection = await engine.connect()
    transaction = await connection.begin()
    maker = async_sessionmaker(bind=connection, expire_on_commit=False, class_=AsyncSession)
    db = maker()

    try:
        yield db
    finally:
        await db.close()
        await transaction.rollback()
        await connection.close()


@pytest.fixture
def vault(test_settings: Settings) -> SecretVault:
    from netsecops.core.crypto import EnvMasterKeyProvider

    return SecretVault(EnvMasterKeyProvider(test_settings))


# -------------------------- application fixtures --------------------------


@pytest.fixture
async def app(test_settings: Settings, session: AsyncSession, vault: SecretVault):
    """FastAPI app with the database and settings dependencies pointed at the test session."""
    from netsecops.api.deps import db_session, settings_dep
    from netsecops.core.config import get_settings
    from netsecops.main import create_app
    from netsecops.services.auth import AuthService

    get_settings.cache_clear()
    application = create_app(test_settings)

    async def _override_session() -> AsyncIterator[AsyncSession]:
        yield session

    def _override_settings() -> Settings:
        return test_settings

    application.dependency_overrides[db_session] = _override_session
    application.dependency_overrides[settings_dep] = _override_settings

    # Services built inside request handlers need the test vault, not one from a
    # master key the test environment does not have.
    original_vault_property = AuthService.vault

    AuthService.vault = property(lambda self: vault)  # type: ignore[assignment]
    try:
        yield application
    finally:
        AuthService.vault = original_vault_property  # type: ignore[assignment]
        application.dependency_overrides.clear()
        get_settings.cache_clear()


@pytest.fixture
async def client(app) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://testserver"
    ) as http_client:
        yield http_client


# ----------------------------- user factories -----------------------------


async def make_user(
    session: AsyncSession,
    *,
    username: str | None = None,
    roles: set[Role] | None = None,
    password: str = TEST_PASSWORD,
    is_active: bool = True,
    mfa_enabled: bool = False,
) -> User:
    from netsecops.core.security import hash_password

    username = username or f"user_{uuid.uuid4().hex[:8]}"
    user = User(
        username=username,
        email=f"{username}@example.com",
        full_name=username.replace("_", " ").title(),
        password_hash=hash_password(password),
        is_active=is_active,
        mfa_enabled=mfa_enabled,
    )
    session.add(user)
    await session.flush()

    for role in roles or set():
        session.add(UserRole(user_id=user.id, role=role.value))
    await session.flush()
    await session.refresh(user)
    return user


@pytest.fixture
def user_factory(session: AsyncSession):
    async def _factory(**kwargs) -> User:
        return await make_user(session, **kwargs)

    return _factory


@pytest.fixture
async def super_admin(session: AsyncSession) -> User:
    return await make_user(session, username="admin_user", roles={Role.SUPER_ADMIN})


@pytest.fixture
async def analyst(session: AsyncSession) -> User:
    return await make_user(session, username="analyst_user", roles={Role.SECURITY_ANALYST})


@pytest.fixture
async def engineer(session: AsyncSession) -> User:
    return await make_user(session, username="engineer_user", roles={Role.NETWORK_ENGINEER})


@pytest.fixture
async def auditor(session: AsyncSession) -> User:
    return await make_user(session, username="auditor_user", roles={Role.AUDITOR})


def principal_for(user: User, scope: Scope | None = None) -> Principal:
    return Principal(
        id=user.id,
        username=user.username,
        roles=user.role_set,
        scope=scope or Scope.all(),
    )


@pytest.fixture
def authenticate(app, session: AsyncSession):
    """Override the principal dependency so a test can call the API as any user.

    This bypasses the login flow deliberately: the login flow has its own tests, and the
    authorization matrix should not depend on it passing.
    """
    from netsecops.api.deps import current_principal

    def _as(user: User, *, token_scopes: set[Permission] | None = None) -> None:
        async def _override() -> Principal:
            return Principal(
                id=user.id,
                username=user.username,
                roles=user.role_set,
                scope=Scope.all(),
                is_service_account=token_scopes is not None,
                token_scopes=frozenset(token_scopes) if token_scopes is not None else None,
            )

        app.dependency_overrides[current_principal] = _override

    yield _as
    app.dependency_overrides.pop(current_principal, None)
