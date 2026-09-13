"""Settings tests (SRS Appendix C).

These build Settings the way a deployment does — from environment variables — rather
than from keyword arguments. A container caught a CORS parsing failure that unit tests
constructing Settings directly could never have seen, so the env path is tested here
explicitly.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from netsecops.core.config import Environment, MasterKeyProvider, Settings

BASE_ENV = {
    "SECRET_KEY": "a-signing-key-long-enough-for-tests-0123456789",
    "DATABASE_URL": "postgresql+asyncpg://u:p@localhost:5442/db",
}


def build(monkeypatch: pytest.MonkeyPatch, **env: str) -> Settings:
    """Construct Settings purely from the environment, as a deployment does."""
    for key in [
        *BASE_ENV,
        "NETSECOPS_CORS_ORIGINS",
        "NETSECOPS_ENV",
        "NETSECOPS_DEBUG",
        "NETSECOPS_COOKIE_SECURE",
        "MASTER_KEY",
    ]:
        monkeypatch.delenv(key, raising=False)

    for key, value in {**BASE_ENV, **env}.items():
        monkeypatch.setenv(key, value)

    # _env_file="" stops a developer's local .env from leaking into the test.
    return Settings(_env_file=None)  # type: ignore[call-arg]


class TestCorsOrigins:
    def test_comma_separated_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = build(
            monkeypatch,
            NETSECOPS_CORS_ORIGINS="http://localhost:5173,http://localhost:8080",
        )
        assert settings.cors_origins == ["http://localhost:5173", "http://localhost:8080"]

    def test_json_array(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = build(
            monkeypatch, NETSECOPS_CORS_ORIGINS='["https://a.example", "https://b.example"]'
        )
        assert settings.cors_origins == ["https://a.example", "https://b.example"]

    def test_single_origin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = build(monkeypatch, NETSECOPS_CORS_ORIGINS="https://one.example")
        assert settings.cors_origins == ["https://one.example"]

    def test_whitespace_and_trailing_commas_tolerated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = build(monkeypatch, NETSECOPS_CORS_ORIGINS=" https://a.example , , ")
        assert settings.cors_origins == ["https://a.example"]

    def test_default_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert build(monkeypatch).cors_origins == ["http://localhost:5173"]

    def test_malformed_json_is_a_clear_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with pytest.raises(ValidationError, match="does not parse"):
            build(monkeypatch, NETSECOPS_CORS_ORIGINS='["unterminated')


class TestProductionGuards:
    """A misconfigured production deployment must fail at boot, not silently run."""

    def test_debug_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with pytest.raises(ValidationError, match="debug must be False"):
            build(monkeypatch, NETSECOPS_ENV="prod", NETSECOPS_DEBUG="true")

    def test_insecure_cookies_are_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with pytest.raises(ValidationError, match="cookie_secure must be True"):
            build(monkeypatch, NETSECOPS_ENV="prod", NETSECOPS_COOKIE_SECURE="false")

    def test_wildcard_cors_is_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with pytest.raises(ValidationError, match="wildcard CORS"):
            build(monkeypatch, NETSECOPS_ENV="prod", NETSECOPS_CORS_ORIGINS="*")

    def test_valid_production_config_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = build(
            monkeypatch,
            NETSECOPS_ENV="prod",
            NETSECOPS_COOKIE_SECURE="true",
            NETSECOPS_CORS_ORIGINS="https://netsecops.example",
        )
        assert settings.is_production
        assert settings.cookie_secure

    def test_dev_may_be_permissive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = build(
            monkeypatch,
            NETSECOPS_ENV="dev",
            NETSECOPS_DEBUG="true",
            NETSECOPS_COOKIE_SECURE="false",
        )
        assert settings.env is Environment.DEV
        assert not settings.is_production


class TestAliases:
    """An explicit keyword must win over the environment, not be silently ignored."""

    def test_keyword_overrides_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECRET_KEY", "from-the-environment-0123456789abcdef")
        settings = Settings(
            secret_key="passed-explicitly-0123456789abcdef",  # type: ignore[arg-type]
            _env_file=None,  # type: ignore[call-arg]
        )
        assert settings.secret_key.get_secret_value() == "passed-explicitly-0123456789abcdef"

    def test_environment_is_used_when_no_keyword(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = build(monkeypatch)
        assert settings.secret_key.get_secret_value() == BASE_ENV["SECRET_KEY"]


class TestDerivedValues:
    def test_sync_database_url_strips_the_async_driver(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = build(monkeypatch)
        assert settings.sync_database_url.startswith("postgresql://")
        assert "asyncpg" not in settings.sync_database_url

    def test_master_key_provider_defaults_to_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert build(monkeypatch).master_key_provider is MasterKeyProvider.ENV

    def test_secret_key_is_not_exposed_by_repr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """C-2 — a settings dump must never print the signing key."""
        settings = build(monkeypatch)
        assert BASE_ENV["SECRET_KEY"] not in repr(settings)
        assert BASE_ENV["SECRET_KEY"] not in str(settings.model_dump())
