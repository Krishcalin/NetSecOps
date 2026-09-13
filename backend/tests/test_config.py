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
        "NVD_API_KEY",
        "CISCO_PSIRT_CLIENT_ID",
        "CISCO_PSIRT_CLIENT_SECRET",
    ]:
        monkeypatch.delenv(key, raising=False)

    for key, value in {**BASE_ENV, **env}.items():
        monkeypatch.setenv(key, value)

    # _env_file="" stops a developer's local .env from leaking into the test.
    return Settings(_env_file=None)  # type: ignore[call-arg]


class TestVulnerabilityFeedCredentials:
    """Appendix C names these without the NETSECOPS_ prefix (FR-VUL-02, FR-VUL-08)."""

    def test_psirt_credentials_load_under_their_appendix_c_names(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = build(
            monkeypatch,
            CISCO_PSIRT_CLIENT_ID="client-id-from-the-api-console",
            CISCO_PSIRT_CLIENT_SECRET="the-client-secret",
            NVD_API_KEY="an-nvd-key",
        )

        assert settings.cisco_psirt_client_id is not None
        assert (
            settings.cisco_psirt_client_secret.get_secret_value()  # type: ignore[union-attr]
            == "the-client-secret"
        )
        assert settings.nvd_api_key is not None
        assert settings.cisco_psirt_configured is True

    def test_the_prefixed_spelling_still_works(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """.env.example has documented NETSECOPS_NVD_API_KEY since Phase 0. Setting a
        validation_alias stops env_prefix applying, so both spellings are listed — and
        this asserts the documented one did not quietly stop working."""
        monkeypatch.setenv("NETSECOPS_NVD_API_KEY", "prefixed")
        monkeypatch.setenv("NETSECOPS_CISCO_PSIRT_CLIENT_ID", "prefixed-id")
        settings = Settings(_env_file=None, **BASE_ENV)  # type: ignore[call-arg,arg-type]

        assert settings.nvd_api_key is not None
        assert settings.cisco_psirt_client_id is not None

    def test_the_secret_is_not_in_the_repr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SecretStr, so a settings object logged or included in a traceback cannot
        disclose the credential (C-2)."""
        settings = build(monkeypatch, CISCO_PSIRT_CLIENT_SECRET="do-not-print-me")

        assert "do-not-print-me" not in repr(settings)
        assert "do-not-print-me" not in str(settings.cisco_psirt_client_secret)

    def test_feeds_are_optional(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """FR-VUL-08: an air-gapped deployment runs from imported bundles, so missing
        feed credentials must never stop the application starting."""
        settings = build(monkeypatch)

        assert settings.cisco_psirt_client_id is None
        assert settings.cisco_psirt_configured is False
        assert settings.feeds_offline_mode is False

    def test_empty_environment_variables_read_as_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`docker compose` renders `${CISCO_PSIRT_CLIENT_ID:-}` as an empty string,
        which is what the shipped compose file produces when the operator has not set
        one. Without this, the credentials would be SecretStr('') and the system would
        believe it could authenticate."""
        settings = build(
            monkeypatch,
            CISCO_PSIRT_CLIENT_ID="",
            CISCO_PSIRT_CLIENT_SECRET="   ",
            NVD_API_KEY="",
        )

        assert settings.cisco_psirt_client_id is None
        assert settings.cisco_psirt_client_secret is None
        assert settings.nvd_api_key is None
        assert settings.cisco_psirt_configured is False

    def test_half_configured_credentials_do_not_count_as_configured(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A client id with no secret cannot obtain a token. Reporting it as configured
        would turn a setup mistake into a runtime failure four phases later."""
        settings = build(monkeypatch, CISCO_PSIRT_CLIENT_ID="only-the-id")
        assert settings.cisco_psirt_configured is False


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
