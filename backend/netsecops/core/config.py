"""Application settings (SRS Appendix C).

All configuration arrives via environment variables so that no secret ever lives in
the repository or an image layer (SEC-08). Values are validated by Pydantic at import
time, so a misconfigured deployment fails fast at boot rather than mid-assessment.
"""

from __future__ import annotations

import json
import secrets
from enum import StrEnum
from functools import lru_cache
from typing import Annotated, Literal, Self

from pydantic import (
    AliasChoices,
    Field,
    PostgresDsn,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Environment(StrEnum):
    DEV = "dev"
    TEST = "test"
    STAGING = "staging"
    PROD = "prod"


class MasterKeyProvider(StrEnum):
    """Where the credential-vault master key comes from (FR-CRED-02)."""

    ENV = "env"
    FILE = "file"
    VAULT = "vault"
    AWSKMS = "awskms"
    AZUREKV = "azurekv"
    GCPKMS = "gcpkms"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="NETSECOPS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ── Core ────────────────────────────────────────────────────────────────
    env: Environment = Environment.DEV
    debug: bool = False
    app_name: str = "NetSecOps"
    api_v1_prefix: str = "/api/v1"

    # ── Database (DATA-03) ──────────────────────────────────────────────────
    # AliasChoices, not a bare validation_alias: with a single alias the field name
    # itself stops being accepted, so `Settings(database_url=...)` in tests and scripts
    # would be silently ignored in favour of whatever the environment holds.
    database_url: PostgresDsn = Field(
        default=PostgresDsn("postgresql+asyncpg://netsecops:netsecops@localhost:5442/netsecops"),
        validation_alias=AliasChoices("database_url", "DATABASE_URL"),
    )
    db_pool_size: int = Field(default=10, ge=1, le=100)
    db_max_overflow: int = Field(default=20, ge=0, le=200)
    db_echo: bool = False

    # ── Auth / JWT (FR-AUTH-02) ─────────────────────────────────────────────
    secret_key: SecretStr = Field(
        default_factory=lambda: SecretStr(secrets.token_urlsafe(64)),
        validation_alias=AliasChoices("secret_key", "SECRET_KEY"),
    )
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    access_token_ttl_minutes: int = Field(default=15, ge=1, le=15)
    refresh_token_ttl_hours: int = Field(default=8, ge=1, le=8)

    # ── Password policy (FR-AUTH-01) ────────────────────────────────────────
    password_min_length: int = Field(default=12, ge=12)
    password_require_upper: bool = True
    password_require_lower: bool = True
    password_require_digit: bool = True
    password_require_symbol: bool = True
    password_history: int = Field(default=5, ge=0)
    password_max_age_days: int = Field(default=90, ge=0)

    # ── Lockout (FR-AUTH-06) ────────────────────────────────────────────────
    lockout_max_attempts: int = Field(default=5, ge=1)
    lockout_duration_minutes: int = Field(default=15, ge=1)

    # ── MFA (FR-AUTH-03) ────────────────────────────────────────────────────
    mfa_issuer: str = "NetSecOps"
    mfa_totp_period_seconds: int = 30
    mfa_totp_digits: int = 6
    # RFC 6238 clock drift tolerance, in periods either side of "now".
    mfa_totp_valid_window: int = Field(default=1, ge=0, le=2)

    # ── OIDC single sign-on (FR-AUTH-04) ────────────────────────────────────
    #: The connection to the identity provider is deployment configuration, so it lives
    #: here beside the database URL rather than in the `settings` table. What an
    #: administrator edits day to day — which IdP group carries which role — does live
    #: in the database, because that is a policy decision and it changes with the
    #: organisation rather than with the deployment.
    oidc_enabled: bool = False
    #: The issuer, from which `.well-known/openid-configuration` is derived. Must be
    #: HTTPS: every endpoint in the discovery document is taken on this URL's authority,
    #: so http:// here would let anything on the path redirect sign-in wherever it liked.
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("oidc_client_secret", "OIDC_CLIENT_SECRET"),
    )
    #: Where the IdP sends the browser back. Registered with the IdP, and sent again on
    #: the token exchange, so it has to match exactly — including the scheme and any
    #: trailing path.
    oidc_redirect_url: str | None = None
    #: `openid` is mandatory and is added if missing. `profile` and `email` are what the
    #: account match needs; a group claim usually needs one more, and which one depends
    #: on the IdP (`groups`, `roles`, or something bespoke).
    oidc_scopes: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["openid", "profile", "email"]
    )
    #: The ID-token claim carrying the user's groups. Entra ID calls it `groups`, Okta
    #: usually `groups`, Keycloak whatever the mapper was named.
    oidc_group_claim: str = "groups"
    #: How long a discovery document and its JWKS are held before being re-fetched.
    #: Signing keys rotate, and a cache that never expires turns a routine rotation into
    #: an outage that looks like the IdP is down.
    oidc_metadata_ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    #: How long a browser has to come back from the IdP with its authorization code.
    #: The state row is deleted on first use regardless.
    oidc_login_timeout_seconds: int = Field(default=600, ge=60, le=1800)
    #: What the sign-in button says. "Sign in with Entra ID" tells somebody which
    #: credentials to reach for; "Single sign-on" makes them guess.
    oidc_button_label: str = Field(default="Single sign-on", min_length=1, max_length=60)
    #: Where the console lives, when it is not served from this origin.
    #:
    #: Empty is the deployed case: Caddy serves the console and the API together, so the
    #: callback can redirect to a plain path. It exists for development, where the API
    #: is on :8000 and Vite on :5173 — and for that split to work at all the cookies
    #: have to be reachable from both, which is a `cookie_domain` question rather than
    #: this one.
    oidc_console_base_url: str = ""

    # ── Credential vault master key (FR-CRED-02) ────────────────────────────
    master_key_provider: MasterKeyProvider = MasterKeyProvider.ENV
    master_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("master_key", "MASTER_KEY")
    )
    master_key_path: str | None = Field(
        default=None, validation_alias=AliasChoices("master_key_path", "MASTER_KEY_PATH")
    )

    # ── Cookies / CORS / web tier (SEC-02, SEC-03) ──────────────────────────
    cookie_secure: bool = True
    cookie_domain: str | None = None
    cookie_samesite: Literal["strict", "lax", "none"] = "strict"
    # NoDecode stops pydantic-settings from JSON-decoding this before validation runs.
    # Without it a comma-separated NETSECOPS_CORS_ORIGINS raises at import time, and
    # the process never starts.
    cors_origins: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["http://localhost:5173"]
    )

    # ── Device access defaults (SRS §3.5, used from Phase 1) ────────────────
    device_connect_timeout: int = Field(default=15, ge=1)
    device_command_timeout: int = Field(default=60, ge=1)
    worker_concurrency: int = Field(default=20, ge=1)
    allow_legacy_ssh_ciphers: bool = False
    #: Whether an API-collected device's TLS certificate must validate against a trusted
    #: chain. Off by default, and that is a considered position rather than laziness:
    #: management interfaces overwhelmingly carry self-signed certificates, and an
    #: operator who cannot change that would otherwise be unable to use the product at
    #: all. Continuity comes from the per-device fingerprint pin instead — first contact
    #: is recorded and any later change is refused (FR-COL-10) — which is the same
    #: trust-on-first-use discipline already applied to SSH host keys. An estate with an
    #: internal CA should turn this on.
    verify_device_tls: bool = False

    # ── Vulnerability feeds (FR-VUL-07/08, used from Phase 6) ───────────────
    #: Refuse every outbound feed fetch. The C-7 guarantee, as a switch.
    #:
    #: Fetching *refuses* under this rather than quietly doing nothing, because a
    #: scheduled sync that appears configured, never runs and reports no error is the
    #: stale-feed-that-looks-current failure the whole subsystem exists to prevent.
    feeds_offline_mode: bool = False

    #: Hold the layer-3 graph between requests, keyed on a fingerprint of the devices
    #: and snapshots it was built from (`topology/cache.py`).
    #:
    #: On by default because the graph costs roughly 580ms at 650 devices and every
    #: screen that touches topology built its own — one dashboard load built two. The
    #: switch exists anyway: this is a product careful about stale answers, and an
    #: operator who would rather pay the rebuild than trust a fingerprint should be
    #: able to say so without patching the source.
    topology_graph_cache: bool = True

    #: How often a scheduled feed sync runs, as cron. FR-VUL-07's "default daily".
    #:
    #: 04:17 rather than midnight: every scheduler in the world fires on the hour, and
    #: CISA and FIRST publish to the same public endpoints for everyone.
    feeds_sync_cron: str = "17 4 * * *"

    #: Outbound proxy for feed fetches only (FR-ADM-01).
    #:
    #: Feed-specific rather than global on purpose. The hosts this product talks to fall
    #: into two groups with opposite routing in most estates — customer equipment on
    #: internal networks, and public feed endpoints — and a single proxy setting would
    #: send device traffic through it too. Unset, httpx still honours the standard
    #: HTTPS_PROXY environment variable.
    feeds_proxy_url: str | None = None

    #: Override for the NVD API endpoint, so an internal mirror can serve it. The
    #: deployments that most need current vulnerability data are often the ones whose
    #: workers have no direct egress.
    nvd_api_url: str | None = None

    # ── SIEM forwarding (FR-INT-02, FR-ADM-01) ──────────────────────────────
    #: Unset means forwarding is off. There is no separate enable flag: two switches for
    #: one decision is how a deployment ends up configured-but-disabled and nobody
    #: notices for a quarter.
    siem_syslog_host: str | None = None
    #: 6514 is the IANA port for syslog over TLS. 514 is the cleartext one, and the
    #: default here is deliberately not that.
    siem_syslog_port: int = 6514
    #: `cef` for ArcSight-lineage collectors, `json` for everything newer.
    siem_syslog_format: str = "cef"
    siem_syslog_tls: bool = True
    #: Verifying the collector's certificate. Findings and the audit trail are being
    #: shipped to whatever answers on that address, so turning this off is a decision an
    #: operator makes explicitly and one the forwarder logs a warning about every run.
    siem_syslog_verify: bool = True
    siem_syslog_ca_file: str | None = None

    # Appendix C names these without the NETSECOPS_ prefix, so each needs the same
    # AliasChoices treatment as DATABASE_URL and SECRET_KEY — with the field name kept
    # as the first choice, or constructing Settings(...) directly stops working.
    #
    # The prefixed spelling is listed too, and is not redundant: setting any
    # validation_alias stops pydantic-settings applying env_prefix to that field, so
    # omitting it would silently break `NETSECOPS_NVD_API_KEY`, which is the form
    # .env.example has documented since Phase 0.
    nvd_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("nvd_api_key", "NVD_API_KEY", "NETSECOPS_NVD_API_KEY"),
    )

    #: Cisco PSIRT openVuln API (FR-VUL-02, Appendix C). Obtained from the Cisco API
    #: Console as a Service application using the Client Credentials grant; the pair is
    #: exchanged at https://id.cisco.com/oauth2/default/v1/token for a bearer token
    #: that lasts an hour, so the Phase 6 client caches and refreshes it rather than
    #: authenticating per request.
    #:
    #: Optional, and must stay optional: FR-VUL-08 requires air-gapped deployments to
    #: work from `feeds_offline_mode` and imported bundles, so nothing may fail to
    #: start because these are unset. SecretStr so the client secret is masked in
    #: `netsecops-cli show-config`, in logs and in every error path (C-2).
    cisco_psirt_client_id: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "cisco_psirt_client_id",
            "CISCO_PSIRT_CLIENT_ID",
            "NETSECOPS_CISCO_PSIRT_CLIENT_ID",
        ),
    )
    cisco_psirt_client_secret: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "cisco_psirt_client_secret",
            "CISCO_PSIRT_CLIENT_SECRET",
            "NETSECOPS_CISCO_PSIRT_CLIENT_SECRET",
        ),
    )

    @field_validator(
        "nvd_api_key",
        "cisco_psirt_client_id",
        "cisco_psirt_client_secret",
        "oidc_client_secret",
        "oidc_issuer",
        "oidc_client_id",
        "oidc_redirect_url",
        mode="before",
    )
    @classmethod
    def _blank_optional_setting_is_unset(cls, value: object) -> object:
        """Treat an empty environment variable as absent.

        `docker compose` renders `${CISCO_PSIRT_CLIENT_ID:-}` as an empty string, not as
        an unset variable, so the default deployment would otherwise produce
        `SecretStr('')` — and `cisco_psirt_configured` would answer True for credentials
        that cannot authenticate. The symptom would be an opaque 401 from Cisco rather
        than the clean fallback to offline mode that FR-VUL-08 requires.

        The OIDC fields are here for the same reason and one more: an empty issuer that
        stayed an empty string would be reported as "must be an https:// URL" rather
        than "is not set", which sends whoever is setting it up looking for a typo in a
        value they never supplied.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @property
    def cisco_psirt_configured(self) -> bool:
        """True only when both halves are present. A client id without a secret cannot
        obtain a token, so reporting it as configured turns a setup mistake into a
        runtime failure somewhere much less obvious."""
        return self.cisco_psirt_client_id is not None and self.cisco_psirt_client_secret is not None

    # ── Observability (NFR-LOG-01, NFR-OBS-01) ──────────────────────────────
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: Literal["json", "console"] = "json"
    metrics_enabled: bool = True

    # ── Audit (FR-AUD-02) ───────────────────────────────────────────────────
    audit_retention_days: int = Field(default=730, ge=1)

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        """Parse CORS origins from a JSON array or a comma-separated string.

        With NoDecode on the field, this validator is the only parser, so it must
        handle both forms. Operators reach for `a,b` far more often than `["a","b"]`.
        """
        if not isinstance(v, str):
            return v

        text = v.strip()
        if text.startswith("["):
            try:
                return json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"cors_origins looks like JSON but does not parse: {exc}") from exc

        return [origin.strip() for origin in text.split(",") if origin.strip()]

    @field_validator("oidc_scopes", mode="before")
    @classmethod
    def _split_scopes(cls, v: object) -> object:
        """Scopes as a JSON array, a comma-separated list, or the space-separated form
        the OAuth specification itself uses — all three get typed into env files."""
        if not isinstance(v, str):
            return v

        text = v.strip()
        if text.startswith("["):
            try:
                return json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(f"oidc_scopes looks like JSON but does not parse: {exc}") from exc

        separator = "," if "," in text else " "
        return [scope.strip() for scope in text.split(separator) if scope.strip()]

    @model_validator(mode="after")
    def _guard_oidc(self) -> Self:
        """Refuse single sign-on that is switched on and cannot work (FR-AUTH-04).

        Every field here is needed before the first redirect, so a missing one produces
        a failure at the moment somebody tries to sign in — on the login screen, in
        front of whoever the rollout was for. Raising at startup instead puts it in
        front of whoever set it up, while they still have the terminal open.
        """
        if not self.oidc_enabled:
            return self

        missing = [
            name
            for name in ("oidc_issuer", "oidc_client_id", "oidc_client_secret", "oidc_redirect_url")
            if getattr(self, name) is None
        ]
        if missing:
            raise ValueError(
                f"oidc_enabled is true but {', '.join(sorted(missing))} "
                f"{'is' if len(missing) == 1 else 'are'} not set."
            )

        assert self.oidc_issuer is not None  # noqa: S101 - just established
        if not self.oidc_issuer.startswith("https://"):
            # Everything else — the authorization endpoint, the token endpoint, the
            # signing keys — is discovered from this URL and trusted because it came
            # from it. Over http:// anything on the path chooses where sign-in goes and
            # which keys verify the answer.
            raise ValueError("oidc_issuer must be an https:// URL.")

        if "openid" not in self.oidc_scopes:
            # Without it the provider runs a plain OAuth flow and returns no ID token,
            # which is the only part of the response that says who signed in.
            self.oidc_scopes = ["openid", *self.oidc_scopes]

        return self

    @model_validator(mode="after")
    def _guard_production(self) -> Self:
        """Fail closed on unsafe production configuration."""
        if self.env is Environment.PROD:
            if self.debug:
                raise ValueError("debug must be False in production")
            if not self.cookie_secure:
                raise ValueError("cookie_secure must be True in production")
            if "*" in self.cors_origins:
                raise ValueError("wildcard CORS origin is not permitted in production")
        return self

    @property
    def sso_console_login_path(self) -> str:
        """Where the SSO callback sends a browser that could not be signed in."""
        return f"{self.oidc_console_base_url.rstrip('/')}/login"

    @property
    def sso_console_home_path(self) -> str:
        """Where it sends one that could, absent a remembered destination."""
        return f"{self.oidc_console_base_url.rstrip('/')}/" if self.oidc_console_base_url else "/"

    @property
    def is_production(self) -> bool:
        return self.env is Environment.PROD

    @property
    def sync_database_url(self) -> str:
        """Alembic runs synchronously; strip the asyncpg driver suffix."""
        return str(self.database_url).replace("+asyncpg", "")


@lru_cache
def get_settings() -> Settings:
    return Settings()
