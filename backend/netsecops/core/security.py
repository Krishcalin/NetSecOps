"""Authentication primitives: Argon2id hashing, JWT issuance, TOTP, password policy.

Covers FR-AUTH-01 (Argon2id + policy), FR-AUTH-02 (short-lived access / rotating refresh
tokens) and FR-AUTH-03 (RFC 6238 TOTP).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import string
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Final

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from netsecops.core.config import Settings, get_settings
from netsecops.core.errors import AuthenticationError, PasswordPolicyError

# OWASP Password Storage Cheat Sheet minimum for Argon2id: 19 MiB, 2 iterations, 1 lane.
_hasher: Final[PasswordHasher] = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

SYMBOLS: Final[str] = string.punctuation


class TokenType(StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"
    MFA_PENDING = "mfa_pending"


# ───────────────────────────── password hashing ─────────────────────────────


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time-ish verification. Never raises on a wrong password."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True when the stored hash uses outdated parameters and should be upgraded on login."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def password_fingerprint(password: str) -> str:
    """Deterministic fingerprint for password-history comparison (FR-AUTH-01).

    Argon2 salts every hash, so stored history hashes cannot be compared directly against
    a new candidate without verifying one by one. That is the correct approach and is what
    :func:`verify_password` is used for; this helper exists only for the cheap pre-check
    of "is this literally the current password again".
    """
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# ───────────────────────────── password policy ──────────────────────────────


def validate_password_policy(password: str, settings: Settings | None = None) -> None:
    """Raise :class:`PasswordPolicyError` if ``password`` violates policy (FR-AUTH-01)."""
    settings = settings or get_settings()
    failures: list[str] = []

    if len(password) < settings.password_min_length:
        failures.append(f"must be at least {settings.password_min_length} characters")
    if settings.password_require_upper and not any(c.isupper() for c in password):
        failures.append("must contain an uppercase letter")
    if settings.password_require_lower and not any(c.islower() for c in password):
        failures.append("must contain a lowercase letter")
    if settings.password_require_digit and not any(c.isdigit() for c in password):
        failures.append("must contain a digit")
    if settings.password_require_symbol and not any(c in SYMBOLS for c in password):
        failures.append("must contain a symbol")

    if failures:
        raise PasswordPolicyError(
            "Password does not meet the configured policy.", violations=failures
        )


def generate_password(length: int = 20) -> str:
    """Generate a compliant random password (used for the bootstrap admin)."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        try:
            validate_password_policy(candidate)
        except PasswordPolicyError:
            continue
        return candidate


# ──────────────────────────────── JWT tokens ────────────────────────────────


def _now() -> datetime:
    return datetime.now(UTC)


def create_token(
    *,
    subject: str,
    token_type: TokenType,
    expires_delta: timedelta,
    settings: Settings | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, str, datetime]:
    """Mint a signed JWT.

    Returns ``(encoded_token, jti, expires_at)``. The ``jti`` is returned so refresh
    tokens can be persisted and revoked (FR-AUTH-02).
    """
    settings = settings or get_settings()
    issued_at = _now()
    expires_at = issued_at + expires_delta
    jti = str(uuid.uuid4())

    claims: dict[str, Any] = {
        "sub": subject,
        "typ": token_type.value,
        "jti": jti,
        "iat": int(issued_at.timestamp()),
        "nbf": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": settings.app_name,
    }
    if extra_claims:
        claims.update(extra_claims)

    encoded = jwt.encode(
        claims, settings.secret_key.get_secret_value(), algorithm=settings.jwt_algorithm
    )
    return encoded, jti, expires_at


def create_access_token(
    subject: str, *, settings: Settings | None = None, **extra: Any
) -> tuple[str, str, datetime]:
    settings = settings or get_settings()
    return create_token(
        subject=subject,
        token_type=TokenType.ACCESS,
        expires_delta=timedelta(minutes=settings.access_token_ttl_minutes),
        settings=settings,
        extra_claims=extra or None,
    )


def create_refresh_token(
    subject: str, *, settings: Settings | None = None, **extra: Any
) -> tuple[str, str, datetime]:
    settings = settings or get_settings()
    return create_token(
        subject=subject,
        token_type=TokenType.REFRESH,
        expires_delta=timedelta(hours=settings.refresh_token_ttl_hours),
        settings=settings,
        extra_claims=extra or None,
    )


def create_mfa_pending_token(
    subject: str, *, settings: Settings | None = None
) -> tuple[str, str, datetime]:
    """Short-lived ticket proving the password step passed but TOTP has not (FR-AUTH-03)."""
    return create_token(
        subject=subject,
        token_type=TokenType.MFA_PENDING,
        expires_delta=timedelta(minutes=5),
        settings=settings,
    )


def decode_token(
    token: str, *, expected_type: TokenType | None = None, settings: Settings | None = None
) -> dict[str, Any]:
    """Decode and validate a JWT, raising :class:`AuthenticationError` on any problem."""
    settings = settings or get_settings()
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            settings.secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            issuer=settings.app_name,
            options={"require": ["exp", "iat", "sub", "jti", "typ"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError("Token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError("Token is invalid.") from exc

    if expected_type is not None and claims.get("typ") != expected_type.value:
        raise AuthenticationError("Token is not valid for this operation.")
    return claims


def hash_token(token: str) -> str:
    """SHA-256 of a token, for storing refresh tokens and API tokens without the plaintext."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ─────────────────────────────── API tokens ─────────────────────────────────

API_TOKEN_PREFIX: Final[str] = "nso_"  # noqa: S105 - a prefix, not a secret


def generate_api_token() -> tuple[str, str, str]:
    """Create a service-account API token (FR-AUTH-07).

    Returns ``(plaintext, lookup_prefix, sha256_hash)``. Only the prefix and hash are
    stored; the plaintext is shown exactly once (FR-CRED-03 applies the same rule to
    device credentials).
    """
    raw = secrets.token_urlsafe(32)
    plaintext = f"{API_TOKEN_PREFIX}{raw}"
    return plaintext, plaintext[: len(API_TOKEN_PREFIX) + 8], hash_token(plaintext)


# ────────────────────────────────── TOTP ────────────────────────────────────


def generate_mfa_secret() -> str:
    return pyotp.random_base32()


def build_totp(secret: str, settings: Settings | None = None) -> pyotp.TOTP:
    settings = settings or get_settings()
    return pyotp.TOTP(
        secret, digits=settings.mfa_totp_digits, interval=settings.mfa_totp_period_seconds
    )


def mfa_provisioning_uri(secret: str, account_name: str, settings: Settings | None = None) -> str:
    """``otpauth://`` URI for authenticator-app enrolment."""
    settings = settings or get_settings()
    return build_totp(secret, settings).provisioning_uri(
        name=account_name, issuer_name=settings.mfa_issuer
    )


def verify_totp(secret: str, code: str, settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != settings.mfa_totp_digits:
        return False
    return build_totp(secret, settings).verify(code, valid_window=settings.mfa_totp_valid_window)


def generate_recovery_codes(count: int = 10) -> list[str]:
    """Single-use recovery codes, issued alongside TOTP enrolment."""
    return [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(count)]
