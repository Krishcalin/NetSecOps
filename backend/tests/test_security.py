"""Password hashing, policy, JWT and TOTP tests (FR-AUTH-01/02/03)."""

from __future__ import annotations

import time
from datetime import timedelta

import jwt
import pyotp
import pytest

from netsecops.core.config import Environment, Settings
from netsecops.core.errors import AuthenticationError, PasswordPolicyError
from netsecops.core.security import (
    API_TOKEN_PREFIX,
    TokenType,
    create_access_token,
    create_refresh_token,
    create_token,
    decode_token,
    generate_api_token,
    generate_mfa_secret,
    generate_password,
    generate_recovery_codes,
    hash_password,
    hash_token,
    mfa_provisioning_uri,
    validate_password_policy,
    verify_password,
    verify_totp,
)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        env=Environment.TEST,
        secret_key="unit-test-signing-key-0123456789abcdef",  # type: ignore[arg-type]
        cookie_secure=False,
    )


class TestPasswordHashing:
    def test_hash_verifies(self) -> None:
        h = hash_password("Correct-Horse-9!")
        assert verify_password("Correct-Horse-9!", h)

    def test_wrong_password_rejected(self) -> None:
        assert not verify_password("wrong", hash_password("Correct-Horse-9!"))

    def test_hash_is_argon2id(self) -> None:
        assert hash_password("Correct-Horse-9!").startswith("$argon2id$")

    def test_hash_is_salted(self) -> None:
        assert hash_password("same") != hash_password("same")

    def test_verify_never_raises_on_garbage_hash(self) -> None:
        assert verify_password("anything", "not-a-hash") is False


class TestPasswordPolicy:
    @pytest.mark.parametrize(
        ("password", "expected_violation"),
        [
            ("Short1!", "at least 12"),
            ("alllowercase123!", "uppercase"),
            ("ALLUPPERCASE123!", "lowercase"),
            ("NoDigitsHereAtAll!", "digit"),
            ("NoSymbolsHere1234", "symbol"),
        ],
    )
    def test_rejects_weak_passwords(self, password: str, expected_violation: str) -> None:
        with pytest.raises(PasswordPolicyError) as exc:
            validate_password_policy(password)
        assert any(expected_violation in v for v in exc.value.extra["violations"])

    def test_accepts_compliant_password(self) -> None:
        validate_password_policy("Compliant-Passw0rd!")

    def test_generated_passwords_always_comply(self) -> None:
        for _ in range(20):
            validate_password_policy(generate_password())


class TestJWT:
    def test_access_token_round_trip(self, settings: Settings) -> None:
        token, jti, expires = create_access_token("user-123", settings=settings)
        claims = decode_token(token, expected_type=TokenType.ACCESS, settings=settings)

        assert claims["sub"] == "user-123"
        assert claims["jti"] == jti
        assert claims["typ"] == TokenType.ACCESS.value
        assert claims["exp"] == int(expires.timestamp())
        assert claims["exp"] > claims["iat"]

    def test_token_type_is_enforced(self, settings: Settings) -> None:
        """An access token must not be usable where a refresh token is expected."""
        token, _, _ = create_access_token("u", settings=settings)
        with pytest.raises(AuthenticationError, match="not valid for this operation"):
            decode_token(token, expected_type=TokenType.REFRESH, settings=settings)

    def test_expired_token_is_rejected(self, settings: Settings) -> None:
        token, _, _ = create_token(
            subject="u",
            token_type=TokenType.ACCESS,
            expires_delta=timedelta(seconds=-1),
            settings=settings,
        )
        with pytest.raises(AuthenticationError, match="expired"):
            decode_token(token, settings=settings)

    def test_token_signed_with_another_key_is_rejected(self, settings: Settings) -> None:
        other = Settings(
            env=Environment.TEST,
            secret_key="a-completely-different-signing-key-9876",  # type: ignore[arg-type]
            cookie_secure=False,
        )
        token, _, _ = create_access_token("u", settings=other)
        with pytest.raises(AuthenticationError, match="invalid"):
            decode_token(token, settings=settings)

    def test_algorithm_confusion_is_rejected(self, settings: Settings) -> None:
        """An unsigned 'alg: none' token must never be accepted."""
        forged = jwt.encode(
            {"sub": "attacker", "typ": "access", "jti": "x", "iat": 1, "exp": 1 << 31},
            key="",
            algorithm="none",
        )
        with pytest.raises(AuthenticationError):
            decode_token(forged, settings=settings)

    def test_refresh_token_lives_longer_than_access_token(self, settings: Settings) -> None:
        _, _, access_exp = create_access_token("u", settings=settings)
        _, _, refresh_exp = create_refresh_token("u", settings=settings)
        assert refresh_exp > access_exp

    def test_each_token_gets_a_unique_jti(self, settings: Settings) -> None:
        jtis = {create_refresh_token("u", settings=settings)[1] for _ in range(10)}
        assert len(jtis) == 10


class TestApiTokens:
    def test_generate_returns_prefix_and_hash(self) -> None:
        plaintext, prefix, digest = generate_api_token()
        assert plaintext.startswith(API_TOKEN_PREFIX)
        assert plaintext.startswith(prefix)
        assert digest == hash_token(plaintext)
        assert len(digest) == 64

    def test_tokens_are_unique(self) -> None:
        assert len({generate_api_token()[0] for _ in range(50)}) == 50


class TestTOTP:
    def test_valid_code_accepted(self, settings: Settings) -> None:
        secret = generate_mfa_secret()
        assert verify_totp(secret, pyotp.TOTP(secret).now(), settings)

    def test_wrong_code_rejected(self, settings: Settings) -> None:
        assert not verify_totp(generate_mfa_secret(), "000000", settings)

    def test_non_numeric_code_rejected(self, settings: Settings) -> None:
        assert not verify_totp(generate_mfa_secret(), "abcdef", settings)

    def test_code_from_another_secret_rejected(self, settings: Settings) -> None:
        assert not verify_totp(
            generate_mfa_secret(), pyotp.TOTP(generate_mfa_secret()).now(), settings
        )

    def test_code_outside_the_window_rejected(self, settings: Settings) -> None:
        secret = generate_mfa_secret()
        stale = pyotp.TOTP(secret).at(int(time.time()) - 300)
        assert not verify_totp(secret, stale, settings)

    def test_provisioning_uri_carries_issuer(self, settings: Settings) -> None:
        uri = mfa_provisioning_uri(generate_mfa_secret(), "user@example.test", settings)
        assert uri.startswith("otpauth://totp/")
        assert "issuer=NetSecOps" in uri

    def test_recovery_codes_are_unique(self) -> None:
        codes = generate_recovery_codes(10)
        assert len(codes) == len(set(codes)) == 10
