"""Envelope encryption tests (FR-CRED-02, DATA-01)."""

from __future__ import annotations

import base64
import json

import pytest

from netsecops.core.config import Environment, MasterKeyProvider, Settings
from netsecops.core.crypto import (
    CryptoError,
    EncryptedBlob,
    EnvMasterKeyProvider,
    MasterKeyUnavailableError,
    SecretVault,
    build_vault,
    generate_master_key,
)


def _settings(master_key: str | None = None) -> Settings:
    return Settings(
        env=Environment.TEST,
        secret_key="x" * 48,  # type: ignore[arg-type]
        master_key=master_key,  # type: ignore[arg-type]
        master_key_provider=MasterKeyProvider.ENV,
        cookie_secure=False,
    )


class TestRoundTrip:
    def test_seal_and_open(self, vault: SecretVault) -> None:
        sealed = vault.seal("enable-secret-value", aad="row-1")
        assert vault.open(sealed, aad="row-1") == b"enable-secret-value"

    def test_ciphertext_does_not_contain_plaintext(self, vault: SecretVault) -> None:
        sealed = vault.seal("SuperSecretCommunity", aad="row-1")
        assert b"SuperSecretCommunity" not in sealed
        assert "SuperSecretCommunity" not in sealed.decode("utf-8")

    def test_same_plaintext_seals_differently_each_time(self, vault: SecretVault) -> None:
        """A fresh data key and nonce per seal means no ciphertext equality oracle."""
        a = vault.seal("identical", aad="row-1")
        b = vault.seal("identical", aad="row-1")
        assert a != b
        assert vault.open(a, aad="row-1") == vault.open(b, aad="row-1")

    def test_accepts_bytes_input(self, vault: SecretVault) -> None:
        assert vault.open(vault.seal(b"\x00\xffbinary", aad="r"), aad="r") == b"\x00\xffbinary"


class TestAADBinding:
    """DATA-01 — a blob is bound to the row it belongs to."""

    def test_wrong_aad_fails_to_open(self, vault: SecretVault) -> None:
        sealed = vault.seal("secret", aad="credential-row-1")
        with pytest.raises(CryptoError, match="Decryption failed"):
            vault.open(sealed, aad="credential-row-2")

    def test_blob_cannot_be_replayed_into_another_row(self, vault: SecretVault) -> None:
        stolen = vault.seal("admin-password", aad="row-A")
        # An attacker with write access to the database copies row A's blob into row B.
        with pytest.raises(CryptoError):
            vault.open(stolen, aad="row-B")


class TestTamperDetection:
    def test_flipped_ciphertext_byte_is_rejected(self, vault: SecretVault) -> None:
        sealed = vault.seal("secret", aad="r")
        envelope = EncryptedBlob.from_bytes(sealed)

        corrupted = bytearray(envelope.ciphertext)
        corrupted[0] ^= 0x01
        tampered = EncryptedBlob(
            version=envelope.version,
            key_id=envelope.key_id,
            wrapped_key=envelope.wrapped_key,
            wrap_nonce=envelope.wrap_nonce,
            ciphertext=bytes(corrupted),
            nonce=envelope.nonce,
        ).to_bytes()

        with pytest.raises(CryptoError):
            vault.open(tampered, aad="r")

    def test_malformed_blob_is_rejected(self, vault: SecretVault) -> None:
        with pytest.raises(CryptoError, match="Malformed"):
            vault.open(b"not-json-at-all", aad="r")

    def test_unknown_version_is_rejected(self, vault: SecretVault) -> None:
        sealed = json.loads(vault.seal("s", aad="r").decode("utf-8"))
        sealed["v"] = 99
        with pytest.raises(CryptoError, match="Unsupported blob version"):
            vault.open(json.dumps(sealed).encode("utf-8"), aad="r")


class TestRotation:
    def test_rewrap_preserves_plaintext(self, vault: SecretVault) -> None:
        sealed = vault.seal("rotate-me", aad="r")
        rewrapped = vault.rewrap(sealed, aad="r")

        assert rewrapped != sealed  # fresh data key and nonce
        assert vault.open(rewrapped, aad="r") == b"rotate-me"

    def test_rewrap_under_a_new_master_key(self) -> None:
        old_key, new_key = generate_master_key(), generate_master_key()

        old_vault = SecretVault(EnvMasterKeyProvider(_settings(old_key)))
        sealed = old_vault.seal("device-password", aad="cred-1")

        # The operator swaps MASTER_KEY, then re-wraps: read with the old, write with
        # the new. Here that is modelled by decrypting first, then re-sealing.
        plaintext = old_vault.open(sealed, aad="cred-1")
        new_vault = SecretVault(EnvMasterKeyProvider(_settings(new_key)))
        resealed = new_vault.seal(plaintext, aad="cred-1")

        assert new_vault.open(resealed, aad="cred-1") == b"device-password"
        with pytest.raises(CryptoError):
            old_vault.open(resealed, aad="cred-1")


class TestMasterKeyProvider:
    def test_missing_master_key_is_a_clear_error(self) -> None:
        with pytest.raises(MasterKeyUnavailableError, match="MASTER_KEY is not set"):
            build_vault(_settings(None))

    def test_hex_encoded_key_is_accepted(self) -> None:
        hex_key = base64.b64decode(generate_master_key()).hex()
        vault = SecretVault(EnvMasterKeyProvider(_settings(hex_key)))
        assert vault.open(vault.seal("ok", aad="r"), aad="r") == b"ok"

    def test_short_key_is_rejected(self) -> None:
        with pytest.raises(MasterKeyUnavailableError, match="exactly 32 bytes"):
            EnvMasterKeyProvider(_settings(base64.b64encode(b"too-short").decode()))

    def test_generated_key_is_256_bit(self) -> None:
        assert len(base64.b64decode(generate_master_key())) == 32
