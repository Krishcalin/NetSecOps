"""Envelope encryption for secret material (FR-CRED-02, DATA-01).

Each secret gets its own random 256-bit data key. The plaintext is sealed with
AES-256-GCM under that data key; the data key is itself sealed ("wrapped") under a master
key supplied by a configurable provider. Rotating the master key therefore only requires
re-wrapping the small data keys, never re-encrypting every stored secret.

DATA-01 requires the row id to be bound in as additional authenticated data, so a
ciphertext lifted from one row cannot be replayed into another.

Wire format (``EncryptedBlob``) is versioned so a future algorithm change stays readable.
"""

from __future__ import annotations

import base64
import json
import os
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from netsecops.core.config import MasterKeyProvider, Settings, get_settings

BLOB_VERSION: Final[int] = 1
KEY_BYTES: Final[int] = 32  # AES-256
NONCE_BYTES: Final[int] = 12  # GCM standard nonce


class CryptoError(Exception):
    """Raised when sealing or opening secret material fails."""


class MasterKeyUnavailableError(CryptoError):
    """The configured provider could not supply a master key."""


@dataclass(frozen=True, slots=True)
class EncryptedBlob:
    """Serialisable envelope. Stored in ``bytea`` columns."""

    version: int
    key_id: str
    wrapped_key: bytes
    wrap_nonce: bytes
    ciphertext: bytes
    nonce: bytes

    def to_bytes(self) -> bytes:
        payload = {
            "v": self.version,
            "kid": self.key_id,
            "wk": _b64(self.wrapped_key),
            "wn": _b64(self.wrap_nonce),
            "ct": _b64(self.ciphertext),
            "n": _b64(self.nonce),
        }
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> EncryptedBlob:
        try:
            payload: dict[str, Any] = json.loads(raw.decode("utf-8"))
            return cls(
                version=int(payload["v"]),
                key_id=str(payload["kid"]),
                wrapped_key=_unb64(payload["wk"]),
                wrap_nonce=_unb64(payload["wn"]),
                ciphertext=_unb64(payload["ct"]),
                nonce=_unb64(payload["n"]),
            )
        except (ValueError, KeyError, TypeError) as exc:
            raise CryptoError("Malformed encrypted blob") from exc


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


# ─────────────────────────── master key providers ───────────────────────────


class MasterKeyProviderBase(ABC):
    """Supplies master keys by id. Providers are pluggable per FR-CRED-02.

    Every provider is constructed from :class:`Settings`, so :func:`build_vault` can
    select one from configuration without knowing which it picked.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    @abstractmethod
    def get_key(self, key_id: str) -> bytes:
        """Return the 32-byte master key for ``key_id``."""

    @abstractmethod
    def current_key_id(self) -> str:
        """Return the key id new secrets should be wrapped under."""


class EnvMasterKeyProvider(MasterKeyProviderBase):
    """Master key from ``MASTER_KEY`` (base64 or hex), suitable for dev and small deployments."""

    KEY_ID = "env-1"

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        if settings.master_key is None:
            raise MasterKeyUnavailableError(
                "MASTER_KEY is not set. Generate one with: netsecops-cli generate-master-key"
            )
        self._key = _decode_key(settings.master_key.get_secret_value())

    def get_key(self, key_id: str) -> bytes:
        if key_id != self.KEY_ID:
            raise MasterKeyUnavailableError(f"Unknown master key id: {key_id}")
        return self._key

    def current_key_id(self) -> str:
        return self.KEY_ID


class FileMasterKeyProvider(MasterKeyProviderBase):
    """Master key read from a mounted file (Kubernetes/Docker secret)."""

    KEY_ID = "file-1"

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        if not settings.master_key_path:
            raise MasterKeyUnavailableError("MASTER_KEY_PATH is not set")
        path = Path(settings.master_key_path)
        if not path.is_file():
            raise MasterKeyUnavailableError(f"Master key file not found: {path}")
        self._key = _decode_key(path.read_text(encoding="utf-8").strip())

    def get_key(self, key_id: str) -> bytes:
        if key_id != self.KEY_ID:
            raise MasterKeyUnavailableError(f"Unknown master key id: {key_id}")
        return self._key

    def current_key_id(self) -> str:
        return self.KEY_ID


def _decode_key(material: str) -> bytes:
    """Accept base64 or hex; reject anything that is not exactly 256 bits."""
    decoders: tuple[Callable[[str], bytes], ...] = (base64.b64decode, bytes.fromhex)
    for decode in decoders:
        try:
            key = decode(material)
        except (ValueError, TypeError):
            continue
        if len(key) == KEY_BYTES:
            return bytes(key)
    raise MasterKeyUnavailableError(
        f"Master key must decode to exactly {KEY_BYTES} bytes (base64 or hex)"
    )


def generate_master_key() -> str:
    """Generate a fresh base64-encoded master key for operators to store safely."""
    return base64.b64encode(os.urandom(KEY_BYTES)).decode("ascii")


# ─────────────────────────────── the vault ──────────────────────────────────


class SecretVault:
    """Seals and opens secret material using envelope encryption."""

    def __init__(self, provider: MasterKeyProviderBase) -> None:
        self._provider = provider

    def seal(self, plaintext: bytes | str, *, aad: str) -> bytes:
        """Encrypt ``plaintext``, binding it to ``aad`` (the owning row id, DATA-01)."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        data_key = os.urandom(KEY_BYTES)
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, aad.encode("utf-8"))

        key_id = self._provider.current_key_id()
        wrap_nonce = os.urandom(NONCE_BYTES)
        wrapped_key = AESGCM(self._provider.get_key(key_id)).encrypt(
            wrap_nonce, data_key, key_id.encode("utf-8")
        )

        return EncryptedBlob(
            version=BLOB_VERSION,
            key_id=key_id,
            wrapped_key=wrapped_key,
            wrap_nonce=wrap_nonce,
            ciphertext=ciphertext,
            nonce=nonce,
        ).to_bytes()

    def open(self, blob: bytes, *, aad: str) -> bytes:
        """Decrypt a sealed blob. Raises :class:`CryptoError` if tampered or mis-bound."""
        envelope = EncryptedBlob.from_bytes(blob)
        if envelope.version != BLOB_VERSION:
            raise CryptoError(f"Unsupported blob version: {envelope.version}")

        try:
            data_key = AESGCM(self._provider.get_key(envelope.key_id)).decrypt(
                envelope.wrap_nonce, envelope.wrapped_key, envelope.key_id.encode("utf-8")
            )
            return AESGCM(data_key).decrypt(
                envelope.nonce, envelope.ciphertext, aad.encode("utf-8")
            )
        except InvalidTag as exc:
            raise CryptoError("Decryption failed: blob is corrupt, tampered, or mis-bound") from exc

    def rewrap(self, blob: bytes, *, aad: str) -> bytes:
        """Re-wrap a blob under the provider's current master key (FR-CRED-02 rotation).

        The plaintext is recovered and re-sealed, which also produces a fresh data key —
        so rotation limits the blast radius of both a leaked master key and a leaked
        data key.
        """
        return self.seal(self.open(blob, aad=aad), aad=aad)


_PROVIDERS: dict[MasterKeyProvider, type[MasterKeyProviderBase]] = {
    MasterKeyProvider.ENV: EnvMasterKeyProvider,
    MasterKeyProvider.FILE: FileMasterKeyProvider,
}


def build_vault(settings: Settings | None = None) -> SecretVault:
    settings = settings or get_settings()
    provider_cls = _PROVIDERS.get(settings.master_key_provider)
    if provider_cls is None:
        # Vault/KMS providers arrive with FR-CRED-06 in Phase 1.
        raise MasterKeyUnavailableError(
            f"Master key provider '{settings.master_key_provider}' is not implemented yet"
        )
    return SecretVault(provider_cls(settings))
