"""Authenticated encryption for hosted Pinterest credentials (AES-256-GCM with versioned keys).

Enforces:
- AES-256-GCM with fresh 96-bit (12-byte) nonces per encryption.
- Authenticated Additional Data (AAD) binding owner UUID, provider account ID, and key version.
- Tamper, forgery, and cross-owner substitution rejection.
- Multi-key support for seamless zero-downtime key rotation.
"""

from __future__ import annotations

import base64
import json
import secrets
import uuid

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionError(Exception):
    """Base exception for encryption/decryption failures."""


class DecryptionError(EncryptionError):
    """Raised when ciphertext is invalid, tampered, or AAD does not match."""


class KeyNotFoundError(EncryptionError):
    """Raised when the key ID encoded in the ciphertext is unknown."""


def build_aad(
    owner_id: uuid.UUID | str,
    provider_account_id: str,
    key_id: str,
    schema_version: int = 1,
) -> bytes:
    """Construct canonical binary Associated Additional Data (AAD).

    Binds the ciphertext to this specific owner, provider account, key ID, and schema version.
    """
    aad_data = {
        "owner_id": str(owner_id),
        "provider_account_id": str(provider_account_id),
        "key_id": str(key_id),
        "version": schema_version,
    }
    # Deterministic JSON encoding (sorted keys, compact separators)
    return json.dumps(aad_data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class CredentialCipher:
    """Manages authenticated encryption and decryption using AES-256-GCM."""

    def __init__(
        self,
        keys: dict[str, bytes],
        primary_key_id: str = "primary",
    ) -> None:
        """Initialize cipher with a mapping of key_id -> 32-byte AES key."""
        if not keys:
            raise ValueError("At least one encryption key must be provided")
        if primary_key_id not in keys:
            raise ValueError(f"Primary key ID {primary_key_id!r} not found in provided keys")

        self.primary_key_id = primary_key_id
        self._ciphers: dict[str, AESGCM] = {}
        for kid, key_bytes in keys.items():
            if len(key_bytes) != 32:
                raise ValueError(
                    f"Key {kid!r} has invalid length {len(key_bytes)}; expected 32 bytes"
                )
            self._ciphers[kid] = AESGCM(key_bytes)

    @classmethod
    def from_env(
        cls,
        key_material: str | None = None,
        key_id: str = "primary",
        fallback_keys_json: str | None = None,
    ) -> CredentialCipher:
        """Construct from raw base64/hex key material or JSON dictionary."""
        keys: dict[str, bytes] = {}

        if fallback_keys_json:
            parsed = json.loads(fallback_keys_json)
            for k, val in parsed.items():
                keys[k] = cls._decode_key(val)

        if key_material:
            keys[key_id] = cls._decode_key(key_material)

        if not keys:
            raise ValueError("No encryption keys configured")

        primary = key_id if key_id in keys else next(iter(keys.keys()))
        return cls(keys=keys, primary_key_id=primary)

    @staticmethod
    def _decode_key(raw: str) -> bytes:
        raw = raw.strip()
        # Try hex first if 64 chars
        if len(raw) == 64:
            try:
                return bytes.fromhex(raw)
            except ValueError:
                pass
        # Try base64
        try:
            decoded = base64.b64decode(raw)
            if len(decoded) == 32:
                return decoded
        except (ValueError, TypeError):
            pass
        # If raw string is 32 chars
        if len(raw.encode("utf-8")) == 32:
            return raw.encode("utf-8")
        raise ValueError("Encryption key must be 32 bytes (raw, 64-char hex, or base64)")

    def encrypt(
        self,
        plaintext: str,
        owner_id: uuid.UUID | str,
        provider_account_id: str,
        key_id: str | None = None,
        schema_version: int = 1,
    ) -> str:
        """Encrypt plaintext using AES-256-GCM with fresh nonce and bound AAD.

        Format: v1.<key_id>.<b64_nonce>.<b64_ciphertext_and_tag>
        """
        active_key_id = key_id or self.primary_key_id
        if active_key_id not in self._ciphers:
            raise KeyNotFoundError(f"Key {active_key_id!r} not found for encryption")

        cipher = self._ciphers[active_key_id]
        nonce = secrets.token_bytes(12)  # 96-bit standard AES-GCM nonce
        aad = build_aad(owner_id, provider_account_id, active_key_id, schema_version)

        ciphertext = cipher.encrypt(nonce, plaintext.encode("utf-8"), aad)

        b64_nonce = base64.urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
        b64_cipher = base64.urlsafe_b64encode(ciphertext).decode("ascii").rstrip("=")

        return f"v1.{active_key_id}.{b64_nonce}.{b64_cipher}"

    def decrypt(
        self,
        encoded_ciphertext: str,
        owner_id: uuid.UUID | str,
        provider_account_id: str,
        schema_version: int = 1,
    ) -> str:
        """Decrypt ciphertext verifying nonce, tag, and bound AAD.

        Raises DecryptionError if tag or AAD mismatch.
        """
        parts = encoded_ciphertext.split(".")
        if len(parts) != 4 or parts[0] != "v1":
            raise DecryptionError("Invalid ciphertext format")

        _, kid, b64_nonce, b64_cipher = parts
        if kid not in self._ciphers:
            raise KeyNotFoundError(f"Key {kid!r} not available to decrypt payload")

        def pad(s: str) -> bytes:
            return (s + "=" * (-len(s) % 4)).encode("ascii")

        try:
            nonce = base64.urlsafe_b64decode(pad(b64_nonce))
            ciphertext = base64.urlsafe_b64decode(pad(b64_cipher))
        except Exception as e:
            raise DecryptionError("Malformed base64 in ciphertext") from e

        cipher = self._ciphers[kid]
        aad = build_aad(owner_id, provider_account_id, kid, schema_version)

        try:
            plaintext_bytes = cipher.decrypt(nonce, ciphertext, aad)
            return plaintext_bytes.decode("utf-8")
        except InvalidTag as e:
            raise DecryptionError(
                "Decryption failed: authentication tag verification failed. "
                "Ciphertext may be tampered or Associated Data does not match."
            ) from e

    def rotate_key(
        self,
        encoded_ciphertext: str,
        owner_id: uuid.UUID | str,
        provider_account_id: str,
        new_key_id: str,
        schema_version: int = 1,
    ) -> str:
        """Decrypt under current key and re-encrypt under new_key_id."""
        plaintext = self.decrypt(encoded_ciphertext, owner_id, provider_account_id, schema_version)
        return self.encrypt(
            plaintext,
            owner_id,
            provider_account_id,
            key_id=new_key_id,
            schema_version=schema_version,
        )
