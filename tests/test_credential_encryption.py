"""Tests for authenticated encryption with versioned external keys and bound AAD (Task 2.3)."""

from __future__ import annotations

import secrets
import uuid

import pytest

from pinterest_mcp.persistence.encryption import (
    CredentialCipher,
    DecryptionError,
    KeyNotFoundError,
    build_aad,
)


@pytest.fixture
def cipher_keys():
    k1 = secrets.token_bytes(32)
    k2 = secrets.token_bytes(32)
    return {"primary": k1, "secondary": k2}


@pytest.fixture
def cipher(cipher_keys):
    return CredentialCipher(keys=cipher_keys, primary_key_id="primary")


def test_round_trip_encryption_and_fresh_nonces(cipher):
    owner_id = uuid.uuid4()
    provider_acc = "123456789012345678"
    token = "pina_test_access_token_super_secret"

    enc1 = cipher.encrypt(token, owner_id=owner_id, provider_account_id=provider_acc)
    enc2 = cipher.encrypt(token, owner_id=owner_id, provider_account_id=provider_acc)

    # Fresh 96-bit nonces mean two encryptions of same plaintext have distinct ciphertexts
    assert enc1 != enc2
    assert token not in enc1
    assert token not in enc2

    # Round-trip decryption recovers identical token
    assert cipher.decrypt(enc1, owner_id=owner_id, provider_account_id=provider_acc) == token
    assert cipher.decrypt(enc2, owner_id=owner_id, provider_account_id=provider_acc) == token


def test_tampered_ciphertext_rejected(cipher):
    owner_id = uuid.uuid4()
    provider_acc = "123456789012345678"
    token = "pina_secret_token"

    encrypted = cipher.encrypt(token, owner_id=owner_id, provider_account_id=provider_acc)
    parts = encrypted.split(".")

    # Tamper with the last character of the ciphertext/tag payload
    tampered_body = parts[3][:-1] + ("A" if parts[3][-1] != "A" else "B")
    tampered = f"{parts[0]}.{parts[1]}.{parts[2]}.{tampered_body}"

    with pytest.raises(DecryptionError, match="authentication tag verification failed"):
        cipher.decrypt(tampered, owner_id=owner_id, provider_account_id=provider_acc)


def test_cross_owner_substitution_rejected(cipher):
    owner_alice = uuid.uuid4()
    owner_bob = uuid.uuid4()
    provider_acc = "123456789012345678"
    token = "pina_alice_secret"

    # Alice's token encrypted with Alice's owner_id in AAD
    encrypted = cipher.encrypt(token, owner_id=owner_alice, provider_account_id=provider_acc)

    # Attempting to decrypt under Bob's owner_id must be rejected
    with pytest.raises(DecryptionError, match="Associated Data"):
        cipher.decrypt(encrypted, owner_id=owner_bob, provider_account_id=provider_acc)


def test_cross_account_substitution_rejected(cipher):
    owner_id = uuid.uuid4()
    acc_1 = "111111111111111111"
    acc_2 = "222222222222222222"
    token = "pina_acc1_secret"

    encrypted = cipher.encrypt(token, owner_id=owner_id, provider_account_id=acc_1)

    # Attempting to decrypt with mismatched provider_account_id must be rejected
    with pytest.raises(DecryptionError):
        cipher.decrypt(encrypted, owner_id=owner_id, provider_account_id=acc_2)


def test_key_rotation_without_plaintext_exposure(cipher_keys):
    k1 = cipher_keys["primary"]
    k2 = cipher_keys["secondary"]
    k3 = secrets.token_bytes(32)

    cipher_old = CredentialCipher({"v1": k1, "v2": k2}, primary_key_id="v1")
    owner_id = uuid.uuid4()
    provider_acc = "999888777666555444"
    token = "pina_rotating_token"

    # 1. Encrypted under v1
    enc_v1 = cipher_old.encrypt(
        token, owner_id=owner_id, provider_account_id=provider_acc, key_id="v1"
    )
    assert enc_v1.startswith("v1.v1.")

    # 2. Add v3 key and set primary
    cipher_new = CredentialCipher({"v1": k1, "v2": k2, "v3": k3}, primary_key_id="v3")

    # 3. Rotate to v3
    enc_v3 = cipher_new.rotate_key(
        enc_v1, owner_id=owner_id, provider_account_id=provider_acc, new_key_id="v3"
    )
    assert enc_v3.startswith("v1.v3.")
    assert token not in enc_v3

    # Decrypt under v3
    assert cipher_new.decrypt(enc_v3, owner_id=owner_id, provider_account_id=provider_acc) == token


def test_unknown_key_id_raises_key_not_found(cipher):
    owner_id = uuid.uuid4()
    provider_acc = "1234567890"

    bogus = "v1.nonexistent_key_id.MDEyMzQ1Njc4OTAx.AQIDBA=="
    with pytest.raises(KeyNotFoundError, match="not available"):
        cipher.decrypt(bogus, owner_id=owner_id, provider_account_id=provider_acc)


def test_database_record_contains_no_plaintext(cipher):
    """Verify that stored ciphertext format contains zero plaintext leakage."""
    owner_id = uuid.uuid4()
    provider_acc = "123456789012345678"
    secret_access = "pina_super_sensitive_access_token_xyz"
    secret_refresh = "pinr_super_sensitive_refresh_token_abc"

    enc_access = cipher.encrypt(secret_access, owner_id, provider_acc)
    enc_refresh = cipher.encrypt(secret_refresh, owner_id, provider_acc)

    # Neither secret should appear in ciphertext
    assert secret_access not in enc_access
    assert secret_refresh not in enc_refresh

    # Verify AAD contains proper structure
    aad = build_aad(owner_id, provider_acc, "primary")
    assert str(owner_id).encode("utf-8") in aad
    assert provider_acc.encode("utf-8") in aad
