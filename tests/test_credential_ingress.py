"""Tests for private TLS credential ingress, HMAC request binding, and replay prevention."""

from __future__ import annotations

import json
import os
import tempfile
import time
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from pinterest_mcp.persistence.encryption import CredentialCipher
from pinterest_mcp.persistence.ingress import (
    IngressSecurityError,
    MemoryNonceStore,
    compute_body_digest,
    compute_hmac_signature,
    process_credential_ingress,
)
from pinterest_mcp.persistence.models import Base, OAuthCompletionReceipt, PinterestConnection, User

SHARED_SECRET = "test-broker-handoff-secret-with-high-entropy-12345"
TEST_KEY = b"12345678901234567890123456789012"  # 32 bytes


@pytest.fixture
async def db_session():
    # Use temporary file database so tables and state are properly maintained
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session

    await engine.dispose()
    if os.path.exists(db_path):
        os.remove(db_path)


@pytest.fixture
def cipher():
    return CredentialCipher(keys={"key-2026": TEST_KEY}, primary_key_id="key-2026")


@pytest.fixture
def nonce_store():
    return MemoryNonceStore()


def make_signed_request(
    body_dict: dict,
    secret: str = SHARED_SECRET,
    method: str = "POST",
    path: str = "/internal/credential-ingress",
    timestamp: float | None = None,
    nonce: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[dict[str, str], bytes]:
    body_bytes = json.dumps(body_dict, sort_keys=True).encode("utf-8")
    ts = str(time.time() if timestamp is None else timestamp)
    n = nonce or uuid.uuid4().hex
    body_digest = compute_body_digest(body_bytes)
    sig = compute_hmac_signature(
        secret=secret,
        method=method,
        path=path,
        timestamp=ts,
        nonce=n,
        body_digest=body_digest,
    )
    headers = {
        "x-signature": sig,
        "x-timestamp": ts,
        "x-nonce": n,
    }
    if extra_headers:
        headers.update(extra_headers)
    return headers, body_bytes


@pytest.mark.asyncio
async def test_successful_credential_ingress_persists_user_connection_receipt(
    db_session: AsyncSession, cipher: CredentialCipher, nonce_store: MemoryNonceStore
):
    payload = {
        "transaction_id": "tx-1001",
        "issuer": "https://auth.example.com/realms/mcp",
        "subject": "usr-sub-1001",
        "provider_account_id": "987654321012345678",
        "account_username": "paboratory",
        "account_type": "BUSINESS",
        "tokens": {
            "access_token": "pina_test_access_token",
            "refresh_token": "pinr_test_refresh_token",
            "expires_in": 3600,
            "refresh_token_expires_in": 5184000,
            "scope": "boards:read pins:read user_accounts:read",
        },
    }
    headers, body = make_signed_request(payload)

    result = await process_credential_ingress(
        session=db_session,
        cipher=cipher,
        nonce_store=nonce_store,
        shared_secret=SHARED_SECRET,
        method="POST",
        path="/internal/credential-ingress",
        headers=headers,
        body=body,
    )
    await db_session.commit()

    assert result["status"] == "persisted"
    assert result["transaction_id"] == "tx-1001"
    owner_uuid = uuid.UUID(result["owner_id"])

    # Verify user row
    user = await db_session.get(User, owner_uuid)
    assert user is not None
    assert user.subject == "usr-sub-1001"
    assert user.provider_account_id == "987654321012345678"

    # Verify connection row
    conn = (
        await db_session.execute(
            select(PinterestConnection).where(PinterestConnection.owner_id == owner_uuid)
        )
    ).scalar_one()
    assert conn.status == "active"
    assert conn.credential_version == 1
    # Verify tokens are encrypted
    assert conn.encrypted_access_token != "pina_test_access_token"
    decrypted_access = cipher.decrypt(
        conn.encrypted_access_token,
        owner_id=user.id,
        provider_account_id=user.provider_account_id,
    )
    assert decrypted_access == "pina_test_access_token"

    # Verify receipt row
    receipt = (
        await db_session.execute(
            select(OAuthCompletionReceipt).where(OAuthCompletionReceipt.transaction_id == "tx-1001")
        )
    ).scalar_one()
    assert receipt.status == "completed"
    assert receipt.owner_id == owner_uuid


@pytest.mark.asyncio
async def test_expired_timestamp_rejected(
    db_session: AsyncSession, cipher: CredentialCipher, nonce_store: MemoryNonceStore
):
    payload = {
        "transaction_id": "tx-expired",
        "issuer": "https://auth.example.com",
        "subject": "usr-exp",
        "provider_account_id": "111",
        "tokens": {"access_token": "token"},
    }
    old_timestamp = time.time() - 400.0  # 400s in past (>300s window)
    headers, body = make_signed_request(payload, timestamp=old_timestamp)

    with pytest.raises(IngressSecurityError, match="Request timestamp expired"):
        await process_credential_ingress(
            session=db_session,
            cipher=cipher,
            nonce_store=nonce_store,
            shared_secret=SHARED_SECRET,
            method="POST",
            path="/internal/credential-ingress",
            headers=headers,
            body=body,
        )


@pytest.mark.asyncio
async def test_tampered_payload_rejected(
    db_session: AsyncSession, cipher: CredentialCipher, nonce_store: MemoryNonceStore
):
    payload = {
        "transaction_id": "tx-tamper",
        "issuer": "https://auth.example.com",
        "subject": "usr-tamper",
        "provider_account_id": "222",
        "tokens": {"access_token": "token"},
    }
    headers, _ = make_signed_request(payload)
    # Tamper with body bytes
    tampered_body = json.dumps({**payload, "provider_account_id": "hacked"}).encode("utf-8")

    with pytest.raises(IngressSecurityError, match="Invalid request signature"):
        await process_credential_ingress(
            session=db_session,
            cipher=cipher,
            nonce_store=nonce_store,
            shared_secret=SHARED_SECRET,
            method="POST",
            path="/internal/credential-ingress",
            headers=headers,
            body=tampered_body,
        )


@pytest.mark.asyncio
async def test_nonce_replay_attack_rejected(
    db_session: AsyncSession, cipher: CredentialCipher, nonce_store: MemoryNonceStore
):
    payload = {
        "transaction_id": "tx-replay-1",
        "issuer": "https://auth.example.com",
        "subject": "usr-replay",
        "provider_account_id": "333",
        "tokens": {"access_token": "token"},
    }
    headers, body = make_signed_request(payload)

    # First attempt succeeds
    res1 = await process_credential_ingress(
        session=db_session,
        cipher=cipher,
        nonce_store=nonce_store,
        shared_secret=SHARED_SECRET,
        method="POST",
        path="/internal/credential-ingress",
        headers=headers,
        body=body,
    )
    await db_session.commit()
    assert res1["status"] == "persisted"

    # Second attempt with same nonce but different transaction_id
    payload2 = {**payload, "transaction_id": "tx-replay-2"}
    body2 = json.dumps(payload2, sort_keys=True).encode("utf-8")
    body2_digest = compute_body_digest(body2)
    sig2 = compute_hmac_signature(
        secret=SHARED_SECRET,
        method="POST",
        path="/internal/credential-ingress",
        timestamp=headers["x-timestamp"],
        nonce=headers["x-nonce"],  # Reused nonce!
        body_digest=body2_digest,
    )
    headers2 = {
        "x-signature": sig2,
        "x-timestamp": headers["x-timestamp"],
        "x-nonce": headers["x-nonce"],
    }

    with pytest.raises(IngressSecurityError, match="nonce has already been consumed"):
        await process_credential_ingress(
            session=db_session,
            cipher=cipher,
            nonce_store=nonce_store,
            shared_secret=SHARED_SECRET,
            method="POST",
            path="/internal/credential-ingress",
            headers=headers2,
            body=body2,
        )


@pytest.mark.asyncio
async def test_public_routing_attempt_rejected(
    db_session: AsyncSession, cipher: CredentialCipher, nonce_store: MemoryNonceStore
):
    payload = {
        "transaction_id": "tx-public",
        "issuer": "https://auth.example.com",
        "subject": "usr-pub",
        "provider_account_id": "444",
        "tokens": {"access_token": "token"},
    }
    headers, body = make_signed_request(
        payload, extra_headers={"x-forwarded-host": "public.mcp.example.com"}
    )

    with pytest.raises(IngressSecurityError, match="Public routing rejected"):
        await process_credential_ingress(
            session=db_session,
            cipher=cipher,
            nonce_store=nonce_store,
            shared_secret=SHARED_SECRET,
            method="POST",
            path="/internal/credential-ingress",
            headers=headers,
            body=body,
        )


@pytest.mark.asyncio
async def test_foreign_owner_account_mismatch_rejected(
    db_session: AsyncSession, cipher: CredentialCipher, nonce_store: MemoryNonceStore
):
    # Setup initial owner with provider account 555
    payload1 = {
        "transaction_id": "tx-user-1",
        "issuer": "https://auth.example.com",
        "subject": "usr-fixed",
        "provider_account_id": "555",
        "tokens": {"access_token": "token1"},
    }
    h1, b1 = make_signed_request(payload1)
    await process_credential_ingress(
        session=db_session,
        cipher=cipher,
        nonce_store=nonce_store,
        shared_secret=SHARED_SECRET,
        method="POST",
        path="/internal/credential-ingress",
        headers=h1,
        body=b1,
    )
    await db_session.commit()

    # Same subject attempting to bind to a different provider account 999
    payload2 = {
        "transaction_id": "tx-user-2",
        "issuer": "https://auth.example.com",
        "subject": "usr-fixed",
        "provider_account_id": "999",  # Foreign account
        "tokens": {"access_token": "token2"},
    }
    h2, b2 = make_signed_request(payload2)

    with pytest.raises(IngressSecurityError, match="cannot bind to foreign account"):
        await process_credential_ingress(
            session=db_session,
            cipher=cipher,
            nonce_store=nonce_store,
            shared_secret=SHARED_SECRET,
            method="POST",
            path="/internal/credential-ingress",
            headers=h2,
            body=b2,
        )

    # Different subject attempting to steal provider account 555
    payload3 = {
        "transaction_id": "tx-user-3",
        "issuer": "https://auth.example.com",
        "subject": "usr-foreign-intruder",
        "provider_account_id": "555",  # Already bound to usr-fixed
        "tokens": {"access_token": "token3"},
    }
    h3, b3 = make_signed_request(payload3)

    with pytest.raises(IngressSecurityError, match="already bound to another owner"):
        await process_credential_ingress(
            session=db_session,
            cipher=cipher,
            nonce_store=nonce_store,
            shared_secret=SHARED_SECRET,
            method="POST",
            path="/internal/credential-ingress",
            headers=h3,
            body=b3,
        )


@pytest.mark.asyncio
async def test_idempotent_duplicate_transaction_and_payload_mismatch(
    db_session: AsyncSession, cipher: CredentialCipher, nonce_store: MemoryNonceStore
):
    payload = {
        "transaction_id": "tx-idem-1",
        "issuer": "https://auth.example.com",
        "subject": "usr-idem",
        "provider_account_id": "777",
        "tokens": {"access_token": "token_idem"},
    }
    h1, b1 = make_signed_request(payload)

    res1 = await process_credential_ingress(
        session=db_session,
        cipher=cipher,
        nonce_store=nonce_store,
        shared_secret=SHARED_SECRET,
        method="POST",
        path="/internal/credential-ingress",
        headers=h1,
        body=b1,
    )
    await db_session.commit()
    assert res1["status"] == "persisted"

    # Retry same transaction with same payload (new nonce)
    h2, b2 = make_signed_request(payload)
    res2 = await process_credential_ingress(
        session=db_session,
        cipher=cipher,
        nonce_store=nonce_store,
        shared_secret=SHARED_SECRET,
        method="POST",
        path="/internal/credential-ingress",
        headers=h2,
        body=b2,
    )
    assert res2["status"] == "idempotent_duplicate"
    assert res2["owner_id"] == res1["owner_id"]

    # Reusing same transaction_id with mismatched payload
    mismatched_payload = {**payload, "provider_account_id": "778"}
    h3, b3 = make_signed_request(mismatched_payload)
    with pytest.raises(IngressSecurityError, match="mismatched payload"):
        await process_credential_ingress(
            session=db_session,
            cipher=cipher,
            nonce_store=nonce_store,
            shared_secret=SHARED_SECRET,
            method="POST",
            path="/internal/credential-ingress",
            headers=h3,
            body=b3,
        )


@pytest.mark.asyncio
async def test_fault_injection_rolls_back_without_partial_state(
    db_session: AsyncSession, cipher: CredentialCipher, nonce_store: MemoryNonceStore, monkeypatch
):
    payload = {
        "transaction_id": "tx-fault-inject",
        "issuer": "https://auth.example.com",
        "subject": "usr-fault",
        "provider_account_id": "888",
        "tokens": {"access_token": "token_fault"},
    }
    h1, b1 = make_signed_request(payload)

    # Monkeypatch session.flush to fail after user creation, simulating storage commit failure
    original_flush = db_session.flush
    flush_count = 0

    async def failing_flush():
        nonlocal flush_count
        flush_count += 1
        if flush_count >= 2:  # fail when flushing connection/receipt
            raise RuntimeError("Injected database failure before commit")
        await original_flush()

    monkeypatch.setattr(db_session, "flush", failing_flush)

    with pytest.raises(RuntimeError, match="Injected database failure"):
        await process_credential_ingress(
            session=db_session,
            cipher=cipher,
            nonce_store=nonce_store,
            shared_secret=SHARED_SECRET,
            method="POST",
            path="/internal/credential-ingress",
            headers=h1,
            body=b1,
        )

    # Roll back session
    await db_session.rollback()

    # Verify no receipt and no connection exist in DB
    receipt = await db_session.scalar(
        select(OAuthCompletionReceipt).where(
            OAuthCompletionReceipt.transaction_id == "tx-fault-inject"
        )
    )
    assert receipt is None

    conn = await db_session.scalar(
        select(PinterestConnection).where(PinterestConnection.provider_account_id == "888")
    )
    assert conn is None

    # Now restore normal flush and retry: retry must succeed completely
    monkeypatch.setattr(db_session, "flush", original_flush)
    h_retry, b_retry = make_signed_request(payload)
    res_retry = await process_credential_ingress(
        session=db_session,
        cipher=cipher,
        nonce_store=nonce_store,
        shared_secret=SHARED_SECRET,
        method="POST",
        path="/internal/credential-ingress",
        headers=h_retry,
        body=b_retry,
    )
    await db_session.commit()
    assert res_retry["status"] == "persisted"


@pytest.mark.asyncio
@pytest.mark.parametrize("delay", [0, 361, 599])
async def test_exact_signed_replay_rejected_even_with_receipt(
    db_session, cipher, nonce_store, monkeypatch, delay
):
    now = time.time()
    monkeypatch.setattr("pinterest_mcp.persistence.ingress.time.time", lambda: now)
    payload = {
        "transaction_id": "tx-exact-replay",
        "issuer": "https://auth.example.com",
        "subject": "usr-exact-replay",
        "provider_account_id": "888",
        "tokens": {"access_token": "test-token"},
    }
    headers, body = make_signed_request(payload, timestamp=now + 300)
    kwargs = {
        "session": db_session,
        "cipher": cipher,
        "nonce_store": nonce_store,
        "shared_secret": SHARED_SECRET,
        "method": "POST",
        "path": "/internal/credential-ingress",
        "headers": headers,
        "body": body,
    }
    await process_credential_ingress(**kwargs)
    await db_session.commit()
    monkeypatch.setattr("pinterest_mcp.persistence.ingress.time.time", lambda: now + delay)
    with pytest.raises(IngressSecurityError, match="nonce has already been consumed"):
        await process_credential_ingress(**kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("timestamp", [float("nan"), float("inf"), float("-inf")])
async def test_nonfinite_signed_timestamp_rejected(db_session, cipher, nonce_store, timestamp):
    headers, body = make_signed_request({}, timestamp=timestamp)
    with pytest.raises(IngressSecurityError, match="timestamp expired"):
        await process_credential_ingress(
            session=db_session,
            cipher=cipher,
            nonce_store=nonce_store,
            shared_secret=SHARED_SECRET,
            method="POST",
            path="/internal/credential-ingress",
            headers=headers,
            body=body,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("header", ["x-FoRwArDeD-hOsT", "fOrWaRdEd", "vIa"])
async def test_mixed_case_public_headers_rejected(db_session, cipher, nonce_store, header):
    headers, body = make_signed_request({}, extra_headers={header: "public.example.com"})
    with pytest.raises(IngressSecurityError, match="Public routing rejected"):
        await process_credential_ingress(
            session=db_session,
            cipher=cipher,
            nonce_store=nonce_store,
            shared_secret=SHARED_SECRET,
            method="POST",
            path="/internal/credential-ingress",
            headers=headers,
            body=body,
        )
