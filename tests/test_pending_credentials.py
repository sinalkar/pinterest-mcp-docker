"""Pending-vault tests; optional service URLs must point to disposable test databases."""

import asyncio
import os
import time
import uuid

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from pinterest_mcp.persistence.encryption import CredentialCipher, DecryptionError
from pinterest_mcp.persistence.ingress import (
    IngressSecurityError,
    MemoryNonceStore,
    RedisNonceStore,
)
from pinterest_mcp.persistence.ingress_app import create_credential_ingress
from pinterest_mcp.persistence.models import Base, PendingCredential, PinterestConnection, User
from pinterest_mcp.persistence.pending import expire_pending, process_pending
from pinterest_mcp.persistence.repository import ConnectionRepository
from tests.test_credential_ingress import SHARED_SECRET, make_signed_request

ISSUER = "https://auth.example.com/realms/pinterest"


@pytest.fixture
async def store(tmp_path):
    url = os.environ.get("PENDING_TEST_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/pending.db")
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.fixture
def cipher():
    return CredentialCipher({"test": b"k" * 32}, "test")


@pytest.fixture
def stage():
    return {
        "action": "stage",
        "transaction_id": str(uuid.uuid4()),
        "issuer": ISSUER,
        "binding": "b" * 64,
        "provider_account_id": str(uuid.uuid4().int)[:18],
        "expires_at": time.time() + 295,
        "tokens": {
            "access_token": "sentinel-access",
            "refresh_token": "sentinel-refresh",
            "expires_in": 3600,
            "refresh_token_expires_in": 5184000,
            "scope": "user_accounts:read,pins:read",
        },
    }


def complete(stage, **overrides):
    return {key: value for key, value in stage.items() if key not in {"tokens", "expires_at"}} | {
        "action": "complete",
        "subject": "subject-" + stage["provider_account_id"],
        **overrides,
    }


async def transact(store, cipher, payload, **kwargs):
    async with store.begin() as session:
        return await process_pending(session, cipher, payload, **kwargs)


@pytest.mark.asyncio
async def test_stage_encrypted_complete_idempotent_and_expiry_not_extended(store, cipher, stage):
    first = await transact(store, cipher, stage)
    assert await transact(store, cipher, stage) == first
    async with store() as session:
        row = await session.get(PendingCredential, stage["transaction_id"])
        assert "sentinel" not in row.encrypted_payload
        assert row.expires_at == stage["expires_at"]
        assert (
            await session.scalar(
                select(User).where(User.provider_account_id == stage["provider_account_id"])
            )
            is None
        )
    response = await transact(store, cipher, complete(stage))
    assert response["status"] == "completed"
    assert await transact(store, cipher, complete(stage)) == response
    async with store() as session:
        row = await session.get(PendingCredential, stage["transaction_id"])
        assert row.encrypted_payload is None
        conn = await session.scalar(
            select(PinterestConnection).where(
                PinterestConnection.provider_account_id == stage["provider_account_id"]
            )
        )
        assert conn.credential_version == 1
        assert await ConnectionRepository(session).get_decrypted_tokens(conn.owner_id, cipher) == (
            "sentinel-access",
            "sentinel-refresh",
        )
        assert conn.access_token_expires_at == row.received_at + 3600


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field,value",
    [
        ("binding", "c" * 64),
        ("issuer", "https://foreign.example"),
        ("provider_account_id", "999999"),
    ],
)
async def test_foreign_binding_rejected(store, cipher, stage, field, value):
    await transact(store, cipher, stage)
    with pytest.raises(IngressSecurityError):
        await transact(store, cipher, complete(stage, **{field: value}))


@pytest.mark.asyncio
async def test_changed_stage_and_completed_subject_rejected(store, cipher, stage):
    await transact(store, cipher, stage)
    changed = {**stage, "tokens": {**stage["tokens"], "access_token": "substitute"}}
    with pytest.raises(IngressSecurityError):
        await transact(store, cipher, changed)
    await transact(store, cipher, complete(stage))
    with pytest.raises(IngressSecurityError):
        await transact(store, cipher, complete(stage, subject="foreign-subject"))


@pytest.mark.asyncio
@pytest.mark.parametrize("invalidate", ["expiry", "cancel"])
async def test_expiry_and_cancel_erase_pending_ciphertext(store, cipher, stage, invalidate):
    await transact(store, cipher, stage)
    if invalidate == "expiry":
        async with store.begin() as session:
            await expire_pending(session, stage["expires_at"])
    else:
        await transact(store, cipher, complete(stage, action="cancel"))
    with pytest.raises(IngressSecurityError):
        await transact(store, cipher, complete(stage))
    async with store() as session:
        assert (
            await session.get(PendingCredential, stage["transaction_id"])
        ).encrypted_payload is None


@pytest.mark.asyncio
async def test_cross_transaction_ciphertext_substitution_rejected(store, cipher, stage):
    await transact(store, cipher, stage)
    second = {**stage, "transaction_id": str(uuid.uuid4())}
    await transact(store, cipher, second)
    async with store.begin() as session:
        a = await session.get(PendingCredential, stage["transaction_id"])
        b = await session.get(PendingCredential, second["transaction_id"])
        b.encrypted_payload = a.encrypted_payload
    with pytest.raises(DecryptionError):
        await transact(store, cipher, complete(second))


@pytest.mark.asyncio
async def test_completion_rollback_is_retryable(store, cipher, stage):
    await transact(store, cipher, stage)
    with pytest.raises(RuntimeError, match="fault"):
        async with store.begin() as session:
            await process_pending(session, cipher, complete(stage))
            raise RuntimeError("fault before commit")
    async with store() as session:
        assert (await session.get(PendingCredential, stage["transaction_id"])).status == "pending"
        assert (
            await session.scalar(
                select(User).where(User.provider_account_id == stage["provider_account_id"])
            )
            is None
        )
    assert (await transact(store, cipher, complete(stage)))["status"] == "completed"


@pytest.mark.asyncio
async def test_disconnect_invalidates_pending_and_completed_retries(store, cipher, stage):
    await transact(store, cipher, stage)
    await transact(store, cipher, complete(stage))
    second = {**stage, "transaction_id": str(uuid.uuid4())}
    await transact(store, cipher, second)
    async with store.begin() as session:
        user = await session.scalar(
            select(User).where(User.provider_account_id == stage["provider_account_id"])
        )
        await ConnectionRepository(session).disconnect_connection(user.id)
    for payload in (complete(stage), complete(second)):
        with pytest.raises(IngressSecurityError):
            await transact(store, cipher, payload)
    async with store() as session:
        assert (
            await session.get(PendingCredential, second["transaction_id"])
        ).encrypted_payload is None


@pytest.mark.asyncio
async def test_private_wire_requests_and_replay(store, cipher, stage):
    redis = None
    if os.environ.get("PENDING_TEST_REDIS_URL"):
        from redis.asyncio import Redis

        redis = Redis.from_url(os.environ["PENDING_TEST_REDIS_URL"])
    nonces = RedisNonceStore(redis) if redis else MemoryNonceStore()
    app = create_credential_ingress(
        session_factory=store,
        cipher=cipher,
        nonce_store=nonces,
        shared_secret=SHARED_SECRET,
        issuer=ISSUER,
    )
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://private.test"
        ) as client:
            headers, body = make_signed_request(stage)
            response = await client.post(
                "/internal/credential-ingress", headers=headers, content=body
            )
            assert response.status_code == 200
            assert "sentinel" not in response.text
            assert (
                await client.post("/internal/credential-ingress", headers=headers, content=body)
            ).status_code == 400
            headers, body = make_signed_request(complete(stage))
            assert (
                await client.post("/internal/credential-ingress", headers=headers, content=body)
            ).status_code == 200
            headers, body = make_signed_request(
                complete(stage), extra_headers={"fOrWaRdEd": "public"}
            )
            assert (
                await client.post("/internal/credential-ingress", headers=headers, content=body)
            ).status_code == 400
            headers, body = make_signed_request(complete(stage))
            assert (
                await client.post(
                    "http://private.test/internal/credential-ingress", headers=headers, content=body
                )
            ).status_code == 400
    finally:
        if redis:
            await redis.aclose()


@pytest.mark.asyncio
@pytest.mark.skipif(
    not os.environ.get("PENDING_TEST_DATABASE_URL"), reason="Requires isolated PostgreSQL"
)
async def test_postgres_concurrent_completion_converges(store, cipher, stage):
    await transact(store, cipher, stage)
    responses = await asyncio.gather(*(transact(store, cipher, complete(stage)) for _ in range(6)))
    assert all(response == responses[0] for response in responses)
    async with store() as session:
        assert (
            await session.scalar(
                select(func.count())
                .select_from(User)
                .where(User.provider_account_id == stage["provider_account_id"])
            )
            == 1
        )
        conn = await session.scalar(
            select(PinterestConnection).where(
                PinterestConnection.provider_account_id == stage["provider_account_id"]
            )
        )
        assert conn.credential_version == 1


@pytest.mark.asyncio
@pytest.mark.skipif(
    not os.environ.get("PENDING_TEST_DATABASE_URL"), reason="Requires isolated PostgreSQL"
)
async def test_postgres_disconnect_wins_over_waiting_completion(store, cipher, stage):
    from pinterest_mcp.persistence.pending import lock_account

    await transact(store, cipher, stage)
    await transact(store, cipher, complete(stage))
    next_login = {**stage, "transaction_id": str(uuid.uuid4())}
    await transact(store, cipher, next_login)
    async with store.begin() as session:
        await lock_account(session, stage["provider_account_id"])
        waiting = asyncio.create_task(transact(store, cipher, complete(next_login)))
        user = await session.scalar(
            select(User).where(User.provider_account_id == stage["provider_account_id"])
        )
        await ConnectionRepository(session).disconnect_connection(user.id)
    with pytest.raises(IngressSecurityError):
        await waiting
    async with store() as session:
        conn = await session.scalar(
            select(PinterestConnection).where(
                PinterestConnection.provider_account_id == stage["provider_account_id"]
            )
        )
        assert conn.status == "disconnected"
        assert conn.encrypted_refresh_token is None


@pytest.mark.asyncio
async def test_changed_completion_payload_cannot_reuse_receipt(store, cipher, stage):
    await transact(store, cipher, stage)
    await transact(store, cipher, complete(stage))
    with pytest.raises(IngressSecurityError):
        await transact(store, cipher, complete(stage, unexpected="changed"))
