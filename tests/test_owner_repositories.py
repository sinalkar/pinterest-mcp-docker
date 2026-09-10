"""Tests for owner-filtered repositories, versioning, and foreign account rejection (Task 2.4)."""

from __future__ import annotations

import os
import secrets
import tempfile

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from pinterest_mcp.persistence.db import create_all_tables, drop_all_tables
from pinterest_mcp.persistence.encryption import CredentialCipher
from pinterest_mcp.persistence.repository import (
    ConcurrentModificationError,
    ConnectionRepository,
    ForeignAccountError,
    ImmediateOperationRepository,
    InactiveConnectionError,
    UserRepository,
)


@pytest.fixture
async def async_engine():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", echo=False)
    await create_all_tables(engine)
    yield engine
    await drop_all_tables(engine)
    await engine.dispose()
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def session_factory(async_engine):
    return async_sessionmaker(bind=async_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
def cipher():
    return CredentialCipher(keys={"primary": secrets.token_bytes(32)}, primary_key_id="primary")


@pytest.mark.asyncio
async def test_owner_isolation_and_foreign_record_inaccessibility(session_factory, cipher):
    async with session_factory() as session:
        user_repo = UserRepository(session)
        conn_repo = ConnectionRepository(session)

        alice = await user_repo.create_user("iss", "alice_sub", "pinner_alice")
        bob = await user_repo.create_user("iss", "bob_sub", "pinner_bob")
        await session.commit()

        # Alice creates connection
        await conn_repo.save_initial_connection(
            owner_id=alice.id,
            provider_account_id="pinner_alice",
            access_token="pina_alice_token",
            refresh_token="pinr_alice_token",
            access_token_expires_at=2000.0,
            refresh_token_expires_at=4000.0,
            scopes="boards:read pins:read",
            cipher=cipher,
        )
        await session.commit()

    # Query as Bob
    async with session_factory() as session:
        conn_repo = ConnectionRepository(session)
        # Bob cannot see Alice's connection
        bob_conn = await conn_repo.get_for_owner(bob.id)
        assert bob_conn is None

        # Bob cannot decrypt Alice's tokens
        with pytest.raises(InactiveConnectionError, match="No connection found"):
            await conn_repo.get_decrypted_tokens(bob.id, cipher)

        # Alice can access her own tokens
        access, refresh = await conn_repo.get_decrypted_tokens(alice.id, cipher)
        assert access == "pina_alice_token"
        assert refresh == "pinr_alice_token"


@pytest.mark.asyncio
async def test_safe_disconnect_clears_ciphertext(session_factory, cipher):
    async with session_factory() as session:
        user_repo = UserRepository(session)
        conn_repo = ConnectionRepository(session)

        user = await user_repo.create_user("iss", "user_sub", "pinner_123")
        await conn_repo.save_initial_connection(
            owner_id=user.id,
            provider_account_id="pinner_123",
            access_token="pina_token",
            refresh_token="pinr_token",
            access_token_expires_at=2000.0,
            refresh_token_expires_at=4000.0,
            scopes="read",
            cipher=cipher,
        )
        await session.commit()

        # Disconnect
        disconnected_conn = await conn_repo.disconnect_connection(user.id)
        await session.commit()
        assert disconnected_conn.status == "disconnected"
        assert disconnected_conn.encrypted_refresh_token is None
        assert "pina_token" not in disconnected_conn.encrypted_access_token

    # Token access on disconnected account must raise InactiveConnectionError
    async with session_factory() as session:
        conn_repo = ConnectionRepository(session)
        with pytest.raises(InactiveConnectionError, match="not active"):
            await conn_repo.get_decrypted_tokens(user.id, cipher)


@pytest.mark.asyncio
async def test_versioned_concurrency_conflict_handling(session_factory, cipher):
    async with session_factory() as session:
        user_repo = UserRepository(session)
        conn_repo = ConnectionRepository(session)

        user = await user_repo.create_user("iss", "user_race", "pinner_race")
        conn = await conn_repo.save_initial_connection(
            owner_id=user.id,
            provider_account_id="pinner_race",
            access_token="pina_v1",
            refresh_token="pinr_v1",
            access_token_expires_at=1000.0,
            refresh_token_expires_at=2000.0,
            scopes="read",
            cipher=cipher,
        )
        await session.commit()
        assert conn.credential_version == 1

        # First update succeeds: version 1 -> 2
        await conn_repo.update_tokens_versioned(
            owner_id=user.id,
            expected_version=1,
            new_access_token="pina_v2",
            new_refresh_token="pinr_v2",
            access_expires_at=2000.0,
            refresh_expires_at=3000.0,
            cipher=cipher,
        )
        await session.commit()

        # Stale concurrent update using expected_version=1 must be rejected
        with pytest.raises(ConcurrentModificationError, match="Version conflict"):
            await conn_repo.update_tokens_versioned(
                owner_id=user.id,
                expected_version=1,
                new_access_token="pina_v2_stale",
                new_refresh_token="pinr_v2_stale",  # gitleaks:allow -- fake stale-token fixture
                access_expires_at=2000.0,
                refresh_expires_at=3000.0,
                cipher=cipher,
            )


@pytest.mark.asyncio
async def test_foreign_reconnect_rejection(session_factory, cipher):
    async with session_factory() as session:
        user_repo = UserRepository(session)
        conn_repo = ConnectionRepository(session)

        user = await user_repo.create_user("iss", "user_reconnect", "legit_pinner_acc")
        await conn_repo.save_initial_connection(
            owner_id=user.id,
            provider_account_id="legit_pinner_acc",
            access_token="tok1",
            refresh_token="tok2",
            access_token_expires_at=1000.0,
            refresh_token_expires_at=2000.0,
            scopes="read",
            cipher=cipher,
        )
        await session.commit()

        # Reconnect with foreign Pinterest account ID must fail
        with pytest.raises(ForeignAccountError, match="cannot substitute foreign account"):
            await conn_repo.save_initial_connection(
                owner_id=user.id,
                provider_account_id="foreign_pinner_acc",
                access_token="foreign_tok",
                refresh_token="foreign_ref",
                access_token_expires_at=2000.0,
                refresh_token_expires_at=3000.0,
                scopes="read",
                cipher=cipher,
            )

        # Reconnect with identical account ID succeeds
        reconnected = await conn_repo.save_initial_connection(
            owner_id=user.id,
            provider_account_id="legit_pinner_acc",
            access_token="new_legit_tok",
            refresh_token="new_legit_ref",
            access_token_expires_at=3000.0,
            refresh_token_expires_at=4000.0,
            scopes="read",
            cipher=cipher,
        )
        await session.commit()
        assert reconnected.status == "active"
        assert reconnected.credential_version == 2


@pytest.mark.asyncio
async def test_immediate_operation_owner_filtering(session_factory):
    async with session_factory() as session:
        user_repo = UserRepository(session)
        op_repo = ImmediateOperationRepository(session)

        u1 = await user_repo.create_user("iss", "u1", "p1")
        u2 = await user_repo.create_user("iss", "u2", "p2")
        await session.commit()

        await op_repo.create_operation(
            owner_id=u1.id,
            operation_key="op_u1_key",
            tool_name="create_pin",
            payload_hash="hash1",
        )
        await session.commit()

    async with session_factory() as session:
        op_repo = ImmediateOperationRepository(session)

        # u2 querying u1's operation key gets None
        assert await op_repo.get_operation(u2.id, "op_u1_key") is None

        # u1 querying own operation key succeeds
        op = await op_repo.get_operation(u1.id, "op_u1_key")
        assert op is not None
        assert op.tool_name == "create_pin"
        assert op.dispatch_state == "pending"

        # Complete operation
        completed = await op_repo.complete_operation(
            owner_id=u1.id,
            operation_key="op_u1_key",
            dispatch_state="committed",
            response_payload='{"pin_id": "123"}',
        )
        assert completed.dispatch_state == "committed"
