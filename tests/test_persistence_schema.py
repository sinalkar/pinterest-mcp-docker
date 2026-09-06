"""Tests for application database schema, migrations, uniqueness constraints, and cascades."""

from __future__ import annotations

import asyncio
import os
import tempfile
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from pinterest_mcp.persistence.db import create_all_tables, drop_all_tables
from pinterest_mcp.persistence.models import (
    ImmediateOperation,
    OAuthCompletionReceipt,
    PinterestConnection,
    User,
    utc_now,
)


@pytest.fixture
async def async_engine():
    # Use temporary file SQLite so all connections share the exact same database
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


@pytest.mark.asyncio
async def test_user_and_connection_creation_and_cascade(session_factory):
    async with session_factory() as session:
        user = User(
            issuer="https://mcp.pheniox.cloud/auth/realms/pinterest",
            subject="keycloak-user-uuid-1",
            provider_account_id="111222333444555666",
            lifecycle_status="active",
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        user_id = user.id
        assert isinstance(user_id, uuid.UUID)

        conn = PinterestConnection(
            owner_id=user_id,
            provider_account_id="111222333444555666",
            account_username="alice",
            account_type="BUSINESS",
            encrypted_access_token="enc_access_token_data",
            encrypted_refresh_token="enc_refresh_token_data",
            access_token_expires_at=1800000000.0,
            refresh_token_expires_at=1850000000.0,
            scopes="boards:read pins:read",
            key_id="primary",
            credential_version=1,
            status="active",
        )
        session.add(conn)

        receipt = OAuthCompletionReceipt(
            transaction_id="txn_abc_123",
            owner_id=user_id,
            provider_account_id="111222333444555666",
            payload_hash="sha256_hash_value",
            status="completed",
            expires_at=utc_now(),
        )
        session.add(receipt)

        op = ImmediateOperation(
            operation_key="op_create_pin_1",
            owner_id=user_id,
            tool_name="create_pin",
            payload_hash="sha256_op_payload",
            dispatch_state="committed",
            response_payload='{"id": "new_pin_id"}',
        )
        session.add(op)
        await session.commit()

    # Query back and verify relationships
    async with session_factory() as session:
        result = await session.execute(select(User).where(User.id == user_id))
        queried_user = result.scalar_one()
        assert queried_user.provider_account_id == "111222333444555666"

        conn_result = await session.execute(
            select(PinterestConnection).where(PinterestConnection.owner_id == user_id)
        )
        assert conn_result.scalar_one().account_username == "alice"

        # Delete user and verify cascade deletes connection, receipt, operation
        await session.delete(queried_user)
        await session.commit()

    async with session_factory() as session:
        assert (await session.execute(select(PinterestConnection))).scalars().all() == []
        assert (await session.execute(select(OAuthCompletionReceipt))).scalars().all() == []
        assert (await session.execute(select(ImmediateOperation))).scalars().all() == []


@pytest.mark.asyncio
async def test_unique_constraint_issuer_subject(session_factory):
    async with session_factory() as session:
        u1 = User(
            issuer="https://mcp.pheniox.cloud/auth/realms/pinterest",
            subject="duplicate-subject",
            provider_account_id="acc_1",
        )
        session.add(u1)
        await session.commit()

    # Inserting another user with identical issuer and subject must fail
    async with session_factory() as session:
        u2 = User(
            issuer="https://mcp.pheniox.cloud/auth/realms/pinterest",
            subject="duplicate-subject",
            provider_account_id="acc_2",
        )
        session.add(u2)
        with pytest.raises(IntegrityError):
            await session.commit()


@pytest.mark.asyncio
async def test_unique_constraint_provider_account_id(session_factory):
    async with session_factory() as session:
        u1 = User(
            issuer="https://mcp.pheniox.cloud/auth/realms/pinterest",
            subject="subject-1",
            provider_account_id="same-pinterest-id",
        )
        session.add(u1)
        await session.commit()

    # Inserting another user with same provider_account_id must fail
    async with session_factory() as session:
        u2 = User(
            issuer="https://other.auth.com",
            subject="subject-2",
            provider_account_id="same-pinterest-id",
        )
        session.add(u2)
        with pytest.raises(IntegrityError):
            await session.commit()


@pytest.mark.asyncio
async def test_one_connection_per_owner_constraint(session_factory):
    async with session_factory() as session:
        user = User(
            issuer="https://mcp.pheniox.cloud/auth/realms/pinterest",
            subject="subject-owner",
            provider_account_id="acc_owner",
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        c1 = PinterestConnection(
            owner_id=user.id,
            provider_account_id="acc_owner",
            encrypted_access_token="tok1",
            access_token_expires_at=1000.0,
            scopes="read",
        )
        session.add(c1)
        await session.commit()

        # Second connection for same owner must fail
        c2 = PinterestConnection(
            owner_id=user.id,
            provider_account_id="acc_owner",
            encrypted_access_token="tok2",
            access_token_expires_at=2000.0,
            scopes="read",
        )
        session.add(c2)
        with pytest.raises(IntegrityError):
            await session.commit()


@pytest.mark.asyncio
async def test_concurrent_account_creation_race(session_factory):
    """Simulates concurrent tasks attempting to create an owner for the same Pinterest account.

    Only one must succeed; the loser must encounter an IntegrityError.
    """

    async def try_create(subject: str) -> bool:
        async with session_factory() as session:
            try:
                user = User(
                    issuer="https://mcp.pheniox.cloud/auth/realms/pinterest",
                    subject=subject,
                    provider_account_id="shared-concurrent-pinner-id",
                )
                session.add(user)
                await session.commit()
                return True
            except IntegrityError:
                await session.rollback()
                return False

    results = await asyncio.gather(
        try_create("concurrent-subject-A"),
        try_create("concurrent-subject-B"),
    )

    # Exactly one succeeded and one failed
    assert results.count(True) == 1
    assert results.count(False) == 1

    # Verify only one record exists in DB
    async with session_factory() as session:
        users = (await session.execute(select(User))).scalars().all()
        assert len(users) == 1
        assert users[0].provider_account_id == "shared-concurrent-pinner-id"


def test_alembic_migrations_offline(capsys):
    """Test that Alembic offline migrations execute and generate valid DDL without error."""
    from alembic import command
    from alembic.config import Config

    alembic_cfg = Config("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", "postgresql+asyncpg://localhost/offline_test")
    # Run offline migration to head
    command.upgrade(alembic_cfg, "head", sql=True)
    captured = capsys.readouterr()
    sql_output = captured.out

    assert "CREATE TABLE users" in sql_output
    assert "CREATE TABLE pinterest_connections" in sql_output
    assert "CREATE TABLE oauth_completion_receipts" in sql_output
    assert "CREATE TABLE immediate_operations" in sql_output
    assert "uq_users_issuer_subject" in sql_output
