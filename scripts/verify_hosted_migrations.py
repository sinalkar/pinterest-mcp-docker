"""Exercise fresh/additive migrations using an explicitly disposable PostgreSQL database.

This writes synthetic test data. Never point PENDING_TEST_DATABASE_URL at production.
"""

from __future__ import annotations

import asyncio
import os
import uuid

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select, text
from sqlalchemy.ext.asyncio import create_async_engine

from pinterest_mcp.persistence.models import User


async def assert_empty(url: str) -> None:
    engine = create_async_engine(url)
    try:
        async with engine.connect() as connection:
            tables = await connection.run_sync(lambda conn: inspect(conn).get_table_names())
            if tables:
                raise RuntimeError("Migration verification requires an empty disposable database")
    finally:
        await engine.dispose()


async def seed_or_verify(url: str, owner_id: uuid.UUID, *, verify: bool) -> None:
    engine = create_async_engine(url)
    try:
        async with engine.begin() as connection:
            if not verify:
                await connection.execute(
                    User.__table__.insert().values(
                        id=owner_id,
                        issuer="https://migration-test.invalid",
                        subject="synthetic-owner",
                        provider_account_id="migration-test-account",
                        lifecycle_status="active",
                    )
                )
            else:
                found = await connection.scalar(select(User.id).where(User.id == owner_id))
                if found != owner_id:
                    raise RuntimeError("Additive migration did not preserve the existing owner")
                revision = await connection.scalar(text("SELECT version_num FROM alembic_version"))
                if revision != "002_pending_credentials":
                    raise RuntimeError("Unexpected migration revision")
                await connection.execute(
                    text("SELECT transaction_id FROM pending_credentials LIMIT 1")
                )
    finally:
        await engine.dispose()


def main() -> None:
    url = os.environ.get("PENDING_TEST_DATABASE_URL", "")
    if not url.startswith("postgresql+asyncpg://"):
        raise ValueError("PENDING_TEST_DATABASE_URL must select disposable PostgreSQL")
    # Avoid reading an unrelated operator DATABASE_URL from the surrounding environment.
    os.environ["DATABASE_URL"] = url
    asyncio.run(assert_empty(url))
    cfg = Config("alembic.ini")
    owner = uuid.uuid4()
    command.upgrade(cfg, "001_initial_schema")
    asyncio.run(seed_or_verify(url, owner, verify=False))
    command.upgrade(cfg, "head")
    command.upgrade(cfg, "head")  # Retrying an applied migration must be harmless.
    asyncio.run(seed_or_verify(url, owner, verify=True))
    print("Fresh migration, additive upgrade, retry and owner preservation passed")


if __name__ == "__main__":
    main()
