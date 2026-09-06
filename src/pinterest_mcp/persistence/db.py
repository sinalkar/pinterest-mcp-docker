"""Database session and connection management for hosted persistence."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from ..config import Settings
from .models import Base


def get_async_engine(settings: Settings, **kwargs: Any) -> AsyncEngine:
    """Create an AsyncEngine from validated settings."""
    if not settings.database_url:
        raise ValueError("DATABASE_URL is not configured")

    url = settings.database_url.get_secret_value()
    # Default pooling and timeout configurations
    engine_kwargs: dict[str, Any] = {
        "echo": False,
        "future": True,
    }
    if "sqlite" in url:
        # SQLite-specific settings for tests
        engine_kwargs["connect_args"] = {"check_same_thread": False}
    else:
        # PostgreSQL-specific pooling
        engine_kwargs["pool_size"] = kwargs.get("pool_size", 10)
        engine_kwargs["max_overflow"] = kwargs.get("max_overflow", 20)
        engine_kwargs["pool_pre_ping"] = True

    engine_kwargs.update(kwargs)
    return create_async_engine(url, **engine_kwargs)


def get_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create an async_sessionmaker bound to the engine."""
    return async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


@asynccontextmanager
async def session_scope(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Provide a transactional async session scope."""
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def create_all_tables(engine: AsyncEngine) -> None:
    """Create all tables declared in Base.metadata (used in testing and bootstrapping)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def drop_all_tables(engine: AsyncEngine) -> None:
    """Drop all tables declared in Base.metadata (used in test tear-down)."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
