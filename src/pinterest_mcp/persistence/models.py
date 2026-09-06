"""SQLAlchemy models for hosted Pinterest account persistence and audit records.

Tables:
- users: internal identity mapped to external MCP issuer+subject and Pinterest account ID.
- pinterest_connections: encrypted access and refresh tokens, rotation versions, and status.
- oauth_completion_receipts: idempotent browser-bound transaction receipts.
- immediate_operations: deduplicated immediate write operations and audit log.
"""

from __future__ import annotations

import datetime
import uuid
from typing import Any

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    """Base declarative class for hosted persistence."""


# Cross-database UUID type supporting both PostgreSQL native UUID and SQLite
class UniversalUUID(TypeDecorator):
    """Platform-independent UUID type.

    Uses PostgreSQL's native UUID type, or String(36) on SQLite/others.
    """

    impl = String(36)
    cache_ok = True

    def load_dialect_impl(self, dialect: Any) -> Any:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if dialect.name == "postgresql":
            return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
        return str(value)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.UTC)


class User(Base):
    """Internal user record mapping verified MCP issuer + subject to Pinterest account ID."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UniversalUUID, primary_key=True, default=uuid.uuid4
    )
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    subject: Mapped[str] = mapped_column(String(256), nullable=False)
    provider_account_id: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    lifecycle_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="active"
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    connection: Mapped[PinterestConnection | None] = relationship(
        "PinterestConnection", back_populates="owner", uselist=False, cascade="all, delete-orphan"
    )
    receipts: Mapped[list[OAuthCompletionReceipt]] = relationship(
        "OAuthCompletionReceipt", back_populates="owner", cascade="all, delete-orphan"
    )
    operations: Mapped[list[ImmediateOperation]] = relationship(
        "ImmediateOperation", back_populates="owner", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("issuer", "subject", name="uq_users_issuer_subject"),
    )


class PinterestConnection(Base):
    """Per-owner encrypted Pinterest token pair, rotation version, and lifecycle status."""

    __tablename__ = "pinterest_connections"

    id: Mapped[uuid.UUID] = mapped_column(
        UniversalUUID, primary_key=True, default=uuid.uuid4
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UniversalUUID,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    provider_account_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    account_username: Mapped[str | None] = mapped_column(String(256), nullable=True)
    account_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    encrypted_access_token: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted_refresh_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    access_token_expires_at: Mapped[float] = mapped_column(Float, nullable=False)
    refresh_token_expires_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    scopes: Mapped[str] = mapped_column(String(512), nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False, default="primary")
    credential_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="active"
    )  # active, disconnected, reconnect_required, expired
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    owner: Mapped[User] = relationship("User", back_populates="connection")


class OAuthCompletionReceipt(Base):
    """Idempotent OAuth transaction receipt preventing replay and duplicate provisioning."""

    __tablename__ = "oauth_completion_receipts"

    transaction_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UniversalUUID,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider_account_id: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="completed"
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    expires_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    owner: Mapped[User] = relationship("User", back_populates="receipts")


class ImmediateOperation(Base):
    """Deduplication and audit record for immediate write operations."""

    __tablename__ = "immediate_operations"

    operation_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UniversalUUID,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tool_name: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)  # SHA-256
    dispatch_state: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # pending, committed, failed, uncertain
    response_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    owner: Mapped[User] = relationship("User", back_populates="operations")


class PendingCredential(Base):
    """Encrypted, non-dispatchable first-login envelope and bounded completion tombstone."""

    __tablename__ = "pending_credentials"

    transaction_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    binding: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_account_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    encrypted_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[float] = mapped_column(Float, nullable=False, index=True)
    received_at: Mapped[float] = mapped_column(Float, nullable=False)
    expected_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    completed_subject: Mapped[str | None] = mapped_column(String(256), nullable=True)
