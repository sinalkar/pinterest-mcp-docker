"""Initial schema for users, pinterest_connections, receipts, and operations.

Revision ID: 001_initial_schema
Revises: None
Create Date: 2026-09-05 21:10:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from pinterest_mcp.persistence.models import UniversalUUID

# revision identifiers, used by Alembic.
revision: str = "001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. users table
    op.create_table(
        "users",
        sa.Column("id", UniversalUUID(), nullable=False),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("subject", sa.String(length=256), nullable=False),
        sa.Column("provider_account_id", sa.String(length=64), nullable=False),
        sa.Column(
            "lifecycle_status", sa.String(length=32), nullable=False, server_default="active"
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("issuer", "subject", name="uq_users_issuer_subject"),
    )
    op.create_index(
        op.f("ix_users_provider_account_id"), "users", ["provider_account_id"], unique=True
    )

    # 2. pinterest_connections table
    op.create_table(
        "pinterest_connections",
        sa.Column("id", UniversalUUID(), nullable=False),
        sa.Column("owner_id", UniversalUUID(), nullable=False),
        sa.Column("provider_account_id", sa.String(length=64), nullable=False),
        sa.Column("account_username", sa.String(length=256), nullable=True),
        sa.Column("account_type", sa.String(length=64), nullable=True),
        sa.Column("encrypted_access_token", sa.Text(), nullable=False),
        sa.Column("encrypted_refresh_token", sa.Text(), nullable=True),
        sa.Column("access_token_expires_at", sa.Float(), nullable=False),
        sa.Column("refresh_token_expires_at", sa.Float(), nullable=True),
        sa.Column("scopes", sa.String(length=512), nullable=False),
        sa.Column("key_id", sa.String(length=64), nullable=False, server_default="primary"),
        sa.Column("credential_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_pinterest_connections_owner_id"),
        "pinterest_connections",
        ["owner_id"],
        unique=True,
    )
    op.create_index(
        op.f("ix_pinterest_connections_provider_account_id"),
        "pinterest_connections",
        ["provider_account_id"],
        unique=False,
    )

    # 3. oauth_completion_receipts table
    op.create_table(
        "oauth_completion_receipts",
        sa.Column("transaction_id", sa.String(length=128), nullable=False),
        sa.Column("owner_id", UniversalUUID(), nullable=False),
        sa.Column("provider_account_id", sa.String(length=64), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="completed"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("transaction_id"),
    )
    op.create_index(
        op.f("ix_oauth_completion_receipts_owner_id"),
        "oauth_completion_receipts",
        ["owner_id"],
        unique=False,
    )

    # 4. immediate_operations table
    op.create_table(
        "immediate_operations",
        sa.Column("operation_key", sa.String(length=128), nullable=False),
        sa.Column("owner_id", UniversalUUID(), nullable=False),
        sa.Column("tool_name", sa.String(length=64), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("dispatch_state", sa.String(length=32), nullable=False),
        sa.Column("response_payload", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("operation_key"),
    )
    op.create_index(
        op.f("ix_immediate_operations_owner_id"),
        "immediate_operations",
        ["owner_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("immediate_operations")
    op.drop_table("oauth_completion_receipts")
    op.drop_table("pinterest_connections")
    op.drop_table("users")
