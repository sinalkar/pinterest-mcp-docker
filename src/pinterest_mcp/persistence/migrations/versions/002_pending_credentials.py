"""Encrypted pending broker credentials, separate from usable connections."""

import sqlalchemy as sa
from alembic import op

revision = "002_pending_credentials"
down_revision = "001_initial_schema"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "pending_credentials",
        sa.Column("transaction_id", sa.String(128), primary_key=True),
        sa.Column("issuer", sa.String(512), nullable=False),
        sa.Column("binding", sa.String(64), nullable=False),
        sa.Column("provider_account_id", sa.String(64), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("encrypted_payload", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.Float(), nullable=False),
        sa.Column("received_at", sa.Float(), nullable=False),
        sa.Column("expected_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("completed_subject", sa.String(256), nullable=True),
    )
    op.create_index(
        "ix_pending_credentials_provider_account_id", "pending_credentials", ["provider_account_id"]
    )
    op.create_index("ix_pending_credentials_expires_at", "pending_credentials", ["expires_at"])


def downgrade():
    op.drop_table("pending_credentials")
