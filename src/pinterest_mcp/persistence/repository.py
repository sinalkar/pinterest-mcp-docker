"""Owner-filtered repositories and versioned connection lifecycle management.

Enforces:
- Strict owner isolation: all read and write queries filter by owner UUID.
- Foreign record isolation: accessing another user's connection or operations fails safely.
- Versioned concurrency control: increments credential_version on every token renewal.
- Safe disconnect: clears usable ciphertext and marks status 'disconnected'.
- Foreign reconnect rejection: rejects replacing an owner's account with a foreign ID.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .encryption import CredentialCipher
from .models import (
    ImmediateOperation,
    PinterestConnection,
    User,
)


class RepositoryError(Exception):
    """Base exception for persistence repository errors."""


class InactiveConnectionError(RepositoryError):
    """Raised when attempting to access tokens on a non-active connection."""


class ConcurrentModificationError(RepositoryError):
    """Raised when an update fails due to a credential version conflict."""


class ForeignAccountError(RepositoryError):
    """Raised when a reconnect attempts to link a foreign account to an existing owner."""


class UserRepository:
    """Repository for managing application owners."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        result = await self.session.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_by_issuer_subject(self, issuer: str, subject: str) -> User | None:
        result = await self.session.execute(
            select(User).where(User.issuer == issuer, User.subject == subject)
        )
        return result.scalar_one_or_none()

    async def get_by_provider_account(self, provider_account_id: str) -> User | None:
        result = await self.session.execute(
            select(User).where(User.provider_account_id == provider_account_id)
        )
        return result.scalar_one_or_none()

    async def create_user(
        self,
        issuer: str,
        subject: str,
        provider_account_id: str,
        lifecycle_status: str = "active",
    ) -> User:
        user = User(
            issuer=issuer,
            subject=subject,
            provider_account_id=provider_account_id,
            lifecycle_status=lifecycle_status,
        )
        self.session.add(user)
        await self.session.flush()
        return user


class ConnectionRepository:
    """Owner-filtered repository for managing Pinterest connections and encrypted credentials."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_for_owner(self, owner_id: uuid.UUID) -> PinterestConnection | None:
        """Fetch connection strictly filtered by owner_id."""
        result = await self.session.execute(
            select(PinterestConnection).where(PinterestConnection.owner_id == owner_id)
        )
        return result.scalar_one_or_none()

    async def get_decrypted_tokens(
        self,
        owner_id: uuid.UUID,
        cipher: CredentialCipher,
    ) -> tuple[str, str | None]:
        """Retrieve and decrypt tokens for owner.

        Fails if connection is not found, not active, or tampering is detected.
        """
        conn = await self.get_for_owner(owner_id)
        if conn is None:
            raise InactiveConnectionError("No connection found for owner")
        if conn.status != "active":
            raise InactiveConnectionError(
                f"Connection is not active (current status: {conn.status!r})"
            )

        access_token = cipher.decrypt(
            conn.encrypted_access_token,
            owner_id=owner_id,
            provider_account_id=conn.provider_account_id,
        )
        refresh_token = (
            cipher.decrypt(
                conn.encrypted_refresh_token,
                owner_id=owner_id,
                provider_account_id=conn.provider_account_id,
            )
            if conn.encrypted_refresh_token
            else None
        )
        return access_token, refresh_token

    async def save_initial_connection(
        self,
        owner_id: uuid.UUID,
        provider_account_id: str,
        access_token: str,
        refresh_token: str | None,
        access_token_expires_at: float,
        refresh_token_expires_at: float | None,
        scopes: str,
        cipher: CredentialCipher,
        account_username: str | None = None,
        account_type: str | None = None,
    ) -> PinterestConnection:
        """Persist newly authorized connection with encrypted tokens."""
        existing = await self.get_for_owner(owner_id)
        if existing:
            # Check foreign account substitution
            if existing.provider_account_id != provider_account_id:
                raise ForeignAccountError(
                    f"Existing connection belongs to {existing.provider_account_id}, "
                    f"cannot substitute foreign account {provider_account_id}"
                )
            return await self.reconnect_connection(
                owner_id=owner_id,
                provider_account_id=provider_account_id,
                access_token=access_token,
                refresh_token=refresh_token,
                access_token_expires_at=access_token_expires_at,
                refresh_token_expires_at=refresh_token_expires_at,
                scopes=scopes,
                cipher=cipher,
                account_username=account_username,
                account_type=account_type,
            )

        enc_access = cipher.encrypt(
            access_token, owner_id=owner_id, provider_account_id=provider_account_id
        )
        enc_refresh = (
            cipher.encrypt(
                refresh_token, owner_id=owner_id, provider_account_id=provider_account_id
            )
            if refresh_token
            else None
        )

        conn = PinterestConnection(
            owner_id=owner_id,
            provider_account_id=provider_account_id,
            account_username=account_username,
            account_type=account_type,
            encrypted_access_token=enc_access,
            encrypted_refresh_token=enc_refresh,
            access_token_expires_at=access_token_expires_at,
            refresh_token_expires_at=refresh_token_expires_at,
            scopes=scopes,
            key_id=cipher.primary_key_id,
            credential_version=1,
            status="active",
        )
        self.session.add(conn)
        await self.session.flush()
        return conn

    async def update_tokens_versioned(
        self,
        owner_id: uuid.UUID,
        expected_version: int,
        new_access_token: str,
        new_refresh_token: str | None,
        access_expires_at: float,
        refresh_expires_at: float | None,
        cipher: CredentialCipher,
    ) -> PinterestConnection:
        """Update tokens using optimistic concurrency control on credential_version."""
        conn = await self.get_for_owner(owner_id)
        if conn is None:
            raise InactiveConnectionError("Connection not found")
        if conn.credential_version != expected_version:
            raise ConcurrentModificationError(
                f"Version conflict: expected {expected_version}, found {conn.credential_version}"
            )

        enc_access = cipher.encrypt(
            new_access_token, owner_id=owner_id, provider_account_id=conn.provider_account_id
        )
        enc_refresh = (
            cipher.encrypt(
                new_refresh_token, owner_id=owner_id, provider_account_id=conn.provider_account_id
            )
            if new_refresh_token
            else None
        )

        conn.encrypted_access_token = enc_access
        conn.encrypted_refresh_token = enc_refresh
        conn.access_token_expires_at = access_expires_at
        conn.refresh_token_expires_at = refresh_expires_at
        conn.credential_version = expected_version + 1
        conn.status = "active"

        await self.session.flush()
        return conn

    async def disconnect_connection(self, owner_id: uuid.UUID) -> PinterestConnection:
        """Safely disconnect: clear usable ciphertext, mark status disconnected."""
        conn = await self.get_for_owner(owner_id)
        if conn is None:
            raise InactiveConnectionError("Connection not found")

        # Use the same account lock as pending completion, then refresh after waiting.
        from sqlalchemy import update

        from .models import PendingCredential
        from .pending import lock_account

        await lock_account(self.session, conn.provider_account_id)
        await self.session.refresh(conn)
        await self.session.execute(
            update(PendingCredential)
            .where(
                PendingCredential.provider_account_id == conn.provider_account_id,
                PendingCredential.status == "pending",
            )
            .values(encrypted_payload=None, status="cancelled")
        )

        # Overwrite ciphertext with tombstone marker (safe against token leakage)
        # This literal destroys credential usability; it is not an authentication secret.
        conn.encrypted_access_token = "REVOKED_AND_DISCONNECTED"  # noqa: S105  # nosec B105
        conn.encrypted_refresh_token = None
        conn.status = "disconnected"
        conn.credential_version += 1

        await self.session.flush()
        return conn

    async def reconnect_connection(
        self,
        owner_id: uuid.UUID,
        provider_account_id: str,
        access_token: str,
        refresh_token: str | None,
        access_token_expires_at: float,
        refresh_token_expires_at: float | None,
        scopes: str,
        cipher: CredentialCipher,
        account_username: str | None = None,
        account_type: str | None = None,
    ) -> PinterestConnection:
        """Reconnect existing owner connection; verifies account ID matches."""
        conn = await self.get_for_owner(owner_id)
        if conn is None:
            raise InactiveConnectionError("Connection not found")
        if conn.provider_account_id != provider_account_id:
            raise ForeignAccountError(
                f"Reconnect account ID {provider_account_id} does not match owner's "
                f"registered Pinterest account ID {conn.provider_account_id}"
            )

        enc_access = cipher.encrypt(
            access_token, owner_id=owner_id, provider_account_id=provider_account_id
        )
        enc_refresh = (
            cipher.encrypt(
                refresh_token, owner_id=owner_id, provider_account_id=provider_account_id
            )
            if refresh_token
            else None
        )

        conn.encrypted_access_token = enc_access
        conn.encrypted_refresh_token = enc_refresh
        conn.access_token_expires_at = access_token_expires_at
        conn.refresh_token_expires_at = refresh_token_expires_at
        conn.scopes = scopes
        if account_username:
            conn.account_username = account_username
        if account_type:
            conn.account_type = account_type
        conn.status = "active"
        conn.credential_version += 1

        await self.session.flush()
        return conn


class ImmediateOperationRepository:
    """Owner-filtered repository for idempotent operations."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_operation(
        self, owner_id: uuid.UUID, operation_key: str
    ) -> ImmediateOperation | None:
        """Strictly owner-filtered query."""
        result = await self.session.execute(
            select(ImmediateOperation).where(
                ImmediateOperation.owner_id == owner_id,
                ImmediateOperation.operation_key == operation_key,
            )
        )
        return result.scalar_one_or_none()

    async def create_operation(
        self,
        owner_id: uuid.UUID,
        operation_key: str,
        tool_name: str,
        payload_hash: str,
        dispatch_state: str = "pending",
    ) -> ImmediateOperation:
        op = ImmediateOperation(
            operation_key=operation_key,
            owner_id=owner_id,
            tool_name=tool_name,
            payload_hash=payload_hash,
            dispatch_state=dispatch_state,
        )
        self.session.add(op)
        await self.session.flush()
        return op

    async def complete_operation(
        self,
        owner_id: uuid.UUID,
        operation_key: str,
        dispatch_state: str,
        response_payload: str | None = None,
        error_message: str | None = None,
    ) -> ImmediateOperation:
        op = await self.get_operation(owner_id, operation_key)
        if op is None:
            raise RepositoryError("Operation not found for owner")

        op.dispatch_state = dispatch_state
        op.response_payload = response_payload
        op.error_message = error_message
        await self.session.flush()
        return op
