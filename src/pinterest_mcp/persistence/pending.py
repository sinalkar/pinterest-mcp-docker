"""Two-stage credential handoff. Callers must commit before acknowledging success."""

from __future__ import annotations

import datetime
import hashlib
import json
import math
import re
import time
from typing import Any

from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from .encryption import CredentialCipher
from .ingress import IngressSecurityError
from .models import OAuthCompletionReceipt, PendingCredential, PinterestConnection
from .repository import ConnectionRepository, UserRepository


async def lock_account(session: AsyncSession, account: str) -> None:
    """Shared PostgreSQL transaction lock; SQLite is used only for serial unit tests."""
    if session.get_bind().dialect.name == "postgresql":
        key = int.from_bytes(
            hashlib.sha256(f"pinterest-account:{account}".encode()).digest()[:8], "big", signed=True
        )
        await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})


def required_text(payload: dict, key: str, maximum: int = 512) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise IngressSecurityError("Invalid handoff metadata")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise IngressSecurityError("Invalid handoff metadata")
    return value


def binding_fields(payload: dict) -> tuple[str, str, str, str]:
    transaction = required_text(payload, "transaction_id", 128)
    issuer = required_text(payload, "issuer")
    binding = required_text(payload, "binding", 64)
    account = required_text(payload, "provider_account_id", 64)
    if not re.fullmatch(r"[a-f0-9]{64}", binding) or not re.fullmatch(r"[0-9]+", account):
        raise IngressSecurityError("Invalid transaction binding")
    return transaction, issuer, binding, account


def envelope_aad(row: PendingCredential) -> str:
    # Domain separation prevents pending ciphertext being decrypted as an owned token.
    return json.dumps(
        ["pending-v1", row.transaction_id, row.issuer, row.binding, row.expires_at],
        separators=(",", ":"),
    )


def validate_tokens(payload: dict) -> None:
    tokens = payload.get("tokens")
    if not isinstance(tokens, dict):
        raise IngressSecurityError("Invalid token envelope")
    required_text(tokens, "access_token", 16384)
    required_text(tokens, "refresh_token", 16384)
    scopes = required_text(tokens, "scope")
    if "user_accounts:read" not in re.split(r"[,\s]+", scopes):
        raise IngressSecurityError("Missing account permission")
    for key in ("expires_in", "refresh_token_expires_in"):
        value = tokens.get(key)
        if type(value) is not int or not 0 < value <= 315360000:
            raise IngressSecurityError("Invalid token expiry")


async def expire_pending(session: AsyncSession, now: float | None = None) -> int:
    """Erase expired ciphertext. Tombstones prevent stale references from being reused."""
    result = await session.execute(
        update(PendingCredential)
        .where(
            PendingCredential.expires_at <= (time.time() if now is None else now),
            PendingCredential.status == "pending",
        )
        .values(encrypted_payload=None, status="expired")
    )
    return result.rowcount


async def process_pending(
    session: AsyncSession,
    cipher: CredentialCipher,
    payload: dict[str, Any],
    *,
    now: float | None = None,
) -> dict[str, Any]:
    """Process an already authenticated stage/complete/cancel request atomically."""
    supplied_clock = now
    now = time.time() if supplied_clock is None else supplied_clock
    transaction, issuer, binding, account = binding_fields(payload)
    action = payload.get("action")
    if action not in {"stage", "complete", "cancel"}:
        raise IngressSecurityError("Invalid handoff action")
    await lock_account(session, account)
    # Lock contention must not extend a transaction's usable lifetime.
    now = time.time() if supplied_clock is None else supplied_clock
    row = await session.scalar(
        select(PendingCredential)
        .where(PendingCredential.transaction_id == transaction)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if row is not None and (row.issuer, row.binding, row.provider_account_id) != (
        issuer,
        binding,
        account,
    ):
        raise IngressSecurityError("Transaction binding mismatch")

    if action == "stage":
        validate_tokens(payload)
        deadline = payload.get("expires_at")
        if (
            type(deadline) not in (int, float)
            or not math.isfinite(deadline)
            or not now < deadline <= now + 300
        ):
            raise IngressSecurityError("Invalid or expired transaction deadline")
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if row is not None:
            if row.status != "pending" or row.expires_at <= now or row.payload_hash != digest:
                raise IngressSecurityError("Pending transaction cannot be reused")
            return {"status": "staged", "transaction_id": transaction}
        conn = await session.scalar(
            select(PinterestConnection)
            .where(PinterestConnection.provider_account_id == account)
            .execution_options(populate_existing=True)
        )
        row = PendingCredential(
            transaction_id=transaction,
            issuer=issuer,
            binding=binding,
            provider_account_id=account,
            payload_hash=digest,
            expires_at=float(deadline),
            received_at=now,
            expected_version=conn.credential_version if conn else 0,
            status="pending",
        )
        row.encrypted_payload = cipher.encrypt(
            json.dumps(payload, separators=(",", ":")), envelope_aad(row), account
        )
        session.add(row)
        await session.flush()
        return {"status": "staged", "transaction_id": transaction}

    if row is None:
        raise IngressSecurityError("Pending transaction unavailable")
    if action == "cancel":
        if row.status == "pending":
            row.encrypted_payload = None
            row.status = "cancelled"
            await session.flush()
        return {"status": "cancelled", "transaction_id": transaction}
    if row.expires_at <= now or row.status not in {"pending", "completed"}:
        raise IngressSecurityError("Pending transaction unavailable")
    subject = required_text(payload, "subject", 256)
    users = UserRepository(session)
    connections = ConnectionRepository(session)
    if row.status == "completed":
        if row.completed_subject != subject:
            raise IngressSecurityError("Completed transaction owner mismatch")
        receipt = await session.get(OAuthCompletionReceipt, transaction)
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        if receipt is None or receipt.payload_hash != digest:
            raise IngressSecurityError("Completed transaction payload mismatch")
        conn = await connections.get_for_owner(receipt.owner_id) if receipt else None
        if conn is None or conn.status != "active":
            raise IngressSecurityError("Completed connection unavailable")
        return {"status": "completed", "transaction_id": transaction}

    user = await users.get_by_issuer_subject(issuer, subject)
    account_owner = await users.get_by_provider_account(account)
    if user and user.lifecycle_status != "active":
        raise IngressSecurityError("Account unavailable")
    if (user and user.provider_account_id != account) or (account_owner and account_owner != user):
        raise IngressSecurityError("Account owner mismatch")
    conn = await connections.get_for_owner(user.id) if user else None
    if (conn.credential_version if conn else 0) != row.expected_version:
        raise IngressSecurityError("Connection changed during login")
    if row.encrypted_payload is None:
        raise IngressSecurityError("Pending credentials unavailable")
    envelope = json.loads(cipher.decrypt(row.encrypted_payload, envelope_aad(row), account))
    tokens = envelope["tokens"]
    if row.received_at + tokens["expires_in"] <= now:
        raise IngressSecurityError("Pending provider credentials expired")
    if user is None:
        user = await users.create_user(issuer, subject, account)
    await connections.save_initial_connection(
        owner_id=user.id,
        provider_account_id=account,
        access_token=tokens["access_token"],
        refresh_token=tokens["refresh_token"],
        access_token_expires_at=row.received_at + tokens["expires_in"],
        refresh_token_expires_at=row.received_at + tokens["refresh_token_expires_in"],
        scopes=tokens["scope"],
        cipher=cipher,
        account_username=envelope.get("account_username"),
        account_type=envelope.get("account_type"),
    )
    session.add(
        OAuthCompletionReceipt(
            transaction_id=transaction,
            owner_id=user.id,
            provider_account_id=account,
            payload_hash=hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
            expires_at=datetime.datetime.fromtimestamp(row.expires_at, datetime.UTC),
            status="completed",
        )
    )
    row.status = "completed"
    row.completed_subject = subject
    row.encrypted_payload = None
    await session.flush()
    return {"status": "completed", "transaction_id": transaction}
