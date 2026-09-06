"""Private TLS credential ingress service with HMAC request binding and replay prevention.

Reachable only on the private backend network.
Validates:
- Method, path, timestamp, nonce, and exact body digest via HMAC-SHA256 with BROKER_HANDOFF_SECRET.
- Timestamp freshness window (max 300 seconds).
- Atomic nonce consumption in Redis (or test store) preventing replay attacks.
- Idempotent transaction receipt committing credentials and stable user mapping.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import math
import time
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .encryption import CredentialCipher
from .models import OAuthCompletionReceipt
from .repository import ConnectionRepository, UserRepository


class IngressSecurityError(Exception):
    """Raised when an ingress request fails security, freshness, replay, or isolation checks."""


class NonceStore(Protocol):
    """Protocol for atomic nonce replay validation."""

    async def consume_nonce(self, nonce: str, ttl_seconds: int = 601) -> bool:
        """Atomically mark nonce as consumed. Returns True if fresh, False if replayed."""
        ...


class MemoryNonceStore:
    """In-memory nonce store with expiration for tests and local validation."""

    def __init__(self) -> None:
        self._nonces: dict[str, float] = {}

    async def consume_nonce(self, nonce: str, ttl_seconds: int = 601) -> bool:
        now = time.time()
        # Clean expired
        expired = [n for n, exp in self._nonces.items() if exp < now]
        for n in expired:
            del self._nonces[n]

        if nonce in self._nonces:
            return False
        self._nonces[nonce] = now + ttl_seconds
        return True


class RedisNonceStore:
    """Redis-backed atomic nonce store using SET NX EX."""

    def __init__(self, redis_client: Any) -> None:
        self.redis = redis_client

    async def consume_nonce(self, nonce: str, ttl_seconds: int = 601) -> bool:
        key = f"broker:nonce:{nonce}"
        # Redis SET with NX=True, EX=ttl_seconds returns True if set, None/False if existed
        result = await self.redis.set(key, "1", ex=ttl_seconds, nx=True)
        return bool(result)


def compute_body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def compute_hmac_signature(
    secret: str | bytes,
    method: str,
    path: str,
    timestamp: str | int | float,
    nonce: str,
    body_digest: str,
) -> str:
    """Compute canonical HMAC-SHA256 signature for the request."""
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    canonical_string = f"{method.upper()}\n{path}\n{timestamp}\n{nonce}\n{body_digest}"
    mac = hmac.new(secret_bytes, canonical_string.encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()


def verify_hmac_signature(
    secret: str | bytes,
    method: str,
    path: str,
    timestamp: str | int | float,
    nonce: str,
    body: bytes,
    signature: str,
    max_age_seconds: float = 300.0,
) -> None:
    """Verify HMAC signature and timestamp freshness. Raises IngressSecurityError on failure."""
    # 1. Freshness check
    try:
        ts_float = float(timestamp)
    except (ValueError, TypeError) as e:
        raise IngressSecurityError("Invalid timestamp header") from e

    now = time.time()
    if not math.isfinite(ts_float) or abs(now - ts_float) > max_age_seconds:
        raise IngressSecurityError("Request timestamp expired or outside allowable window")

    # 2. Signature verification
    body_digest = compute_body_digest(body)
    expected_sig = compute_hmac_signature(
        secret=secret,
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body_digest=body_digest,
    )

    if not hmac.compare_digest(expected_sig, signature):
        raise IngressSecurityError("Invalid request signature")


async def authenticate_ingress(
    nonce_store: NonceStore,
    shared_secret: str | bytes,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
) -> None:
    # HTTP header names are case-insensitive; reject ambiguous duplicate names.
    normalized_headers = {name.lower(): value for name, value in headers.items()}
    if len(normalized_headers) != len(headers):
        raise IngressSecurityError("Duplicate request headers")
    headers = normalized_headers
    # 0. Reject public routing attempts: credential ingress must remain strictly internal/private
    public_routing_headers = (
        "x-forwarded-host",
        "x-forwarded-for",
        "x-forwarded-proto",
        "forwarded",
        "via",
    )
    for h in public_routing_headers:
        if h in headers or h.title() in headers or h.upper() in headers:
            raise IngressSecurityError(
                f"Public routing rejected: private credential ingress header {h!r} detected"
            )

    signature = headers.get("x-signature") or headers.get("X-Signature")
    timestamp = headers.get("x-timestamp") or headers.get("X-Timestamp")
    nonce = headers.get("x-nonce") or headers.get("X-Nonce")

    if not signature or not timestamp or not nonce:
        raise IngressSecurityError(
            "Missing mandatory authentication headers (Signature/Timestamp/Nonce)"
        )

    # 1. Verify HMAC signature & timestamp
    verify_hmac_signature(
        secret=shared_secret,
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        body=body,
        signature=signature,
    )

    if not await nonce_store.consume_nonce(nonce):
        raise IngressSecurityError("Request nonce has already been consumed")


async def process_credential_ingress(
    session: AsyncSession,
    cipher: CredentialCipher,
    nonce_store: NonceStore,
    shared_secret: str | bytes,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
) -> dict[str, Any]:
    """Authenticate and persist a broker-to-ingress credential handoff payload.

    Required headers:
    - X-Signature: HMAC-SHA256 hex string
    - X-Timestamp: Unix timestamp
    - X-Nonce: Random unique nonce string
    """
    await authenticate_ingress(nonce_store, shared_secret, method, path, headers, body)

    # 2. Parse JSON body
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception as e:
        raise IngressSecurityError("Malformed JSON payload") from e

    transaction_id = payload.get("transaction_id")
    issuer = payload.get("issuer")
    subject = payload.get("subject")
    provider_account_id = str(payload.get("provider_account_id", ""))
    tokens = payload.get("tokens", {})

    if not transaction_id or not issuer or not subject or not provider_account_id or not tokens:
        raise IngressSecurityError("Missing required fields in ingress payload")

    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    expires_in = tokens.get("expires_in", 3600)
    refresh_expires_in = tokens.get("refresh_token_expires_in")
    scopes = tokens.get("scope", "boards:read pins:read")

    if not access_token:
        raise IngressSecurityError("Missing access_token in token payload")

    # 3. Check idempotent receipt before modifying data
    payload_hash = compute_body_digest(body)
    existing_receipt = await session.scalar(
        select(OAuthCompletionReceipt).where(
            OAuthCompletionReceipt.transaction_id == transaction_id
        )
    )
    if existing_receipt is not None:
        if existing_receipt.payload_hash != payload_hash:
            raise IngressSecurityError("Transaction ID already exists with mismatched payload")
        return {
            "status": "idempotent_duplicate",
            "owner_id": str(existing_receipt.owner_id),
            "transaction_id": transaction_id,
        }

    now_ts = time.time()
    access_expires_at = now_ts + float(expires_in)
    refresh_expires_at = now_ts + float(refresh_expires_in) if refresh_expires_in else None

    user_repo = UserRepository(session)
    conn_repo = ConnectionRepository(session)

    # 5. Foreign owner isolation checks
    existing_user = await user_repo.get_by_issuer_subject(issuer, subject)
    if existing_user is not None:
        if existing_user.provider_account_id != provider_account_id:
            msg = (
                f"Subject {subject} is bound to provider {existing_user.provider_account_id}, "
                f"cannot bind to foreign account {provider_account_id}"
            )
            raise IngressSecurityError(msg)
    else:
        # Check if provider account is already bound to another user
        other_user = await user_repo.get_by_provider_account(provider_account_id)
        if other_user is not None:
            raise IngressSecurityError(
                f"Provider account {provider_account_id} is already bound to another owner"
            )
        # First login mapping: create user
        existing_user = await user_repo.create_user(
            issuer=issuer,
            subject=subject,
            provider_account_id=provider_account_id,
            lifecycle_status="active",
        )

    # 6. Persist or update connection
    conn = await conn_repo.save_initial_connection(
        owner_id=existing_user.id,
        provider_account_id=provider_account_id,
        access_token=access_token,
        refresh_token=refresh_token,
        access_token_expires_at=access_expires_at,
        refresh_token_expires_at=refresh_expires_at,
        scopes=scopes,
        cipher=cipher,
        account_username=payload.get("account_username"),
        account_type=payload.get("account_type"),
    )

    # 7. Record completion receipt (5-minute TTL)
    expires_at = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=5)
    receipt = OAuthCompletionReceipt(
        transaction_id=transaction_id,
        owner_id=existing_user.id,
        provider_account_id=provider_account_id,
        payload_hash=payload_hash,
        status="completed",
        expires_at=expires_at,
    )
    session.add(receipt)
    await session.flush()

    return {
        "status": "persisted",
        "owner_id": str(existing_user.id),
        "credential_version": conn.credential_version,
        "transaction_id": transaction_id,
    }
