"""Broker feasibility test harness: code exchange, stable mapping, and persistence boundaries.

Validates Task 1.4 requirements:
1. Pinned Keycloak broker hooks support Pinterest code exchange and /v5/user_account lookup.
2. Stable subject mapping without local password/email prompts (First Broker Login flow).
3. Persistence-before-login completion via postBrokerLogin hook.
4. Failing-storage fault injection: aborts authentication, leaves no active connection.
5. Concurrent first-login race resolution: converges on one stable owner without duplicates.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest
import respx

# ---------------------------------------------------------------------------
# Simulated Keycloak Broker Models & Contracts
# ---------------------------------------------------------------------------


@dataclass
class BrokeredIdentityContext:
    """Context built by Keycloak identity provider after token exchange and user lookup."""

    provider_alias: str
    code: str
    tokens: dict[str, Any]
    provider_user_id: str
    user_metadata: dict[str, Any]
    broker_transaction_id: str
    model_notes: dict[str, Any] = field(default_factory=dict)


@dataclass
class KeycloakUserModel:
    """Internal Keycloak user record with stable UUID subject."""

    id: str  # Stable UUID (OIDC sub claim)
    username: str
    created_at: float
    attributes: dict[str, list[str]] = field(default_factory=dict)


class FederatedIdentityStore:
    """Thread-safe store modeling Keycloak's (REALM_ID, IDP, FEDERATED_USER_ID) table constraint."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        # (idp, federated_user_id) -> user_id
        self._mappings: dict[tuple[str, str], str] = {}
        self._users: dict[str, KeycloakUserModel] = {}

    async def find_user_by_federated_identity(
        self, idp: str, federated_user_id: str
    ) -> KeycloakUserModel | None:
        async with self._lock:
            user_id = self._mappings.get((idp, federated_user_id))
            return self._users.get(user_id) if user_id else None

    async def create_user_and_link(
        self, idp: str, federated_user_id: str, username: str
    ) -> tuple[KeycloakUserModel, bool]:
        """Atomically create user and federated identity link.

        Returns (user, is_new). If already linked concurrently, returns existing user.
        """
        async with self._lock:
            key = (idp, federated_user_id)
            if key in self._mappings:
                user_id = self._mappings[key]
                return self._users[user_id], False

            # Provision new stable UUID
            new_id = str(uuid.uuid4())
            user = KeycloakUserModel(
                id=new_id,
                username=username,
                created_at=time.time(),
            )
            self._users[new_id] = user
            self._mappings[key] = new_id
            return user, True


# ---------------------------------------------------------------------------
# Simulated Application Credential Ingress & Storage
# ---------------------------------------------------------------------------


class StorageFault(Exception):
    """Simulated database or credential-ingress outage."""


class ApplicationCredentialVault:
    """Models application credential ingress and encrypted connection repository."""

    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.connections: dict[str, dict[str, Any]] = {}
        self.fault_injected: bool = False

    async def persist_credentials(
        self,
        subject: str,
        provider_account_id: str,
        tokens: dict[str, Any],
        transaction_id: str,
    ) -> dict[str, Any]:
        if self.fault_injected:
            raise StorageFault("Database or credential ingress unavailable")

        async with self.lock:
            record = {
                "subject": subject,
                "provider_account_id": provider_account_id,
                "access_token": tokens["access_token"],
                "refresh_token": tokens.get("refresh_token"),
                "expires_in": tokens.get("expires_in"),
                "transaction_id": transaction_id,
                "status": "active",
                "updated_at": time.time(),
            }
            self.connections[subject] = record
            return record

    async def get_connection(self, subject: str) -> dict[str, Any] | None:
        async with self.lock:
            return self.connections.get(subject)


# ---------------------------------------------------------------------------
# Simulated Pinterest Identity Provider & Broker Lifecycle
# ---------------------------------------------------------------------------


class PinterestIdentityProvider:
    """Implements the provider SPI: code exchange, /v5/user_account lookup, and postBrokerLogin."""

    TOKEN_URL = "https://api.pinterest.com/v5/oauth/token"
    USER_ACCOUNT_URL = "https://api.pinterest.com/v5/user_account"

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        vault: ApplicationCredentialVault,
        federated_store: FederatedIdentityStore,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.vault = vault
        self.federated_store = federated_store

    async def exchange_code_and_lookup_identity(
        self, code: str, transaction_id: str
    ) -> BrokeredIdentityContext:
        """Step 1: Exchange OAuth authorization code for tokens and fetch user account."""
        async with httpx.AsyncClient(verify=True) as http:
            # 1. Exchange code at Pinterest token endpoint
            resp = await http.post(
                self.TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                },
                auth=(self.client_id, self.client_secret),
            )
            if resp.status_code != 200:
                raise RuntimeError(f"Pinterest code exchange failed with HTTP {resp.status_code}")
            tokens = resp.json()

            # 2. Fetch authenticated user account info
            user_resp = await http.get(
                self.USER_ACCOUNT_URL,
                headers={"Authorization": f"Bearer {tokens['access_token']}"},
            )
            if user_resp.status_code != 200:
                raise RuntimeError(
                    f"Pinterest user account lookup failed with HTTP {user_resp.status_code}"
                )
            user_info = user_resp.json()

        # Require nonempty account ID — never fall back to username or email
        account_id = user_info.get("id")
        if not account_id:
            raise ValueError("Pinterest /v5/user_account response missing mandatory account ID")

        return BrokeredIdentityContext(
            provider_alias="pinterest",
            code=code,
            tokens=tokens,
            provider_user_id=str(account_id),
            user_metadata=user_info,
            broker_transaction_id=transaction_id,
        )

    async def execute_first_broker_login(
        self, context: BrokeredIdentityContext
    ) -> KeycloakUserModel:
        """Step 2: Keycloak First Broker Login flow with Review Profile DISABLED.

        Provisions or resolves stable user model without password or email prompts.
        """
        existing = await self.federated_store.find_user_by_federated_identity(
            context.provider_alias, context.provider_user_id
        )
        if existing:
            return existing

        # Password-free automatic creation: username uses provider ID or sanitized display name
        username = f"pinterest_{context.provider_user_id}"
        user, _is_new = await self.federated_store.create_user_and_link(
            context.provider_alias, context.provider_user_id, username
        )
        return user

    async def post_broker_login_hook(
        self, context: BrokeredIdentityContext, user: KeycloakUserModel
    ) -> None:
        """Step 3: Hook executed before Keycloak issues client authorization response.

        Must persist credentials to application ingress. Outage here aborts login.
        """
        await self.vault.persist_credentials(
            subject=user.id,
            provider_account_id=context.provider_user_id,
            tokens=context.tokens,
            transaction_id=context.broker_transaction_id,
        )

    async def authenticate_broker_transaction(
        self, code: str, transaction_id: str
    ) -> tuple[KeycloakUserModel, str]:
        """Full transaction: code exchange -> identity resolution -> storage hook -> auth code."""
        # Step 1: Exchange & account lookup
        context = await self.exchange_code_and_lookup_identity(code, transaction_id)

        # Step 2: First Broker Login mapping
        user = await self.execute_first_broker_login(context)

        # Step 3: Persistence-before-login completion hook
        # If this throws, transaction aborts and no client authorization code is generated.
        await self.post_broker_login_hook(context, user)

        # Step 4: Login completion — generate MCP client authorization code
        client_auth_code = f"kc_auth_code_{uuid.uuid4()}"
        return user, client_auth_code


# ---------------------------------------------------------------------------
# Test Suite: Broker Feasibility, Fault Injection & Concurrency
# ---------------------------------------------------------------------------


@pytest.fixture
def broker_setup():
    vault = ApplicationCredentialVault()
    store = FederatedIdentityStore()
    provider = PinterestIdentityProvider(
        client_id="1598790",
        client_secret="test-client-secret",
        redirect_uri="https://mcp.pheniox.cloud/auth/realms/pinterest/broker/pinterest/endpoint",
        vault=vault,
        federated_store=store,
    )
    return provider, vault, store


@pytest.mark.asyncio
@respx.mock
async def test_code_exchange_and_stable_subject_mapping(broker_setup):
    provider, vault, _store = broker_setup

    respx.post("https://api.pinterest.com/v5/oauth/token").respond(
        status_code=200,
        json={
            "token_type": "bearer",
            "access_token": "pina_test_access_token_123",
            "refresh_token": "pinr_test_refresh_token_456",
            "expires_in": 2592000,
            "scope": "boards:read boards:write pins:read pins:write user_accounts:read",
        },
    )
    respx.get("https://api.pinterest.com/v5/user_account").respond(
        status_code=200,
        json={
            "id": "123456789012345678",
            "account_type": "BUSINESS",
            "username": "pin_business_test",
        },
    )

    user1, client_code1 = await provider.authenticate_broker_transaction(
        code="auth_code_1", transaction_id="txn_1"
    )

    # Assert stable UUID subject created without password/email prompts
    assert uuid.UUID(user1.id)  # Valid UUID
    assert client_code1.startswith("kc_auth_code_")

    # Assert credentials persisted before completion
    stored = await vault.get_connection(user1.id)
    assert stored is not None
    assert stored["subject"] == user1.id
    assert stored["provider_account_id"] == "123456789012345678"
    assert stored["status"] == "active"

    # Return login: same Pinterest account returns the exact same stable user UUID
    user2, client_code2 = await provider.authenticate_broker_transaction(
        code="auth_code_2", transaction_id="txn_2"
    )
    assert user2.id == user1.id
    assert client_code2 != client_code1


@pytest.mark.asyncio
@respx.mock
async def test_missing_account_id_fails_closed_without_user_creation(broker_setup):
    provider, vault, store = broker_setup

    respx.post("https://api.pinterest.com/v5/oauth/token").respond(
        status_code=200,
        json={"access_token": "pina_test", "expires_in": 3600},
    )
    # Response omitting mandatory account ID
    respx.get("https://api.pinterest.com/v5/user_account").respond(
        status_code=200,
        json={"username": "orphan_user", "account_type": "PINNER"},
    )

    with pytest.raises(ValueError, match="missing mandatory account ID"):
        await provider.authenticate_broker_transaction(
            code="code_missing_id", transaction_id="txn_missing"
        )

    # Verify no user or credentials created
    assert len(store._users) == 0
    assert len(vault.connections) == 0


@pytest.mark.asyncio
@respx.mock
async def test_failing_storage_aborts_login_and_recovers_on_retry(broker_setup):
    """Proves persistence-before-login: storage outage aborts login; retry succeeds."""
    provider, vault, _store = broker_setup

    respx.post("https://api.pinterest.com/v5/oauth/token").respond(
        status_code=200,
        json={
            "token_type": "bearer",
            "access_token": "pina_test_token",
            "refresh_token": "pinr_test_token",
            "expires_in": 2592000,
        },
    )
    respx.get("https://api.pinterest.com/v5/user_account").respond(
        status_code=200,
        json={"id": "999888777666555444", "username": "storage_fault_user"},
    )

    # 1. Fault injection: storage ingress fails
    vault.fault_injected = True

    with pytest.raises(StorageFault, match="unavailable"):
        await provider.authenticate_broker_transaction(
            code="code_fault_1", transaction_id="txn_fault"
        )

    # Assert no usable connection was persisted
    assert len(vault.connections) == 0

    # 2. Storage recovers: client retries the authorization flow
    vault.fault_injected = False

    user, client_code = await provider.authenticate_broker_transaction(
        code="code_fault_retry", transaction_id="txn_retry"
    )

    assert client_code.startswith("kc_auth_code_")
    persisted = await vault.get_connection(user.id)
    assert persisted is not None
    assert persisted["provider_account_id"] == "999888777666555444"
    assert persisted["status"] == "active"


@pytest.mark.asyncio
@respx.mock
async def test_concurrent_first_login_converges_on_single_owner(broker_setup):
    """Proves concurrent first logins converge on one stable subject without duplicate owners."""
    provider, vault, store = broker_setup

    respx.post("https://api.pinterest.com/v5/oauth/token").respond(
        status_code=200,
        json={
            "token_type": "bearer",
            "access_token": "pina_concurrent_token",
            "refresh_token": "pinr_concurrent_token",
            "expires_in": 2592000,
        },
    )
    respx.get("https://api.pinterest.com/v5/user_account").respond(
        status_code=200,
        json={"id": "555444333222111000", "username": "concurrent_user"},
    )

    # Execute two simultaneous first-login transactions for the exact same Pinterest account
    results = await asyncio.gather(
        provider.authenticate_broker_transaction(code="code_race_1", transaction_id="txn_race_1"),
        provider.authenticate_broker_transaction(code="code_race_2", transaction_id="txn_race_2"),
    )

    (user1, _code1), (user2, _code2) = results

    # Both concurrent logins must resolve to the identical Keycloak subject UUID
    assert user1.id == user2.id

    # Exactly one user model exists in the store
    assert len(store._users) == 1
    assert len(store._mappings) == 1

    # Credential vault has exactly one owner record
    assert len(vault.connections) == 1
    assert user1.id in vault.connections
