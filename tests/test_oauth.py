"""Tests for OAuth 2.1 resource-server mode (Tasks 7.1-7.8)."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWKClient
from starlette.testclient import TestClient

from pinterest_mcp.config import Settings, Transport
from pinterest_mcp.http_app import create_http_app
from pinterest_mcp.oauth import JWTTokenVerifier


@pytest.fixture
def rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key


def generate_test_token(
    private_key,
    issuer: str = "https://auth.example.com",
    audience: str = "https://mcp.example.com",
    scopes: list[str] | None = None,
    expires_in: int = 3600,
    kid: str = "test-key-1",
    client_id: str = "test-client-id",
) -> str:
    now = int(time.time())
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": "user-123",
        "client_id": client_id,
        "scope": " ".join(scopes) if scopes else "read:boards write:pins",
        "iat": now,
        "exp": now + expires_in,
    }
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": kid})


@pytest.mark.asyncio
async def test_jwt_token_verifier_valid_and_invalid_tokens(rsa_key_pair):
    public_key = rsa_key_pair.public_key()

    mock_jwk_client = MagicMock(spec=PyJWKClient)
    mock_jwk = MagicMock()
    mock_jwk.key = public_key
    mock_jwk_client.get_signing_key_from_jwt.return_value = mock_jwk

    verifier = JWTTokenVerifier(
        issuer="https://auth.example.com",
        resource_url="https://mcp.example.com",
        jwk_client=mock_jwk_client,
    )

    # Valid token
    valid_tok = generate_test_token(rsa_key_pair)
    access_token = await verifier.verify_token(valid_tok)
    assert access_token is not None
    assert access_token.client_id == "test-client-id"
    assert "read:boards" in access_token.scopes

    # Expired token
    expired_tok = generate_test_token(rsa_key_pair, expires_in=-100)
    access_token_exp = await verifier.verify_token(expired_tok)
    assert access_token_exp is None

    # Foreign audience
    foreign_aud_tok = generate_test_token(rsa_key_pair, audience="https://other.example.com")
    access_token_aud = await verifier.verify_token(foreign_aud_tok)
    assert access_token_aud is None

    # Foreign issuer
    foreign_iss_tok = generate_test_token(rsa_key_pair, issuer="https://evil.example.com")
    access_token_iss = await verifier.verify_token(foreign_iss_tok)
    assert access_token_iss is None


def test_oauth_routes_and_well_known_metadata():
    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_OAUTH_ISSUER="https://auth.example.com",
        MCP_RESOURCE_URL="https://mcp.example.com/mcp",
        MCP_OAUTH_REQUIRED_SCOPES="read:boards, write:pins",
    )
    app = create_http_app(settings)
    with TestClient(app, base_url="http://127.0.0.1:8080") as client:
        # Well known metadata route is accessible unauthenticated
        res = client.get("/.well-known/oauth-protected-resource/mcp")
        assert res.status_code == 200
        data = res.json()
        assert data["resource"] == "https://mcp.example.com/mcp"
        assert any("https://auth.example.com" in s for s in data["authorization_servers"])
        assert "read:boards" in data["scopes_supported"]

        # Assert no auth server provider routes are mounted (/authorize, /token, /register)
        for route in ("/authorize", "/token", "/register", "/oauth/authorize", "/oauth/token"):
            res_auth = client.get(route)
            assert res_auth.status_code == 404

        # Unauthenticated request to /mcp returns 401 with WWW-Authenticate header
        res_mcp = client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert res_mcp.status_code == 401
        www_auth = res_mcp.headers.get("www-authenticate", "")
        assert "Bearer" in www_auth
        assert "resource_metadata=" in www_auth
        assert "invalid_token" in www_auth


def test_oauth_end_to_end_middleware(rsa_key_pair, monkeypatch, caplog):
    import logging

    public_key = rsa_key_pair.public_key()
    mock_jwk_client = MagicMock(spec=PyJWKClient)
    mock_jwk = MagicMock()
    mock_jwk.key = public_key
    mock_jwk_client.get_signing_key_from_jwt.return_value = mock_jwk

    # Monkeypatch PyJWKClient constructor in oauth.py
    monkeypatch.setattr("pinterest_mcp.oauth.PyJWKClient", lambda *args, **kwargs: mock_jwk_client)

    settings = Settings(
        MCP_TRANSPORT=Transport.HTTP,
        MCP_HOST="127.0.0.1",
        MCP_OAUTH_ISSUER="https://auth.example.com",
        MCP_RESOURCE_URL="https://mcp.example.com/mcp",
        MCP_OAUTH_REQUIRED_SCOPES="read:boards",
        MCP_JSON_RESPONSE=True,
    )
    app = create_http_app(settings)

    with (
        caplog.at_level(logging.DEBUG),
        TestClient(app, base_url="http://127.0.0.1:8080") as client,
    ):
        # 1. Valid token with required scope
        valid_tok = generate_test_token(
            rsa_key_pair,
            issuer="https://auth.example.com",
            audience="https://mcp.example.com/mcp",
            scopes=["read:boards", "write:pins"],
        )
        init_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"},
            },
        }
        res_valid = client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {valid_tok}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json=init_payload,
        )
        assert res_valid.status_code == 200

        # 2. Token with insufficient scope -> 403 Forbidden
        insufficient_tok = generate_test_token(
            rsa_key_pair,
            issuer="https://auth.example.com",
            audience="https://mcp.example.com/mcp",
            scopes=["other:scope"],
        )
        res_scope = client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {insufficient_tok}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        assert res_scope.status_code == 403
        assert "insufficient_scope" in res_scope.headers.get("www-authenticate", "")

        # 3. Expired token -> 401 Unauthorized
        expired_tok = generate_test_token(
            rsa_key_pair,
            issuer="https://auth.example.com",
            audience="https://mcp.example.com/mcp",
            scopes=["read:boards"],
            expires_in=-300,
        )
        res_exp = client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {expired_tok}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json={"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}},
        )
        assert res_exp.status_code == 401
        assert "invalid_token" in res_exp.headers.get("www-authenticate", "")

        # 4. Verify no token strings appear in logs
        for record in caplog.records:
            assert valid_tok not in record.message
            assert insufficient_tok not in record.message
            assert expired_tok not in record.message


