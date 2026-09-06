"""Tests for explicit local vs hosted mode configuration and credential restrictions."""

from __future__ import annotations

import pytest

from pinterest_mcp.config import ConfigError, load_settings


def test_default_mode_is_local():
    settings = load_settings({})
    assert settings.mode == "local"
    assert settings.is_local is True
    assert settings.is_hosted is False


def test_local_mode_allows_operator_credentials_and_no_database():
    settings = load_settings(
        {
            "MCP_MODE": "local",
            "PINTEREST_ACCESS_TOKEN": "pina_operator_token",
            "MCP_TRANSPORT": "stdio",
        }
    )
    assert settings.is_local is True
    assert settings.access_token is not None
    assert settings.access_token.get_secret_value() == "pina_operator_token"
    assert settings.database_url is None
    assert settings.pinterest_credentials_ready is True


def test_hosted_mode_rejects_operator_access_token():
    with pytest.raises(ConfigError) as exc_info:
        load_settings(
            {
                "MCP_MODE": "hosted",
                "MCP_TRANSPORT": "http",
                "MCP_OAUTH_ISSUER": "https://mcp.pheniox.cloud/auth/realms/pinterest",
                "DATABASE_URL": "postgresql+asyncpg://user:pass@localhost/db",
                "PINTEREST_ACCESS_TOKEN": "pina_operator_secret",
            }
        )
    msg = str(exc_info.value)
    assert "PINTEREST_ACCESS_TOKEN" in msg
    assert "pina_operator_secret" not in msg


def test_hosted_mode_rejects_operator_refresh_token():
    with pytest.raises(ConfigError) as exc_info:
        load_settings(
            {
                "MCP_MODE": "hosted",
                "MCP_TRANSPORT": "http",
                "MCP_OAUTH_ISSUER": "https://mcp.pheniox.cloud/auth/realms/pinterest",
                "DATABASE_URL": "postgresql+asyncpg://user:pass@localhost/db",
                "PINTEREST_REFRESH_TOKEN": "pinr_operator_secret",
            }
        )
    msg = str(exc_info.value)
    assert "PINTEREST_REFRESH_TOKEN" in msg
    assert "pinr_operator_secret" not in msg


def test_hosted_mode_rejects_shared_bearer_auth():
    with pytest.raises(ConfigError) as exc_info:
        load_settings(
            {
                "MCP_MODE": "hosted",
                "MCP_TRANSPORT": "http",
                "MCP_AUTH_TOKEN": "shared_bearer_secret",
                "DATABASE_URL": "postgresql+asyncpg://user:pass@localhost/db",
            }
        )
    msg = str(exc_info.value)
    assert "MCP_AUTH_TOKEN" in msg
    assert "shared_bearer_secret" not in msg


def test_hosted_mode_requires_oauth_issuer_and_database():
    # Missing both
    with pytest.raises(ConfigError) as exc_info:
        load_settings({"MCP_MODE": "hosted", "MCP_TRANSPORT": "http"})
    msg = str(exc_info.value)
    assert "MCP_OAUTH_ISSUER" in msg or "DATABASE_URL" in msg

    # Missing database
    with pytest.raises(ConfigError) as exc_info:
        load_settings(
            {
                "MCP_MODE": "hosted",
                "MCP_TRANSPORT": "http",
                "MCP_OAUTH_ISSUER": "https://mcp.pheniox.cloud/auth/realms/pinterest",
            }
        )
    assert "DATABASE_URL" in str(exc_info.value)


def test_hosted_mode_valid_configuration():
    settings = load_settings(
        {
            "MCP_MODE": "hosted",
            "MCP_TRANSPORT": "http",
            "MCP_HOST": "0.0.0.0",
            "MCP_OAUTH_ISSUER": "https://mcp.pheniox.cloud/auth/realms/pinterest",
            "MCP_RESOURCE_URL": "https://mcp.pheniox.cloud/mcp",
            "DATABASE_URL": "postgresql+asyncpg://app_user:secret_pw@postgres:5432/mcp",
            "REDIS_URL": "redis://redis:6379/0",
            "CREDENTIAL_ENCRYPTION_KEY": "base64_encryption_key_material",
            "BROKER_HANDOFF_SECRET": "hmac_shared_secret",
        }
    )
    assert settings.is_hosted is True
    assert settings.is_local is False
    assert settings.pinterest_credentials_ready is True
    assert settings.database_url is not None
    assert (
        settings.database_url.get_secret_value()
        == "postgresql+asyncpg://app_user:secret_pw@postgres:5432/mcp"
    )
    assert settings.redis_url is not None
    assert settings.credential_key_id == "primary"
