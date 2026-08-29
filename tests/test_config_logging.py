"""Tests for configuration and logging redaction (Task 1.5)."""

from __future__ import annotations

import logging

import pytest

from pinterest_mcp.config import ConfigError, load_settings
from pinterest_mcp.logging_setup import RedactingFilter, redact


def test_invalid_mcp_port_aborts_and_names_variable():
    with pytest.raises(ConfigError) as exc_info:
        load_settings({"MCP_PORT": "invalid_port"})
    err_msg = str(exc_info.value)
    assert "MCP_PORT" in err_msg


def test_comma_separated_list_settings_load_from_environment_shape():
    settings = load_settings(
        {
            "MCP_ALLOWED_HOSTS": "127.0.0.1:8080,localhost:8080",
            "MCP_OAUTH_REQUIRED_SCOPES": "read:boards,write:pins",
        }
    )
    assert settings.allowed_hosts == ["127.0.0.1:8080", "localhost:8080"]
    assert settings.oauth_required_scopes == ["read:boards", "write:pins"]


def test_secret_validation_failure_names_variable_without_leaking_secret():
    secret_val = "super_secret_token_123456789"
    with pytest.raises(ConfigError) as exc_info:
        # PINTEREST_CLIENT_ID is secret, providing an invalid type/structure if applicable
        # or testing secret redaction on error description
        load_settings({"MCP_PORT": "-1", "PINTEREST_CLIENT_ID": secret_val})
    err_msg = str(exc_info.value)
    assert "PINTEREST_CLIENT_ID" in err_msg or "MCP_PORT" in err_msg
    assert secret_val not in err_msg


def test_log_records_carry_redaction_markers():
    secret_token = "pina_abcdefghijklmnopqrstuvwxyz123456789"
    bearer_token = "Bearer secret_bearer_token_xyz123"

    redacted_secret = redact(secret_token)
    assert secret_token not in redacted_secret
    assert "[REDACTED]" in redacted_secret

    redacted_bearer = redact(bearer_token)
    assert "secret_bearer_token" not in redacted_bearer
    assert "[REDACTED]" in redacted_bearer

    filter_obj = RedactingFilter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=1,
        msg=f"Connecting with token {secret_token} and auth {bearer_token}",
        args=(),
        exc_info=None,
    )
    filter_obj.filter(record)
    assert secret_token not in record.getMessage()
    assert "[REDACTED]" in record.getMessage()


def test_readme_configuration_table_covers_all_settings_fields():
    import re
    from pathlib import Path

    from pinterest_mcp.config import Settings

    readme_path = Path(__file__).resolve().parent.parent / "README.md"
    content = readme_path.read_text(encoding="utf-8")

    # Extract all backticked variables from the Environment Variables Reference table
    env_vars_in_readme = set(re.findall(r"`([A-Z0-9_]+)`", content))

    for field_name, field_info in Settings.model_fields.items():
        env_alias = field_info.alias or field_name.upper()
        assert env_alias in env_vars_in_readme, (
            f"Field {env_alias} missing in README configuration table"
        )
