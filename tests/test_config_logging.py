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
