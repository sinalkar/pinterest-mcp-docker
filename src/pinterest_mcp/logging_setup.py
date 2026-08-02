"""Logging configuration with mandatory secret redaction.

Everything goes to stderr: under the stdio transport, stdout carries MCP
protocol frames and nothing else, so a stray log line there corrupts the
session.

The redaction filter is deliberately applied to the root logger rather than to
individual call sites. A log statement that has to remember to redact is a log
statement that will eventually forget.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from typing import Any

REDACTED = "[REDACTED]"

# Patterns are matched against the *formatted* record, so they catch secrets
# that arrived via args, exception text, or an f-string alike.
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Authorization: Bearer <token>  /  "Bearer <token>"
    (re.compile(r"(?i)\b(bearer)\s+[\w\-.~+/]{8,}=*"), r"\1 " + REDACTED),
    # Authorization / Cookie / Set-Cookie headers in any repr form
    (
        re.compile(
            r"(?i)('|\")?(authorization|cookie|set-cookie)('|\")?\s*[:=]\s*('|\")?[^'\"\s,}]+"
        ),
        r"\2=" + REDACTED,
    ),
    # JSON-ish or kwarg-ish secret fields
    (
        re.compile(
            r"(?i)('|\")?\b("
            r"access_token|refresh_token|client_secret|client_id|api_key|"
            r"password|auth_token|mcp_auth_token"
            r")\b('|\")?\s*[:=]\s*('|\")?[^'\"\s,}\)]+"
        ),
        r"\2=" + REDACTED,
    ),
    # Pinterest tokens are long opaque strings; catch bare pina_/pinsl_ forms.
    (re.compile(r"\bpin[a-z]*_[A-Za-z0-9_\-]{16,}"), REDACTED),
    # base64 image payloads — never useful in a log, always enormous
    (
        re.compile(r"(?i)('|\")?\bdata\b('|\")?\s*[:=]\s*('|\")?[A-Za-z0-9+/]{200,}={0,2}"),
        r"data=" + REDACTED,
    ),
    (
        re.compile(r"\bdata:image/[a-z+]+;base64,[A-Za-z0-9+/=]{50,}"),
        "data:image/…;base64," + REDACTED,
    ),
)


def redact(text: str) -> str:
    """Strip anything that looks like a credential out of ``text``."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class RedactingFilter(logging.Filter):
    """Rewrites each record's rendered message with secrets removed."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:  # pragma: no cover - malformed args shouldn't kill logging
            rendered = str(record.msg)
        cleaned = redact(rendered)
        if cleaned != rendered or record.args:
            record.msg = cleaned
            record.args = ()
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


class JsonFormatter(logging.Formatter):
    """Minimal structured formatter — no dependency, no surprises."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", fmt: str = "text") -> None:
    """Install the stderr handler and the redaction filter on the root logger."""
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.addFilter(RedactingFilter())
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s"))

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)
    # httpx logs full request URLs at INFO, which can carry query-string tokens.
    logging.getLogger("httpx").setLevel(max(logging.WARNING, root.level))
