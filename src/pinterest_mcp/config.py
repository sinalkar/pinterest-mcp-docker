"""Runtime configuration, validated once at startup.

Every knob the server reads comes from the environment and is validated here
before a listener is bound or a credential is used. Validation failures abort
the process with a message naming the offending variable — never its value,
since several of them are secrets.
"""

from __future__ import annotations

import os
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Variables whose *values* must never reach a log or an error message.
SECRET_ENV_VARS = frozenset(
    {
        "PINTEREST_CLIENT_ID",
        "PINTEREST_CLIENT_SECRET",
        "PINTEREST_ACCESS_TOKEN",
        "PINTEREST_REFRESH_TOKEN",
        "MCP_AUTH_TOKEN",
    }
)

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

# Loopback defaults for DNS-rebinding protection, matching what the SDK's own
# `sse_app()` derives automatically for a loopback bind (see design D7).
_LOOPBACK_ALLOWED_HOSTS = ("127.0.0.1:*", "localhost:*", "[::1]:*")
_LOOPBACK_ALLOWED_ORIGINS = (
    "http://127.0.0.1:*",
    "http://localhost:*",
    "http://[::1]:*",
)


class Transport(str, Enum):  # noqa: UP042
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    HTTP_SSE = "http+sse"


TRANSPORT_VALUES = tuple(t.value for t in Transport)


class ConfigError(RuntimeError):
    """Raised when the environment cannot produce a usable configuration."""


def _default_token_path() -> Path:
    """`$XDG_STATE_HOME/pinterest-mcp/token.json`, falling back to ~/.local/state."""
    state_home = os.environ.get("XDG_STATE_HOME")
    base = Path(state_home) if state_home else Path.home() / ".local" / "state"
    return base / "pinterest-mcp" / "token.json"


class Settings(BaseSettings):
    """Validated runtime settings. Construct via :func:`load_settings`."""

    model_config = SettingsConfigDict(
        env_file=None,  # the process environment is the only source
        extra="ignore",
        validate_default=True,
    )

    # -- transport -----------------------------------------------------
    transport: Transport = Field(default=Transport.STDIO, alias="MCP_TRANSPORT")
    host: str = Field(default="127.0.0.1", alias="MCP_HOST")
    port: Annotated[int, Field(ge=1, le=65535)] = Field(default=8080, alias="MCP_PORT")
    path: str = Field(default="/mcp", alias="MCP_PATH")
    sse_path: str = Field(default="/sse", alias="MCP_SSE_PATH")
    message_path: str = Field(default="/messages/", alias="MCP_MESSAGE_PATH")
    auth_token: SecretStr | None = Field(default=None, alias="MCP_AUTH_TOKEN")

    # -- streamable-HTTP options (design D3) ----------------------------
    json_response: bool = Field(default=False, alias="MCP_JSON_RESPONSE")
    stateless: bool = Field(default=False, alias="MCP_STATELESS")
    resumability: bool = Field(default=False, alias="MCP_RESUMABILITY")
    event_store_max_events: Annotated[int, Field(gt=0)] = Field(
        default=1000, alias="MCP_EVENT_STORE_MAX_EVENTS"
    )
    max_request_bytes: Annotated[int, Field(gt=0)] = Field(
        default=4 * 1024 * 1024, alias="MCP_MAX_REQUEST_BYTES"
    )
    session_idle_timeout: Annotated[float, Field(gt=0)] | None = Field(
        default=None, alias="MCP_SESSION_IDLE_TIMEOUT"
    )
    sse_retry_interval_ms: Annotated[int, Field(gt=0)] | None = Field(
        default=None, alias="MCP_SSE_RETRY_INTERVAL_MS"
    )

    # -- transport security and CORS (design D7) ------------------------
    dns_rebinding_protection: bool = Field(default=True, alias="MCP_DNS_REBINDING_PROTECTION")
    allowed_hosts: list[str] = Field(default_factory=list, alias="MCP_ALLOWED_HOSTS")
    allowed_origins: list[str] = Field(default_factory=list, alias="MCP_ALLOWED_ORIGINS")
    cors_allow_credentials: bool = Field(default=False, alias="MCP_CORS_ALLOW_CREDENTIALS")

    # -- OAuth 2.1 resource-server mode (design D5) ---------------------
    oauth_issuer: str | None = Field(default=None, alias="MCP_OAUTH_ISSUER")
    oauth_jwks_url: str | None = Field(default=None, alias="MCP_OAUTH_JWKS_URL")
    resource_url: str | None = Field(default=None, alias="MCP_RESOURCE_URL")
    oauth_required_scopes: list[str] = Field(
        default_factory=list, alias="MCP_OAUTH_REQUIRED_SCOPES"
    )

    # -- logging -------------------------------------------------------
    log_level: Literal["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"] = Field(
        default="INFO", alias="LOG_LEVEL"
    )
    log_format: Literal["text", "json"] = Field(default="text", alias="LOG_FORMAT")

    # -- Pinterest credentials ----------------------------------------
    client_id: SecretStr | None = Field(default=None, alias="PINTEREST_CLIENT_ID")
    client_secret: SecretStr | None = Field(default=None, alias="PINTEREST_CLIENT_SECRET")
    access_token: SecretStr | None = Field(default=None, alias="PINTEREST_ACCESS_TOKEN")
    refresh_token: SecretStr | None = Field(default=None, alias="PINTEREST_REFRESH_TOKEN")

    # -- storage and file access --------------------------------------
    token_path: Path = Field(default_factory=_default_token_path, alias="PINTEREST_TOKEN_PATH")
    allowed_image_dir: Path = Field(default_factory=Path.home, alias="PINTEREST_ALLOWED_IMAGE_DIR")
    allow_local_paths: bool = Field(default=False, alias="PINTEREST_ALLOW_LOCAL_PATHS")
    max_image_bytes: Annotated[int, Field(gt=0, le=64 * 1024 * 1024)] = Field(
        default=10 * 1024 * 1024, alias="PINTEREST_MAX_IMAGE_BYTES"
    )

    # -- outbound HTTP -------------------------------------------------
    http_timeout: Annotated[float, Field(gt=0, le=300)] = Field(
        default=30.0, alias="PINTEREST_HTTP_TIMEOUT"
    )
    max_response_bytes: Annotated[int, Field(gt=0)] = Field(
        default=32 * 1024 * 1024, alias="PINTEREST_MAX_RESPONSE_BYTES"
    )

    @field_validator("path", "sse_path")
    @classmethod
    def _path_must_be_absolute(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("must start with '/'")
        return v.rstrip("/") or "/"

    @field_validator("message_path")
    @classmethod
    def _message_path_must_be_absolute(cls, v: str) -> str:
        # Left trailing-slash-preserving: `SseServerTransport` matches this
        # path by prefix, and the SDK's own default already carries one.
        if not v.startswith("/"):
            raise ValueError("must start with '/'")
        return v

    @field_validator("allowed_hosts", "allowed_origins", "oauth_required_scopes", mode="before")
    @classmethod
    def _split_csv(cls, v: str | list[str] | None) -> list[str] | None:
        """Accept a comma-separated string from the environment.

        `pydantic-settings` otherwise expects a JSON array for a `list[str]`
        field, which is an awkward shape for a `.env` file or `docker run -e`.
        """
        if v is None or isinstance(v, list):
            return v
        return [item.strip() for item in v.split(",") if item.strip()]

    @field_validator("token_path", "allowed_image_dir")
    @classmethod
    def _expand(cls, v: Path) -> Path:
        return Path(os.path.expandvars(v.expanduser()))

    @model_validator(mode="after")
    def _http_requires_auth_off_loopback(self) -> Settings:
        """Refuse to expose an unauthenticated MCP endpoint beyond loopback.

        Publishing port 8080 without this check means anyone who can reach the
        host can post to the operator's Pinterest account. A shared bearer
        token and OAuth resource-server mode are the two accepted ways to
        satisfy this; they are mutually exclusive (see
        `_auth_modes_are_mutually_exclusive`).
        """
        if self.is_http and not self.is_loopback and self.effective_auth_mode == "none":
            raise ValueError(
                "MCP_AUTH_TOKEN or MCP_OAUTH_ISSUER is required when MCP_HOST is not "
                f"loopback (got {self.host!r}). Set one of them, or bind 127.0.0.1."
            )
        return self

    @model_validator(mode="after")
    def _auth_modes_are_mutually_exclusive(self) -> Settings:
        if self.auth_token is not None and self.oauth_issuer is not None:
            raise ValueError(
                "MCP_AUTH_TOKEN and MCP_OAUTH_ISSUER are mutually exclusive: choose a "
                "shared bearer token or OAuth resource-server mode, not both."
            )
        return self

    @model_validator(mode="after")
    def _stateless_is_incompatible_with_sessionful_features(self) -> Settings:
        if self.stateless and self.resumability:
            raise ValueError(
                "MCP_STATELESS and MCP_RESUMABILITY are incompatible: resumability "
                "replays events on a session's stream, and stateless mode keeps no "
                "session to replay onto."
            )
        if self.stateless and self.transport in (Transport.SSE, Transport.HTTP_SSE):
            raise ValueError(
                f"MCP_STATELESS is incompatible with MCP_TRANSPORT={self.transport.value!r}: "
                "the deprecated HTTP+SSE transport is inherently session-based."
            )
        return self

    @model_validator(mode="after")
    def _cors_wildcard_forbids_credentials(self) -> Settings:
        if "*" in self.allowed_origins and self.cors_allow_credentials:
            raise ValueError(
                "MCP_ALLOWED_ORIGINS cannot include '*' while "
                "MCP_CORS_ALLOW_CREDENTIALS is enabled: a wildcard origin combined "
                "with credentialed cross-origin requests defeats the origin check."
            )
        return self

    @model_validator(mode="after")
    def _sse_and_streamable_paths_must_differ(self) -> Settings:
        if self.transport is Transport.HTTP_SSE and self.path == self.sse_path:
            raise ValueError("MCP_PATH and MCP_SSE_PATH must be different paths.")
        if self.message_path.rstrip("/") in (self.path, self.sse_path):
            raise ValueError("MCP_MESSAGE_PATH must not be the same as MCP_PATH or MCP_SSE_PATH.")
        return self

    @property
    def is_loopback(self) -> bool:
        return self.host in LOOPBACK_HOSTS

    @property
    def is_http(self) -> bool:
        """True for every transport that binds an HTTP listener."""
        return self.transport is not Transport.STDIO

    @property
    def effective_auth_mode(self) -> Literal["none", "bearer", "oauth"]:
        """The authentication mode actually in effect.

        There is no `MCP_AUTH_MODE` variable to set directly — it is derived
        from which credential is configured, so there is exactly one way to
        turn on a given mode rather than a mode flag that can disagree with
        the credentials it names (see design D3).
        """
        if self.auth_token is not None:
            return "bearer"
        if self.oauth_issuer is not None:
            return "oauth"
        return "none"

    @property
    def effective_allowed_hosts(self) -> list[str]:
        """`MCP_ALLOWED_HOSTS`, defaulting to the loopback set on a loopback bind."""
        if self.allowed_hosts:
            return self.allowed_hosts
        if self.is_loopback:
            return list(_LOOPBACK_ALLOWED_HOSTS)
        return []

    @property
    def effective_allowed_origins_for_security(self) -> list[str]:
        """`MCP_ALLOWED_ORIGINS`, defaulting to the loopback set on a loopback bind.

        This feeds `TransportSecuritySettings`, which *rejects* disallowed
        origins. It is deliberately not the same list CORS *grants* browser
        access to — an operator may want DNS-rebinding protection without
        opting any browser origin into CORS (see design D7).
        """
        if self.allowed_origins:
            return self.allowed_origins
        if self.is_loopback:
            return list(_LOOPBACK_ALLOWED_ORIGINS)
        return []

    @property
    def local_paths_enabled(self) -> bool:
        """Local image paths only make sense when client and server share a disk."""
        if self.transport is Transport.STDIO:
            return True
        return self.allow_local_paths


def _describe(err: ValidationError) -> str:
    """Render a validation error naming variables but never their values."""
    lines = []
    for e in err.errors():
        field = str(e["loc"][0]) if e["loc"] else "<config>"
        env_name = _ENV_BY_FIELD.get(field, field.upper())
        msg = e["msg"]
        # Pydantic echoes the offending input in some messages; for secrets that
        # would defeat the whole point of naming-without-showing.
        if env_name in SECRET_ENV_VARS:
            msg = msg.split(",")[0]
        lines.append(f"  {env_name}: {msg}")
    return "\n".join(lines)


_ENV_BY_FIELD = {
    name: (field.alias or name.upper()) for name, field in Settings.model_fields.items()
}


def load_settings(env: dict[str, str] | None = None) -> Settings:
    """Build settings from the environment, raising :class:`ConfigError` on bad input."""
    source = os.environ if env is None else env
    try:
        return Settings(**{k: v for k, v in source.items() if k in _ENV_BY_FIELD.values()})
    except ValidationError as err:
        raise ConfigError(f"Invalid configuration:\n{_describe(err)}") from None


def load_settings_or_exit(env: dict[str, str] | None = None) -> Settings:
    """Same as :func:`load_settings`, but exits non-zero instead of raising."""
    try:
        return load_settings(env)
    except ConfigError as err:
        print(str(err), file=sys.stderr)
        raise SystemExit(2) from None
