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


class Transport(str, Enum):  # noqa: UP042
    STDIO = "stdio"
    HTTP = "http"


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
    auth_token: SecretStr | None = Field(default=None, alias="MCP_AUTH_TOKEN")

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

    @field_validator("path")
    @classmethod
    def _path_must_be_absolute(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("must start with '/'")
        return v.rstrip("/") or "/"

    @field_validator("token_path", "allowed_image_dir")
    @classmethod
    def _expand(cls, v: Path) -> Path:
        return Path(os.path.expandvars(v.expanduser()))

    @model_validator(mode="after")
    def _http_requires_auth_off_loopback(self) -> Settings:
        """Refuse to expose an unauthenticated MCP endpoint beyond loopback.

        Publishing port 8080 without this check means anyone who can reach the
        host can post to the operator's Pinterest account.
        """
        if self.transport is Transport.HTTP and not self.is_loopback and self.auth_token is None:
            raise ValueError(
                f"MCP_AUTH_TOKEN is required when MCP_HOST is not loopback "
                f"(got {self.host!r}). Set MCP_AUTH_TOKEN, or bind 127.0.0.1."
            )
        return self

    @property
    def is_loopback(self) -> bool:
        return self.host in LOOPBACK_HOSTS

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
