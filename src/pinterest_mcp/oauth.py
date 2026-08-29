"""OAuth 2.1 resource-server mode token verification (Design D5, Tasks 7.1-7.8).

Validates JWT access tokens using JWKS without logging token or secret contents.
"""

from __future__ import annotations

import logging
from typing import Any

import anyio
import jwt
from jwt import PyJWKClient
from mcp.server.auth.provider import AccessToken

logger = logging.getLogger(__name__)

DEFAULT_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"]


class JWTTokenVerifier:
    """TokenVerifier implementation validating signed JWTs against issuer JWKS."""

    def __init__(
        self,
        issuer: str,
        resource_url: str | None = None,
        jwks_url: str | None = None,
        algorithms: list[str] | None = None,
        jwk_client: PyJWKClient | None = None,
        allowed_subjects: list[str] | None = None,
    ) -> None:
        self.issuer = issuer
        self.resource_url = resource_url
        self.jwks_url = jwks_url or f"{issuer.rstrip('/')}/.well-known/jwks.json"
        self.algorithms = algorithms or DEFAULT_ALGORITHMS
        self.allowed_subjects = set(allowed_subjects or [])
        self._jwk_client = jwk_client or PyJWKClient(
            self.jwks_url,
            cache_keys=True,
            max_cached_keys=16,
            cache_jwk_set=True,
            lifespan=3600,
        )

    def _verify_sync(self, token: str) -> AccessToken | None:
        try:
            signing_key = self._jwk_client.get_signing_key_from_jwt(token)
            options = {"require": ["exp", "iss"]}
            if self.resource_url:
                options["require"].append("aud")

            payload: dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                algorithms=self.algorithms,
                issuer=self.issuer,
                audience=self.resource_url,
                options=options,
            )
            subject = payload.get("sub")
            if self.allowed_subjects and subject not in self.allowed_subjects:
                logger.debug("Token subject is not allowed")
                return None

            raw_scope = payload.get("scope") or payload.get("scopes") or payload.get("scp") or []
            if isinstance(raw_scope, str):
                scopes = [s.strip() for s in raw_scope.split() if s.strip()]
            elif isinstance(raw_scope, list):
                scopes = [str(s) for s in raw_scope]
            else:
                scopes = []

            client_id = str(
                payload.get("client_id")
                or payload.get("azp")
                or payload.get("sub")
                or "unknown-client"
            )

            aud = payload.get("aud")
            if isinstance(aud, str):
                resource = aud
            elif isinstance(aud, list) and aud:
                resource = aud[0]
            else:
                resource = None

            return AccessToken(
                token=token,
                client_id=client_id,
                scopes=scopes,
                expires_at=payload.get("exp"),
                resource=resource,
                subject=str(subject) if subject else None,
                claims=payload,
            )
        except jwt.PyJWTError as err:
            logger.debug("Token verification failed: %s", err.__class__.__name__)
            return None
        except Exception:
            logger.debug("Unexpected error during token verification")
            return None

    async def verify_token(self, token: str) -> AccessToken | None:
        return await anyio.to_thread.run_sync(self._verify_sync, token)
