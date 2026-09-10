"""Persistence package for hosted multi-user Pinterest connections and audit records."""

from .db import (
    create_all_tables,
    drop_all_tables,
    get_async_engine,
    get_session_factory,
    session_scope,
)
from .encryption import (
    CredentialCipher,
    DecryptionError,
    EncryptionError,
    KeyNotFoundError,
    build_aad,
)
from .ingress import (
    IngressSecurityError,
    MemoryNonceStore,
    NonceStore,
    RedisNonceStore,
    compute_hmac_signature,
    process_credential_ingress,
    verify_hmac_signature,
)
from .models import (
    Base,
    ImmediateOperation,
    OAuthCompletionReceipt,
    PinterestConnection,
    User,
)
from .repository import (
    ConcurrentModificationError,
    ConnectionRepository,
    ForeignAccountError,
    ImmediateOperationRepository,
    InactiveConnectionError,
    RepositoryError,
    UserRepository,
)

__all__ = [
    "Base",
    "ConcurrentModificationError",
    "ConnectionRepository",
    "CredentialCipher",
    "DecryptionError",
    "EncryptionError",
    "ForeignAccountError",
    "ImmediateOperation",
    "ImmediateOperationRepository",
    "InactiveConnectionError",
    "IngressSecurityError",
    "KeyNotFoundError",
    "MemoryNonceStore",
    "NonceStore",
    "OAuthCompletionReceipt",
    "PinterestConnection",
    "RedisNonceStore",
    "RepositoryError",
    "User",
    "UserRepository",
    "build_aad",
    "compute_hmac_signature",
    "create_all_tables",
    "drop_all_tables",
    "get_async_engine",
    "get_session_factory",
    "process_credential_ingress",
    "session_scope",
    "verify_hmac_signature",
]
