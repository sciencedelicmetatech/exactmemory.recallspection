"""
ExactMemory v3.0.0 – Tamper-evident key-value store with HMAC-SHA256 integrity,
replay resistance, key rotation, transparency log, and remote anchor.

BREAKING from v1.x/v2.x:
- 32-byte tags enforced (was 16-byte)
- container_key_id='container' required
- require_log=True by default
- get_with_status() restores missing vs tampered distinction

Zero dependencies, pure Python stdlib.
"""

from .core import (
    ExactMemory,
    ExactMemoryError,
    TamperError,
    RollbackError,
    LogCompromisedError,
    MissingKeyError,
    TransparencyLog,
    RemoteAnchor,
)

# Backwards compat aliases for v1.1.0 names you had
# v1: IntegrityError, TamperDetectedError, ReplayDetectedError, ExpiredRecordError, UnknownKeyIdError, KeyNotFoundError
IntegrityError = TamperError
TamperDetectedError = TamperError
ReplayDetectedError = TamperError  # replay is a form of tamper in v3
ExpiredRecordError = TamperError
UnknownKeyIdError = ExactMemoryError
KeyNotFoundError = MissingKeyError

__version__ = "3.0.0"

__all__ = [
    # v3 core
    "ExactMemory",
    "ExactMemoryError",
    "TamperError",
    "RollbackError",
    "LogCompromisedError",
    "MissingKeyError",
    "TransparencyLog",
    "RemoteAnchor",
    # v1 compat aliases
    "IntegrityError",
    "TamperDetectedError",
    "ReplayDetectedError",
    "ExpiredRecordError",
    "UnknownKeyIdError",
    "KeyNotFoundError",
]
