"""
ExactMemory – Tamper-evident key-value store with HMAC-SHA256 integrity,
replay resistance, and key rotation.
"""

from .core import (
    ExactMemory,
    IntegrityError,
    TamperDetectedError,
    ReplayDetectedError,
    ExpiredRecordError,
    UnknownKeyIdError,
    KeyNotFoundError,
)

__version__ = "1.1.0"

__all__ = [
    "ExactMemory",
    "IntegrityError",
    "TamperDetectedError",
    "ReplayDetectedError",
    "ExpiredRecordError",
    "UnknownKeyIdError",
    "KeyNotFoundError",
]
