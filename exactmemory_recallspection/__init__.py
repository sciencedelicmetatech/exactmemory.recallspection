from .core import (
    ExactMemory,
    ExactMemoryError,
    TamperError,
    RollbackError,
    LogCompromisedError,
    MissingKeyError,
    FormatVersionError,
    AdmissionError,  # <-- Added for PR4
    TransparencyLog,
    RemoteAnchor,
)

__version__ = "3.3.0"  # <-- Bumped

__all__ = [
    "ExactMemory",
    "ExactMemoryError",
    "TamperError",
    "RollbackError",
    "LogCompromisedError",
    "MissingKeyError",
    "FormatVersionError",
    "AdmissionError",  # <-- Added
    "TransparencyLog",
    "RemoteAnchor",
    # v1 compat aliases (unchanged)
    "IntegrityError",
    "TamperDetectedError",
    "ReplayDetectedError",
    "ExpiredRecordError",
    "UnknownKeyIdError",
    "KeyNotFoundError",
]