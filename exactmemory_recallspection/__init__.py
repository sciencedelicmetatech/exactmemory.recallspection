from .core import (
    ExactMemory,
    ExactMemoryError,
    TamperError,
    RollbackError,
    LogCompromisedError,
    MissingKeyError,
    FormatVersionError,          # <-- add
    TransparencyLog,
    RemoteAnchor,
)
...
__version__ = "3.2.0"            # <-- bump

__all__ = [
    "ExactMemory",
    "ExactMemoryError",
    "TamperError",
    "RollbackError",
    "LogCompromisedError",
    "MissingKeyError",
    "FormatVersionError",        # <-- add
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