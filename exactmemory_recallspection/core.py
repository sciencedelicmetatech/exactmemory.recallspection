"""
ExactMemory core.

Security model
--------------
Each record is stored as:

    [key_id (2B)] [version (8B)] [timestamp (8B)] [nonce (16B)] [payload] [HMAC (16B)]

where:
- key_id     : uint16, identifies which key from the keyring signed the record
- version    : uint64, monotonically increasing per key digest
- timestamp  : float64 epoch seconds, used for freshness/TTL
- nonce      : 16 random bytes, unique per write
- payload    : zlib-compressed JSON
- HMAC       : HMAC-SHA256 over (key_digest || header || nonce || payload), truncated to 16 bytes

Properties:
- Tamper-evident: any bit flip in any field fails HMAC verification.
- Replay-resistant: monotonic version + timestamp + optional TTL reject
  previously-valid records.
- Key-rotatable: multiple keys in a keyring, each record carries its key_id.
- Metadata-bound: HMAC covers key_id, version, timestamp, and nonce, not
  just the payload.
- Substitution-resistant: HMAC binds the record to the SHA3-256 key digest,
  so a blob from one key cannot be replayed into another key's slot.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
import zlib
from typing import Any, Dict, Optional, Tuple


# ---------- Exceptions ----------

class IntegrityError(ValueError):
    """Base class for all integrity failures."""


class TamperDetectedError(IntegrityError):
    """HMAC verification failed."""


class ReplayDetectedError(IntegrityError):
    """Record version is older than the highest seen for this key."""


class ExpiredRecordError(IntegrityError):
    """Record timestamp is outside the TTL window."""


class UnknownKeyIdError(IntegrityError):
    """Record uses a key_id not present in the keyring."""


class KeyNotFoundError(KeyError):
    """Key not present in the store (only when raise_on_missing=True)."""


# ---------- Record layout ----------

HEADER_FMT = ">HQd"                          # key_id, version, timestamp
HEADER_SIZE = struct.calcsize(HEADER_FMT)    # 18 bytes
NONCE_SIZE = 16
HMAC_SIZE = 16


class ExactMemory:
    """
    Tamper-evident, replay-resistant, key-rotatable key-value store.

    Args:
        keys: mapping of key_id (int) -> secret bytes (>= 32 bytes recommended).
              If None, a single random key with id 1 is generated.
        current_key_id: key_id used for new writes. Defaults to max(keys).
        ttl_seconds: optional freshness window. None disables TTL.
        hash_name: HMAC hash function ("sha256" recommended; "sha3_256" also OK).
        clock_skew_seconds: tolerance for timestamps slightly in the future.
    """

    FORMAT = "exactmemory-v2"
    VERSION = "1.1.0"

    def __init__(
        self,
        keys: Optional[Dict[int, bytes]] = None,
        current_key_id: Optional[int] = None,
        ttl_seconds: Optional[float] = None,
        hash_name: str = "sha256",
        clock_skew_seconds: float = 60.0,
    ):
        if keys is None:
            keys = {1: secrets.token_bytes(32)}
        if not keys:
            raise ValueError("keys must not be empty")
        for kid, k in keys.items():
            if not isinstance(kid, int) or kid < 0 or kid > 0xFFFF:
                raise ValueError(f"key_id {kid} must be in [0, 65535]")
            if not isinstance(k, (bytes, bytearray)) or len(k) < 16:
                raise ValueError(f"key {kid} must be bytes >= 16 bytes")
        if hash_name not in ("sha256", "sha3_256", "sha512", "sha3_512"):
            raise ValueError(f"unsupported hash_name: {hash_name}")

        self._keys: Dict[int, bytes] = {k: bytes(v) for k, v in keys.items()}
        self._current_key_id = (
            current_key_id if current_key_id is not None else max(self._keys)
        )
        if self._current_key_id not in self._keys:
            raise ValueError(f"current_key_id {self._current_key_id} not in keys")

        self._ttl = ttl_seconds
        self._hash_name = hash_name
        self._clock_skew = clock_skew_seconds

        self._store: Dict[bytes, bytes] = {}
        self._max_version: Dict[bytes, int] = {}
        self._counter: int = 0

    # ---------- Key management ----------

    def rotate_key(self, new_key: Optional[bytes] = None) -> int:
        """Add a new key and set it as current. Returns the new key_id."""
        new_id = max(self._keys) + 1
        if new_id > 0xFFFF:
            raise ValueError("key_id space exhausted")
        self._keys[new_id] = new_key or secrets.token_bytes(32)
        self._current_key_id = new_id
        return new_id

    @property
    def current_key_id(self) -> int:
        return self._current_key_id

    @property
    def key_ids(self):
        return sorted(self._keys.keys())

    # ---------- Public API ----------

    def add(self, key: str, value: Any) -> None:
        """Store a key-value pair. Overwrites any existing value."""
        digest = self._hash(key)
        self._counter += 1
        version = self._counter
        timestamp = time.time()
        nonce = secrets.token_bytes(NONCE_SIZE)
        blob = self._pack(key, value, version, timestamp, nonce)
        self._store[digest] = blob
        self._max_version[digest] = version

    def get(self, key: str, raise_on_missing: bool = False) -> Optional[Any]:
        """
        Retrieve a value.

        Raises:
            TamperDetectedError   on HMAC mismatch
            ReplayDetectedError   on version rollback
            ExpiredRecordError    on timestamp outside TTL
            UnknownKeyIdError     on unrecognised key_id
            KeyNotFoundError      on missing key (only if raise_on_missing)
        """
        digest = self._hash(key)
        blob = self._store.get(digest)
        if blob is None:
            if raise_on_missing:
                raise KeyNotFoundError(key)
            return None

        value, meta = self._unpack(key, blob)

        now = time.time()
        age = now - meta["timestamp"]
        if age < -self._clock_skew:
            raise ExpiredRecordError(
                f"Record for '{key}' has future timestamp (age={age:.2f}s)"
            )
        if self._ttl is not None and age > self._ttl:
            raise ExpiredRecordError(
                f"Record for '{key}' expired (age={age:.2f}s > ttl={self._ttl}s)"
            )

        prev = self._max_version.get(digest)
        if prev is not None and meta["version"] < prev:
            raise ReplayDetectedError(
                f"Replay for '{key}': version {meta['version']} < {prev}"
            )
        self._max_version[digest] = meta["version"]

        return value

    def delete(self, key: str) -> bool:
        """Remove a key. Returns True if it existed."""
        digest = self._hash(key)
        if digest in self._store:
            del self._store[digest]
            return True
        return False

    def __contains__(self, key: str) -> bool:
        return self._hash(key) in self._store

    def __len__(self) -> int:
        return len(self._store)

    # ---------- Persistence ----------

    def save(self, path: str) -> None:
        """Write the entire store to a JSON file."""
        data = {
            "format": self.FORMAT,
            "version": self.VERSION,
            "counter": self._counter,
            "current_key_id": self._current_key_id,
            "hash_name": self._hash_name,
            "ttl_seconds": self._ttl,
            "clock_skew_seconds": self._clock_skew,
            "keys": {
                str(k): base64.b64encode(v).decode("ascii")
                for k, v in self._keys.items()
            },
            "max_version": {
                base64.b64encode(k).decode("ascii"): v
                for k, v in self._max_version.items()
            },
            "entries": {
                base64.b64encode(k).decode("ascii"): base64.b64encode(v).decode("ascii")
                for k, v in self._store.items()
            },
        }
        with open(path, "w") as f:
            json.dump(data, f, separators=(",", ":"))

    def load(self, path: str) -> None:
        """Load a previously saved store, replacing in-memory state."""
        with open(path, "r") as f:
            data = json.load(f)

        if "entries" not in data or "keys" not in data:
            raise IntegrityError("Unrecognised file format")

        self._counter = data["counter"]
        self._current_key_id = data["current_key_id"]
        self._hash_name = data.get("hash_name", "sha256")
        self._ttl = data.get("ttl_seconds")
        self._clock_skew = data.get("clock_skew_seconds", 60.0)
        self._keys = {
            int(k): base64.b64decode(v) for k, v in data["keys"].items()
        }
        self._max_version = {
            base64.b64decode(k): v for k, v in data["max_version"].items()
        }
        self._store = {
            base64.b64decode(k): base64.b64decode(v)
            for k, v in data["entries"].items()
        }

    # ---------- Internals ----------

    @staticmethod
    def _hash(key: str) -> bytes:
        return hashlib.sha3_256(key.encode("utf-8")).digest()

    def _hmac(self, key_id: int, data: bytes) -> bytes:
        if key_id not in self._keys:
            raise UnknownKeyIdError(f"Unknown key_id: {key_id}")
        return hmac.new(self._keys[key_id], data, self._hash_name).digest()

    def _pack(
        self, key: str, value: Any, version: int, timestamp: float, nonce: bytes
    ) -> bytes:
        key_id = self._current_key_id
        digest = self._hash(key)
        header = struct.pack(HEADER_FMT, key_id, version, timestamp)
        json_bytes = json.dumps(value).encode("utf-8")
        payload = zlib.compress(json_bytes, level=6)
        body = header + nonce + payload
        mac = self._hmac(key_id, digest + body)[:HMAC_SIZE]
        return body + mac

    def _unpack(self, key: str, blob: bytes) -> Tuple[Any, Dict[str, Any]]:
        min_size = HEADER_SIZE + NONCE_SIZE + HMAC_SIZE
        if len(blob) < min_size:
            raise TamperDetectedError(
                f"Record too short ({len(blob)} < {min_size})"
            )

        body = blob[:-HMAC_SIZE]
        mac = blob[-HMAC_SIZE:]

        key_id, version, timestamp = struct.unpack(HEADER_FMT, body[:HEADER_SIZE])
        digest = self._hash(key)

        expected = self._hmac(key_id, digest + body)[:HMAC_SIZE]
        if not hmac.compare_digest(mac, expected):
            raise TamperDetectedError("HMAC verification failed")

        nonce = body[HEADER_SIZE:HEADER_SIZE + NONCE_SIZE]
        payload = body[HEADER_SIZE + NONCE_SIZE:]

        try:
            json_bytes = zlib.decompress(payload)
            value = json.loads(json_bytes.decode("utf-8"))
        except (zlib.error, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise TamperDetectedError(f"Payload decode failed: {e}")

        return value, {
            "key_id": key_id,
            "version": version,
            "timestamp": timestamp,
            "nonce": nonce,
        }
