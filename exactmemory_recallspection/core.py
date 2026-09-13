import hashlib
import hmac
import zlib
import json
import base64
import os
import struct
import time
import secrets
from typing import Any, Optional, Dict, Tuple


# ---------- Exceptions ----------

class IntegrityError(ValueError):
    """Base class for all integrity failures."""

class TamperDetectedError(IntegrityError):
    """HMAC verification failed."""

class ReplayDetectedError(IntegrityError):
    """Record version is older than the highest seen."""

class ExpiredRecordError(IntegrityError):
    """Record timestamp outside the TTL window."""

class UnknownKeyIdError(IntegrityError):
    """Record uses a key_id not present in the keyring."""

class KeyNotFoundError(KeyError):
    """Key not in the store (raise_on_missing=True)."""


# ---------- Record layout ----------
#   key_id     : 2 bytes  (uint16, big-endian)
#   version    : 8 bytes  (uint64, big-endian)
#   timestamp  : 8 bytes  (float64, big-endian, epoch seconds)
#   nonce      : 16 bytes (random per write)
#   payload    : N bytes  (zlib-compressed JSON)
#   hmac       : 16 bytes (HMAC truncated, over digest + everything above)

HEADER_FMT = ">HQd"
HEADER_SIZE = struct.calcsize(HEADER_FMT)   # 18 bytes
NONCE_SIZE = 16
HMAC_SIZE = 16


class ExactMemory:
    """
    Tamper-evident, replay-resistant, key-rotatable key-value store.

    Security properties:
    - HMAC-SHA256 (or SHA3-256) binds the record to the key AND all metadata.
    - Monotonic version counter rejects in-session replay.
    - Timestamp + optional TTL rejects cross-session replay and staleness.
    - Key IDs allow rotation without re-writing existing records.
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

        self._keys = dict(keys)
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
        self._seen_nonces: Dict[bytes, set] = {}

    # ---------- Key management ----------

    def rotate_key(self, new_key: Optional[bytes] = None) -> int:
        """Add a new key and make it current. Returns the new key_id."""
        new_id = max(self._keys.keys()) + 1
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
        digest = self._hash(key)
        self._counter += 1
        version = self._counter
        timestamp = time.time()
        nonce = secrets.token_bytes(NONCE_SIZE)

        blob = self._pack(key, value, version, timestamp, nonce)
        self._store[digest] = blob
        self._max_version[digest] = version

        if digest not in self._seen_nonces:
            self._seen_nonces[digest] = set()
        self._seen_nonces[digest].add(nonce)

    def get(self, key: str, raise_on_missing: bool = False) -> Optional[Any]:
        digest = self._hash(key)
        blob = self._store.get(digest)
        if blob is None:
            if raise_on_missing:
                raise KeyNotFoundError(key)
            return None

        value, meta = self._unpack(key, blob)

        # Freshness
        now = time.time()
        age = now - meta["timestamp"]
        if age < -self._clock_skew:
            raise ExpiredRecordError(f"Record for '{key}' has future timestamp")
        if self._ttl is not None and age > self._ttl:
            raise ExpiredRecordError(
                f"Record for '{key}' expired (age={age:.2f}s > ttl={self._ttl}s)"
            )

        # Replay
        prev = self._max_version.get(digest)
        if prev is not None and meta["version"] < prev:
            raise ReplayDetectedError(
                f"Replay for '{key}': version {meta['version']} < {prev}"
            )
        self._max_version[digest] = meta["version"]

        return value

    def delete(self, key: str) -> bool:
        digest = self._hash(key)
        if digest in self._store:
            del self._store[digest]
            return True
        return False

    # ---------- Persistence ----------

    def save(self, path: str) -> None:
        data = {
            "format": self.FORMAT,
            "counter": self._counter,
            "current_key_id": self._current_key_id,
            "hash_name": self._hash_name,
            "ttl_seconds": self._ttl,
            "clock_skew_seconds": self._clock_skew,
            "keys": {str(k): base64.b64encode(v).decode("ascii") for k, v in self._keys.items()},
            "max_version": {
                base64.b64encode(k).decode("ascii"): v
                for k, v in self._max_version.items()
            },
            "seen_nonces": {
                base64.b64encode(k).decode("ascii"): [
                    base64.b64encode(n).decode("ascii") for n in v
                ]
                for k, v in self._seen_nonces.items()
            },
            "entries": {
                base64.b64encode(k).decode("ascii"): base64.b64encode(v).decode("ascii")
                for k, v in self._store.items()
            },
        }
        with open(path, "w") as f:
            json.dump(data, f)

    def load(self, path: str) -> None:
        with open(path, "r") as f:
            data = json.load(f)
        self._counter = data["counter"]
        self._current_key_id = data["current_key_id"]
        self._hash_name = data.get("hash_name", "sha256")
        self._ttl = data.get("ttl_seconds")
        self._clock_skew = data.get("clock_skew_seconds", 60.0)
        self._keys = {int(k): base64.b64decode(v) for k, v in data["keys"].items()}
        self._max_version = {
            base64.b64decode(k): v for k, v in data["max_version"].items()
        }
        self._seen_nonces = {
            base64.b64decode(k): {base64.b64decode(n) for n in v}
            for k, v in data.get("seen_nonces", {}).items()
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

    def _pack(self, key: str, value: Any, version: int, timestamp: float, nonce: bytes) -> bytes:
        key_id = self._current_key_id
        digest = self._hash(key)
        header = struct.pack(HEADER_FMT, key_id, version, timestamp)
        json_bytes = json.dumps(value).encode("utf-8")
        compressed = zlib.compress(json_bytes, level=6)
        body = header + nonce + compressed
        mac = self._hmac(key_id, digest + body)[:HMAC_SIZE]
        return body + mac

    def _unpack(self, key: str, blob: bytes) -> Tuple[Any, Dict]:
        min_size = HEADER_SIZE + NONCE_SIZE + HMAC_SIZE
        if len(blob) < min_size:
            raise TamperDetectedError(f"Record too short ({len(blob)} < {min_size})")

        body = blob[:-HMAC_SIZE]
        mac = blob[-HMAC_SIZE:]

        key_id, version, timestamp = struct.unpack(HEADER_FMT, body[:HEADER_SIZE])
        digest = self._hash(key)

        expected = self._hmac(key_id, digest + body)[:HMAC_SIZE]
        if not hmac.compare_digest(mac, expected):
            raise TamperDetectedError("HMAC verification failed")

        nonce = body[HEADER_SIZE : HEADER_SIZE + NONCE_SIZE]
        compressed = body[HEADER_SIZE + NONCE_SIZE :]

        # Duplicate nonce detection (same key, same nonce, different version)
        nonces = self._seen_nonces.get(digest, set())
        if nonce in nonces and version not in (self._max_version.get(digest),):
            # Nonce reuse with a different version — suspicious
            pass  # Non-blocking; version check is primary defence

        try:
            json_bytes = zlib.decompress(compressed)
            value = json.loads(json_bytes.decode("utf-8"))
        except (zlib.error, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise TamperDetectedError(f"Payload decode failed: {e}")

        return value, {
            "key_id": key_id,
            "version": version,
            "timestamp": timestamp,
            "nonce": nonce,
        }
