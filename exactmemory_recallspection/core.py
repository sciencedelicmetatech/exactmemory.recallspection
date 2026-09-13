"""
ExactMemory core — v1.2.0

Security model
--------------
Per-record blob:
    [key_id (2B)] [version (8B)] [timestamp (8B)] [nonce (16B)] [payload] [HMAC (16B)]
    HMAC-SHA256 over (key_digest || header || nonce || payload), truncated to 16B.

Container (on disk, save/load):
    { "container": <base64 canonical-JSON>, "mac": <base64 HMAC-SHA256> }
    Container MAC covers: format, version, counter, current_key_id, hash_name,
    ttl_seconds, clock_skew_seconds, key_ids (list of valid IDs), max_version,
    entries. Keys are NEVER written to disk.

Deletion:
    A tombstone is written as a normal signed record with payload
    {"__tombstone__": True}. get() on a tombstone raises KeyNotFoundError
    (or returns None if raise_on_missing=False), but the record remains
    versioned so replay of the pre-delete value is caught.
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


class IntegrityError(ValueError): pass
class TamperDetectedError(IntegrityError): pass
class ReplayDetectedError(IntegrityError): pass
class ExpiredRecordError(IntegrityError): pass
class UnknownKeyIdError(IntegrityError): pass
class KeyNotFoundError(KeyError): pass


HEADER_FMT = ">HQd"
HEADER_SIZE = struct.calcsize(HEADER_FMT)
NONCE_SIZE = 16
HMAC_SIZE = 16
CONTAINER_MAC_SIZE = 32
CONTAINER_DOMAIN = b"exactmemory-container-v1"
TOMBSTONE_MARKER = "__tombstone__"


class ExactMemory:
    FORMAT = "exactmemory-v3"
    VERSION = "1.2.0"

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
        self._current_key_id = current_key_id if current_key_id is not None else max(self._keys)
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
        digest = self._hash(key)
        self._counter += 1
        version = self._counter
        timestamp = time.time()
        nonce = secrets.token_bytes(NONCE_SIZE)
        blob = self._pack(key, value, version, timestamp, nonce)
        self._store[digest] = blob
        self._max_version[digest] = version

    def get(self, key: str, raise_on_missing: bool = False) -> Optional[Any]:
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
            raise ExpiredRecordError(f"Record for '{key}' has future timestamp")
        if self._ttl is not None and age > self._ttl:
            raise ExpiredRecordError(f"Record for '{key}' expired")

        prev = self._max_version.get(digest)
        if prev is not None and meta["version"] < prev:
            raise ReplayDetectedError(
                f"Replay for '{key}': version {meta['version']} < {prev}"
            )
        self._max_version[digest] = meta["version"]

        # Tombstone handling
        if isinstance(value, dict) and value.get(TOMBSTONE_MARKER) is True:
            if raise_on_missing:
                raise KeyNotFoundError(key)
            return None

        return value

    def delete(self, key: str) -> bool:
        digest = self._hash(key)
        if digest not in self._store:
            return False
        # Write a signed tombstone — never a bare del.
        self._counter += 1
        version = self._counter
        timestamp = time.time()
        nonce = secrets.token_bytes(NONCE_SIZE)
        blob = self._pack(key, {TOMBSTONE_MARKER: True}, version, timestamp, nonce)
        self._store[digest] = blob
        self._max_version[digest] = version
        return True

    def __contains__(self, key: str) -> bool:
        digest = self._hash(key)
        blob = self._store.get(digest)
        if blob is None:
            return False
        try:
            value, _ = self._unpack(key, blob)
        except IntegrityError:
            return False
        return not (isinstance(value, dict) and value.get(TOMBSTONE_MARKER) is True)

    def __len__(self) -> int:
        return sum(1 for k in self._store if k in self)

    # ---------- Persistence ----------

    def save(self, path: str) -> None:
        """
        Persist the store to a file.

        Keys are NEVER written. load() must be called on an ExactMemory
        constructed with the same keys, or it will raise IntegrityError.
        """
        container = {
            "format": self.FORMAT,
            "version": self.VERSION,
            "counter": self._counter,
            "current_key_id": self._current_key_id,
            "hash_name": self._hash_name,
            "ttl_seconds": self._ttl,
            "clock_skew_seconds": self._clock_skew,
            "key_ids": sorted(self._keys.keys()),
            "max_version": {
                base64.b64encode(k).decode("ascii"): v
                for k, v in self._max_version.items()
            },
            "entries": {
                base64.b64encode(k).decode("ascii"): base64.b64encode(v).decode("ascii")
                for k, v in self._store.items()
            },
        }
        payload = json.dumps(container, sort_keys=True, separators=(",", ":")).encode("utf-8")
        mac = self._container_mac(payload)

        with open(path, "w") as f:
            json.dump({
                "container": base64.b64encode(payload).decode("ascii"),
                "mac": base64.b64encode(mac).decode("ascii"),
            }, f, separators=(",", ":"))

    def load(self, path: str) -> None:
        """
        Load a store from a file.

        Uses the CALLER's keys (from the constructor). Any keys present in
        the file are ignored — keys are never read from disk. If the container
        MAC does not verify under the caller's keys, IntegrityError is raised.
        """
        with open(path, "r") as f:
            wrapper = json.load(f)
        if "container" not in wrapper or "mac" not in wrapper:
            raise IntegrityError("Unrecognised file format (expected v3 container)")

        payload = base64.b64decode(wrapper["container"])
        mac = base64.b64decode(wrapper["mac"])

        expected = self._container_mac(payload)
        if not hmac.compare_digest(mac, expected):
            raise IntegrityError("Container MAC verification failed")

        container = json.loads(payload.decode("utf-8"))

        # Caller's keys must cover every key_id referenced in the file.
        file_key_ids = set(int(x) for x in container.get("key_ids", []))
        caller_key_ids = set(self._keys.keys())
        if not file_key_ids.issubset(caller_key_ids):
            missing = file_key_ids - caller_key_ids
            raise UnknownKeyIdError(
                f"File references key_ids {missing} not present in caller's keyring"
            )

        # Restore state — but do NOT touch self._keys or self._current_key_id.
        self._counter = container["counter"]
        self._hash_name = container["hash_name"]
        self._ttl = container["ttl_seconds"]
        self._clock_skew = container["clock_skew_seconds"]
        # current_key_id must be in caller's keys
        cur = container["current_key_id"]
        if cur not in self._keys:
            raise UnknownKeyIdError(f"current_key_id {cur} not in caller's keyring")
        self._current_key_id = cur

        self._max_version = {
            base64.b64decode(k): v for k, v in container["max_version"].items()
        }
        self._store = {
            base64.b64decode(k): base64.b64decode(v)
            for k, v in container["entries"].items()
        }

    # ---------- Internals ----------

    @staticmethod
    def _hash(key: str) -> bytes:
        return hashlib.sha3_256(key.encode("utf-8")).digest()

    def _hmac(self, key_id: int, data: bytes) -> bytes:
        if key_id not in self._keys:
            raise UnknownKeyIdError(f"Unknown key_id: {key_id}")
        return hmac.new(self._keys[key_id], data, self._hash_name).digest()

    def _container_mac(self, payload: bytes) -> bytes:
        """
        Container MAC key is derived from the caller's keyring.

        Derivation: HMAC(K_root, CONTAINER_DOMAIN) where K_root is the key
        with the smallest key_id. This makes the container MAC independent of
        rotation order and reproducible on load with the same keyring.
        """
        root_id = min(self._keys)
        root_key = self._keys[root_id]
        derived = hmac.new(root_key, CONTAINER_DOMAIN, self._hash_name).digest()
        return hmac.new(derived, payload, self._hash_name).digest()[:CONTAINER_MAC_SIZE]

    def _pack(self, key: str, value: Any, version: int, timestamp: float, nonce: bytes) -> bytes:
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
            raise TamperDetectedError("Record too short")
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
            value = json.loads(zlib.decompress(payload).decode("utf-8"))
        except (zlib.error, json.JSONDecodeError, UnicodeDecodeError) as e:
            raise TamperDetectedError(f"Payload decode failed: {e}")
        return value, {"key_id": key_id, "version": version, "timestamp": timestamp, "nonce": nonce}
