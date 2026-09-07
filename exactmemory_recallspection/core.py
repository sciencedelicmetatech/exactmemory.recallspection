import hashlib
import hmac
import zlib
import json
import base64
import os
from typing import Any, Optional, Dict


class ExactMemory:
    """
    A tamper‑evident key‑value store with cryptographic HMAC checksums.

    Keys are strings; values can be any JSON‑serializable object.
    Each entry is stored as:
        SHA3‑256(key) → zlib.compress(json.dumps(value)) + HMAC‑SHA3‑256(compressed)

    On retrieval, the HMAC is verified. Without the secret key,
    an attacker cannot forge a valid checksum.

    Args:
        secret_key (bytes, optional): 32‑byte HMAC key. If not provided,
            a random key is generated.
    """

    def __init__(self, secret_key: Optional[bytes] = None):
        self._secret = secret_key or os.urandom(32)
        self._store: Dict[bytes, bytes] = {}

    # ---------- Public API ----------

    def add(self, key: str, value: Any) -> None:
        """Store a key‑value pair. Overwrites if key already exists."""
        digest = self._hash(key)
        blob = self._pack(value)
        self._store[digest] = blob

    def get(self, key: str) -> Optional[Any]:
        """
        Retrieve a value. Returns None if key not found.
        Raises ValueError if data is corrupted or tampered.
        """
        digest = self._hash(key)
        blob = self._store.get(digest)
        if blob is None:
            return None
        try:
            return self._unpack(blob)
        except (ValueError, zlib.error, json.JSONDecodeError):
            raise ValueError(f"Tamper‑detected: corrupted data for key '{key}'")

    def delete(self, key: str) -> bool:
        """Remove a key. Returns True if existed, False otherwise."""
        digest = self._hash(key)
        if digest in self._store:
            del self._store[digest]
            return True
        return False

    def save(self, path: str) -> None:
        """
        Persist the entire store to a JSON file.

        The file format is a dict mapping base64‑encoded key digests
        to base64‑encoded packed blobs.
        """
        serializable = {
            base64.b64encode(k).decode('ascii'): base64.b64encode(v).decode('ascii')
            for k, v in self._store.items()
        }
        with open(path, 'w') as f:
            json.dump(serializable, f)

    def load(self, path: str) -> None:
        """
        Load a previously saved store from a JSON file.
        Replaces the current in‑memory store.
        """
        with open(path, 'r') as f:
            data = json.load(f)
        self._store = {
            base64.b64decode(k.encode('ascii')): base64.b64decode(v.encode('ascii'))
            for k, v in data.items()
        }

    # ---------- Internal helpers ----------

    @staticmethod
    def _hash(key: str) -> bytes:
        """SHA3‑256 digest of the key (32 bytes)."""
        return hashlib.sha3_256(key.encode('utf-8')).digest()

    def _pack(self, value: Any) -> bytes:
        """
        Pack a value into a blob:
            zlib.compress(json.dumps(value).encode()) + HMAC‑SHA3‑256(compressed)
        """
        json_bytes = json.dumps(value).encode('utf-8')
        compressed = zlib.compress(json_bytes, level=6)
        # 16‑byte HMAC (first 16 bytes of 32‑byte output)
        mac = hmac.new(self._secret, compressed, hashlib.sha3_256).digest()[:16]
        return compressed + mac

    def _unpack(self, blob: bytes) -> Any:
        """
        Unpack a blob, verifying the HMAC.
        Raises ValueError on corruption or tampering.
        """
        if len(blob) < 16:
            raise ValueError("Invalid blob: too short")
        compressed = blob[:-16]
        mac = blob[-16:]
        expected = hmac.new(self._secret, compressed, hashlib.sha3_256).digest()[:16]
        if not hmac.compare_digest(mac, expected):
            raise ValueError("HMAC mismatch – data tampered or corrupted")
        json_bytes = zlib.decompress(compressed)
        return json.loads(json_bytes.decode('utf-8'))