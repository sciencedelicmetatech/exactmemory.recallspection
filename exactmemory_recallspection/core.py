# ExactMemory v3.0.0 - Final Release
# BREAKING from v2.x: 32-byte tags, explicit container_key_id, require_log, remote_anchor
# Zero dependencies, pure Python stdlib

import os
import hmac
import hashlib
import json
import time
import zlib
import tempfile
from typing import Dict, Optional, Tuple

try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

def sha3_256_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()

class ExactMemoryError(Exception): pass
class TamperError(ExactMemoryError): pass
class RollbackError(ExactMemoryError): pass
class LogCompromisedError(ExactMemoryError): pass
class MissingKeyError(ExactMemoryError): pass

class RemoteAnchor:
    def anchor(self, chain_hash: str, max_version: int, container_hash: str): raise NotImplementedError
    def get_latest(self) -> Optional[dict]: raise NotImplementedError
    def verify(self, chain_hash: str) -> bool: raise NotImplementedError

class TransparencyLog:
    def __init__(self, log_path: str, require_log: bool = True):
        self.log_path = log_path
        self.require_log = require_log
    def _canonical(self, obj) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()
    def append(self, counter: int, max_version: int, container_hash: str) -> dict:
        prev_hash = "0"*64
        last = self._last_entry()
        if last:
            prev_hash = last['chain_hash']
        entry = {'timestamp': int(time.time()), 'counter': counter, 'max_version': max_version, 'container_hash': container_hash, 'prev_hash': prev_hash}
        chain_hash = sha3_256_hex((prev_hash + self._canonical(entry).decode()).encode())
        entry['chain_hash'] = chain_hash
        with open(self.log_path, 'a') as f:
            if HAS_FCNTL:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.write(self._canonical(entry).decode() + "\n")
            f.flush()
            os.fsync(f.fileno())
            if HAS_FCNTL:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return entry
    def _last_entry(self):
        if not os.path.exists(self.log_path):
            return None
        try:
            with open(self.log_path, 'r') as f:
                lines = [l.strip() for l in f if l.strip()]
                return json.loads(lines[-1]) if lines else None
        except:
            return None
    def verify_chain(self):
        if not os.path.exists(self.log_path):
            if self.require_log:
                return False, "Log file missing but require_log=True - possible deletion attack"
            return True, "No log yet (opt-in)"
        with open(self.log_path, 'r') as f:
            lines = [l.strip() for l in f if l.strip()]
        prev_hash = "0"*64
        for i, line in enumerate(lines):
            entry = json.loads(line)
            if entry.get('prev_hash') != prev_hash:
                return False, f"Line {i} prev_hash mismatch"
            entry_copy = {k: v for k, v in entry.items() if k != 'chain_hash'}
            recomputed = sha3_256_hex((prev_hash + self._canonical(entry_copy).decode()).encode())
            if not hmac.compare_digest(recomputed, entry['chain_hash']):
                return False, f"Line {i} chain_hash invalid"
            prev_hash = entry['chain_hash']
        return True, f"Chain OK - {len(lines)} entries"
    def get_tip(self):
        return self._last_entry()

class ExactMemory:
    VERSION = "3.0.0"
    def __init__(self, keys: Dict[str, bytes], container_key_id: str = 'container', ttl_seconds: Optional[int]=None, log_path: str="./transparency.log", remote_anchor: Optional[RemoteAnchor]=None, require_log: bool=True, strict_rollback: bool=True):
        if container_key_id not in keys:
            raise ValueError(f"container_key_id '{container_key_id}' must exist in keys - which key signs? Explicitly required (v3.0.0 breaking change)")
        self.keys = keys
        self.container_key_id = container_key_id
        self.ttl = ttl_seconds
        self.store = {}
        self.counter = 0
        self.max_version = 0
        self.per_key_max = {}
        self.tombstones = {}
        self.log = TransparencyLog(log_path, require_log=require_log)
        self.remote_anchor = remote_anchor
        self.require_log = require_log
        self.strict_rollback = strict_rollback
        self.tag_len = 32

    def _canonical(self, record: dict) -> bytes:
        return json.dumps(record, sort_keys=True, separators=(',', ':')).encode()
    def _make_tag(self, key_id: str, record: dict) -> bytes:
        rec = record.copy()
        rec['_key_hash'] = sha3_256_hex(rec['key'].encode())
        rec['_key_id_hash'] = sha3_256_hex(key_id.encode())
        return hmac.new(self.keys[key_id], self._canonical(rec), hashlib.sha256).digest()[:32]

    def put(self, k, v, key_id=None):
        kid = key_id or next(iter([kk for kk in self.keys if kk != self.container_key_id]))
        self.counter += 1
        record = {'key': k, 'value': v, 'key_id': kid, 'version': self.counter, 'timestamp': int(time.time()), 'nonce': os.urandom(16).hex()}
        tag = self._make_tag(kid, record)
        self.store[k] = (record, tag)
        self.max_version = self.counter
        self.per_key_max[k] = self.counter
        self.tombstones.pop(k, None)
        return record

    def get_with_status(self, k) -> Tuple[Optional[object], str]:
        if k in self.tombstones:
            rec, tag = self.tombstones[k]
            if not hmac.compare_digest(tag, self._make_tag(rec['key_id'], rec)):
                return None, "tampered"
            return None, "tombstoned"
        if k not in self.store:
            return None, "missing"
        rec, tag = self.store[k]
        if not hmac.compare_digest(tag, self._make_tag(rec['key_id'], rec)):
            return None, "tampered"
        if rec['version'] < self.per_key_max.get(k, 0):
            return None, "tampered"
        if self.ttl is not None and int(time.time()) - rec['timestamp'] > self.ttl:
            return None, "expired"
        return rec['value'], "ok"

    def get(self, k, raise_on_missing=False, raise_on_tampered=False, raise_on_expired=False):
        value, status = self.get_with_status(k)
        if status == "ok":
            return value
        if status == "missing" and raise_on_missing:
            raise MissingKeyError(f"Key '{k}' not found")
        if status in ("tampered", "tombstoned") and raise_on_tampered:
            raise TamperError(f"Key '{k}' {status}")
        if status == "expired" and raise_on_expired:
            raise TamperError(f"Key '{k}' expired")
        return None

    def delete(self, k, key_id=None):
        kid = key_id or next(iter([kk for kk in self.keys if kk != self.container_key_id]))
        self.counter += 1
        tomb = {'key': k, 'deleted': True, 'version': self.counter, 'key_id': kid, 'timestamp': int(time.time()), 'nonce': os.urandom(16).hex()}
        tag = self._make_tag(kid, tomb)
        self.tombstones[k] = (tomb, tag)
        self.store.pop(k, None)
        self.max_version = self.counter
        self.per_key_max[k] = self.counter

    def save(self, path: str):
        entries = [(key, rec, tag.hex()) for key, (rec, tag) in self.store.items()]
        tombs = [(key, rec, tag.hex()) for key, (rec, tag) in self.tombstones.items()]
        container = {'counter': self.counter, 'max_version': self.max_version, 'per_key_max': self.per_key_max, 'entries': entries, 'tombstones': tombs, 'tag_len': 32, 'version': self.VERSION, 'container_key_id': self.container_key_id}
        raw = json.dumps(container, sort_keys=True, separators=(',', ':')).encode()
        compressed = zlib.compress(raw, 6)
        container_hash = sha3_256_hex(compressed)
        mac = hmac.new(self.keys[self.container_key_id], compressed, hashlib.sha256).digest()
        with open(path, 'wb') as f:
            if HAS_FCNTL:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.write(mac + compressed)
            f.flush()
            os.fsync(f.fileno())
            if HAS_FCNTL:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        log_entry = self.log.append(self.counter, self.max_version, container_hash)
        if self.remote_anchor:
            self.remote_anchor.anchor(log_entry['chain_hash'], self.max_version, container_hash)

    def load(self, path: str, keys: Dict[str, bytes]):
        valid, msg = self.log.verify_chain()
        if not valid:
            raise LogCompromisedError(msg)
        tip = self.log.get_tip()
        if self.require_log and not tip:
            raise LogCompromisedError("Log required but missing - possible deletion attack. Set require_log=False to opt-in")
        if self.remote_anchor and tip:
            latest_remote = self.remote_anchor.get_latest()
            if latest_remote and tip['max_version'] < latest_remote['max_version']:
                raise RollbackError(f"Log rollback vs remote anchor: log {tip['max_version']} < remote {latest_remote['max_version']}")
        with open(path, 'rb') as f:
            if HAS_FCNTL:
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            blob = f.read()
            if HAS_FCNTL:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        if len(blob) < 32:
            raise TamperError("File too short")
        mac, compressed = blob[:32], blob[32:]
        expected_mac = hmac.new(keys[self.container_key_id], compressed, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise TamperError("Container MAC failed")
        container_hash = sha3_256_hex(compressed)
        raw = zlib.decompress(compressed)
        container = json.loads(raw)
        if tip and container['max_version'] < tip['max_version']:
            raise RollbackError(f"ROLLBACK DETECTED! File {container['max_version']} < log {tip['max_version']}")
        self.keys = keys
        self.counter = container['counter']
        self.max_version = container['max_version']
        self.per_key_max = container.get('per_key_max', {})
        self.store = {}
        expired = 0
        for k, rec, tag_hex in container['entries']:
            if self.ttl is not None and int(time.time()) - rec['timestamp'] > self.ttl:
                expired += 1
                continue
            self.store[k] = (rec, bytes.fromhex(tag_hex))
        self.tombstones = {k: (rec, bytes.fromhex(tag_hex)) for k, rec, tag_hex in container.get('tombstones', [])}

def make_store(log_path="./transparency.log", require_log=True):
    keys = {'k1': b'secret-key-32-bytes-long-12345678', 'k2': b'another-secret-key-32-bytes-8765', 'container': b'container-key-32-bytes-long-123456'}
    return ExactMemory(keys=keys, log_path=log_path, require_log=require_log), keys

# Tests (same as v2.1.0, now v3.0.0)
def test_basic_put_get():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        store, _ = make_store(os.path.join(tmp, "log"))
        store.put("user_123", {"theme": "dark"})
        assert store.get("user_123") == {"theme": "dark"}

def test_32byte_tags():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        store, _ = make_store(os.path.join(tmp, "log"))
        store.put("a", "data")
        rec, tag = store.store["a"]
        assert len(tag) == 32

def test_rollback_protection():
    import tempfile, shutil
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "log")
        db_v5 = os.path.join(tmp, "db_v5")
        db_v10 = os.path.join(tmp, "db_v10")
        store, keys = make_store(log_path)
        for i in range(5):
            store.put(f"k{i}", f"v{i}")
        store.save(db_v5)
        shutil.copy(db_v5, db_v5+".bak")
        for i in range(5, 10):
            store.put(f"k{i}", f"v{i}")
        store.save(db_v10)
        shutil.copy(db_v5+".bak", db_v10)
        new_store, _ = make_store(log_path)
        try:
            new_store.load(db_v10, keys)
            assert False
        except Exception as e:
            assert "ROLLBACK" in str(e)

if __name__ == "__main__":
    import pytest, sys
    sys.exit(pytest.main([__file__, "-v"]))
