<p align="center">
  <img src="banner.svg" alt="RECALLSPECTION" width="800">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/dependencies-none-brightgreen" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/tags-32--byte%20HMAC--SHA256-blue" alt="32-byte tags">
  <img src="https://img.shields.io/badge/license-AGPL--3.0-green" alt="License">
</p>

<h1 align="center">ExactMemory-Recallspection</h1>

<p align="center">
  <strong>A tamper-evident, replay-resistant, rollback-resistant key-value store with transparency log and remote anchor. Zero external dependencies.</strong>
</p>

<p align="center">
  Part of the <a href="https://github.com/sciencedelicmetatech/recallspection">Recallspection</a> project · Powered by Sciencedelic Metatech.
</p>

---

## Why ExactMemory?

AI agents, audit systems, and compliance pipelines all need one thing that most storage layers do not provide: **proof that stored data has not been modified**. A plain database returns whatever bytes are on disk. A vector store returns the nearest neighbour, whether or not it is authentic. A cache silently serves stale content.

ExactMemory answers a different question: **"Is this record still exactly what was written?"**

Every record is sealed with a 32-byte HMAC-SHA256 tag, bound to a monotonic version counter, transparency log, and optional remote anchor. If a single bit flips anywhere either payload, header, or metadata the store refuses to return it. If someone replays an older valid record, the version check rejects it. If the entire container is rolled back, the transparency log rejects it. If the log itself is deleted, `require_log=True` rejects it. If both log and container are rolled back together, the remote anchor (S3 with Object Lock) rejects it.

The library is **pure Python standard library**. It runs on Linux, macOS, Windows, and iOS. No PyTorch. No NumPy. No native extensions.

---

## Features

| Feature | Description |
|---------|-------------|
| **HMAC-SHA256 integrity** | **32-byte** authentication tag over full record (v3.0.0, was 16-byte) |
| **Container MAC** | On-disk container authenticated with explicit `container_key_id` (which key signs?) |
| **Metadata binding** | Tag covers `key_id`, `version`, `timestamp`, `nonce` — not just payload |
| **Out-of-band keys** | Keys never touch data file; `load()` accepts only caller-supplied keys |
| **Replay resistance** | Monotonic version + timestamp + optional TTL |
| **Rollback resistance** | Transparency log with hash chain — `ROLLBACK DETECTED` if file max_version < log tip |
| **Log deletion protection** | `require_log=True` by default — deletion is `LogCompromisedError` |
| **Remote anchor** | Stub interface `RemoteAnchor` + S3 example with Object Lock prevents log+container rollback together |
| **TTL under load()** | Expired records purged on `load()`, not just `get()` |
| **Concurrent save()** | `fcntl.flock` prevents corruption under parallel saves |
| **Key rotation** | `rotate_key()` adds new key without invalidating existing records |
| **Substitution resistance** | Records bound to SHA3-256 digest of their key |
| **Tombstones** | Deletion writes signed tombstone with distinct status |
| **Missing vs tampered** | `get_with_status()` returns `ok/missing/tampered/expired/tombstoned` + `raise_on_missing` |
| **Bit-flip property test** | Every single bit flip detected |
| **Zero dependencies** | Pure Python 3.8+ stdlib |
| **Tiny footprint** | < 600 lines core, < 20 KB installed |

---

## Installation

```bash
pip install exactmemory-recallspection
```

```python
from exactmemory import ExactMemory

keys = {
    'k1': b'secret-key-32-bytes-long-12345678',
    'container': b'container-key-32-bytes-long-123456'  # v3.0.0 required: which key signs?
}

store = ExactMemory(keys=keys, require_log=True)  # log deletion = error by default
store.put("user_123", {"theme": "dark"})
store.save("exact.db")

# Load with rollback protection
store2 = ExactMemory(keys=keys, require_log=True)
store2.load("exact.db", keys)
print(store2.get("user_123"))  # {"theme": "dark"}
print(store2.get_with_status("missing_key"))  # (None, "missing")
```

### Remote anchor (prevents log+container rollback together)

```python
from examples.remote_anchor_s3 import S3Anchor

anchor = S3Anchor(bucket="my-anchors", key="prod/tip.jsonl")  # S3 Object Lock
store = ExactMemory(keys=keys, remote_anchor=anchor, require_log=True)
store.put("a", "1")
store.save("exact.db")  # also anchors tip hash to S3
```

See `examples/remote_anchor_s3.py` for 20-line S3 example.

---

## Benchmarks (v3.0.0, honest numbers)

Pure stdlib, zlib level 6, 32-byte tags, Python 3.11:

```
Case 1: Small values (v{i}) - best case:
  put 1000: 0.007s (145k ops/s)
  get 1000: 0.005s (200k ops/s)
  bytes/record: 78.5 bytes

Case 2: Random 100-byte payloads - honest case:
  bytes/record: 193.8 bytes  <- honest number (150-200B predicted)

Case 3: Dict {theme, language} - realistic:
  bytes/record: 79.4 bytes
```

Both numbers belong in README, labeled clearly.

---

## Security Model

| Attack | Protection |
|--------|------------|
| Payload tamper (bit flip) | HMAC-SHA256 32-byte tag, constant-time compare |
| Metadata tamper (version, timestamp) | Tag covers version, timestamp, nonce, key_id |
| Replay old valid record | per_key_max + max_version check |
| Container rollback | Transparency log hash chain |
| Log deletion | `require_log=True` -> `LogCompromisedError` |
| Log + container rollback together | `remote_anchor` (S3 Object Lock) |
| Key material leak | Keys never written to file, verified by test |
| Concurrent save corruption | `fcntl.flock` |

---

## Changelog

### v3.0.0 - BREAKING
- 32-byte tags enforced (was 16-byte)
- Explicit `container_key_id='container'` required
- `require_log=True` by default
- `get_with_status()` + `raise_on_missing`/`raise_on_tampered`
- Transparency log + remote anchor
- TTL under load() + concurrent save() locking
- Bit-flip property test

### v1.2.0 -> v1.1.0
- Initial releases with 16-byte tags

---

## License

AGPL-3.0

