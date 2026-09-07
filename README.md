# ExactMemory · Recallspection

**Tamper‑evident key‑value store with HMAC‑protected checksums.**

- Zero external dependencies (pure Python standard library).
- Stores any JSON‑serializable value.
- Protected with **HMAC‑SHA3‑256** (16‑byte tag) using a secret key.
- Detects accidental corruption **and** malicious tampering (key kept secret).
- Optional persistence via `save()` / `load()`.

## Installation

```bash
pip install exactmemory-recallspection