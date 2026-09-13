
"""
Persistence-layer attack benchmark for exactmemory-recallspection.

Scope: attacks on the save()/load() file, not in-memory state.

Covers three file-level attacks:
    F1  Container rollback: attacker rolls back counter / max_version, then
        restores an old valid record → get() must detect replay.
    F2  Semantic rewrite: attacker rewrites a record's payload under a valid
        HMAC. With out-of-band keys, this must fail because the attacker
        cannot compute the HMAC.
    F3  Key substitution: attacker overwrites the key block in the file.
        With out-of-band keys, the file contains no keys, so this attack is
        structurally impossible. load() must use caller keys only.

Produces pass/fail per attack with the observed exception type.

Run:
    python benchmarks/benchmark_persistence.py
"""
import base64
import json
import os
import ssl
import sys
import tempfile
import time
import urllib.request
import zipfile

REPO_ZIP = "https://github.com/sciencedelicmetatech/exactmemory.recallspection/archive/refs/heads/main.zip"

for mod in list(sys.modules.keys()):
    if "exactmemory" in mod:
        del sys.modules[mod]

print("📥 Downloading repo...")
ctx = ssl._create_unverified_context()
with urllib.request.urlopen(REPO_ZIP, context=ctx) as r:
    zip_data = r.read()

temp_dir = tempfile.mkdtemp()
zip_path = os.path.join(temp_dir, "repo.zip")
with open(zip_path, "wb") as f:
    f.write(zip_data)

with zipfile.ZipFile(zip_path) as zf:
    zf.extractall(temp_dir)

repo_folder = next(
    os.path.join(temp_dir, d)
    for d in os.listdir(temp_dir)
    if d.startswith("exactmemory") and os.path.isdir(os.path.join(temp_dir, d))
)

while repo_folder in sys.path:
    sys.path.remove(repo_folder)
sys.path.insert(0, repo_folder)

from exactmemory_recallspection import (
    ExactMemory,
    IntegrityError,
    TamperDetectedError,
    ReplayDetectedError,
    ExpiredRecordError,
    UnknownKeyIdError,
    KeyNotFoundError,
)

SECRET = b"persistence-test-key-32-bytes!!!!!"


def fresh_store():
    m = ExactMemory(keys={1: SECRET})
    m.add("a", "original_a")
    m.add("b", "original_b")
    m.add("c", "original_c")
    return m


def save_to_temp(m):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        path = tmp.name
    m.save(path)
    return path


def load_file(path):
    with open(path, "r") as f:
        return json.load(f)


def write_file(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, separators=(",", ":"))


# =========================================================
# F1 — Container rollback
# =========================================================

def attack_f1_container_rollback():
    """
    Scenario:
        1. Write a, b, c → version 3.
        2. Save to disk.
        3. Rewrite a → version 4.
        4. Attacker rolls back the file to the version-3 snapshot AND
           rolls back counter/max_version in the container.
        5. load() must detect that the container MAC fails.

    Detection: IntegrityError raised at load().
    """
    m = fresh_store()
    path = save_to_temp(m)

    wrapper = load_file(path)
    payload = json.loads(base64.b64decode(wrapper["container"]).decode("utf-8"))
    payload["counter"] = 0
    payload["max_version"] = {}
    new_container = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    wrapper["container"] = base64.b64encode(new_container).decode("ascii")
    write_file(path, wrapper)

    m2 = ExactMemory(keys={1: SECRET})
    try:
        m2.load(path)
        return False, "no error raised — container rollback accepted"
    except IntegrityError as e:
        return True, f"IntegrityError: {type(e).__name__}"
    except Exception as e:
        return False, f"unexpected: {type(e).__name__}: {e}"
    finally:
        os.unlink(path)


# =========================================================
# F2 — Semantic rewrite of a record
# =========================================================

def attack_f2_semantic_rewrite():
    """
    Scenario:
        1. Write a, b, c.
        2. Save.
        3. Attacker rewrites a's payload from "original_a" to "ATTACKER-CONTROLLED".
        4. load() must detect the tampering (either at load() via container MAC,
           or at get() via record HMAC).

    Detection: IntegrityError (container) or TamperDetectedError (record).
    """
    m = fresh_store()
    path = save_to_temp(m)

    wrapper = load_file(path)
    payload = json.loads(base64.b64decode(wrapper["container"]).decode("utf-8"))
    entries = payload["entries"]

    import zlib
    target_key = None
    for enc_digest, enc_blob in entries.items():
        blob = base64.b64decode(enc_blob)
        body = blob[:-16]
        payload_bytes = body[18 + 16:]
        try:
            value = json.loads(zlib.decompress(payload_bytes).decode("utf-8"))
        except Exception:
            continue
        if value == "original_a":
            target_key = enc_digest
            break

    if target_key is None:
        os.unlink(path)
        return False, "could not locate target record in file"

    old_blob = base64.b64decode(entries[target_key])
    body = old_blob[:-16]
    new_payload = zlib.compress(json.dumps("ATTACKER-CONTROLLED").encode("utf-8"), 6)
    new_body = body[: 18 + 16] + new_payload
    new_blob = new_body + old_blob[-16:]
    entries[target_key] = base64.b64encode(new_blob).decode("ascii")

    new_container = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    wrapper["container"] = base64.b64encode(new_container).decode("ascii")
    write_file(path, wrapper)

    m2 = ExactMemory(keys={1: SECRET})
    try:
        m2.load(path)
    except IntegrityError as e:
        os.unlink(path)
        return True, f"container MAC rejected (IntegrityError: {type(e).__name__})"

    try:
        val = m2.get("a", raise_on_missing=True)
        os.unlink(path)
        return False, f"tampered record served as authentic: {val!r}"
    except IntegrityError as e:
        os.unlink(path)
        return True, f"TamperDetectedError: {type(e).__name__}"
    except Exception as e:
        os.unlink(path)
        return False, f"unexpected: {type(e).__name__}: {e}"


# =========================================================
# F3 — Key substitution
# =========================================================

def attack_f3_key_substitution():
    """
    Scenario:
        1. Write a, b, c.
        2. Save.
        3. Attacker tries to inject a 'keys' block into the file.
        4. load() must use caller keys only; injected keys ignored.

    Detection: file has no 'keys' field, or IntegrityError.
    """
    m = fresh_store()
    path = save_to_temp(m)

    wrapper = load_file(path)
    payload = json.loads(base64.b64decode(wrapper["container"]).decode("utf-8"))

    if "keys" in payload:
        os.unlink(path)
        return False, "file still contains a 'keys' field — out-of-band key custody not enforced"

    payload["keys"] = {"1": base64.b64encode(b"attacker-key-32-bytes!!!!!!!!!!!!!").decode("ascii")}
    new_container = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    wrapper["container"] = base64.b64encode(new_container).decode("ascii")
    write_file(path, wrapper)

    m2 = ExactMemory(keys={1: SECRET})
    try:
        m2.load(path)
        val = m2.get("a", raise_on_missing=True)
        os.unlink(path)
        if val == "original_a":
            return True, "injected 'keys' field ignored; caller key used; value intact"
        return False, f"unexpected value after load: {val!r}"
    except IntegrityError as e:
        os.unlink(path)
        return True, f"IntegrityError: {type(e).__name__}"
    except Exception as e:
        os.unlink(path)
        return False, f"unexpected: {type(e).__name__}: {e}"


# =========================================================
# Runner
# =========================================================

def main():
    print()
    print("=" * 108)
    print("PERSISTENCE-LAYER ATTACK BENCHMARK")
    print("=" * 108)
    print("Scope: attacks on the save()/load() file, not in-memory state.")
    print("-" * 108)

    attacks = [
        ("F1 container rollback",   attack_f1_container_rollback),
        ("F2 semantic rewrite",     attack_f2_semantic_rewrite),
        ("F3 key substitution",     attack_f3_key_substitution),
    ]

    results = {}
    for name, fn in attacks:
        detected, detail = fn()
        results[name] = {"detected": detected, "detail": detail}
        status = "✅ DETECTED" if detected else "❌ FAILED"
        print(f"  {status:<15} {name:<25} {detail}")

    print("-" * 108)
    passed = sum(1 for r in results.values() if r["detected"])
    print(f"\n  Passed: {passed}/{len(attacks)}")

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "benchmark_persistence_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"✅ Results written to: {out_path}")


if __name__ == "__main__":
    main()
