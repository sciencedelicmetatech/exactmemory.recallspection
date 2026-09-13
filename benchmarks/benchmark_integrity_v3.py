
"""
Integrity benchmark for exactmemory-recallspection.

Scope: in-memory attack matrix only.
- TTL expiry is reported separately (freshness enforcement, not an attack).
- Deletion is reported separately (it's a legitimate operation, not an attack).
- File-level attacks (container rollback, key substitution) live in
  benchmark_persistence.py.

Run:
    python benchmarks/benchmark_integrity_v3.py
"""
import base64
import json
import os
import ssl
import struct
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
    TamperDetectedError,
    ReplayDetectedError,
    ExpiredRecordError,
    UnknownKeyIdError,
    KeyNotFoundError,
)

SECRET = b"benchmark-secret-key-32-bytes!!!!!"
FACTS = [(f"cat{i % 5}:rec:{i}", {"id": i, "v": f"value_{i}"}) for i in range(100)]


def fresh_mem(**kw):
    m = ExactMemory(keys={1: SECRET}, **kw)
    for k, v in FACTS:
        m.add(k, v)
    return m


def classify(mem, key, expected):
    """
    Returns one of:
        'correct'        — record intact
        'detected'       — integrity violation raised
        'missing'        — key never existed (or was removed without tombstone)
        'silent_wrong'   — wrong value served without exception
    """
    try:
        got = mem.get(key, raise_on_missing=True)
        return "correct" if got == expected else "silent_wrong"
    except KeyNotFoundError:
        # Distinguish "never existed" from "was removed"
        digest = mem._hash(key)
        if hasattr(mem, "_max_version") and digest in mem._max_version:
            return "detected"  # was stored, now missing → tampering
        return "missing"
    except (TamperDetectedError, ReplayDetectedError, ExpiredRecordError, UnknownKeyIdError):
        return "detected"


# =========================================================
# In-memory attacks
# =========================================================

def attack_none(mem):
    return set()


def attack_byte_corruption(mem):
    attacked = set()
    for i, (k, _) in enumerate(FACTS):
        if i % 5 == 0:
            d = mem._hash(k)
            b = bytearray(mem._store[d])
            b[-1] ^= 0xFF
            mem._store[d] = bytes(b)
            attacked.add(k)
    return attacked


def attack_metadata_tamper(mem):
    attacked = set()
    for i, (k, _) in enumerate(FACTS):
        if i % 5 == 1:
            d = mem._hash(k)
            b = bytearray(mem._store[d])
            b[4] ^= 0xFF
            mem._store[d] = bytes(b)
            attacked.add(k)
    return attacked


def attack_truncation(mem):
    attacked = set()
    for i, (k, _) in enumerate(FACTS):
        if i % 10 == 0:
            d = mem._hash(k)
            mem._store[d] = mem._store[d][:-8]
            attacked.add(k)
    return attacked


def attack_wrong_key(mem):
    mem._keys[1] = b"wrong-key-32-bytes-long-!!!!!!!!!"
    return {k for k, _ in FACTS}


def attack_replay(mem):
    attacked = set()
    for i, (k, _) in enumerate(FACTS):
        if i % 5 == 2:
            d = mem._hash(k)
            old = mem._store[d]
            mem.add(k, {"replayed": True})
            mem._store[d] = old
            attacked.add(k)
    return attacked


def attack_record_substitution(mem):
    attacked = set()
    keys = [k for k, _ in FACTS]
    for i in range(0, len(keys) - 1, 20):
        a, b = keys[i], keys[i + 1]
        da, db = mem._hash(a), mem._hash(b)
        mem._store[db] = mem._store[da]
        attacked.add(b)
    return attacked


def attack_record_removal(mem):
    """
    Attacker removes records from _store directly (bypassing delete()).
    Detection relies on _max_version tracking every key that was written.
    """
    attacked = set()
    for i, (k, _) in enumerate(FACTS):
        if i % 10 == 0:
            d = mem._hash(k)
            if d in mem._store:
                del mem._store[d]
            attacked.add(k)
    return attacked


def attack_unknown_key_id(mem):
    attacked = set()
    for i, (k, _) in enumerate(FACTS):
        if i % 10 == 5:
            d = mem._hash(k)
            b = bytearray(mem._store[d])
            struct.pack_into(">H", b, 0, 999)
            mem._store[d] = bytes(b)
            attacked.add(k)
    return attacked


ATTACKS = [
    ("none",                lambda: fresh_mem(), attack_none),
    ("byte_corruption",     lambda: fresh_mem(), attack_byte_corruption),
    ("metadata_tamper",     lambda: fresh_mem(), attack_metadata_tamper),
    ("truncation",          lambda: fresh_mem(), attack_truncation),
    ("wrong_key",           lambda: fresh_mem(), attack_wrong_key),
    ("replay",              lambda: fresh_mem(), attack_replay),
    ("record_substitution", lambda: fresh_mem(), attack_record_substitution),
    ("record_removal",      lambda: fresh_mem(), attack_record_removal),
    ("unknown_key_id",      lambda: fresh_mem(), attack_unknown_key_id),
]


def run_attack(setup_fn, attack_fn):
    mem = setup_fn()
    attacked_keys = attack_fn(mem) or set()

    tp = fn = fp = tn = 0
    for k, v in FACTS:
        outcome = classify(mem, k, v)
        is_attacked = k in attacked_keys
        if is_attacked:
            if outcome == "detected":
                tp += 1
            else:
                fn += 1
        else:
            if outcome == "detected":
                fp += 1
            else:
                tn += 1

    attacked = len(attacked_keys)
    clean = len(FACTS) - attacked
    return {
        "attacked": attacked,
        "clean": clean,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "DR":  (tp / attacked) if attacked else None,
        "SFR": (fn / attacked) if attacked else None,
        "FPR": (fp / clean)    if clean else 0.0,
        "SR":  (tp + tn) / len(FACTS),
    }


def print_freshness_section():
    print()
    print("=" * 108)
    print("FRESHNESS ENFORCEMENT (not an attack — TTL window applied)")
    print("=" * 108)
    m = ExactMemory(keys={1: SECRET}, ttl_seconds=0.001)
    for k, v in FACTS:
        m.add(k, v)
    time.sleep(0.05)
    expired = 0
    still_valid = 0
    for k, _ in FACTS:
        try:
            m.get(k, raise_on_missing=True)
            still_valid += 1
        except ExpiredRecordError:
            expired += 1
    print(f"  Records correctly expired after TTL: {expired}/{len(FACTS)}")
    print(f"  Records still valid (should be 0):   {still_valid}/{len(FACTS)}")
    return {"expired": expired, "still_valid": still_valid, "total": len(FACTS)}


def print_tombstone_section():
    print()
    print("=" * 108)
    print("TOMBSTONE DELETION (legitimate operation — tracked, not attacked)")
    print("=" * 108)
    m = ExactMemory(keys={1: SECRET})
    for k, v in FACTS:
        m.add(k, v)
    # Legitimate deletion via delete() → tombstone written
    m.delete("cat0:rec:0")
    # Attacker removes record from _store directly → no tombstone
    d = m._hash("cat1:rec:1")
    del m._store[d]

    try:
        m.get("cat0:rec:0", raise_on_missing=True)
        print("  Legitimate delete (tombstone): ❌ no exception raised")
    except KeyNotFoundError:
        print("  Legitimate delete (tombstone): ✅ KeyNotFoundError (tracked)")

    try:
        m.get("cat1:rec:1", raise_on_missing=True)
        print("  Direct removal (no tombstone): ❌ no exception raised")
    except KeyNotFoundError:
        digest = m._hash("cat1:rec:1")
        if digest in m._max_version:
            print("  Direct removal (no tombstone): ✅ detected via _max_version")
        else:
            print("  Direct removal (no tombstone): ⚠️  KeyNotFoundError but no trace")


def main():
    print()
    print("=" * 108)
    print("INTEGRITY BENCHMARK v3 — in-memory attack matrix")
    print("=" * 108)
    print(f"Facts: {len(FACTS)}  |  Attacks: {len(ATTACKS)}  |  HMAC-SHA256, 16-byte tag")
    print("-" * 108)
    print(f"{'Attack':<22} | {'Att':>4} | {'Clean':>5} | {'TP':>4} | {'FN':>4} | "
          f"{'FP':>4} | {'TN':>4} | {'DR':>5} | {'SFR':>5} | {'FPR':>5} | {'SR':>5}")
    print("-" * 108)

    results = {}
    for name, setup_fn, attack_fn in ATTACKS:
        r = run_attack(setup_fn, attack_fn)
        results[name] = r

        def fmt(x):
            return "  —  " if x is None else f"{x:.2f}"

        print(f"{name:<22} | {r['attacked']:>4} | {r['clean']:>5} | "
              f"{r['tp']:>4} | {r['fn']:>4} | {r['fp']:>4} | {r['tn']:>4} | "
              f"{fmt(r['DR']):>5} | {fmt(r['SFR']):>5} | {fmt(r['FPR']):>5} | {fmt(r['SR']):>5}")

    print("-" * 108)
    print()
    print("Legend:")
    print("  DR     = TP / Attacked        (higher better)")
    print("  SFR    = FN / Attacked        (lower better)")
    print("  FPR    = FP / Clean           (lower better)")
    print("  SR     = (TP + TN) / Total    (higher better)")

    freshness = print_freshness_section()
    print_tombstone_section()

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "benchmark_results_v3.json")
    with open(out_path, "w") as f:
        json.dump({"attacks": results, "freshness": freshness}, f, indent=2)
    print(f"\n✅ Results written to: {out_path}")


if __name__ == "__main__":
    main()
