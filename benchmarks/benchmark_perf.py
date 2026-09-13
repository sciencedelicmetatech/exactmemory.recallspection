
"""
Performance benchmark for exactmemory-recallspection.

Measures four things the audit flagged as missing:

    1. Latency percentiles (p50/p95/p99) for add() and get()
    2. Throughput (records/sec) at each scale
    3. Storage overhead per record (across payload sizes)
    4. Whole-file replay — honest demonstration of the documented gap

Scales: 100, 1,000, 10,000 records by default.
Edit SCALES below to include 100_000 if you have memory to spare.

Run:
    python benchmarks/benchmark_perf.py

Output:
    benchmarks/benchmark_perf_results.json
"""
import base64
import json
import os
import ssl
import statistics
import sys
import tempfile
import time
import urllib.request
import zipfile
import zlib

REPO_ZIP = (
    "https://github.com/sciencedelicmetatech/exactmemory.recallspection/"
    "archive/refs/heads/main.zip"
)

# ------------------------------------------------------------
# Download and import
# ------------------------------------------------------------
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

SECRET = b"perf-bench-secret-32-bytes-!!!!!!!"


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def percentile(sorted_vals, p):
    """Linear-interpolation percentile. No numpy dependency."""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * p / 100.0
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def fmt_us(x):
    return f"{x:8.2f} µs"


def fmt_bytes(x):
    if x < 1024:
        return f"{x:.0f} B"
    if x < 1024 * 1024:
        return f"{x / 1024:.1f} KB"
    return f"{x / (1024 * 1024):.2f} MB"


# ------------------------------------------------------------
# 1. Latency + throughput at multiple scales
# ------------------------------------------------------------

def run_scale(scale):
    print(f"\n{'=' * 78}")
    print(f"SCALE: {scale:,} records")
    print(f"{'=' * 78}")

    keys = [f"key_{i}" for i in range(scale)]
    values = [{"id": i, "data": "x" * 50} for i in range(scale)]

    mem = ExactMemory(keys={1: SECRET})

    # Warm up to avoid first-call JIT/import skew
    mem.add("__warmup__", "x")
    mem.get("__warmup__", raise_on_missing=True)

    # --- add() ---
    add_times = []
    t_add_start = time.perf_counter()
    for k, v in zip(keys, values):
        t0 = time.perf_counter()
        mem.add(k, v)
        t1 = time.perf_counter()
        add_times.append((t1 - t0) * 1e6)
    t_add_total = time.perf_counter() - t_add_start

    # --- get() ---
    get_times = []
    t_get_start = time.perf_counter()
    for k in keys:
        t0 = time.perf_counter()
        try:
            mem.get(k, raise_on_missing=True)
        except IntegrityError:
            pass
        t1 = time.perf_counter()
        get_times.append((t1 - t0) * 1e6)
    t_get_total = time.perf_counter() - t_get_start

    add_sorted = sorted(add_times)
    get_sorted = sorted(get_times)

    # --- storage ---
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        path = tmp.name
    mem.save(path)
    file_size = os.path.getsize(path)
    os.unlink(path)

    r = {
        "scale": scale,
        "add": {
            "total_s": t_add_total,
            "throughput_rec_s": scale / t_add_total,
            "p50_us": percentile(add_sorted, 50),
            "p95_us": percentile(add_sorted, 95),
            "p99_us": percentile(add_sorted, 99),
            "mean_us": statistics.mean(add_times),
            "min_us": min(add_times),
            "max_us": max(add_times),
        },
        "get": {
            "total_s": t_get_total,
            "throughput_rec_s": scale / t_get_total,
            "p50_us": percentile(get_sorted, 50),
            "p95_us": percentile(get_sorted, 95),
            "p99_us": percentile(get_sorted, 99),
            "mean_us": statistics.mean(get_times),
            "min_us": min(get_times),
            "max_us": max(get_times),
        },
        "storage": {
            "file_size_bytes": file_size,
            "bytes_per_record": file_size / scale,
        },
    }

    print(f"  add()   throughput: {r['add']['throughput_rec_s']:>10,.0f} rec/s   "
          f"total: {r['add']['total_s']:.3f}s")
    print(f"          p50: {fmt_us(r['add']['p50_us'])}   "
          f"p95: {fmt_us(r['add']['p95_us'])}   "
          f"p99: {fmt_us(r['add']['p99_us'])}")
    print(f"  get()   throughput: {r['get']['throughput_rec_s']:>10,.0f} rec/s   "
          f"total: {r['get']['total_s']:.3f}s")
    print(f"          p50: {fmt_us(r['get']['p50_us'])}   "
          f"p95: {fmt_us(r['get']['p95_us'])}   "
          f"p99: {fmt_us(r['get']['p99_us'])}")
    print(f"  storage  file: {fmt_bytes(file_size)}   "
          f"per record: {r['storage']['bytes_per_record']:.0f} B")

    return r


# ------------------------------------------------------------
# 2. Storage overhead across payload sizes
# ------------------------------------------------------------

def measure_storage_overhead():
    print(f"\n{'=' * 78}")
    print("STORAGE OVERHEAD BY PAYLOAD SIZE (100 records each)")
    print(f"{'=' * 78}")
    print(f"  {'Payload':<18} | {'Payload B':>10} | {'Compressed B':>13} | "
          f"{'File B':>12} | {'Per-record B':>14} | {'Fixed B':>9}")
    print(f"  {'-' * 18} | {'-' * 10} | {'-' * 13} | "
          f"{'-' * 12} | {'-' * 14} | {'-' * 9}")

    payloads = [
        ("tiny (~10 B)",    "x" * 10),
        ("small (~100 B)",  "x" * 100),
        ("medium (~1 KB)",  "x" * 1024),
        ("large (~10 KB)",  "x" * 10240),
    ]

    results = {}
    for name, payload in payloads:
        mem = ExactMemory(keys={1: SECRET})
        for i in range(100):
            mem.add(f"key_{i}", payload)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            path = tmp.name
        mem.save(path)
        file_size = os.path.getsize(path)
        os.unlink(path)

        compressed = len(zlib.compress(json.dumps(payload).encode("utf-8"), 6))
        per_record = file_size / 100
        # Fixed = per-record bytes that are NOT compressed payload
        fixed = per_record - compressed
        results[name] = {
            "payload_bytes": len(payload),
            "compressed_bytes": compressed,
            "file_bytes": file_size,
            "bytes_per_record": per_record,
            "fixed_overhead_bytes": fixed,
        }
        print(f"  {name:<18} | {len(payload):>10} | {compressed:>13} | "
              f"{file_size:>12,} | {per_record:>14.1f} | {fixed:>9.1f}")

    print()
    print("  Interpretation:")
    print("    - 'Compressed B' is the zlib-compressed payload.")
    print("    - 'Fixed B' is per-record bytes that are not payload:")
    print("        key_id (2) + version (8) + timestamp (8) + nonce (16)")
    print("        + HMAC (16) + key digest (32) + base64 expansion.")
    print("    - Repeated 'x' characters compress extremely well; real")
    print("      data will show a larger 'Compressed B' and lower 'Fixed B'.")

    return results


# ------------------------------------------------------------
# 3. Whole-file replay demonstration (honest)
# ------------------------------------------------------------

def demonstrate_whole_file_replay():
    print(f"\n{'=' * 78}")
    print("WHOLE-FILE REPLAY — honest demonstration of the documented gap")
    print(f"{'=' * 78}")

    mem = ExactMemory(keys={1: SECRET})
    mem.add("balance", 1000)

    # Snapshot 1: balance = 1000
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp1:
        path1 = tmp1.name
    mem.save(path1)

    # Change balance
    mem.add("balance", 9999)

    # Snapshot 2: balance = 9999
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp2:
        path2 = tmp2.name
    mem.save(path2)

    # Attacker replaces the newer file with the older authentic file
    with open(path1, "rb") as f:
        old_content = f.read()
    with open(path2, "wb") as f:
        f.write(old_content)
    print(f"  🔴 Attacker replaced file with authentic older snapshot")

    # Honest party loads — file is authentic, MAC verifies
    m2 = ExactMemory(keys={1: SECRET})
    m2.load(path2)

    # Honest detection status: did the system raise anything?
    system_detected = False
    try:
        loaded = m2.get("balance", raise_on_missing=True)
    except Exception as e:
        loaded = f"<error: {type(e).__name__}>"
        system_detected = True

    print(f"  Current value (before attack): 9999")
    print(f"  Loaded value (after attack):   {loaded}")
    print(f"  Exception raised by system:    {system_detected}")
    print(f"  Silent stale replay:           "
          f"{'YES (gap confirmed)' if not system_detected else 'NO'}")

    print()
    print("  Result: whole-file replay is NOT detectable by container MAC alone.")
    print("  The file is genuinely authentic. Detection requires an external")
    print("  witness — a monotonic counter stored outside the file.")
    print()
    print("  Mitigations:")
    print("    - Short TTL (records expire before replay becomes useful)")
    print("    - External counter (write count to a log server or blockchain)")
    print("    - Cross-file chain (each save() commits to the previous save hash)")

    os.unlink(path1)
    os.unlink(path2)

    return {
        "current_value": 9999,
        "loaded_value": loaded if isinstance(loaded, (int, float, str)) else str(loaded),
        "exception_raised": system_detected,
        "silent_stale_replay": not system_detected,
        "note": (
            "Whole-file replay is not detectable with container MAC alone. "
            "Requires external witness (monotonic counter)."
        ),
    }


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    # Scale range: edit this to add 100_000 if you have memory
    SCALES = [100, 1000, 10000]

    print()
    print("=" * 78)
    print("PERFORMANCE BENCHMARK — exactmemory-recallspection")
    print("=" * 78)
    print(f"Python: {sys.version.split()[0]}")
    print(f"Scales: {SCALES}")

    scale_results = []
    for scale in SCALES:
        scale_results.append(run_scale(scale))

    storage_results = measure_storage_overhead()
    replay_results = demonstrate_whole_file_replay()

    # ------------------------------------------------------------
    # Summary table
    # ------------------------------------------------------------
    print()
    print("=" * 78)
    print("SUMMARY — LATENCY AND THROUGHPUT")
    print("=" * 78)
    print(f"  {'Scale':>7} | {'add p50':>9} | {'add p99':>9} | {'add rec/s':>11} | "
          f"{'get p50':>9} | {'get p99':>9} | {'get rec/s':>11}")
    print(f"  {'-' * 7} | {'-' * 9} | {'-' * 9} | {'-' * 11} | "
          f"{'-' * 9} | {'-' * 9} | {'-' * 11}")
    for r in scale_results:
        print(f"  {r['scale']:>7,} | "
              f"{r['add']['p50_us']:>8.1f}µ | "
              f"{r['add']['p99_us']:>8.1f}µ | "
              f"{r['add']['throughput_rec_s']:>11,.0f} | "
              f"{r['get']['p50_us']:>8.1f}µ | "
              f"{r['get']['p99_us']:>8.1f}µ | "
              f"{r['get']['throughput_rec_s']:>11,.0f}")

    # ------------------------------------------------------------
    # Save JSON
    # ------------------------------------------------------------
    out_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "benchmark_perf_results.json",
    )
    payload = {
        "scales": scale_results,
        "storage_overhead": storage_results,
        "whole_file_replay": replay_results,
    }
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\n✅ Results written to: {out_path}")


if __name__ == "__main__":
    main()
=== END benchmarks/benchmark_perf.py ===
