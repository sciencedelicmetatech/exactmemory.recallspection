#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_cp1_spec.py — Executable spec for Coverage Patch 1.

Pure stdlib. Runs on Pythonista/Pyto.

    python test_cp1_spec.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sys
import time
import zlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# =========================================================================
# Reference patched control
# =========================================================================

TRUSTED_SOURCES = frozenset({"system", "admin", "user_confirmed"})


@dataclass
class _Rec:
    payload: bytes = b""
    version: int = 0
    tag: bytes = b""
    source: str = "unknown"
    trusted: bool = False
    revoked: bool = False
    shadow: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class _LogEntry:
    op: str
    key: str
    version: int
    prev_hash: bytes
    ts: float
    tag: bytes


class PatchedExactMemoryControl:
    """Reference implementation of ExactMemory with CP1 applied."""

    def __init__(self, master: Optional[bytes] = None,
                 container: Optional[bytes] = None):
        self._master = master or secrets.token_bytes(32)
        self._container = container or secrets.token_bytes(32)
        self._store: Dict[str, _Rec] = {}
        self._per_key_max: Dict[str, int] = {}
        self._cmac: Optional[bytes] = None
        self._log_entries: List[_LogEntry] = []

    # -- tagging --------------------------------------------------------

    def _tag(self, key, version, payload, source, trusted, revoked, shadow):
        shadow_bytes = json.dumps(shadow, sort_keys=True,
                                  separators=(",", ":")).encode()
        msg = (
            key.encode() + b"\x00"
            + version.to_bytes(8, "big") + b"\x00"
            + payload + b"\x00"
            + source.encode() + b"\x00"
            + bytes([1 if trusted else 0, 1 if revoked else 0]) + b"\x00"
            + shadow_bytes
        )
        return hmac.new(self._master, msg, hashlib.sha256).digest()

    def _cmac_calc(self):
        h = hashlib.sha256()
        for k in sorted(self._store):
            r = self._store[k]
            shadow_bytes = json.dumps(r.shadow, sort_keys=True,
                                      separators=(",", ":")).encode()
            h.update(k.encode() + b"\x00")
            h.update(r.version.to_bytes(8, "big"))
            h.update(r.tag)
            h.update(r.source.encode())
            h.update(bytes([1 if r.trusted else 0, 1 if r.revoked else 0]))
            h.update(shadow_bytes)
        return hmac.new(self._container, h.digest(), hashlib.sha256).digest()

    def _append_log(self, op: str, key: str, version: int):
        prev = self._log_entries[-1].tag if self._log_entries else b"\x00" * 32
        ts = time.time()
        msg = (op.encode() + b"\x00" + key.encode() + b"\x00"
               + version.to_bytes(8, "big") + b"\x00" + prev
               + b"\x00" + repr(ts).encode())
        tag = hmac.new(self._master, msg, hashlib.sha256).digest()
        self._log_entries.append(_LogEntry(op, key, version, prev, ts, tag))

    # -- public API -----------------------------------------------------

    def put(self, key, value, key_id="agent_key", source="unknown") -> str:
        incoming_trusted = source in TRUSTED_SOURCES
        existing = self._store.get(key)

        # CP1 write policy: untrusted cannot overwrite trusted.
        if existing is not None and existing.trusted and not incoming_trusted:
            existing.shadow.append({
                "value": value,
                "source": source,
                "ts": time.time(),
            })
            # Re-tag because shadow changed. Version does NOT change.
            existing.tag = self._tag(
                key, existing.version, existing.payload,
                existing.source, existing.trusted, existing.revoked,
                existing.shadow)
            self._cmac = self._cmac_calc()
            return "rejected"

        payload = zlib.compress(json.dumps(value).encode())
        v = self._per_key_max.get(key, 0) + 1
        rec = _Rec(payload=payload, version=v, source=source,
                   trusted=incoming_trusted, revoked=False,
                   shadow=existing.shadow if existing else [])
        rec.tag = self._tag(key, v, payload, source,
                            incoming_trusted, False, rec.shadow)
        self._store[key] = rec
        self._per_key_max[key] = v
        self._cmac = self._cmac_calc()
        self._append_log("put", key, v)
        return "ok"

    def revoke(self, key, key_id="agent_key", reason=None) -> str:
        if key not in self._store:
            return "missing"
        rec = self._store[key]
        if rec.revoked:
            return "ok"
        rec.revoked = True
        rec.tag = self._tag(key, rec.version, rec.payload,
                            rec.source, rec.trusted, True, rec.shadow)
        self._cmac = self._cmac_calc()
        self._append_log("revoke", key, rec.version)
        return "ok"

    def get_with_status(self, key, key_id="agent_key"):
        if key not in self._store:
            if key in self._per_key_max:
                return None, "tampered"
            return None, "missing"
        rec = self._store[key]

        # Version regression check (replay detection)
        if rec.version < self._per_key_max.get(key, 0):
            return None, "tampered"

        expected = self._tag(key, rec.version, rec.payload,
                             rec.source, rec.trusted, rec.revoked, rec.shadow)
        if not hmac.compare_digest(expected, rec.tag):
            return None, "tampered"
        if self._cmac is not None:
            if not hmac.compare_digest(self._cmac, self._cmac_calc()):
                return None, "tampered"
        if rec.revoked:
            return None, "revoked"
        try:
            value = json.loads(zlib.decompress(rec.payload))
        except Exception:
            return None, "tampered"
        return value, "ok"

    def get_shadow(self, key) -> List[Dict[str, Any]]:
        if key not in self._store:
            return []
        return list(self._store[key].shadow)

    def find(self, predicate):
        out = []
        for k in list(self._store.keys()):
            v, s = self.get_with_status(k)
            if v is None:
                continue
            try:
                if predicate(v):
                    out.append((k, v, s))
            except Exception:
                pass
        return out

    # -- introspection for tests ---------------------------------------

    def raw_store(self):
        return self._store

    def log_entries(self):
        return self._log_entries

    def container_mac(self):
        return self._cmac


# =========================================================================
# Test framework
# =========================================================================

class TestFail(Exception):
    pass


_results: List[Tuple[str, bool, str]] = []
_section_cursor: int = 0


def check(name: str, fn):
    try:
        fn()
        _results.append((name, True, ""))
    except Exception as e:
        _results.append((name, False, f"{type(e).__name__}: {e}"))


def assert_eq(a, b, msg=""):
    if a != b:
        raise TestFail(f"expected {b!r}, got {a!r} {msg}")


def assert_true(x, msg=""):
    if not x:
        raise TestFail(f"expected truthy {msg}")


def _flush_since_cursor():
    global _section_cursor
    new = _results[_section_cursor:]
    _section_cursor = len(_results)
    for name, ok, msg in new:
        mark = "✓" if ok else "✗"
        print(f"  {mark} {name}")
        if not ok:
            print(f"      {msg}")


# =========================================================================
# Day 1 — Write-time policy
# =========================================================================

def day1():
    m = PatchedExactMemoryControl(master=b"k" * 32, container=b"c" * 32)

    def t1():
        m.put("k1", {"v": 1}, source="system")
        v, s = m.get_with_status("k1")
        assert_eq(v, {"v": 1})
        assert_eq(s, "ok")

    def t2():
        status = m.put("k1", {"v": 2}, source="email")
        assert_eq(status, "rejected")

    def t3():
        v, s = m.get_with_status("k1")
        assert_eq(v, {"v": 1})
        assert_eq(s, "ok")

    def t4():
        shadow = m.get_shadow("k1")
        assert_eq(len(shadow), 1)
        assert_eq(shadow[0]["value"], {"v": 2})
        assert_eq(shadow[0]["source"], "email")

    def t5():
        m.put("k2", {"v": 10}, source="email")
        v, s = m.get_with_status("k2")
        assert_eq(v, {"v": 10})
        assert_eq(s, "ok")

    def t6():
        # Container MAC covers shadow: mutate shadow, MAC must fail.
        m.raw_store()["k1"].shadow.append(
            {"value": {"v": 999}, "source": "tampered", "ts": 0})
        v, s = m.get_with_status("k1")
        assert_eq(s, "tampered")

    def t7():
        m2 = PatchedExactMemoryControl(master=b"k" * 32, container=b"c" * 32)
        m2.put("k", {"v": 1}, source="system")
        v1 = m2.raw_store()["k"].version
        m2.put("k", {"v": 2}, source="email")
        v2 = m2.raw_store()["k"].version
        assert_eq(v1, v2, "(rejected write must not bump version)")

    check("Day1.1 trusted write succeeds", t1)
    check("Day1.2 untrusted overwrite rejected", t2)
    check("Day1.3 original value survives", t3)
    check("Day1.4 shadow contains rejected value", t4)
    check("Day1.5 untrusted first write succeeds", t5)
    check("Day1.6 container MAC covers shadow", t6)
    check("Day1.7 version not bumped on reject", t7)


# =========================================================================
# Day 2 — Revocation
# =========================================================================

def day2():
    m = PatchedExactMemoryControl(master=b"k" * 32, container=b"c" * 32)

    def t1():
        m.put("r1", {"v": 1}, source="system")
        assert_eq(m.revoke("r1"), "ok")

    def t2():
        assert_eq(m.revoke("does_not_exist"), "missing")

    def t3():
        v, s = m.get_with_status("r1")
        assert_eq(v, None)
        assert_eq(s, "revoked")

    def t4():
        m.put("r2", {"revoked": True, "v": 42}, source="system")
        v, s = m.get_with_status("r2")
        assert_eq(s, "ok", "(payload flag must not trigger store status)")
        assert_eq(v["revoked"], True)

    def t5():
        m.put("r3", {"v": 1}, source="system")
        n_before = len(m.log_entries())
        m.revoke("r3")
        n_after = len(m.log_entries())
        assert_eq(n_after, n_before + 1)
        last = m.log_entries()[-1]
        assert_eq(last.op, "revoke")
        assert_eq(last.key, "r3")

    def t6():
        log = m.log_entries()
        prev = b"\x00" * 32
        for entry in log:
            assert_eq(entry.prev_hash, prev)
            prev = entry.tag

    def t7():
        m2 = PatchedExactMemoryControl(master=b"k" * 32, container=b"c" * 32)
        m2.put("a", {"claim": "old"}, source="system")
        m2.put("b", {"claim": "new"}, source="system")
        m2.revoke("a")
        results = m2.find(lambda v: "claim" in v)
        keys = [r[0] for r in results]
        assert_true("a" not in keys, "(revoked record must be skipped by find)")
        assert_true("b" in keys)

    check("Day2.1 revoke present returns ok", t1)
    check("Day2.2 revoke absent returns missing", t2)
    check("Day2.3 revoked returns (None, revoked)", t3)
    check("Day2.4 payload flag does not trigger revoked", t4)
    check("Day2.5 revoke appended to log", t5)
    check("Day2.6 log hash chain intact", t6)
    check("Day2.7 find skips revoked", t7)


# =========================================================================
# Regression gate — A1-A5
# =========================================================================

def regression():

    def a1():
        m = PatchedExactMemoryControl(master=b"k" * 32, container=b"c" * 32)
        m.put("t1", {"v": 1}, source="system")
        rec = m.raw_store()["t1"]
        rec.payload = zlib.compress(json.dumps({"v": 999}).encode())
        v, s = m.get_with_status("t1")
        assert_eq(s, "tampered")

    def a2():
        m = PatchedExactMemoryControl(master=b"k" * 32, container=b"c" * 32)
        m.put("t2", {"v": 1}, source="system")
        old_rec = m.raw_store()["t2"]
        m.put("t2", {"v": 2}, source="system")
        # Rollback to old record. per_key_max stays at 2.
        m.raw_store()["t2"] = old_rec
        m._cmac = m._cmac_calc()
        v, s = m.get_with_status("t2")
        assert_eq(s, "tampered", "(version regression must be detected)")

    def a3():
        m = PatchedExactMemoryControl(master=b"k" * 32, container=b"c" * 32)
        m.put("t3", {"v": 1}, source="system")
        del m.raw_store()["t3"]
        m._cmac = m._cmac_calc()
        v, s = m.get_with_status("t3")
        assert_eq(s, "tampered")

    def a4():
        m = PatchedExactMemoryControl(master=b"k" * 32, container=b"c" * 32)
        m.put("t4", {"v": 1}, source="system")
        m2 = PatchedExactMemoryControl(master=b"X" * 32, container=b"c" * 32)
        m2._store = m._store
        m2._per_key_max = m._per_key_max
        m2._cmac = m._cmac
        v, s = m2.get_with_status("t4")
        assert_eq(s, "tampered")

    def a5():
        m = PatchedExactMemoryControl(master=b"k" * 32, container=b"c" * 32)
        m.put("t5a", {"v": 1}, source="system")
        m.put("t5b", {"v": 2}, source="system")
        fake = _Rec(payload=zlib.compress(b'{"v":99}'),
                    version=1, source="system", trusted=True,
                    tag=b"\x00" * 32)
        m.raw_store()["rogue"] = fake
        m._cmac = m._cmac_calc()
        v, s = m.get_with_status("rogue")
        assert_eq(s, "tampered")

    check("Reg.A1 direct tamper detected", a1)
    check("Reg.A2 replay detected (version regression)", a2)
    check("Reg.A3 deletion detected", a3)
    check("Reg.A4 wrong key detected", a4)
    check("Reg.A5 container MAC tamper detected", a5)


# =========================================================================
# Main
# =========================================================================

def main():
    print("=" * 60)
    print("Coverage Patch 1 — Executable Spec")
    print("=" * 60)
    print()
    print("Day 1 — Write-time policy")
    print("-" * 60)
    day1()
    _flush_since_cursor()
    print()
    print("Day 2 — Revocation")
    print("-" * 60)
    day2()
    _flush_since_cursor()
    print()
    print("Regression gate — A1-A5 integrity")
    print("-" * 60)
    regression()
    _flush_since_cursor()
    print()

    failed = [r for r in _results if not r[1]]
    total = len(_results)
    passed = total - len(failed)
    print("=" * 60)
    print(f"TOTAL: {passed}/{total} passed")
    if failed:
        print()
        print("FAILURES:")
        for name, _, msg in failed:
            print(f"  ✗ {name}")
            print(f"      {msg}")
        print()
        print("SPEC NOT SATISFIED")
        return 1
    print("SPEC SATISFIED — CP1 is implementable as specified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())