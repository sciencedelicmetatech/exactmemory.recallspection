"""Automated test suite for exactmemory-recallspection."""
import struct
import time

import pytest
from hypothesis import given, settings, strategies as st

from exactmemory_recallspection import (
    ExactMemory,
    TamperDetectedError,
    ReplayDetectedError,
    ExpiredRecordError,
    UnknownKeyIdError,
    KeyNotFoundError,
)

KEY = b"a" * 32
KEY2 = b"b" * 32


# ---------- Basic ----------

def test_roundtrip_scalars():
    m = ExactMemory(keys={1: KEY})
    m.add("int", 42)
    m.add("str", "hello")
    m.add("list", [1, 2, 3])
    m.add("dict", {"k": "v"})
    assert m.get("int") == 42
    assert m.get("str") == "hello"
    assert m.get("list") == [1, 2, 3]
    assert m.get("dict") == {"k": "v"}


def test_unknown_key_returns_none():
    m = ExactMemory(keys={1: KEY})
    assert m.get("missing") is None


def test_unknown_key_raises_when_asked():
    m = ExactMemory(keys={1: KEY})
    with pytest.raises(KeyNotFoundError):
        m.get("missing", raise_on_missing=True)


def test_overwrite():
    m = ExactMemory(keys={1: KEY})
    m.add("k", "first")
    m.add("k", "second")
    assert m.get("k") == "second"


def test_delete():
    m = ExactMemory(keys={1: KEY})
    m.add("k", "v")
    assert m.delete("k") is True
    assert m.get("k") is None
    assert m.delete("k") is False


# ---------- Integrity ----------

def test_byte_flip_in_mac():
    m = ExactMemory(keys={1: KEY})
    m.add("k", "v")
    d = m._hash("k")
    b = bytearray(m._store[d])
    b[-1] ^= 0xFF
    m._store[d] = bytes(b)
    with pytest.raises(TamperDetectedError):
        m.get("k")


def test_byte_flip_in_version():
    m = ExactMemory(keys={1: KEY})
    m.add("k", "v")
    d = m._hash("k")
    b = bytearray(m._store[d])
    b[4] ^= 0xFF
    m._store[d] = bytes(b)
    with pytest.raises(TamperDetectedError):
        m.get("k")


def test_byte_flip_in_payload():
    m = ExactMemory(keys={1: KEY})
    m.add("k", "v")
    d = m._hash("k")
    b = bytearray(m._store[d])
    b[HEADER_OFFSET_FOR_TEST := 18 + 16] ^= 0xFF
    m._store[d] = bytes(b)
    with pytest.raises((TamperDetectedError,)):
        m.get("k")


def test_truncation():
    m = ExactMemory(keys={1: KEY})
    m.add("k", "v")
    d = m._hash("k")
    m._store[d] = m._store[d][:-8]
    with pytest.raises(TamperDetectedError):
        m.get("k")


def test_record_substitution():
    m = ExactMemory(keys={1: KEY})
    m.add("a", "va")
    m.add("b", "vb")
    da, db = m._hash("a"), m._hash("b")
    m._store[db] = m._store[da]
    with pytest.raises(TamperDetectedError):
        m.get("b")


# ---------- Replay ----------

def test_replay_detected_in_session():
    m = ExactMemory(keys={1: KEY})
    m.add("k", "old")
    d = m._hash("k")
    old_blob = m._store[d]
    m.add("k", "new")
    m._store[d] = old_blob
    with pytest.raises(ReplayDetectedError):
        m.get("k")


# ---------- Key management ----------

def test_unknown_key_id():
    m = ExactMemory(keys={1: KEY})
    m.add("k", "v")
    d = m._hash("k")
    b = bytearray(m._store[d])
    struct.pack_into(">H", b, 0, 99)
    m._store[d] = bytes(b)
    with pytest.raises(UnknownKeyIdError):
        m.get("k")


def test_key_rotation_preserves_old_records():
    m = ExactMemory(keys={1: KEY})
    m.add("a", "before")
    new_id = m.rotate_key(KEY2)
    assert new_id == 2
    m.add("b", "after")
    assert m.get("a") == "before"
    assert m.get("b") == "after"
    assert m.current_key_id == 2
    assert m.key_ids == [1, 2]


# ---------- Freshness ----------

def test_expired_ttl():
    m = ExactMemory(keys={1: KEY}, ttl_seconds=0.01)
    m.add("k", "v")
    time.sleep(0.05)
    with pytest.raises(ExpiredRecordError):
        m.get("k")


def test_future_timestamp_rejected():
    m = ExactMemory(keys={1: KEY}, clock_skew_seconds=1.0)
    m.add("k", "v")
    d = m._hash("k")
    b = bytearray(m._store[d])
    # bump timestamp by 3600s
    new_ts = time.time() + 3600
    struct.pack_into(">d", b, 10, new_ts)
    # fix HMAC
    body = bytes(b[:-16])
    mac = m._hmac(1, m._hash("k") + body)[:16]
    m._store[d] = body + mac
    with pytest.raises(ExpiredRecordError):
        m.get("k")


# ---------- Persistence ----------

def test_save_load_roundtrip(tmp_path):
    m = ExactMemory(keys={1: KEY})
    m.add("a", 1)
    m.add("b", [2, 3])
    p = str(tmp_path / "state.json")
    m.save(p)

    m2 = ExactMemory(keys={1: KEY})
    m2.load(p)
    assert m2.get("a") == 1
    assert m2.get("b") == [2, 3]
    assert m2.current_key_id == m.current_key_id


# ---------- Fuzz ----------

@given(st.text(min_size=1, max_size=200), st.text(max_size=2000))
@settings(max_examples=100)
def test_fuzz_roundtrip(k, v):
    m = ExactMemory(keys={1: KEY})
    m.add(k, v)
    assert m.get(k) == v


@given(st.text(min_size=1), st.integers(min_value=0))
@settings(max_examples=100)
def test_fuzz_any_bit_flip_detected(k, seed):
    m = ExactMemory(keys={1: KEY})
    m.add(k, "value")
    d = m._hash(k)
    b = bytearray(m._store[d])
    idx = seed % len(b)
    b[idx] ^= 0x01
    m._store[d] = bytes(b)
    with pytest.raises(Exception):
        m.get(k)
