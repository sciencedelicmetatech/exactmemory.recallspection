import pytest
import tempfile
import os
import json
import zlib
from exactmemory_recallspection import ExactMemory


def test_add_get():
    mem = ExactMemory()
    mem.add("key1", "value1")
    mem.add("key2", 42)
    mem.add("key3", [1, 2, 3])

    assert mem.get("key1") == "value1"
    assert mem.get("key2") == 42
    assert mem.get("key3") == [1, 2, 3]
    assert mem.get("missing") is None


def test_overwrite():
    mem = ExactMemory()
    mem.add("key", "first")
    mem.add("key", "second")
    assert mem.get("key") == "second"


def test_delete():
    mem = ExactMemory()
    mem.add("key", "value")
    assert mem.delete("key") is True
    assert mem.get("key") is None
    assert mem.delete("missing") is False


def test_tamper_detection():
    mem = ExactMemory()
    mem.add("key", "important")
    digest = mem._hash("key")
    blob = mem._store[digest]
    # Flip a byte in the compressed data (not the HMAC)
    corrupted = bytes([blob[0] ^ 0xFF]) + blob[1:]
    mem._store[digest] = corrupted
    with pytest.raises(ValueError, match="Tamper-detected"):
        mem.get("key")


def test_forged_value_rejected():
    # This simulates an attacker modifying the JSON and recomputing a bare hash,
    # but they don't know the HMAC key.
    mem = ExactMemory(secret_key=b"fixed_test_key_32_bytes_long!!!")
    mem.add("balance", 100)
    digest = mem._hash("balance")
    blob = mem._store[digest]

    # Unpack the blob to get the original compressed data
    compressed = blob[:-16]
    # Replace the JSON with a different value, compress, and reattach the original HMAC
    new_value = 999999
    new_json = json.dumps(new_value).encode('utf-8')
    new_compressed = zlib.compress(new_json, level=6)
    forged_blob = new_compressed + blob[-16:]
    mem._store[digest] = forged_blob

    with pytest.raises(ValueError, match="HMAC mismatch"):
        mem.get("balance")


def test_save_load():
    mem = ExactMemory()
    mem.add("a", 1)
    mem.add("b", {"x": 2})
    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp:
        path = tmp.name
    mem.save(path)
    new_mem = ExactMemory()
    new_mem.load(path)
    assert new_mem.get("a") == 1
    assert new_mem.get("b") == {"x": 2}
    assert new_mem.get("missing") is None
    os.unlink(path)


def test_load_corrupted_file():
    mem = ExactMemory()
    mem.add("key", "value")
    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp:
        path = tmp.name
    mem.save(path)
    # Corrupt the JSON by inserting a character
    with open(path, 'r') as f:
        data = f.read()
    data = data.replace('"', 'x', 1)
    with open(path, 'w') as f:
        f.write(data)
    new_mem = ExactMemory()
    with pytest.raises(json.JSONDecodeError):
        new_mem.load(path)
    os.unlink(path)