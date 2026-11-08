import pytest
import os
from exactmemory import ExactMemory, TamperError, RollbackError, LogCompromisedError
from portable import export_bundle, import_bundle, verify_bundle, reanchor, MemoryAnchor

KEYS = {'k1': b'secret-key-32-bytes-long-12345678', 'container': b'container-key-32-bytes-long-123456'}

def make_store():
    return ExactMemory(keys=KEYS, container_key_id='container', log_path="./test.log", require_log=True)

def cleanup():
    for f in ["./test.log", "bundle.portable", "bundle_old.portable"]:
        if os.path.exists(f): os.remove(f)

def test_export_import_roundtrip():
    cleanup()
    store = make_store()
    store.put("k1", "v1", key_id="k1")
    store.save("./test.log")
    export_bundle(store, "bundle.portable")
    
    store2 = make_store()
    import_bundle(store2, "bundle.portable")
    assert store2.get("k1") == "v1"
    cleanup()

def test_tamper_bundle_mac():
    cleanup()
    store = make_store()
    store.put("k1", "v1", key_id="k1")
    store.save("./test.log")
    export_bundle(store, "bundle.portable")
    
    # Tamper the bundle
    with open("bundle.portable", "rb") as f: blob = f.read()
    with open("bundle.portable", "wb") as f: f.write(blob[:40] + b"X" + blob[41:])
    
    with pytest.raises(TamperError):
        verify_bundle("bundle.portable", KEYS)
    cleanup()

def test_rollback_bundle():
    cleanup()
    store = make_store()
    store.put("k1", "v1", key_id="k1")
    store.save("./test.log")
    export_bundle(store, "bundle_old.portable")
    
    store.put("k1", "v2", key_id="k1")
    store.save("./test.log")
    
    # Importer has a newer version, old bundle should fail
    with pytest.raises(RollbackError):
        import_bundle(store, "bundle_old.portable")
    cleanup()

def test_t10_erasure_resurrection():
    cleanup()
    store = make_store()
    store.put("user", "secret", key_id="k1")
    store.save("./test.log")
    export_bundle(store, "bundle_old.portable")
    
    # Erase user (T10 setup)
    store.delete("user")
    store.save("./test.log")
    
    # Attacker tries to resurrect the old bundle
    with pytest.raises((RollbackError, TamperError)):
        import_bundle(store, "bundle_old.portable")
    cleanup()

def test_reanchor():
    cleanup()
    anchor1 = MemoryAnchor()
    anchor2 = MemoryAnchor()
    store = make_store()
    store.put("k1", "v1", key_id="k1")
    store.save("./test.log")
    anchor1.anchor(store.log.get_tip()["chain_hash"], 1, "hash")
    
    reanchor(store, anchor1, anchor2)
    assert anchor2.get_latest()["max_version"] == 1
    cleanup()

def test_fork_forged_witness():
    cleanup()
    store = make_store()
    store.put("k1", "v1", key_id="k1")
    store.save("./test.log")
    export_bundle(store, "bundle.portable")
    
    # Forge the witness receipt inside the bundle
    with open("bundle.portable", "rb") as f: blob = f.read()
    mac, raw = blob[:32], blob[32:]
    data = json.loads(raw)
    data["anchor_receipt"] = {"chain_hash": "fake_hash", "max_version": 99}
    forged_raw = json.dumps(data).encode()
    
    # Re-sign with attacker key (fails because they don't have container key)
    with open("bundle.portable", "wb") as f:
        f.write(hmac.new(b"wrong_key", forged_raw, hashlib.sha256).digest() + forged_raw)
        
    with pytest.raises(TamperError):
        verify_bundle("bundle.portable", KEYS)
    cleanup()