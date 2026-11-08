import json
import hmac
import hashlib
import time
import os
from typing import Optional
from exactmemory import ExactMemory, TamperError, RollbackError, LogCompromisedError

class MemoryAnchor:
    """In-memory stub for testing."""
    def __init__(self): self.receipts = []
    def anchor(self, chain_hash: str, max_version: int, container_hash: str):
        self.receipts.append({"chain_hash": chain_hash, "max_version": max_version, "container_hash": container_hash})
    def get_latest(self):
        return self.receipts[-1] if self.receipts else None
    def verify(self, chain_hash: str): return any(r["chain_hash"] == chain_hash for r in self.receipts)

class FileAnchor:
    """Append-only file anchor for production."""
    def __init__(self, path: str): self.path = path
    def anchor(self, chain_hash: str, max_version: int, container_hash: str):
        receipt = {"chain_hash": chain_hash, "max_version": max_version, "container_hash": container_hash, "ts": int(time.time())}
        with open(self.path, "a") as f: f.write(json.dumps(receipt) + "\n")
    def get_latest(self):
        if not os.path.exists(self.path): return None
        with open(self.path, "r") as f:
            lines = [line for line in f if line.strip()]
            return json.loads(lines[-1]) if lines else None
    def verify(self, chain_hash: str):
        if not os.path.exists(self.path): return False
        with open(self.path, "r") as f:
            return any(json.loads(line).get("chain_hash") == chain_hash for line in f if line.strip())


def export_bundle(store: ExactMemory, path: str, anchor: Optional[object] = None):
    """Export a portable bundle: genesis + records + tombstones + anchor receipt."""
    state = store.export_state()
    bundle_data = {
        "version": "1.0",
        "format": "RPRS-1-Portable",
        "state": state,
        "anchor_receipt": anchor.get_latest() if anchor else None
    }
    
    raw = json.dumps(bundle_data, sort_keys=True, separators=(',', ':')).encode()
    
    # Sign the whole bundle with the container key
    mac = store.get_container_mac(raw)
    
    with open(path, "wb") as f:
        f.write(mac + raw)


def verify_bundle(path: str, keys: dict, container_key_id: str = "container", anchor: Optional[object] = None) -> dict:
    """Verify a portable bundle without loading it into a store."""
    with open(path, "rb") as f:
        blob = f.read()
    
    mac, raw = blob[:32], blob[32:]
    
    # 1. Verify Bundle MAC
    expected_mac = hmac.new(keys[container_key_id], raw, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise TamperError("Bundle MAC failed. Forged or tampered bundle.")
        
    bundle_data = json.loads(raw)
    state = bundle_data["state"]
    
    # 2. Verify Anchor Monotonicity
    if anchor and bundle_data.get("anchor_receipt"):
        receipt = bundle_data["anchor_receipt"]
        if not anchor.verify(receipt["chain_hash"]):
            raise LogCompromisedError("Anchor receipt invalid. Bundle was not anchored.")
        latest = anchor.get_latest()
        if latest and state["max_version"] < latest["max_version"]:
            raise RollbackError(f"Bundle v{state['max_version']} < Anchor v{latest['max_version']}. Stale bundle.")

    # 3. Internal Record Verification
    for k, rec, tag_hex in state["entries"]:
        # Verify tag
        rec_copy = rec.copy()
        rec_copy['_key_hash'] = hashlib.sha3_256(rec['key'].encode()).hexdigest()
        rec_copy['_key_id_hash'] = hashlib.sha3_256(rec['key_id'].encode()).hexdigest()
        canon = json.dumps(rec_copy, sort_keys=True, separators=(',', ':')).encode()
        expected_tag = hmac.new(keys[rec['key_id']], canon, hashlib.sha256).digest()[:32]
        if not hmac.compare_digest(expected_tag, bytes.fromhex(tag_hex)):
            raise TamperError(f"Record {k} tag failed.")
            
    return bundle_data


def import_bundle(store: ExactMemory, path: str, anchor: Optional[object] = None):
    """Import a verified bundle into a store."""
    bundle_data = verify_bundle(path, store.keys, store.container_key_id, anchor)
    store.import_state(bundle_data["state"])


def reanchor(store: ExactMemory, old_anchor: object, new_anchor: object):
    """Cross-anchor ceremony. Migrates the high-water mark from old to new."""
    tip = store.log.get_tip()
    if not tip:
        raise LogCompromisedError("No log tip to reanchor.")
        
    latest_old = old_anchor.get_latest()
    if not latest_old or latest_old["chain_hash"] != tip["chain_hash"]:
        raise RollbackError("Store tip does not match old anchor. Cannot reanchor.")
        
    # New anchor signs the old tip
    new_anchor.anchor(tip["chain_hash"], tip["max_version"], latest_old["container_hash"])
    return "Reanchor successful"