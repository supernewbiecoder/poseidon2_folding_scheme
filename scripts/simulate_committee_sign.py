#!/usr/bin/env python3
"""
Simulate committee signing for local testing only.
Generates deterministic Ed25519 keys (seed 0,1,2), signs the attestation message,
and writes `committee` fields into the provided `input.json`.

Usage: simulate_committee_sign.py <input.json>
"""
import json
import sys
import hashlib
from pathlib import Path

try:
    from nacl.signing import SigningKey
except ImportError:
    print("ERROR: PyNaCl not installed. Run: pip install PyNaCl", file=sys.stderr)
    sys.exit(1)


def main(input_json_path):
    p = Path(input_json_path)
    if not p.exists():
        print(f"ERROR: {p} not found", file=sys.stderr)
        return 2

    data = json.loads(p.read_text(encoding="utf-8"))

    proof_artifact = data.get("proof_artifact")
    root = p.parent
    # Resolve artifact path robustly: try several candidate locations to avoid
    # duplicated path segments (e.g., "circuits-circom/circuits-circom/...").
    candidates = []
    if proof_artifact:
        candidates.append(root.joinpath(proof_artifact))
        candidates.append(Path(proof_artifact))
        candidates.append(root.parent.joinpath(proof_artifact))
        # fallback to just the filename inside the same folder
        candidates.append(root.joinpath(Path(proof_artifact).name))
    else:
        candidates.append(root.joinpath("compressed_proof.bin"))

    artifact_path = None
    for c in candidates:
        if c.exists():
            artifact_path = c
            break

    if artifact_path is None:
        # Last attempt: if proof_artifact contains a repeated folder like
        # 'circuits-circom/circuits-circom/...' try to strip the first segment
        if proof_artifact:
            parts = Path(proof_artifact).parts
            if len(parts) > 1:
                stripped = Path(*parts[1:])
                alt = root.joinpath(stripped)
                if alt.exists():
                    artifact_path = alt

    if artifact_path is None:
        print(f"ERROR: proof artifact not found. Tried: {candidates}", file=sys.stderr)
        return 2

    # compute hash same as Rust: sha256, take first 31 bytes
    h = hashlib.sha256()
    with artifact_path.open("rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    digest = h.digest()
    hash_hex = "0x" + digest[:31].hex()

    spartan_hash = data.get("spartan_proof_hash")
    if spartan_hash and spartan_hash.lower() != hash_hex.lower():
        print("WARN: spartan_proof_hash in input.json does not match artifact; updating to computed value")
        data["spartan_proof_hash"] = hash_hex

    safe_z0 = data.get("expected_z0", "")
    safe_zi = data.get("expected_zi", "")
    att = data.get("attestation", {})
    epoch = att.get("epoch", 1)
    domain_sep = att.get("domain_sep", "ENGRAM_SPARTAN_PROOF")

    # Build message bytes exactly as verifier expects
    msg = domain_sep.encode() + str(safe_z0).encode() + str(safe_zi).encode() + str(data.get("spartan_proof_hash")).encode() + int(epoch).to_bytes(4, 'little')

    committee_size = 3
    pubkeys = []
    signatures = []

    for i in range(committee_size):
        seed = bytes([i]) + bytes(31)
        sk = SigningKey(seed)
        signed = sk.sign(msg)
        sig = signed.signature
        pk = sk.verify_key
        pubkeys.append(pk.encode().hex())
        signatures.append(sig.hex())

    # compute pubkeys_hash like Rust (concat hex strings, sha256, take 31 bytes)
    concat = "".join(pubkeys).encode()
    ph = hashlib.sha256(concat).digest()
    pubkeys_hash = "0x" + ph[:31].hex()

    data["committee"] = {
        "size": committee_size,
        "pubkeys": pubkeys,
        "pubkeys_hash": pubkeys_hash,
        "signatures": signatures,
    }

    p.write_text(json.dumps(data), encoding="utf-8")
    print(f"✅ Wrote simulated committee signatures into {p}")
    print(f"   pubkeys_hash={pubkeys_hash[:20]}...")
    return 0


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: simulate_committee_sign.py <input.json>", file=sys.stderr)
        sys.exit(1)
    sys.exit(main(sys.argv[1]))
