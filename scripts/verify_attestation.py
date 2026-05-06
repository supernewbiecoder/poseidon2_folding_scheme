#!/usr/bin/env python3
"""
Verify Committee Multi-Sig attestation before Groth16 wrapping.
Committee nodes each sign the (z0, zi, spartan_proof_hash).
On-chain verifier only checks Groth16 proof (attestation validation done off-chain).

Usage: verify_attestation.py <input.json>
"""

import json
import sys
import hashlib
from pathlib import Path

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
except ImportError:
    print("ERROR: PyNaCl not installed. Run: pip install PyNaCl", file=sys.stderr)
    sys.exit(1)


def verify_committee_attestation(input_json_path):
    """
    Verify all m committee signatures in input.json.
    Returns True if all m signatures valid, False otherwise.
    """
    input_json_path = Path(input_json_path)
    if not input_json_path.exists():
        print(f"ERROR: {input_json_path} not found", file=sys.stderr)
        return False

    try:
        with open(input_json_path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse JSON: {e}", file=sys.stderr)
        return False

    committee = data.get("committee")
    if not committee:
        print("ERROR: No 'committee' field in input.json", file=sys.stderr)
        return False

    try:
        committee_size = committee["size"]
        committee_pubkeys = committee["pubkeys"]
        pubkeys_hash = committee["pubkeys_hash"]
        committee_signatures = committee["signatures"]
    except KeyError as e:
        print(f"ERROR: Missing committee field: {e}", file=sys.stderr)
        return False

    if len(committee_pubkeys) != committee_size:
        print(f"ERROR: Mismatch: committee_size={committee_size}, but got {len(committee_pubkeys)} pubkeys", file=sys.stderr)
        return False

    if len(committee_signatures) != committee_size:
        print(f"ERROR: Mismatch: committee_size={committee_size}, but got {len(committee_signatures)} signatures", file=sys.stderr)
        return False

    if committee_size == 0:
        print("ERROR: committee size is zero or committee not configured in input.json", file=sys.stderr)
        return False

    # Verify pubkeys_hash (to prevent key substitution attacks) if provided
    pubkeys_concat = "".join(committee_pubkeys)
    computed_pubkeys_hash = hashlib.sha256(pubkeys_concat.encode()).hexdigest()
    computed_pubkeys_hash_hex = f"0x{computed_pubkeys_hash[:62]}"  # Take 31 bytes = 62 hex chars

    if pubkeys_hash:
        if computed_pubkeys_hash_hex.lower() != str(pubkeys_hash).lower():
            print(f"ERROR: Pubkeys hash mismatch!", file=sys.stderr)
            print(f"  Expected: {pubkeys_hash}", file=sys.stderr)
            print(f"  Got:      {computed_pubkeys_hash_hex}", file=sys.stderr)
            return False
        print(f"✅ Pubkeys hash verified: {str(pubkeys_hash)[:20]}...")
    else:
        print("WARN: No 'pubkeys_hash' provided in input.json; skipping pubkeys-hash check", file=sys.stderr)

    # Get attestation fields
    attestation = data.get("attestation", {})
    epoch = attestation.get("epoch", 1)
    domain_sep = attestation.get("domain_sep", "ENGRAM_SPARTAN_PROOF")

    # Get proof fields
    z0 = data.get("expected_z0", "")
    zi = data.get("expected_zi", "")
    proof_hash = data.get("spartan_proof_hash", "")
    proof_artifact_field = data.get("proof_artifact")

    # If a proof artifact path is provided, verify its SHA-256 matches
    if proof_artifact_field:
        # Try multiple candidate locations to resolve artifact path robustly
        candidates = [
            input_json_path.parent.joinpath(proof_artifact_field),
            Path(proof_artifact_field),
            input_json_path.parent.parent.joinpath(proof_artifact_field),
            input_json_path.parent.joinpath(Path(proof_artifact_field).name),
        ]
        artifact_path = None
        for c in candidates:
            if c.exists():
                artifact_path = c
                break

        if artifact_path is None:
            # Try stripping leading path segment if present
            parts = Path(proof_artifact_field).parts
            if len(parts) > 1:
                stripped = Path(*parts[1:])
                alt = input_json_path.parent.joinpath(stripped)
                if alt.exists():
                    artifact_path = alt

        if artifact_path is None:
            print(f"ERROR: proof_artifact not found: {input_json_path.parent.joinpath(proof_artifact_field)}", file=sys.stderr)
            return False

        # Compute SHA256 of artifact and reduce to 31 bytes hex (same as Rust)
        h = hashlib.sha256()
        with open(artifact_path, 'rb') as af:
            while True:
                chunk = af.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        digest = h.digest()
        computed = '0x' + digest[:31].hex()
        if computed.lower() != (proof_hash or '').lower():
            print("ERROR: proof artifact hash mismatch!", file=sys.stderr)
            print(f"  Expected: {proof_hash}", file=sys.stderr)
            print(f"  Got:      {computed}", file=sys.stderr)
            return False
        print(f"✅ proof_artifact hash verified: {computed[:20]}...")
    else:
        print("WARN: No 'proof_artifact' field in input.json — cannot validate raw proof file hash", file=sys.stderr)

    # Reconstruct message (MUST MATCH Rust: domain_sep || z0 || zi || proof_hash || epoch)
    domain_sep_bytes = domain_sep.encode()
    z0_bytes = z0.encode() if isinstance(z0, str) else str(z0).encode()
    zi_bytes = zi.encode() if isinstance(zi, str) else str(zi).encode()
    hash_bytes = proof_hash.encode() if isinstance(proof_hash, str) else str(proof_hash).encode()
    epoch_bytes = epoch.to_bytes(4, 'little') if isinstance(epoch, int) else int(epoch).to_bytes(4, 'little')

    msg = domain_sep_bytes + z0_bytes + zi_bytes + hash_bytes + epoch_bytes

    # Verify all m signatures (m-of-m check)
    valid_count = 0
    for i, (pubkey_hex, signature_hex) in enumerate(zip(committee_pubkeys, committee_signatures)):
        try:
            pubkey_bytes = bytes.fromhex(pubkey_hex)
            sig_bytes = bytes.fromhex(signature_hex)
            verify_key = VerifyKey(pubkey_bytes)
            verify_key.verify(msg, sig_bytes)
            print(f"  ✅ Committee[{i}] signature valid: {pubkey_hex[:16]}...")
            valid_count += 1
        except BadSignatureError:
            print(f"  ❌ Committee[{i}] signature FAILED: {pubkey_hex[:16]}...", file=sys.stderr)
            return False
        except Exception as e:
            print(f"  ❌ Committee[{i}] verification error: {e}", file=sys.stderr)
            return False

    if valid_count == committee_size:
        print(f"✅ All {committee_size} committee signatures VALID (m-of-m check passed)")
        print(f"✅ Attestation verified. Ready for Groth16 proving.")
        print(f"   z0={z0[:20]}...")
        print(f"   zi={zi[:20]}...")
        print(f"   proof_hash={proof_hash[:20]}...")
        return True
    else:
        print(f"ERROR: Only {valid_count}/{committee_size} signatures valid", file=sys.stderr)
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: verify_attestation.py <input.json>", file=sys.stderr)
        sys.exit(1)

    input_path = sys.argv[1]
    if verify_committee_attestation(input_path):
        sys.exit(0)
    else:
        sys.exit(1)

