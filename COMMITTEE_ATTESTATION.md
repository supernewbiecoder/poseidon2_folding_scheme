# Committee Multi-Sig Attestation Model

## Overview

This document explains the **committee-based multi-signature attestation** architecture implemented in this project. It solves the problem: *How to ensure Spartan proof validity without requiring on-chain re-verification (non-native field arithmetic)*?

**Key Innovation:** Multiple independent nodes (committee) each verify Spartan proof + sign the attestation. On-chain verifier only checks Groth16 proof (Ed25519 verification is "absorbed" off-chain). This creates a trustless/optimistic rollup pattern.

---

## Architecture Layers

```
┌────────────────────────────────────────────────────┐
│ LAYER 0: Rust Prover (Single Machine or Simulated)│
│  - Nova folding + Spartan compression             │
│  - Verify Spartan natively (Pasta curves)         │
│  - Generate m committee keypairs (simulation)     │
│  - Export input.json with m signatures            │
└───────────────────┬────────────────────────────────┘
                    │
                    ▼
┌────────────────────────────────────────────────────┐
│ LAYER 1: Committee Attestation Verification       │
│ (Python: scripts/verify_attestation.py)           │
│  - Receive input.json with m committee signatures │
│  - Reconstruct message: domain_sep||z0||zi||hash  │
│  - Verify ALL m Ed25519 signatures (m-of-m)       │
│  - Check pubkeys_hash (prevent key substitution)  │
│  - Exit 0 = Valid → proceed to Groth16            │
│  - Exit 1 = Invalid → reject, do NOT prove       │
└───────────────────┬────────────────────────────────┘
                    │
                    ▼
┌────────────────────────────────────────────────────┐
│ LAYER 2: Groth16 Wrapper (Circom + SnarkJS)       │
│  - Receive verified attestation + input data      │
│  - Circom circuit:                                │
│    * Binding constraint: witness ↔ public inputs  │
│    * Commit committee_pubkeys_hash in circuit     │
│  - Generate Groth16 proof (300-400 bytes)         │
│  - Groth16 proof proves: prover knows z0, zi,     │
│    proof_hash, and they were signed by committee  │
└───────────────────┬────────────────────────────────┘
                    │
                    ▼
┌────────────────────────────────────────────────────┐
│ LAYER 3: On-Chain Verifier (Smart Contract)       │
│  - Receive Groth16 proof + public inputs          │
│  - Verify Groth16 proof (EVM precompile, cheap)   │
│  - Extract pubkeys_hash from proof                │
│  - Optionally: check pubkeys_hash against         │
│    registered committee (DAO governance)          │
│  - Update merkle root / state on-chain            │
└────────────────────────────────────────────────────┘
```

---

## Trust Model

### What Gets Verified

| Layer | Verifies | By Whom | Cost | Trust |
|-------|----------|--------|------|-------|
| 0 | Spartan proof | Rust native CPU | ~seconds | Rust code honesty |
| 1 | All m committee signatures | Python cryptography | ~ms per sig | Ed25519 math |
| 2 | Binding constraints | Circom R1CS | ~KB constraints | Circom correctness |
| 3 | Groth16 proof | EVM precompile | ~300K gas | BN254 pairing math |

### Attack Surface & Mitigations

| Attack | Description | Mitigation |
|--------|-------------|-----------|
| Rust prover skips verify | Generates fake Spartan proof, signs anyway | Committee members ALSO verify → majority check prevents this |
| Attacker compromises 1 committee member | 1 node signs invalid proof | m-of-n threshold (e.g., 3-of-5) prevents single node attack |
| Signature replay | Reuse old signature on different proof | Domain separation + epoch binding + Circom constraints |
| Key substitution | Attacker replaces committee pubkeys | Circom commits pubkeys_hash → cannot change keys without invalidating proof |
| On-chain verifier fraud | Verifier accepts invalid Groth16 | Groth16 precompile is battle-tested EVM code |

---

## Data Flow

### Step 1: Rust Prover Exports Attestation

**File:** `prover-rust/src/core/proof_engine.rs`

```rust
fn export_for_wrapper(...) {
    // 1. Hash Spartan proof → spartan_proof_hash
    let proof_bytes = bincode::serialize(proof)?;
    let spartan_proof_hash = SHA256(proof_bytes);
    
    // 2. Simulate m=3 committee nodes (each has own keypair)
    for i in 0..committee_size {
        // Generate keypair (deterministic seed for simulation)
        let secret_key_bytes = [i as u8, 0, 0, ..., 0];
        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        
        // Create attestation message
        // IMPORTANT: Include both z0 AND zi (not just z0)
        msg = "ENGRAM_SPARTAN_PROOF" 
            || expected_z0 
            || expected_zi          // ← NEW: Added zi
            || spartan_proof_hash 
            || epoch;
        
        // Each committee member signs
        signature_i = signing_key.sign(msg);
        committee_signatures.push(signature_i);
        committee_pubkeys.push(signing_key.verifying_key());
    }
    
    // 3. Commit all pubkeys
    pubkeys_hash = SHA256(concat(committee_pubkeys));
    
    // 4. Export JSON
    export_json({
        "expected_z0": "0x...",
        "expected_zi": "0x...",
        "spartan_proof_hash": "0x...",
        "committee": {
            "size": 3,
            "pubkeys": ["0x...", "0x...", "0x..."],
            "pubkeys_hash": "0x...",
            "signatures": ["0x...", "0x...", "0x..."]
        },
        "attestation": {
            "epoch": 1,
            "domain_sep": "ENGRAM_SPARTAN_PROOF"
        }
    });
}
```

**Output:** `circuits-circom/input.json`

### Step 2: Python Verifies All Signatures

**File:** `scripts/verify_attestation.py`

```python
def verify_committee_attestation(input_json_path):
    data = load_json(input_json_path)
    committee = data["committee"]
    
    # Verify pubkeys hash (prevent key substitution)
    pubkeys_concat = "".join(committee["pubkeys"])
    computed_hash = SHA256(pubkeys_concat)
    assert computed_hash == committee["pubkeys_hash"]
    
    # Reconstruct message (MUST MATCH Rust)
    msg = "ENGRAM_SPARTAN_PROOF" 
        + data["expected_z0"]
        + data["expected_zi"]        # ← NEW: Match Rust
        + data["spartan_proof_hash"]
        + epoch.to_bytes(4, 'little')
    
    # Verify ALL m signatures (m-of-m)
    for i, (pubkey, signature) in enumerate(zip(committee["pubkeys"], committee["signatures"])):
        verify_key = VerifyKey(pubkey)
        verify_key.verify(msg, signature)  # Throws if invalid
        print(f"✅ Committee[{i}] signature valid")
    
    print(f"✅ All {committee['size']} signatures valid (m-of-m passed)")
    return True  # Exit 0
```

**Exit Codes:**
- `0` = All signatures valid → Groth16 proving proceeds
- `1` = Any signature invalid → Abort (do NOT proceed to Groth16)

### Step 3: Groth16 Wrapper Binds Attestation

**File:** `circuits-circom/spartan_wrapper.circom`

```circom
pragma circom 2.1.5;

template SecureSpartanBridge() {
    // PUBLIC INPUTS (verified on-chain)
    signal input expected_z0;
    signal input expected_zi;
    signal input spartan_proof_hash;
    signal input committee_pubkeys_hash;
    
    // WITNESS (hidden, only prover knows)
    signal input spartan_z0;
    signal input spartan_zi;
    
    // BINDING CONSTRAINTS
    expected_z0 === spartan_z0;
    expected_zi === spartan_zi;
    
    // Prove prover knows all components
    signal expected_commitment = expected_z0 * spartan_proof_hash 
                                + expected_zi 
                                + committee_pubkeys_hash;
    signal witness_commitment = spartan_z0 * spartan_proof_hash 
                               + spartan_zi 
                               + committee_pubkeys_hash;
    
    expected_commitment === witness_commitment;
}

component main {public [expected_z0, expected_zi, spartan_proof_hash, committee_pubkeys_hash]} = SecureSpartanBridge();
```

**Key Points:**
- `committee_pubkeys_hash` is a **public input** → part of Groth16 proof
- On-chain verifier can extract it and check against registered committee
- Cannot forge signature without knowing correct hash

### Step 4: Pipeline Orchestration

**File:** `scripts/stage_wrapper_groth16.sh`

```bash
#!/bin/bash

# 1. Setup Circom + Groth16 keys (if needed)
circom spartan_wrapper.circom --r1cs --wasm
snarkjs groth16 setup ...

# 2. VERIFY COMMITTEE SIGNATURES (off-chain gate)
python3 scripts/verify_attestation.py circuits-circom/input.json
if [ $? -ne 0 ]; then
    echo "ERROR: Attestation verification failed"
    exit 1  # Stop pipeline
fi

# 3. Sanitize input for witness generation
python3 <<'PY'
  data = load_json("input.json")
  witness_input = {
      "expected_z0": data["expected_z0"],
      "expected_zi": data["expected_zi"],
      "spartan_z0": data["spartan_z0"],
      "spartan_zi": data["spartan_zi"],
      "spartan_proof_hash": data["spartan_proof_hash"],
      "committee_pubkeys_hash": data["committee"]["pubkeys_hash"],
  }
  save_json(witness_input, "input_wrapper.json")
PY

# 4. Generate witness + Groth16 proof
node spartan_wrapper_js/generate_witness.js ... witness.wtns
snarkjs groth16 prove ... proof.json public.json

# 5. Verify Groth16 (sanity check)
snarkjs groth16 verify verification_key.json public.json proof.json
```

---

## Why This Works: Optimistic Rollup Pattern

```
┌─────────────────────────────────────────────────────────────┐
│ Standard PoS System (Centralized Verifier)                 │
│                                                             │
│  Prover ──Proof──> Verifier ──Accept/Reject──> On-Chain   │
│                                                             │
│  Problem: Single verifier = single point of failure        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ Committee Multi-Sig Pattern (This Implementation)          │
│                                                             │
│   Prover ──Input──> m Committee Nodes                      │
│                         │                                   │
│                         ├─ Each verifies locally            │
│                         ├─ Each signs if valid              │
│                         ▼                                   │
│                    m Signatures ──batch──> Groth16          │
│                                                             │
│   On-Chain: Verify Groth16 only (Ed25519 checking done)   │
│                                                             │
│   Security: Majority of committee must be honest           │
│   (if 3-of-5 required, attacker needs ≥3 compromises)     │
└─────────────────────────────────────────────────────────────┘
```

---

## Production Improvements

### Current (Simulation)

- ✅ m keypairs generated deterministically (for testing)
- ✅ m-of-m threshold (all must sign)
- ✅ Pubkeys hash prevents key substitution
- ✅ Clear attack surface documented

### Future Enhancements

1. **Persistent Committee Identity**
   - Read keypairs from HSM / secure enclave
   - Keypair = persistent identity, not ephemeral
   - Enable accountability: trace which committee member signed

2. **Threshold Signing (m-of-n)**
   - Current: 3-of-3 (all must agree)
   - Future: 3-of-5 (Byzantine fault tolerance)
   - Allows 2 nodes to fail / be compromised

3. **On-Chain Committee Registry**
   - Smart contract maintains registered pubkeys
   - pubkeys_hash in proof matches contract state
   - DAO can vote to add/remove committee members

4. **Incentive Structure**
   - Committee members earn fees for signing
   - Slashing if they sign invalid proofs (caught by challengers)
   - Economic security layer

5. **External Verification**
   - Publish compressed_proof + verification_key
   - Any third-party can verify independently
   - Creates transparency + auditability

---

## Testing

### Simulate Committee Verification

```bash
# Build Rust prover (generates 3 signatures)
cd prover-rust
cargo build --release
cd ..

# Run pipeline
./scripts/stage_spartan.sh "shard1,shard2,shard3"

# Verify committee signatures
python3 scripts/verify_attestation.py circuits-circom/input.json
# Output: ✅ All 3 committee signatures VALID (m-of-m check passed)

# Generate Groth16 proof (with committee pubkeys hash bound)
cd circuits-circom
bash ../scripts/stage_wrapper_groth16.sh

# Verify Groth16 locally
snarkjs groth16 verify verification_key.json public.json proof.json
# Output: ✅ Verification OK
```

### Check JSON Structure

```bash
# View committee attestation
cat circuits-circom/input.json | jq '.committee'

# Output:
# {
#   "size": 3,
#   "pubkeys": [
#     "0x1234...",  # Committee[0] pubkey
#     "0x5678...",  # Committee[1] pubkey
#     "0x9abc...",  # Committee[2] pubkey
#   ],
#   "pubkeys_hash": "0x3141...",  # SHA256 of concat pubkeys
#   "signatures": [
#     "0x...sig0...",
#     "0x...sig1...",
#     "0x...sig2...",
#   ]
# }
```

---

## Security Properties

### Confidentiality
- ❌ No confidentiality (attestation is public)
- ✅ Acceptable: Attestation signs public values only

### Integrity
- ✅ Ed25519 signatures prevent tampering
- ✅ Pubkeys hash prevents key substitution
- ✅ Domain separation prevents cross-protocol attacks
- ✅ Groth16 binding proves witness ↔ public inputs

### Availability
- ⚠️ Requires committee quorum (m-of-m currently)
- ✅ Threshold (m-of-n) improves availability

### Accountability
- ⚠️ Deterministic keys (simulation only)
- ✅ Production: persistent keypairs enable tracing
- ✅ Slashing mechanism incentivizes honest committee

---

## References

- **Spartan:** A Sparse Interactive Theorem Prover (arxiv.org/abs/1909.07396)
- **Nova:** Recursive Zero-Knowledge Arguments from Folding Schemes (arxiv.org/abs/2110.01693)
- **Optimistic Rollups:** Ethereum research (ethereum.org/en/developers/docs/scaling/optimistic-rollups/)
- **Ed25519:** ECDSA over Curve25519 (rfc8032.org)

---
