# Poseidon2 Folding Scheme — Architecture (Production-Like PoC)

## Overview

This repository implements a **production-like Proof-of-Concept** for the Engram Proof-of-Space-Time protocol using:
- **Nova Folding Scheme** + **Poseidon2** (Rust, native Pasta curves)
- **Spartan Compression** (native Pasta verification)
- **Committee Attestation** (m-of-m Ed25519 signatures over proof metadata)
- **Groth16 Wrapper** (BN254, on-chain ready)

The current flow separates two **trust domains** with a cryptographic **attestation boundary**: Spartan is verified natively in Rust first, then the committee attestation is checked, and only after that does the BN254 Groth16 wrapper run.

---

## Architecture Layers

### Layer 1: Spartan Proof Generation & Native Verification (Rust)

**Location:** `prover-rust/`

- **Input:** User data shards (via stdin)
- **Process:**
  1. Build Merkle tree with `Poseidon2` hash
  2. Run Nova folding loop over random challenges
  3. Compress folded proof with Spartan
  4. **Verify Spartan proof locally** (native field arithmetic on Pasta curves)
  5. Hash the compressed proof to `spartan_proof_hash`
  6. Generate a **committee attestation**: 3 Ed25519 signatures over the domain-separated message
    ```
    message = "ENGRAM_SPARTAN_PROOF" || expected_z0 || expected_zi || spartan_proof_hash || epoch
    ```
  7. Export `circuits-circom/input.json` with committee metadata and proof bindings
- **Output:** `input.json` containing:
  ```json
  {
    "expected_z0": "0x...",      // commitment root
    "expected_zi": "0x...",       // final state
    "spartan_proof_hash": "0x...", // SHA-256 of compressed proof
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
  }
  ```
- **Trust Assumption:** Rust prover runner is trusted to generate a valid Spartan proof; committee signatures make the exported proof metadata accountable before Groth16 wrapping.

Note (developer/testing): the repository provides a helper script `scripts/simulate_committee_sign.py` for local testing. `run_pipeline.sh` will automatically invoke this simulator if it detects `circuits-circom/input.json` with an empty `committee` (size = 0). This is strictly for local end-to-end testing — in production the committee must independently fetch `compressed_proof.bin`, verify it, and sign with their private keys.

---

### Layer 2: Attestation Verification (Orchestrator)

**Location:** `scripts/verify_attestation.py`

- **Input:** `circuits-circom/input.json` from Layer 1
- **Process:**
  1. Parse JSON and extract committee fields
  2. Reconstruct message: `"ENGRAM_SPARTAN_PROOF" || expected_z0 || expected_zi || spartan_proof_hash || epoch`
  3. **Verify all Ed25519 signatures** using the committee public keys
  4. Check the `pubkeys_hash` to prevent key substitution
  5. Check epoch/domain separation matches expected values
- **Output:** 
  - Exit code 0 if valid
  - Exit code 1 if invalid, with error message
- **Trust Assumption:** The committee attestation proves the Spartan result was observed and signed off by the configured committee before the Groth16 stage runs.

---

### Layer 3: Groth16 Wrapper (Circom, BN254)

**Location:** `circuits-circom/spartan_wrapper.circom`

- **Input:** `input.json` (with verified committee attestation)
- **Process:**
  1. Circom mixin receives public inputs: `expected_z0`, `expected_zi`, `spartan_proof_hash`, `committee_pubkeys_hash`
  2. Witness inputs: `spartan_z0`, `spartan_zi`
  3. **Binding constraints:** Enforce equality between witness and exported public values
  4. Generate Groth16 proof on BN254
- **Output:** `proof.json`, `public.json` (300-400 bytes, on-chain ready)
- **Trust Assumption:** 
  - Circom wrapper does **not** re-verify Spartan proof (non-native field arithmetic in BN254 would be prohibitively expensive).
  - Instead, it **relies on** the committee attestation from Layer 2 and enforces binding constraints over the exported values.
  - On-chain verifier checks Groth16 proof validity; the attestation signature links back to Layer 1 proof.

---

### Layer 4: On-Chain Verification (Optional)

**Location:** Smart contract (future)

- **Input:** Groth16 proof + public inputs + attestation metadata
- **Process:**
  1. Verify Groth16 proof using precompile or verifier contract
  2. Optionally, recover signer from Ed25519 attestation signature and check against trusted list (DAO vote, etc.)
  3. Update merkle root / state on-chain
- **Trust Assumption:** On-chain verifier has access to trusted public keys (registered via governance).

---

## Trust Boundary Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: SPARTAN PROVER (Rust, Pasta curves, NATIVE FIELD) │
│  - Nova folding (off-chain compute)                         │
│  - Spartan compression + verification                       │
│  - EdDSA signature generation (attestation)                 │
│  Output: input.json + signature                             │
└────────────────────────▲────────────────────────────────────┘
                         │ ← Trust Boundary #1: Attestation Signature
┌─────────────────────────▼────────────────────────────────────┐
│ Layer 2: ATTESTATION VERIFIER (Python, Ed25519 check)      │
│  - Verify signature on (z0, hash, epoch)                    │
│  - Confirm domain separation                                │
│  Output: "Valid" or "Invalid"                               │
└────────────────────────▲────────────────────────────────────┘
                         │ ← Trust Boundary #2: Layer 2 passes only if verified
┌─────────────────────────▼────────────────────────────────────┐
│ Layer 3: GROTH16 WRAPPER (Circom, BN254, NATIVE TO BN254)  │
│  - Binding constraints (no Spartan re-verification)         │
│  - Groth16 proof generation                                 │
│  Output: proof.json (on-chain ready)                        │
└────────────────────────▲────────────────────────────────────┘
                         │ ← Trust Boundary #3: Groth16 proof valid
┌─────────────────────────▼────────────────────────────────────┐
│ Layer 4: ON-CHAIN VERIFIER (Smart contract, optional)       │
│  - Verify Groth16 proof                                     │
│  - Optionally check attestation signer                      │
│  Output: State update on-chain                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Why This is "Production-Like"

1. **Attestation Signature:** Proves Layer 1 verification succeeded. Prevents Layer 1 from lying about proof validity.
2. **Domain Separation & Epoch:** Prevents replay attacks and ties proof to specific context.
3. **Clear Trust Boundaries:** Each layer has a single responsibility and cryptographic proof of correctness.
4. **Scalability:** Doesn't require non-native field arithmetic in Circom (expensive). Spartan verification stays native (fast).
5. **Auditability:** Full chain of custody: Spartan → Signature → Groth16 → On-chain.

---

## Limitations (Why Still PoC)

1. **Committee keys are simulated:** The Rust prover currently generates deterministic test keys for 3 committee members. Production should use persistent keys or an HSM/KMS.
2. **m-of-m policy:** The verifier requires all committee signatures today. A threshold m-of-n policy would improve availability.
3. **Replay protection is partial:** Epoch/domain separation is present, but on-chain nonce handling is still a future step.
4. **Circom wrapper remains a binding stub:** It binds exported values and committee hash; it does not re-implement Spartan verification inside BN254.

---

## Running the Pipeline

### Full End-to-End (Orchestrated)

```bash
./run_pipeline.sh
# Interactively enters shard count, challenge count, and shard directory; then runs Spartan + committee attestation + Groth16.
```

### Individual Stages (For Testing/Benchmarking)

**Stage 1: Spartan (Rust)**
```bash
./scripts/stage_spartan.sh 9 ./prover-rust/sample_shards 7
```

**Stage 2: Attestation Verification**
```bash
python3 ./scripts/verify_attestation.py ./circuits-circom/input.json
```

**Cleanup generated artifacts**
```bash
./scripts/clean_generated_artifacts.sh
```

**Stage 3: Groth16 Wrapper**
```bash
./scripts/stage_wrapper_groth16.sh
# (internally calls verify_attestation.py, then proceeds to groth16)
```

---

## Metrics & Benchmark

Run the full pipeline:
```bash
./run_pipeline.sh <<< "shard1,shard2,shard3,shard4"
```

Output includes:
- **BUILD RUST**: Compilation time (can be skipped with warm build)
- **SETUP WRAPPER**: Circom compilation + trusted setup (rebuilds automatically if artifacts are stale)
- **VERIFY ATTESTATION**: Committee signature verification time
- **RUNTIME ONLY**: Spartan proving + Groth16 proving
- **COLD START**: Total end-to-end from scratch
- **VERIFY**: Groth16 verification time
 - **PROOF BYTES**: On-chain proof size (includes Spartan binding bytes; Groth16 proof size for the BN254 wrapper (future); and committee signature bytes)

---

## Next Steps for Full Production

1. **Keypair Management:** Use HSM, KMS, or secure enclave for attestation keypair.
2. **Multi-Signer Attestation:** Implement threshold or committee-based signing.
3. **On-Chain Verifier:** Deploy Groth16 verifier contract; optionally add Ed25519 signature recovery.
4. **Replay Protection:** Add nonce/counter and check on-chain state.
5. **Monitoring & Audit:** Log all proofs, attestations, and verifications for compliance.
6. **Formal Verification:** Prove wrapper Circom constraints are sufficient for binding.

---

## References

- **Nova Folding Scheme:** https://eprint.iacr.org/2021/370.pdf
- **Poseidon Hash:** https://eprint.iacr.org/2023/350.pdf
- **Ed25519 Signature:** RFC 8032
- **Circom Documentation:** https://docs.circom.io/
- **SnarkJS:** https://github.com/iden3/snarkjs
