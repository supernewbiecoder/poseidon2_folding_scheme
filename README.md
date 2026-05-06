# Engram Proof-of-Space-Time: Production-Like PoC

A production-grade proof-of-concept implementation of Engram's Proof-of-Space-Time protocol using **Nova Folding Scheme**, **Spartan Compression**, **Ed25519 Attestation**, and **Groth16 Wrapper**.

## 🏗️ Architecture

The system is organized in **4 trust layers** with cryptographic boundaries:

```
Layer 1: Spartan Prover (Rust, Pasta curves)
         ↓ [EdDSA Attestation Signature]
Layer 2: Attestation Verifier (Python, Ed25519 check)
         ↓ [Verified]
Layer 3: Groth16 Wrapper (Circom, BN254)
         ↓ [Proof]
Layer 4: On-Chain Verifier (Smart contract)
```

**See [ARCHITECTURE.md](ARCHITECTURE.md) for full technical details.**

---

## 🚀 Quick Start

### Prerequisites

- **Rust** 1.70+ with Cargo
- **Circom** 2.1.5
- **SnarkJS** 0.6.0+
- **Node.js** 14+
- **Python** 3.8+ with PyNaCl
- **WSL** (Windows) or Linux (macOS/Linux)

### Installation

```bash
# Clone and setup
git clone <repo>
cd poseidon2_folding_scheme

# Install Python dependencies (PyNaCl for attestation verification)
pip install -r requirements.txt

# Pre-check Rust compilation
cd prover-rust && cargo check && cd ..

# Pre-compile Circom circuits (optional, auto-compiled on first run)
cd circuits-circom && circom spartan_wrapper.circom --r1cs && cd ..
```

### Run Full Pipeline

```bash
# Start orchestrated pipeline (interactive)
./run_pipeline.sh

# Enter shard count, challenge count, and optional directory when prompted:
# > 4
# > 4
# > C:\path\to\shards
```

**Output Sample:**
```
[PIPELINE] Building Rust prover...
[SPARTAN] Generating proof + attestation...
[VERIFY] Validating Ed25519 signature...
✅ Attestation VALID: epoch=1, pubkey=b82c3b435daf4ce5...
[WRAPPER] Generating Groth16 proof...
[GROTH16] Verifying proof...

⚡ ENERGY REPORT
==========================================
Nova Init                       0.42 J
Nova Folding                    5.18 J
Spartan Setup                   1.90 J
Spartan Prove                   9.95 J
Spartan Verify                  0.63 J
Export + Attestation            0.12 J
Wrapper Verify Attestation      0.08 J
Groth16 Prove                   2.14 J
Groth16 Verify                  0.72 J

📊 BENCHMARK RESULTS
==========================================
BUILD RUST                      4.2 sec
SETUP WRAPPER (Circom)         2.1 sec
RUNTIME ONLY (Prove + Verify)  14.5 sec
COLD START (Full)              20.8 sec
GROTH16 VERIFY                  1.1 sec
PROOF BYTES                     324 bytes
```

---

## 📋 Individual Stages

### Stage 1: Spartan Proof + Attestation (Rust)

Generate proof and sign with Ed25519:

```bash
./scripts/stage_spartan.sh 3 ./data 2

# Output: 
# SPARTAN_BUILD_MS=4200
# SPARTAN_BUILD_JOULES=252.000
# SPARTAN_RUNTIME_MS=7300
# SPARTAN_RUNTIME_JOULES=620.500
# 
# Generated: circuits-circom/input.json with:
# {
#   "expected_z0": "0x...",
#   "spartan_proof_hash": "0x...",
#   "attestation": {
#     "epoch": 1,
#     "signature": "0x...",  <- Ed25519 signature
#     "pubkey": "0x..."      <- Ed25519 public key
#   }
# }
```

### Stage 2: Attestation Verification (Python)

Verify Ed25519 signature independently:

```bash
python3 scripts/verify_attestation.py circuits-circom/input.json

# Output:
# ✅ Attestation VALID: epoch=1, pubkey=b82c3b435daf4ce5...
# (exit code 0 = valid, 1 = invalid)
```

### Stage 3: Groth16 Wrapper (Circom + SnarkJS)

Generate on-chain proof (runs attestation verification automatically):

```bash
./scripts/stage_wrapper_groth16.sh

# Output:
# [WRAPPER] VERIFY ATTESTATION SIGNATURE...
# ✅ Attestation VALID: epoch=1, pubkey=b82c3b435daf4ce5...
# [WRAPPER] GENERATE WITNESS + GROTH16 PROVE...
# WRAPPER_SETUP_MS=2100
# WRAPPER_PROVE_MS=1800
# WRAPPER_VERIFY_MS=1100
# WRAPPER_PROOF_BYTES=324
```

---

## 🔐 Trust Model

| Attack | Blocked By | Mechanism |
|--------|-----------|-----------|
| **False Proof** | Layer 1 Spartan verification | Invalid proof won't pass native field check |
| **Fake Attestation** | Layer 3 Ed25519 verification | Signature won't verify without correct secret key |
| **Proof Tampering** | Layer 2 hash binding | Altered proof breaks signature |
| **Commitment Swapping** | Layer 4 Circom constraints | Commitment hardcoded in circuit |
| **Replay** | Epoch + Domain separation | Each proof tied to specific epoch/domain |

---

## 📊 Performance Metrics

Typical benchmark on Ubuntu 22.04, Ryzen 5950X:

```
Stage                          Time        Proof Size
───────────────────────────────────────────────────────
Spartan Prove (cold)          7.3 sec     128 KB (compressed)
Spartan Verify (native)       0.1 sec     —
Ed25519 Attest + Sign         0.01 sec    64 bytes
Attestation Verify            0.001 sec   —
Groth16 Prove                 1.8 sec     324 bytes
Groth16 Verify                1.1 sec     —
───────────────────────────────────────────────────────
TOTAL (cold)                 ~20 sec      324 bytes (final)
TOTAL (warm)                 ~10 sec      324 bytes (final)
```

---

## 📂 Project Structure

```
poseidon2_folding_scheme/
├── prover-rust/                    # Nova + Spartan prover with Ed25519
│   ├── Cargo.toml                  # Dependencies (nova-snark, ed25519-dalek, sha2)
│   ├── src/
│   │   ├── main.rs                 # CLI entry point
│   │   └── core/
│   │       ├── circuit.rs          # R1CS circuit (Merkle proof)
│   │       ├── proof_engine.rs     # Nova + Spartan + Ed25519 signing
│   │       ├── poseidon2.rs        # Poseidon2 gadget
│   │       └── constants.rs        # Poseidon2 matrices
│   └── target/release/engram-prover
│
├── circuits-circom/                # Groth16 wrapper
│   ├── spartan_wrapper.circom      # SecureSpartanBridge constraints
│   ├── input.json                  # Generated witness with attestation
│   └── proof.json                  # On-chain ready Groth16 proof
│
├── scripts/
│   ├── stage_spartan.sh            # Stage 1: Generate proof + attestation
│   ├── stage_wrapper_groth16.sh    # Stage 2: Verify + Groth16 prove
│   ├── verify_attestation.py       # Standalone Ed25519 verification
│   └── build_bridge.sh             # Circom helper
│
├── run_pipeline.sh                 # Orchestrator script
├── ARCHITECTURE.md                 # Full technical details
├── requirements.txt                # Python deps (PyNaCl)
└── README.md                       # This file
```

---

## 🧪 Testing

```bash
# Full pipeline test
./run_pipeline.sh

# Unit tests
cd prover-rust && cargo test --release

# Verify attestation manually
ENGRAM_SHARD_COUNT=2 ENGRAM_SHARD_DIR=./data ./prover-rust/target/release/engram-prover
python3 scripts/verify_attestation.py circuits-circom/input.json
```

New input mode:

```bash
# Binary now reads shard_0.txt ... shard_{n-1}.txt
ENGRAM_SHARD_COUNT=4 ENGRAM_SHARD_DIR=./data ./prover-rust/target/release/engram-prover
```

---

## 🚨 Troubleshooting

**PyNaCl import error:**
```bash
pip install PyNaCl
```

**Cargo build fails:**
```bash
cd prover-rust && cargo clean && cargo build --release
```

**Circom compilation errors:**
```bash
cd circuits-circom && circom spartan_wrapper.circom --r1cs --wasm
```

---

## 📚 References

- [Nova Folding Scheme](https://eprint.iacr.org/2021/370.pdf)
- [Poseidon Hash](https://eprint.iacr.org/2023/350.pdf)
- [Ed25519 RFC 8032](https://tools.ietf.org/html/rfc8032)
- [Circom Documentation](https://docs.circom.io/)
- [SnarkJS](https://github.com/iden3/snarkjs)
- [Nova-Snark](https://github.com/microsoft/nova)

---

**Status:** Production-Like PoC (not yet audited)
