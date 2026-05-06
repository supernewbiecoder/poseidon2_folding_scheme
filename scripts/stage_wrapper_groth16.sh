#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

function get_time_ms() {
  date +%s%3N
}

cd "$ROOT_DIR/circuits-circom"

energy_joules() {
  awk -v watts="$1" -v ms="$2" 'BEGIN { printf "%.3f", (watts * ms) / 1000.0 }'
}

needs_rebuild() {
  local target="$1"
  shift

  if [ ! -f "$target" ]; then
    return 0
  fi

  for source in "$@"; do
    if [ ! -f "$source" ] || [ "$source" -nt "$target" ]; then
      return 0
    fi
  done

  return 1
}

SETUP_MS=0
SETUP_J=0

# Rebuild artifacts when the circuit or its generated R1CS/WASM changes.
if needs_rebuild "spartan_wrapper.r1cs" "spartan_wrapper.circom" || \
   needs_rebuild "spartan_wrapper_js/spartan_wrapper.wasm" "spartan_wrapper.circom" || \
   needs_rebuild "spartan_wrapper_js/witness_calculator.js" "spartan_wrapper.circom"; then
  echo "[WRAPPER] SETUP CIRCOM + ZKEY (generating/regenerating artifacts)..."
  START_SETUP=$(get_time_ms)

  circom spartan_wrapper.circom --r1cs --wasm > /dev/null
fi

if needs_rebuild "circuit_final.zkey" "spartan_wrapper.r1cs" || \
   needs_rebuild "verification_key.json" "circuit_final.zkey"; then
  echo "[WRAPPER] SETUP GROTH16 KEY MATERIAL (zkey + verification key)..."
  START_SETUP=$(get_time_ms)

  if [ ! -f pot12_0000.ptau ] || [ ! -f pot12_final.ptau ]; then
    snarkjs powersoftau new bn128 12 pot12_0000.ptau > /dev/null
    snarkjs powersoftau prepare phase2 pot12_0000.ptau pot12_final.ptau > /dev/null
  fi

  snarkjs groth16 setup spartan_wrapper.r1cs pot12_final.ptau circuit_final.zkey > /dev/null
  snarkjs zkey export verificationkey circuit_final.zkey verification_key.json > /dev/null

  END_SETUP=$(get_time_ms)
  SETUP_MS=$((END_SETUP - START_SETUP))
  SETUP_J=$(energy_joules "${ENGRAM_WATTS_WRAPPER_SETUP:-70}" "$SETUP_MS")
fi

echo "[WRAPPER] VERIFY ATTESTATION SIGNATURE..."
START_VERIFY_ATTESTATION=$(get_time_ms)
python3 "$ROOT_DIR/scripts/verify_attestation.py" "$ROOT_DIR/circuits-circom/input.json" || {
  echo "ERROR: Attestation verification failed" >&2
  exit 1
}
END_VERIFY_ATTESTATION=$(get_time_ms)
VERIFY_ATTESTATION_MS=$((END_VERIFY_ATTESTATION - START_VERIFY_ATTESTATION))
VERIFY_ATTESTATION_J=$(energy_joules "${ENGRAM_WATTS_ATTESTATION_VERIFY:-20}" "$VERIFY_ATTESTATION_MS")

SANITIZED_INPUT="$ROOT_DIR/circuits-circom/input_wrapper.json"
python3 - "$ROOT_DIR/circuits-circom/input.json" "$SANITIZED_INPUT" <<'PY'
import json
import sys

def hex_to_decimal(hex_str):
  """Convert hex string (0x...) to decimal string for Circom"""
  if isinstance(hex_str, str) and hex_str.startswith("0x"):
    return str(int(hex_str, 16))
  return hex_str

src, dst = sys.argv[1], sys.argv[2]
with open(src, "r", encoding="utf-8") as f:
  data = json.load(f)

sanitized = {
  "expected_z0": hex_to_decimal(data["expected_z0"]),
  "expected_zi": hex_to_decimal(data["expected_zi"]),
  "spartan_z0": hex_to_decimal(data["spartan_z0"]),
  "spartan_zi": hex_to_decimal(data["spartan_zi"]),
  "spartan_proof_hash": hex_to_decimal(data["spartan_proof_hash"]),
  "committee_pubkeys_hash": hex_to_decimal(data["committee"]["pubkeys_hash"]),
}

with open(dst, "w", encoding="utf-8") as f:
  json.dump(sanitized, f)
PY

echo "[WRAPPER] GENERATE WITNESS + GROTH16 PROVE..."
START_PROVE=$(get_time_ms)
node spartan_wrapper_js/generate_witness.js spartan_wrapper_js/spartan_wrapper.wasm input_wrapper.json witness.wtns
snarkjs groth16 prove circuit_final.zkey witness.wtns proof.json public.json > /dev/null
END_PROVE=$(get_time_ms)
PROVE_MS=$((END_PROVE - START_PROVE))
PROVE_J=$(energy_joules "${ENGRAM_WATTS_WRAPPER_PROVE:-75}" "$PROVE_MS")

echo "[WRAPPER] VERIFY GROTH16..."
START_VERIFY=$(get_time_ms)
snarkjs groth16 verify verification_key.json public.json proof.json
END_VERIFY=$(get_time_ms)
VERIFY_MS=$((END_VERIFY - START_VERIFY))
VERIFY_J=$(energy_joules "${ENGRAM_WATTS_WRAPPER_VERIFY:-55}" "$VERIFY_MS")

PROOF_BYTES_GROTH=$(wc -c < proof.json | awk '{print $1}')

# Compute signature bytes from input.json (committee.signatures are hex strings like 0x...)
SIG_BYTES=0
if [ -f "$ROOT_DIR/circuits-circom/input.json" ]; then
  SIG_BYTES=$(python3 - <<PY
import json,sys
from pathlib import Path
p = Path(r'''$ROOT_DIR/circuits-circom/input.json''')
try:
  d = json.load(open(p))
  sigs = d.get('committee', {}).get('signatures', []) or []
  total = 0
  for s in sigs:
    if isinstance(s, str) and s.startswith('0x'):
      total += len(s[2:])//2
    elif isinstance(s, str):
      # assume raw hex without 0x
      total += len(s)//2
    else:
      # fallback: measure repr length
      total += len(json.dumps(s))
  print(total)
except Exception:
  print(0)
PY
)
fi

PROOF_BYTES=$PROOF_BYTES_GROTH

echo "WRAPPER_SETUP_MS=$SETUP_MS"
echo "WRAPPER_SETUP_JOULES=$SETUP_J"
echo "WRAPPER_VERIFY_ATTESTATION_MS=$VERIFY_ATTESTATION_MS"
echo "WRAPPER_VERIFY_ATTESTATION_JOULES=$VERIFY_ATTESTATION_J"
echo "WRAPPER_PROVE_MS=$((END_PROVE - START_PROVE))"
echo "WRAPPER_PROVE_JOULES=$PROVE_J"
echo "WRAPPER_VERIFY_MS=$VERIFY_MS"
echo "WRAPPER_VERIFY_JOULES=$VERIFY_J"
echo "WRAPPER_PROOF_BYTES_GROTH=$PROOF_BYTES_GROTH"
echo "WRAPPER_PROOF_BYTES_SIG=$SIG_BYTES"
# Backwards-compatible total
echo "WRAPPER_PROOF_BYTES=$((PROOF_BYTES_GROTH + SIG_BYTES))"
