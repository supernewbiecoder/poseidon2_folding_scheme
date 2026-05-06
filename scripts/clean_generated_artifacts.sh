#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

ARTIFACTS=(
  "$ROOT_DIR/circuits-circom/input.json"
  "$ROOT_DIR/circuits-circom/input_wrapper.json"
  "$ROOT_DIR/circuits-circom/proof.json"
  "$ROOT_DIR/circuits-circom/public.json"
  "$ROOT_DIR/circuits-circom/public_fixed.json"
  "$ROOT_DIR/circuits-circom/witness.json"
  "$ROOT_DIR/circuits-circom/witness_dump.json"
  "$ROOT_DIR/circuits-circom/witness.wtns"
  "$ROOT_DIR/circuits-circom/circuit_final.zkey"
  "$ROOT_DIR/circuits-circom/verification_key.json"
  "$ROOT_DIR/circuits-circom/pot12_0000.ptau"
  "$ROOT_DIR/circuits-circom/pot12_final.ptau"
  "$ROOT_DIR/circuits-circom/spartan_wrapper.r1cs"
  "$ROOT_DIR/circuits-circom/spartan_wrapper_js/spartan_wrapper.wasm"
  "$ROOT_DIR/circuits-circom/spartan_wrapper_js/witness_calculator.js"
)

removed=0
for artifact in "${ARTIFACTS[@]}"; do
  if [ -e "$artifact" ]; then
    rm -f "$artifact"
    removed=$((removed + 1))
  fi
done

echo "Removed $removed generated artifact(s)."
