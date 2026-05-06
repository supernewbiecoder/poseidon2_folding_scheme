#!/bin/bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Hàm tiện ích để lấy thời gian tính bằng mili-giây (ms)
function get_time_ms() {
  date +%s%3N
}

function parse_metric() {
  local key="$1"
  local payload="$2"
  echo "$payload" | awk -F'=' -v k="$key" '$1==k {print $2}' | tail -n 1
}

function sum_values() {
  python3 - "$@" <<'PY'
import sys
values = [float(v) for v in sys.argv[1:] if v not in ('', 'None')]
print(f"{sum(values):.3f}")
PY
}

echo "=========================================================="
echo "🚀 KHỞI ĐỘNG HỆ THỐNG PROOF-OF-SPACETIME (CÓ BENCHMARK)"
echo "=========================================================="

echo -n "Nhập số lượng file shard cần đọc (shard_0.txt...): "
read shard_count
echo -n "Nhập số challenge cần chứng minh trong 1 batch (Enter = 4): "
read challenge_count
if [ -z "$challenge_count" ]; then
  challenge_count=4
fi
echo -n "Nhập thư mục chứa shard (Enter = thư mục hiện tại): "
read shard_dir
if [ -z "$shard_dir" ]; then
  shard_dir="$ROOT_DIR"
fi

START_PIPELINE_WALL=$(get_time_ms)

echo -e "\n[1/2] STAGE SPARTAN (NOVA + SPARTAN, FIELD NATIVE)..."
SPARTAN_OUTPUT=$("$ROOT_DIR/scripts/stage_spartan.sh" "$shard_count" "$shard_dir" "$challenge_count")
echo "$SPARTAN_OUTPUT"

# If prover exported input.json without committee signatures (size = 0),
# run the local simulator to generate test signatures so wrapper can proceed.
INPUT_JSON="$ROOT_DIR/circuits-circom/input.json"
if [ -f "$INPUT_JSON" ]; then
  COMMITTEE_SIZE=$(python3 - <<PY
import json
import sys
p = r'''$INPUT_JSON'''
try:
    d = json.load(open(p))
    c = d.get('committee', {})
    print(int(c.get('size') or 0))
except Exception:
    print(0)
PY
)

  if [ "$COMMITTEE_SIZE" -eq 0 ]; then
    echo "[run_pipeline] No committee signatures found in input.json — running local simulator for testing"
    python3 "$ROOT_DIR/scripts/simulate_committee_sign.py" "$INPUT_JSON"
    echo "[run_pipeline] simulate_committee_sign completed"
  fi
fi
echo -e "\n[2/2] STAGE WRAPPER (GROTH16 BN254)..."
WRAPPER_OUTPUT=$("$ROOT_DIR/scripts/stage_wrapper_groth16.sh")
echo "$WRAPPER_OUTPUT"

END_PIPELINE_WALL=$(get_time_ms)

# =======================================================
# XUẤT BÁO CÁO THỐNG KÊ (BENCHMARK REPORT)
# =======================================================
TIME_RUST_BUILD=$(parse_metric "SPARTAN_BUILD_MS" "$SPARTAN_OUTPUT")
TIME_RUST_BUILD_J=$(parse_metric "SPARTAN_BUILD_JOULES" "$SPARTAN_OUTPUT")
TIME_RUST_RUNTIME=$(parse_metric "SPARTAN_RUNTIME_MS" "$SPARTAN_OUTPUT")
TIME_RUST_RUNTIME_J=$(parse_metric "SPARTAN_RUNTIME_JOULES" "$SPARTAN_OUTPUT")
TIME_WRAPPER_SETUP=$(parse_metric "WRAPPER_SETUP_MS" "$WRAPPER_OUTPUT")
TIME_WRAPPER_SETUP_J=$(parse_metric "WRAPPER_SETUP_JOULES" "$WRAPPER_OUTPUT")
TIME_VERIFY_ATTESTATION=$(parse_metric "WRAPPER_VERIFY_ATTESTATION_MS" "$WRAPPER_OUTPUT")
TIME_VERIFY_ATTESTATION_J=$(parse_metric "WRAPPER_VERIFY_ATTESTATION_JOULES" "$WRAPPER_OUTPUT")
TIME_GROTH16=$(parse_metric "WRAPPER_PROVE_MS" "$WRAPPER_OUTPUT")
TIME_GROTH16_J=$(parse_metric "WRAPPER_PROVE_JOULES" "$WRAPPER_OUTPUT")
TIME_VERIFY=$(parse_metric "WRAPPER_VERIFY_MS" "$WRAPPER_OUTPUT")
TIME_VERIFY_J=$(parse_metric "WRAPPER_VERIFY_JOULES" "$WRAPPER_OUTPUT")
PROOF_BYTES_GROTH=$(parse_metric "WRAPPER_PROOF_BYTES_GROTH" "$WRAPPER_OUTPUT")
PROOF_BYTES_SIG=$(parse_metric "WRAPPER_PROOF_BYTES_SIG" "$WRAPPER_OUTPUT")
PROOF_BYTES=$(parse_metric "WRAPPER_PROOF_BYTES" "$WRAPPER_OUTPUT")

TIME_TOTAL_PROVE_RUNTIME=$((TIME_RUST_RUNTIME + TIME_GROTH16))
ENERGY_TOTAL_PROVE_RUNTIME=$(sum_values "$TIME_RUST_RUNTIME_J" "$TIME_GROTH16_J")
TIME_PIPELINE_WALL=$((END_PIPELINE_WALL - START_PIPELINE_WALL))
TIME_TOTAL_PROVE_COLD=$((TIME_RUST_BUILD + TIME_WRAPPER_SETUP + TIME_TOTAL_PROVE_RUNTIME))
ENERGY_TOTAL_COLD=$(sum_values "$TIME_RUST_BUILD_J" "$TIME_WRAPPER_SETUP_J" "$TIME_RUST_RUNTIME_J" "$TIME_GROTH16_J")
ENERGY_TOTAL_VERIFY=$(sum_values "$TIME_VERIFY_ATTESTATION_J" "$TIME_VERIFY_J")

echo -e "\n=========================================================="
echo "📊 BÁO CÁO THỐNG KÊ THỜI GIAN & KÍCH THƯỚC (BENCHMARK)"
echo "=========================================================="
echo "⏱️ THỜI GIAN BUILD RUST (SEPARATE)           : ${TIME_RUST_BUILD} ms"
echo "⚡ NĂNG LƯỢNG BUILD RUST (EST.)             : ${TIME_RUST_BUILD_J} J"
echo "⏱️ THỜI GIAN SETUP WRAPPER (SEPARATE)        : ${TIME_WRAPPER_SETUP} ms"
echo "⚡ NĂNG LƯỢNG SETUP WRAPPER (EST.)          : ${TIME_WRAPPER_SETUP_J} J"
echo "⏱️ THỜI GIAN VERIFY ATTESTATION             : ${TIME_VERIFY_ATTESTATION} ms"
echo "⚡ NĂNG LƯỢNG VERIFY ATTESTATION (EST.)     : ${TIME_VERIFY_ATTESTATION_J} J"
echo "⏱️ THỜI GIAN SINH BẰNG CHỨNG (RUNTIME ONLY)  : ${TIME_TOTAL_PROVE_RUNTIME} ms"
echo "⚡ NĂNG LƯỢNG SINH BẰNG CHỨNG (EST.)        : ${ENERGY_TOTAL_PROVE_RUNTIME} J"
echo "🎯 SỐ CHALLENGE TRONG 1 BATCH               : ${challenge_count}"
echo "   ├─ Tích lũy (Nova) & Nén (Spartan)     : ${TIME_RUST_RUNTIME} ms"
echo "   │   └─ Năng lượng (EST.)                : ${TIME_RUST_RUNTIME_J} J"
echo "   └─ Bọc Groth16 (Wrapper)               : ${TIME_GROTH16} ms"
echo "       └─ Năng lượng (EST.)                : ${TIME_GROTH16_J} J"
echo "⏱️ THỜI GIAN SINH BẰNG CHỨNG (COLD START)    : ${TIME_TOTAL_PROVE_COLD} ms"
echo "⚡ NĂNG LƯỢNG SINH BẰNG CHỨNG (COLD, EST.)  : ${ENERGY_TOTAL_COLD} J"
echo "⏱️ THỜI GIAN TOÀN PIPELINE (WALL CLOCK)      : ${TIME_PIPELINE_WALL} ms"
echo "⚡ NĂNG LƯỢNG VERIFY TOÀN BỘ (EST.)          : ${ENERGY_TOTAL_VERIFY} J"
echo "----------------------------------------------------------"
echo "✅ THỜI GIAN KIỂM TRA (VERIFICATION)        : ${TIME_VERIFY} ms"
echo "⚡ NĂNG LƯỢNG KIỂM TRA (EST.)               : ${TIME_VERIFY_J} J"
echo "----------------------------------------------------------"
echo "📦 DUNG LƯỢNG BẰNG CHỨNG ON-CHAIN (GROTH)   : ${PROOF_BYTES_GROTH} bytes"
echo "📦 DUNG LƯỢNG BẰNG CHỨNG ON-CHAIN (SIG)     : ${PROOF_BYTES_SIG} bytes"
echo "📦 DUNG LƯỢNG BẰNG CHỨNG ON-CHAIN (TOTAL)   : ${PROOF_BYTES} bytes"
echo "=========================================================="