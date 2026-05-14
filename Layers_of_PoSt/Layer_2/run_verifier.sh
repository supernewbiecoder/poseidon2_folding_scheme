#!/bin/bash

# =====================================================================
# ENGRAM LAYER 2 VERIFIER RUNNER
# Usage: ./run_verifier.sh <DVN_ID> <EPOCH> [PROVER_ID]
# =====================================================================

DVN_ID=$1
EPOCH=$2
PROVER_ID=$3

# Kiểm tra tham số
if [ -z "$DVN_ID" ] || [ -z "$EPOCH" ]; then
    echo "❌ Usage: ./run_verifier.sh <DVN_ID> <EPOCH> [PROVER_ID]"
    echo "   Example: ./run_verifier.sh DVN_001 494072"
    echo "   Example: ./run_verifier.sh DVN_001 494072 1001"
    exit 1
fi

# Đường dẫn tuyệt đối đến thư mục hiện tại (nơi chứa script này)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔍 Verifier Runner"
echo "   Script dir: $SCRIPT_DIR"
echo "   DVN ID: $DVN_ID"
echo "   Epoch: $EPOCH"
if [ -n "$PROVER_ID" ]; then
    echo "   Prover ID: $PROVER_ID"
else
    echo "   Prover ID: (all provers)"
fi
echo ""

# Chạy cargo
cd "$SCRIPT_DIR"

if [ -n "$PROVER_ID" ]; then
    # Chạy với prover cụ thể
    echo "🚀 Running: cargo run -- $DVN_ID $EPOCH $PROVER_ID"
    cargo run -- "$DVN_ID" "$EPOCH" "$PROVER_ID"
else
    # Chạy cho tất cả prover
    echo "🚀 Running: cargo run -- $DVN_ID $EPOCH"
    cargo run -- "$DVN_ID" "$EPOCH"
fi

EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Verification completed successfully"
else
    echo "❌ Verification failed with exit code: $EXIT_CODE"
fi

exit $EXIT_CODE