#!/bin/bash

# =====================================================================
# ENGRAM LAYER 2 VERIFIER RUNNER (WSL Optimized)
# Usage: ./run_verifier.sh <DVN_ID> <EPOCH> [PROVER_ID]
# =====================================================================

# 🌟 NẠP MÔI TRƯỜNG RUST (FIX LỖI CARGO NOT FOUND)
if [ -f "$HOME/.cargo/env" ]; then
    source "$HOME/.cargo/env"
else
    export PATH="$HOME/.cargo/bin:$PATH"
fi

DVN_ID=$1
EPOCH=$2
PROVER_ID=$3

# 1. Kiểm tra tham số đầu vào
if [ -z "$DVN_ID" ] || [ -z "$EPOCH" ]; then
    echo "❌ Lỗi: Thiếu tham số!"
    echo "   Sử dụng: ./run_verifier.sh <DVN_ID> <EPOCH> [PROVER_ID]"
    exit 1
fi

# 2. Định vị thư mục làm việc
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "--------------------------------------------------"
echo "🛰️  Engram Verifier Bridge (WSL Mode)"
echo "   DVN Node: $DVN_ID"
echo "   Epoch:    $EPOCH"
[ -n "$PROVER_ID" ] && echo "   Target:   Prover $PROVER_ID"
echo "--------------------------------------------------"

# 3. Thực thi Cargo
if [ -n "$PROVER_ID" ]; then
    cargo run -- "$DVN_ID" "$EPOCH" "$PROVER_ID"
else
    cargo run -- "$DVN_ID" "$EPOCH"
fi

EXIT_CODE=$?

# 4. Trả về kết quả cho Python
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ [WSL] Xác minh hoàn tất thành công."
else
    echo "❌ [WSL] Lỗi thực thi Cargo (Exit code: $EXIT_CODE)"
fi

exit $EXIT_CODE