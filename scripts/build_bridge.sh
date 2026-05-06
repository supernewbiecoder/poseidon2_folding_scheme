#!/bin/bash
set -e

echo "=========================================================="
echo "🚀 KHỞI ĐỘNG HỆ THỐNG PROOF-OF-SPACETIME TỰ ĐỘNG"
echo "=========================================================="

echo -n "Nhập dữ liệu phân mảnh thực tế (VD: thucpham1,thucpham2...): "
read user_input

# 1. CHẠY RUST PROVER (Tính toán nặng)
echo -e "\n[1/3] ĐANG CHẠY NOVA FOLDING & SPARTAN COMPRESSION..."
cd prover-rust
# Ép dữ liệu đầu vào qua stdin để Rust tự đọc
echo "$user_input" | cargo run --release

# 2. BIÊN DỊCH CIRCOM (Cầu nối Blockchain)
echo -e "\n[2/3] ĐANG BIÊN DỊCH MẠCH GROTH16 (ON-CHAIN BRIDGE)..."
cd ../circuits-circom
circom spartan_wrapper.circom --r1cs --wasm

# Tự động setup nếu thiếu hoặc nếu circuit/R1CS đổi
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

if needs_rebuild "circuit_final.zkey" "spartan_wrapper.r1cs" || needs_rebuild "verification_key.json" "circuit_final.zkey"; then
    echo "  -> Đang tạo Trusted Setup hoặc đồng bộ lại verification key..."
    if [ ! -f pot12_0000.ptau ] || [ ! -f pot12_final.ptau ]; then
        snarkjs powersoftau new bn128 12 pot12_0000.ptau -v > /dev/null
        snarkjs powersoftau prepare phase2 pot12_0000.ptau pot12_final.ptau -v > /dev/null
    fi
    snarkjs groth16 setup spartan_wrapper.r1cs pot12_final.ptau circuit_final.zkey > /dev/null
    snarkjs zkey export verificationkey circuit_final.zkey verification_key.json > /dev/null
fi

# 3. SINH BẰNG CHỨNG 300 BYTES
echo -e "\n[3/3] ĐANG NÉN THÀNH GROTH16 (256-300 Bytes)..."
node spartan_wrapper_js/generate_witness.js spartan_wrapper_js/spartan_wrapper.wasm input.json witness.wtns
snarkjs groth16 prove circuit_final.zkey witness.wtns proof.json public.json > /dev/null

echo -e "\n=========================================================="
echo "✅ HOÀN TẤT! BẰNG CHỨNG ON-CHAIN ĐÃ ĐƯỢC SINH RA."
echo "Dung lượng bằng chứng:"
wc -c < proof.json | awk '{print $1 " bytes"}'
echo "=========================================================="