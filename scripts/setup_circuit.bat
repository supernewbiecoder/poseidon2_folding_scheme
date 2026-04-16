@echo off
echo === BIEN DICH MACH ===
circom circuits/storage_batch_proof.circom --r1cs --wasm --sym

echo === KHOI TAO KHOA ZKP (GROTH16) ===
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v
snarkjs groth16 setup storage_batch_proof.r1cs pot12_final.ptau storage_batch_final.zkey
snarkjs zkey export verificationkey storage_batch_final.zkey verification_key.json

echo === HOAN TAT! ===