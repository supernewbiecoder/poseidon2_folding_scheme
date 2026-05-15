//! Các hằng số toàn hệ thống Engram
use pasta_curves::pallas::Scalar as Fr;
use ff::Field;

/// Độ sâu của Merkle tree (số lần hash từ lá lên gốc)
/// Giá trị này phải khớp giữa DataSector (khi tạo Merkle tree) và PoStStepCircuit.
pub const MERKLE_DEPTH: usize = 23;   // 👈 TUỲ CHỈNH THEO THIẾT KẾ CỦA BẠN (có thể 2, 16, 32...)

/// Số lượng shard được thử thách trong mỗi epoch (thường là 2)
pub const NUM_CHALLENGES: usize = 460;

/// Kích thước mỗi shard (byte) – dùng để padding nếu cần
pub const SHARD_SIZE_BYTES: usize = 4096;

/// Trả về vector path_elements mẫu (dummy) có độ dài MERKLE_DEPTH,
/// dùng cho việc khởi tạo PublicParams.
pub fn dummy_path_elements() -> Vec<Fr> {
    vec![Fr::ZERO; MERKLE_DEPTH]
}

/// Trả về vector path_indices mẫu (dummy) có độ dài MERKLE_DEPTH.
pub fn dummy_path_indices() -> Vec<Fr> {
    vec![Fr::ZERO; MERKLE_DEPTH]
}