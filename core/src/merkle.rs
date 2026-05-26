use pasta_curves::pallas::Scalar as Fr;
use crate::poseidon2::hash_2;

/// Lộ trình xác thực Merkle (Merkle Inclusion Path)
#[derive(Debug, Clone)]
pub struct MerklePath {
    /// Danh sách các node anh em trên lộ trình từ lá lên gốc
    pub siblings: Vec<Fr>,
    /// Bit định hướng (trái/phải) cho mỗi bước
    pub indices: Vec<bool>,
}

/// Tính toán gốc Merkle Root (R_sealed) từ danh sách các lá dữ liệu
pub fn compute_merkle_root(leaves: &[Fr]) -> Fr {
    if leaves.is_empty() {
        return Fr::ZERO;
    }
    
    let mut current_level = leaves.to_vec();
    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                next_level.push(hash_2(chunk[0], chunk[1]));
            } else {
                // Xử lý node lẻ (duplicate node lẻ hoặc padding)
                next_level.push(hash_2(chunk[0], chunk[0]));
            }
        }
        current_level = next_level;
    }
    
    current_level[0]
}

/// Xác thực path_check: MerkleVerify(R_{j_i}, path_{j_i}, j_i, R_sealed) = 1
pub fn verify_merkle_path(root: Fr, leaf: Fr, path: &MerklePath) -> bool {
    let mut current_hash = leaf;

    for (sibling, &is_right_child) in path.siblings.iter().zip(path.indices.iter()) {
        if is_right_child {
            current_hash = hash_2(*sibling, current_hash);
        } else {
            current_hash = hash_2(current_hash, *sibling);
        }
    }

    current_hash == root
}