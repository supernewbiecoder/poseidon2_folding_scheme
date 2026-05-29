use crate::poseidon2::hash_2;
use pasta_curves::pallas::Scalar as Fr;
use rayon::prelude::*;

#[derive(Clone)] // <--- Thêm dòng này
pub struct MerkleTree {
    pub leaves: Vec<Fr>,
    pub nodes: Vec<Vec<Fr>>,
    pub root: Fr,
}

#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub siblings: Vec<Fr>,
    pub path_indices: Vec<bool>, // true = right, false = left
}

impl MerkleTree {
    /// Xây dựng cây từ danh sách Replica và State.
    /// Khắc phục kịch bản tấn công 3: Bắt buộc commit cả S_i
    pub fn build(sealed_chunks: &[(Fr, Fr)]) -> Self {
        assert!(!sealed_chunks.is_empty() && sealed_chunks.len().is_power_of_two(), "Số lượng chunk phải là lũy thừa của 2");

        // Tầng lá: Băm gộp R_i và S_i
        let leaves: Vec<Fr> = sealed_chunks.par_iter()
            .map(|(r_i, s_i)| hash_2(*r_i, *s_i))
            .collect();

        let mut nodes = vec![leaves.clone()];
        let mut current_level = leaves.clone();

        while current_level.len() > 1 {
            let next_level: Vec<Fr> = current_level.par_chunks(2)
                .map(|chunk| hash_2(chunk[0], chunk[1]))
                .collect();
            nodes.push(next_level.clone());
            current_level = next_level;
        }

        Self {
            leaves,
            nodes: nodes.clone(),
            root: nodes.last().unwrap()[0],
        }
    }

    /// Sinh bằng chứng cho một index, sinh ra merkle path từ lá lên gốc
    pub fn generate_proof(&self, mut index: usize) -> MerkleProof {
        let leaf_index = index;
        let mut siblings = Vec::new();
        let mut path_indices = Vec::new();

        for level in &self.nodes[..self.nodes.len() - 1] {
            let is_right = index % 2 == 1;
            path_indices.push(is_right);

            let sibling_index = if is_right { index - 1 } else { index + 1 };
            siblings.push(level[sibling_index]);

            index /= 2;
        }

        MerkleProof { leaf_index, siblings, path_indices }
    }
}

/// Verifier độc lập (Mô phỏng logic sẽ viết trong Circuit)
pub fn verify_merkle_proof(root: Fr, leaf_r: Fr, leaf_s: Fr, proof: &MerkleProof) -> bool {
    if proof.siblings.len() != proof.path_indices.len() {
        return false;
    }

    let expected_path_indices: Vec<bool> = (0..proof.path_indices.len())
        .map(|level| ((proof.leaf_index >> level) & 1) == 1)
        .collect();
    if expected_path_indices != proof.path_indices {
        return false;
    }

    // 1. Tính lại lá
    let mut current_hash = hash_2(leaf_r, leaf_s);

    // 2. Băm ngược lên gốc
    for (sibling, is_right) in proof.siblings.iter().zip(proof.path_indices.iter()) {
        if *is_right {
            current_hash = hash_2(*sibling, current_hash); // Mình là node phải
        } else {
            current_hash = hash_2(current_hash, *sibling); // Mình là node trái
        }
    }

    current_hash == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_proof_verifies_for_matching_leaf_index() {
        let tree = MerkleTree::build(&[
            (Fr::from(1u64), Fr::from(10u64)),
            (Fr::from(2u64), Fr::from(20u64)),
            (Fr::from(3u64), Fr::from(30u64)),
            (Fr::from(4u64), Fr::from(40u64)),
        ]);

        let proof = tree.generate_proof(2);
        assert!(verify_merkle_proof(
            tree.root,
            Fr::from(3u64),
            Fr::from(30u64),
            &proof,
        ));
    }

    #[test]
    fn merkle_proof_rejects_tampered_index_binding() {
        let tree = MerkleTree::build(&[
            (Fr::from(1u64), Fr::from(10u64)),
            (Fr::from(2u64), Fr::from(20u64)),
            (Fr::from(3u64), Fr::from(30u64)),
            (Fr::from(4u64), Fr::from(40u64)),
        ]);

        let mut proof = tree.generate_proof(2);
        proof.leaf_index = 1;
        assert!(!verify_merkle_proof(
            tree.root,
            Fr::from(3u64),
            Fr::from(30u64),
            &proof,
        ));
    }
}