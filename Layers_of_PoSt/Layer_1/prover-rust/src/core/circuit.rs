use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;
use engram_common::MERKLE_DEPTH;
use pasta_curves::pallas::Scalar as Fr;
use ff::Field;
use sha2::{Digest, Sha256};
use crate::constants::{MAT_FULL, MAT_PARTIAL, RC, R_F, R_P, T};
use super::poseidon2::Poseidon2Gadget;

// Hàm băm Poseidon2 chạy trực tiếp (Native) bên ngoài mạch ZK
pub fn native_poseidon2(left: Fr, right: Fr) -> Fr {
    let mut state = [left, right, Fr::ZERO];
    let half_f = R_F / 2;
    let mut tmp = [Fr::ZERO; 3];
    for i in 0..T {
        for j in 0..T { tmp[i] += MAT_FULL[i][j] * state[j]; }
    }
    state = tmp;

    for r in 0..(R_F + R_P) {
        let is_full = r < half_f || r >= half_f + R_P;
        for i in 0..T { state[i] += RC[r][i]; }
        for i in 0..T {
            if is_full || i == 0 {
                let x2 = state[i].square();
                let x4 = x2.square();
                state[i] = x4 * state[i];
            }
        }
        let matrix = if is_full { &*MAT_FULL } else { &*MAT_PARTIAL };
        let mut tmp = [Fr::ZERO; 3];
        for i in 0..T {
            for j in 0..T { tmp[i] += matrix[i][j] * state[j]; }
        }
        state = tmp;
    }
    state[0]
}

#[derive(Clone, Debug)]
pub struct DataSector {
    pub raw_data: Vec<Fr>,
    pub leaves: Vec<Fr>,
    pub tree: Vec<Vec<Fr>>,
    pub commitment_root: Fr,
    pub prover_id: Fr,
    pub epoch: Fr,
}

impl DataSector {
    fn shard_text_to_field(shard_text: &str) -> Fr {
        let digest = Sha256::digest(shard_text.as_bytes());
        let mut limbs = [0u64; 4];
        for (index, chunk) in digest.chunks_exact(8).enumerate() {
            let mut limb_bytes = [0u8; 8];
            limb_bytes.copy_from_slice(chunk);
            limbs[index] = u64::from_le_bytes(limb_bytes);
        }
        Fr::from_raw(limbs)
    }

    pub fn new(raw_shards: Vec<String>, prover_id: Fr, epoch: Fr) -> Self {
        let original_data: Vec<Fr> = raw_shards.iter()
            .map(|s| Self::shard_text_to_field(s))
            .collect();
        let original_len = original_data.len();

        // Số lá cố định = 2^MERKLE_DEPTH
        let target_leaves = 1 << MERKLE_DEPTH;
        let iv = native_poseidon2(prover_id, epoch);

        // CBC sealing cho tất cả lá (kể cả padding)
        let mut leaves = Vec::with_capacity(target_leaves);
        let mut last_hash = iv;
        for i in 0..target_leaves {
            let data = if i < original_len { original_data[i] } else { Fr::ZERO };
            let current_s = native_poseidon2(last_hash, data);
            leaves.push(current_s);
            last_hash = current_s;
        }

        // Xây dựng Merkle tree với độ sâu cố định
        let mut tree = vec![leaves.clone()];
        let mut current_level = leaves.clone();
        // Cần MERKLE_DEPTH iterations để từ 2^MERKLE_DEPTH leaves tới 1 root
        for _ in 1..=MERKLE_DEPTH {
            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { Fr::ZERO };
                next_level.push(native_poseidon2(left, right));
            }
            tree.push(next_level.clone());
            current_level = next_level;
        }
        // Bây giờ current_level có 1 node, đó là root
        let commitment_root = current_level[0];

        Self {
            raw_data: original_data,
            leaves,
            tree,
            commitment_root,
            prover_id,
            epoch,
        }
    }

    pub fn get_proof(&self, index: usize) -> (Fr, Fr, Vec<Fr>, Vec<Fr>) {
        let prev_s = if index == 0 {
            native_poseidon2(self.prover_id, self.epoch)
        } else {
            self.leaves[index - 1]
        };
        let (data, path_elements, path_indices) = self.internal_get_path(index);
        (data, prev_s, path_elements, path_indices)
    }

    fn internal_get_path(&self, leaf_index: usize) -> (Fr, Vec<Fr>, Vec<Fr>) {
        let mut path_elements = Vec::with_capacity(MERKLE_DEPTH);
        let mut path_indices = Vec::with_capacity(MERKLE_DEPTH);
        let mut current_idx = leaf_index;
        for level in 0..MERKLE_DEPTH {
            let sibling_idx = if current_idx % 2 == 0 {
                current_idx + 1
            } else {
                current_idx - 1
            };
            let sibling = self.tree[level]
                .get(sibling_idx)
                .copied()
                .unwrap_or(Fr::ZERO);
            path_elements.push(sibling);
            path_indices.push(if current_idx % 2 == 1 { Fr::ONE } else { Fr::ZERO });
            current_idx /= 2;
        }
        let data = self.raw_data
            .get(leaf_index)
            .copied()
            .unwrap_or(Fr::ZERO);
        (data, path_elements, path_indices)
    }
}

#[derive(Clone, Debug)]
pub struct PoStStepCircuit {
    pub raw_data: Fr,
    pub prev_s: Fr,
    pub challenge_index: Fr,
    pub path_elements: Vec<Fr>,
    pub path_indices: Vec<Fr>,
}

impl StepCircuit<Fr> for PoStStepCircuit {
    fn arity(&self) -> usize { 2 }

    fn synthesize<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<Fr>],
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        let z_step_count = z_in[0].clone();
        let expected_root_var = z_in[1].clone();
        let zero_var = AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(Fr::ZERO))?;

        // CBC: Hash(prev_s, raw_data) == S_i
        let raw_data_var = AllocatedNum::alloc(cs.namespace(|| "raw_data"), || Ok(self.raw_data))?;
        let prev_s_var = AllocatedNum::alloc(cs.namespace(|| "prev_s"), || Ok(self.prev_s))?;

        let mut current_hash = {
            let mut cbc_ns = cs.namespace(|| "cbc_sealing");
            let mut hasher_cbc = Poseidon2Gadget::new(
                &mut cbc_ns,
                vec![prev_s_var.clone(), raw_data_var.clone(), zero_var.clone()],
            );
            hasher_cbc.hash()?[0].clone()
        };

        // Merkle path
        for i in 0..self.path_elements.len() {
            let sibling = AllocatedNum::alloc(
                cs.namespace(|| format!("sibling_{}", i)),
                || Ok(self.path_elements[i]),
            )?;
            let index = AllocatedNum::alloc(
                cs.namespace(|| format!("index_{}", i)),
                || Ok(self.path_indices[i]),
            )?;

            cs.enforce(
                || format!("index_is_bool_{}", i),
                |lc| lc + index.get_variable(),
                |lc| lc + CS::one() - index.get_variable(),
                |lc| lc,
            );

            // 2. Tính diff = sibling - current_hash
            let diff = AllocatedNum::alloc(
                cs.namespace(|| format!("diff_{}", i)),
                || {
                    let s = sibling.get_value().unwrap_or(Fr::ZERO);
                    let c = current_hash.get_value().unwrap_or(Fr::ZERO);
                    Ok(s - c)
                }
            )?;
            cs.enforce(
                || format!("enforce_diff_{}", i),
                |lc| lc + diff.get_variable() + current_hash.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + sibling.get_variable(),
            );

            // 3. Tính c_times_diff = index * diff
            let c_times_diff = AllocatedNum::alloc(
                cs.namespace(|| format!("c_times_diff_{}", i)),
                || {
                    let idx = index.get_value().unwrap_or(Fr::ZERO);
                    let d = diff.get_value().unwrap_or(Fr::ZERO);
                    Ok(idx * d)
                }
            )?;
            cs.enforce(
                || format!("enforce_c_times_diff_{}", i),
                |lc| lc + index.get_variable(),
                |lc| lc + diff.get_variable(),
                |lc| lc + c_times_diff.get_variable(),
            );

            // 4. left = current_hash + c_times_diff 
            // (Nếu index=0 => left = current_hash | Nếu index=1 => left = sibling)
            let left = AllocatedNum::alloc(
                cs.namespace(|| format!("left_{}", i)),
                || {
                    let c = current_hash.get_value().unwrap_or(Fr::ZERO);
                    let cd = c_times_diff.get_value().unwrap_or(Fr::ZERO);
                    Ok(c + cd)
                }
            )?;
            cs.enforce(
                || format!("enforce_left_{}", i),
                |lc| lc + current_hash.get_variable() + c_times_diff.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + left.get_variable(),
            );

            // 5. right = sibling - c_times_diff
            // (Nếu index=0 => right = sibling | Nếu index=1 => right = current_hash)
            let right = AllocatedNum::alloc(
                cs.namespace(|| format!("right_{}", i)),
                || {
                    let s = sibling.get_value().unwrap_or(Fr::ZERO);
                    let cd = c_times_diff.get_value().unwrap_or(Fr::ZERO);
                    Ok(s - cd)
                }
            )?;
            cs.enforce(
                || format!("enforce_right_{}", i),
                |lc| lc + sibling.get_variable() - c_times_diff.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + right.get_variable(),
            );

            current_hash = {
                let mut merkle_ns = cs.namespace(|| format!("merkle_step_{}", i));
                let mut hasher = Poseidon2Gadget::new(
                    &mut merkle_ns,
                    vec![left.clone(), right.clone(), zero_var.clone()],
                );
                hasher.hash()?[0].clone()
            };
        }

        // Enforce root match
        cs.enforce(
            || "root_match",
            |lc| lc + current_hash.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + expected_root_var.get_variable(),
        );

       let next_step = AllocatedNum::alloc(
            cs.namespace(|| "next_step"),
            || Ok(z_step_count.get_value().unwrap() + Fr::ONE),
        )?;
        
        // ✅ TRẢ VỀ current_hash MỚI VỪA ĐƯỢC TÍNH RA
        Ok(vec![next_step, current_hash])
    }
}