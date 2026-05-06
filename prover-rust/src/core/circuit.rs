use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError, LinearCombination};
use nova_snark::traits::circuit::StepCircuit;
use pasta_curves::pallas::Scalar as Fr;
use ff::Field;
use sha2::{Digest, Sha256};
use crate::constants::{MAT_FULL, MAT_PARTIAL, RC, R_F, R_P, T};
use super::poseidon2::Poseidon2Gadget;

pub fn sbox(x: Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

pub fn native_poseidon2(left: Fr, right: Fr) -> Fr {
    let mut state = [left, right, Fr::ZERO];
    let half_f = R_F / 2;
    let mut new_state = [Fr::ZERO; 3];
    for i in 0..T {
        for j in 0..T { new_state[i] += MAT_FULL[i][j] * state[j]; }
    }
    state = new_state;
    for r in 0..(R_F + R_P) {
        let is_full = r < half_f || r >= half_f + R_P;
        for i in 0..T { state[i] += RC[r][i]; }
        for i in 0..T {
            if is_full || i == 0 { state[i] = sbox(state[i]); }
        }
        let matrix = if is_full { &*MAT_FULL } else { &*MAT_PARTIAL };
        let mut new_state = [Fr::ZERO; 3];
        for i in 0..T {
            for j in 0..T { new_state[i] += matrix[i][j] * state[j]; }
        }
        state = new_state;
    }
    state[0]
}

#[allow(dead_code)] // <-- THÊM DÒNG NÀY ĐỂ TẮT CẢNH BÁO
#[derive(Clone, Debug)]
pub struct DataSector {
    pub raw_data: Vec<Fr>, 
    pub leaves: Vec<Fr>,
    pub tree: Vec<Vec<Fr>>,
    pub commitment_root: Fr,
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

    pub fn new(raw_shards: Vec<String>) -> Self {
        let mut raw_data: Vec<Fr> = raw_shards
            .iter()
            .map(|s| Self::shard_text_to_field(s))
            .collect();
        let target_len = raw_data.len().max(1).next_power_of_two();
        while raw_data.len() < target_len { raw_data.push(Fr::ZERO); }
        let leaves: Vec<Fr> = raw_data.iter().map(|&data| native_poseidon2(data, Fr::ZERO)).collect();
        let mut tree = vec![leaves.clone()];
        let mut current_level = leaves.clone();
        while current_level.len() > 1 {
            let mut next_level = vec![];
            for i in (0..current_level.len()).step_by(2) {
                next_level.push(native_poseidon2(current_level[i], current_level[i+1]));
            }
            tree.push(next_level.clone());
            current_level = next_level;
        }
        Self { raw_data, leaves, tree: tree.clone(), commitment_root: current_level[0] }
    }

    pub fn get_proof(&self, index: usize) -> (Fr, Vec<Fr>, Vec<Fr>) {
        let mut path_elements = vec![];
        let mut path_indices = vec![];
        let mut current_idx = index;
        let proof_depth = self.tree.len().saturating_sub(1);
        for level in 0..proof_depth {
            let is_right = current_idx % 2 == 1;
            let sibling_idx = if is_right { current_idx - 1 } else { current_idx + 1 };
            path_elements.push(self.tree[level][sibling_idx]);
            path_indices.push(if is_right { Fr::ONE } else { Fr::ZERO }); 
            current_idx /= 2;
        }
        (self.raw_data[index], path_elements, path_indices) 
    }
}

#[derive(Clone, Debug)]
pub struct PoStStepCircuit {
    pub raw_data: Fr,          
    pub challenge_index: Fr,   
    pub path_elements: Vec<Fr>,
    pub path_indices: Vec<Fr>,
}

impl StepCircuit<Fr> for PoStStepCircuit {
    fn arity(&self) -> usize { 2 } 

    fn synthesize<CS: ConstraintSystem<Fr>>(&self, cs: &mut CS, z_in: &[AllocatedNum<Fr>]) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        let z_step_count = z_in[0].clone(); 
        let expected_root_var = z_in[1].clone(); 
        let zero_var = AllocatedNum::alloc(cs.namespace(|| "zero_cap"), || Ok(Fr::ZERO))?;
        cs.enforce(|| "enforce_zero_cap_safe", |lc| lc + zero_var.get_variable() + CS::one(), |lc| lc + CS::one(), |lc| lc + CS::one());

        let raw_data_var = AllocatedNum::alloc(cs.namespace(|| "raw_data"), || Ok(self.raw_data))?;
        let hash_leaf_inputs = vec![raw_data_var, zero_var.clone(), zero_var.clone()];
        
        let leaf_out = {
            let mut ns_leaf = cs.namespace(|| "hash_leaf");
            let mut hasher_leaf = Poseidon2Gadget::new(&mut ns_leaf, hash_leaf_inputs);
            hasher_leaf.hash()?
        };
        let mut current_hash = leaf_out[0].clone();

        let expected_index_var = AllocatedNum::alloc(cs.namespace(|| "expected_index"), || Ok(self.challenge_index))?;
        let mut reconstructed_index_lc = LinearCombination::zero();
        let mut multiplier = Fr::ONE;

        for i in 0..self.path_elements.len() {
            let sibling = AllocatedNum::alloc(cs.namespace(|| format!("sibling_{}", i)), || Ok(self.path_elements[i]))?;
            let index = AllocatedNum::alloc(cs.namespace(|| format!("index_{}", i)), || Ok(self.path_indices[i]))?;
            cs.enforce(|| format!("boolean_index_safe_{}", i), |lc| lc + index.get_variable(), |lc| lc + index.get_variable(), |lc| lc + index.get_variable());
            reconstructed_index_lc = reconstructed_index_lc + (multiplier, index.get_variable());
            multiplier = multiplier * Fr::from(2u64);

            let diff_val = current_hash.get_value().zip(sibling.get_value()).map(|(c, s)| c - s);
            let diff = AllocatedNum::alloc(cs.namespace(|| format!("diff_{}", i)), || diff_val.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce(|| format!("enforce_diff_{}", i), |lc| lc + current_hash.get_variable() - sibling.get_variable(), |lc| lc + CS::one(), |lc| lc + diff.get_variable());

            let index_diff_val = index.get_value().zip(diff_val).map(|(idx, d)| idx * d);
            let index_diff = AllocatedNum::alloc(cs.namespace(|| format!("index_diff_{}", i)), || index_diff_val.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce(|| format!("enforce_index_diff_{}", i), |lc| lc + index.get_variable(), |lc| lc + diff.get_variable(), |lc| lc + index_diff.get_variable());

            let left_val = current_hash.get_value().zip(index_diff_val).map(|(c, id)| c - id);
            let left = AllocatedNum::alloc(cs.namespace(|| format!("left_{}", i)), || left_val.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce(|| format!("enforce_left_{}", i), |lc| lc + left.get_variable() + index_diff.get_variable(), |lc| lc + CS::one(), |lc| lc + current_hash.get_variable());

            let right_val = sibling.get_value().zip(index_diff_val).map(|(s, id)| s + id);
            let right = AllocatedNum::alloc(cs.namespace(|| format!("right_{}", i)), || right_val.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce(|| format!("enforce_right_{}", i), |lc| lc + right.get_variable() - index_diff.get_variable(), |lc| lc + CS::one(), |lc| lc + sibling.get_variable());

            let hash_inputs = vec![left, right, zero_var.clone()];
            let mut ns = cs.namespace(|| format!("poseidon_{}", i));
            let mut hasher = Poseidon2Gadget::new(&mut ns, hash_inputs);
            let hash_out = hasher.hash()?;
            current_hash = hash_out[0].clone();
        }

        cs.enforce(|| "enforce_challenge_index_match", |lc| lc + &reconstructed_index_lc, |lc| lc + CS::one(), |lc| lc + expected_index_var.get_variable());
        cs.enforce(|| "enforce_merkle_root", |lc| lc + current_hash.get_variable(), |lc| lc + CS::one(), |lc| lc + expected_root_var.get_variable());

        let next_step = AllocatedNum::alloc(cs.namespace(|| "next_step"), || { Ok(z_step_count.get_value().ok_or(SynthesisError::AssignmentMissing)? + Fr::ONE) })?;
        cs.enforce(|| "fwd_step", |lc| lc + z_step_count.get_variable() + CS::one(), |lc| lc + CS::one(), |lc| lc + next_step.get_variable());
        let next_root = AllocatedNum::alloc(cs.namespace(|| "next_root"), || { expected_root_var.get_value().ok_or(SynthesisError::AssignmentMissing) })?;
        cs.enforce(|| "fwd_root", |lc| lc + expected_root_var.get_variable(), |lc| lc + CS::one(), |lc| lc + next_root.get_variable());

        Ok(vec![next_step, next_root]) 
    }
}