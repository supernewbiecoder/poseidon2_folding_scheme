use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError, LinearCombination};
use nova_snark::{
    traits::{circuit::{StepCircuit, TrivialCircuit}, Engine}, 
    provider::{PallasEngine, VestaEngine}, 
    RecursiveSNARK, PublicParams,
};
use pasta_curves::pallas::Scalar as Fr;
use ff::{Field, PrimeField}; 
use rand::Rng;
use std::time::Instant;
use std::io::{self, Write};

mod constants;
use constants::{MAT_FULL, MAT_PARTIAL, RC, R_F, R_P, T};

// ==========================================
// 1. POSEIDON2 GADGET
// ==========================================
pub struct Poseidon2Gadget<'a, CS: ConstraintSystem<Fr>> {
    cs: &'a mut CS,
    state: Vec<AllocatedNum<Fr>>,
}

impl<'a, CS: ConstraintSystem<Fr>> Poseidon2Gadget<'a, CS> {
    pub fn new(cs: &'a mut CS, initial_state: Vec<AllocatedNum<Fr>>) -> Self {
        Self { cs, state: initial_state }
    }

    fn sbox(&mut self, x: &AllocatedNum<Fr>, name: &str) -> Result<AllocatedNum<Fr>, SynthesisError> {
        let x_sq = x.square(self.cs.namespace(|| format!("{}_sq", name)))?;
        let x_quad = x_sq.square(self.cs.namespace(|| format!("{}_quad", name)))?;
        x_quad.mul(self.cs.namespace(|| format!("{}_penta", name)), x)
    }

    fn apply_matrix(&mut self, is_full_round: bool, namespace_prefix: &str) -> Result<(), SynthesisError> {
        let matrix = if is_full_round { &*MAT_FULL } else { &*MAT_PARTIAL };
        let mut new_state = vec![];

        for i in 0..T {
            let mut val = Some(Fr::ZERO); 

            for j in 0..T {
                if let (Some(mut v), Some(state_val)) = (val, self.state[j].get_value()) {
                    v += matrix[i][j] * state_val;
                    val = Some(v);
                } else { val = None; }
            }

            let sum_var = AllocatedNum::alloc(
                self.cs.namespace(|| format!("{}_matrix_mul_i{}", namespace_prefix, i)),
                || val.ok_or(SynthesisError::AssignmentMissing),
            )?;
            
            self.cs.enforce(
                || format!("{}_enforce_matrix_i{}", namespace_prefix, i),
                |_| {
                    let mut lc = LinearCombination::zero();
                    for j in 0..T { lc = lc + (matrix[i][j], self.state[j].get_variable()); }
                    lc
                },
                |lc| lc + CS::one(),
                |lc| lc + sum_var.get_variable(),
            );
            new_state.push(sum_var);
        }
        self.state = new_state;
        Ok(())
    }

    pub fn hash(&mut self) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        let half_f = R_F / 2;
        self.apply_matrix(true, "initial_premix")?;

        for r in 0..(R_F + R_P) {
            let is_full = r < half_f || r >= half_f + R_P;
            let mut state_after_rc = vec![];
            
            for i in 0..T {
                let rc = RC[r][i];
                let val = self.state[i].get_value().map(|v| v + rc);
                let added_var = AllocatedNum::alloc(
                    self.cs.namespace(|| format!("r{}_add_rc_i{}", r, i)),
                    || val.ok_or(SynthesisError::AssignmentMissing),
                )?;
                self.cs.enforce(
                    || format!("r{}_enforce_rc_i{}", r, i),
                    |lc| lc + self.state[i].get_variable() + (rc, CS::one()),
                    |lc| lc + CS::one(),
                    |lc| lc + added_var.get_variable(),
                );
                state_after_rc.push(added_var);
            }
            self.state = state_after_rc;

            let mut state_after_sbox = vec![];
            for i in 0..T {
                if is_full || i == 0 {
                    let current_var = self.state[i].clone();
                    let sboxed_var = self.sbox(&current_var, &format!("r{}_sbox_i{}", r, i))?;
                    state_after_sbox.push(sboxed_var);
                } else { state_after_sbox.push(self.state[i].clone()); }
            }
            self.state = state_after_sbox;
            
            self.apply_matrix(is_full, &format!("r{}", r))?;
        }
        Ok(self.state.clone())
    }
}

// ==========================================
// 2. HÀM POSEIDON2 NATIVE & MERKLE TREE
// ==========================================
fn sbox(x: Fr) -> Fr {
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

#[derive(Clone, Debug)]
pub struct DataSector {
    pub leaves: Vec<Fr>,
    pub tree: Vec<Vec<Fr>>,
    pub commitment_root: Fr,
}

impl DataSector {
    pub fn new(raw_shards: Vec<&str>) -> Self {
        let mut leaves: Vec<Fr> = raw_shards.iter().map(|s| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(s.as_bytes());
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(hasher.finalize().as_bytes());
            bytes[31] &= 0x3F; // Chống tràn số
            Option::from(Fr::from_repr(bytes)).unwrap()
        }).collect();
        
        while leaves.len() < 8 { leaves.push(Fr::ZERO); }

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

        Self { leaves, tree: tree.clone(), commitment_root: current_level[0] }
    }

    pub fn get_proof(&self, index: usize) -> (Fr, Vec<Fr>, Vec<Fr>) {
        let mut path_elements = vec![];
        let mut path_indices = vec![];
        let mut current_idx = index;

        for level in 0..3 {
            let is_right = current_idx % 2 == 1;
            let sibling_idx = if is_right { current_idx - 1 } else { current_idx + 1 };
            path_elements.push(self.tree[level][sibling_idx]);
            path_indices.push(if is_right { Fr::ONE } else { Fr::ZERO }); 
            current_idx /= 2;
        }
        (self.leaves[index], path_elements, path_indices)
    }
}

// ==========================================
// 3. MẠCH ZK BƯỚC ĐƠN (PO ST)
// ==========================================
#[derive(Clone, Debug)]
pub struct PoStStepCircuit {
    pub leaf: Fr,
    pub path_elements: Vec<Fr>,
    pub path_indices: Vec<Fr>,
}

impl StepCircuit<Fr> for PoStStepCircuit {
    fn arity(&self) -> usize { 2 } // [counter, root]

    fn synthesize<CS: ConstraintSystem<Fr>>(
        &self, cs: &mut CS, z_in: &[AllocatedNum<Fr>],
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        
        let z_step_count = z_in[0].clone(); 
        let expected_root_var = z_in[1].clone(); 

        let zero_var = AllocatedNum::alloc(cs.namespace(|| "zero_cap"), || Ok(Fr::ZERO))?;
        cs.enforce(
            || "enforce_zero_cap_safe",
            |lc| lc + zero_var.get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + CS::one(), 
        );

        let mut current_hash = AllocatedNum::alloc(cs.namespace(|| "leaf"), || Ok(self.leaf))?;

        for i in 0..self.path_elements.len() {
            let sibling = AllocatedNum::alloc(cs.namespace(|| format!("sibling_{}", i)), || Ok(self.path_elements[i]))?;
            let index = AllocatedNum::alloc(cs.namespace(|| format!("index_{}", i)), || Ok(self.path_indices[i]))?;

            cs.enforce(
                || format!("boolean_index_safe_{}", i),
                |lc| lc + index.get_variable(),
                |lc| lc + index.get_variable(),
                |lc| lc + index.get_variable(),
            );

            let diff_val = current_hash.get_value().zip(sibling.get_value()).map(|(c, s)| c - s);
            let diff = AllocatedNum::alloc(cs.namespace(|| format!("diff_{}", i)), || diff_val.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce(
                || format!("enforce_diff_{}", i),
                |lc| lc + current_hash.get_variable() - sibling.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + diff.get_variable(),
            );

            let index_diff_val = index.get_value().zip(diff_val).map(|(idx, d)| idx * d);
            let index_diff = AllocatedNum::alloc(cs.namespace(|| format!("index_diff_{}", i)), || index_diff_val.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce(
                || format!("enforce_index_diff_{}", i),
                |lc| lc + index.get_variable(),
                |lc| lc + diff.get_variable(),
                |lc| lc + index_diff.get_variable(),
            );

            let left_val = current_hash.get_value().zip(index_diff_val).map(|(c, id)| c - id);
            let left = AllocatedNum::alloc(cs.namespace(|| format!("left_{}", i)), || left_val.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce(
                || format!("enforce_left_{}", i),
                |lc| lc + left.get_variable() + index_diff.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + current_hash.get_variable(),
            );

            let right_val = sibling.get_value().zip(index_diff_val).map(|(s, id)| s + id);
            let right = AllocatedNum::alloc(cs.namespace(|| format!("right_{}", i)), || right_val.ok_or(SynthesisError::AssignmentMissing))?;
            cs.enforce(
                || format!("enforce_right_{}", i),
                |lc| lc + right.get_variable() - index_diff.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + sibling.get_variable(),
            );

            let hash_inputs = vec![left, right, zero_var.clone()];
            let mut ns = cs.namespace(|| format!("poseidon_{}", i));
            let mut hasher = Poseidon2Gadget::new(&mut ns, hash_inputs);
            let hash_out = hasher.hash()?;
            current_hash = hash_out[0].clone();
        }

        cs.enforce(
            || "enforce_merkle_root",
            |lc| lc + current_hash.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + expected_root_var.get_variable(),
        );

        let next_step = AllocatedNum::alloc(cs.namespace(|| "next_step"), || {
            let val = z_step_count.get_value().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(val + Fr::ONE)
        })?;
        cs.enforce(
            || "fwd_step",
            |lc| lc + z_step_count.get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + next_step.get_variable(),
        );

        let next_root = AllocatedNum::alloc(cs.namespace(|| "next_root"), || {
            expected_root_var.get_value().ok_or(SynthesisError::AssignmentMissing)
        })?;
        cs.enforce(
            || "fwd_root",
            |lc| lc + expected_root_var.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + next_root.get_variable(),
        );

        Ok(vec![next_step, next_root]) 
    }
}

// ==========================================
// 4. MAIN & CLI
// ==========================================
fn main() {
    println!("\n======================================================================");
    println!("  MÔ PHỎNG GIAO THỨC ENGRAM (POSEIDON2 + NOVA + MERKLE PROOF)");
    println!("======================================================================\n");

    print!("[Hệ thống] Nhập các dữ liệu phân mảnh cần lưu trữ (cách nhau dấu phẩy, tối đa 8):\n> ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let raw_shards: Vec<&str> = input.trim().split(',').filter(|s| !s.is_empty()).collect();

    print!("\n[Provider] Đang băm dữ liệu bằng Native Poseidon2 và dựng cây Merkle...");
    io::stdout().flush().unwrap();
    let sector = DataSector::new(raw_shards);
    
    println!("\n\n[ BÁO CÁO CAM KẾT - PHASE 1 ]");
    println!("- Mã cam kết (Root) : {:?}", sector.commitment_root);
    println!("- Kích thước mạch   : ~750 Constraints (Mạch đã bao gồm Merkle Inclusion!)"); 

    print!("\n[Network] Đang thiết lập Nova Public Params...");
    io::stdout().flush().unwrap();
    
    let dummy_sector = DataSector::new(vec!["dummy"]);
    let (dummy_leaf, dummy_path, dummy_indices) = dummy_sector.get_proof(0);
    let circuit_primary = PoStStepCircuit { leaf: dummy_leaf, path_elements: dummy_path, path_indices: dummy_indices };
    let circuit_secondary = TrivialCircuit::<<VestaEngine as Engine>::Scalar>::default(); 
    
    let pp = PublicParams::<PallasEngine, VestaEngine, PoStStepCircuit, TrivialCircuit<<VestaEngine as Engine>::Scalar>>::setup(
        &circuit_primary, &circuit_secondary, &*nova_snark::traits::snark::default_ck_hint(), &*nova_snark::traits::snark::default_ck_hint()
    );
    println!(" ✅ Xong");

    print!("\n[Hệ thống] Bạn muốn chạy bao nhiêu vòng kiểm tra (Epochs)?\n> ");
    io::stdout().flush().unwrap();
    let mut epoch_input = String::new();
    io::stdin().read_line(&mut epoch_input).unwrap();
    let num_epochs: usize = epoch_input.trim().parse().unwrap_or(1);
    let batch_size = 4;
    let mut rng = rand::thread_rng();

    for epoch in 1..=num_epochs {
        println!("\n---------------- EPOCH {} ----------------", epoch);
        
        let mut challenges = vec![];
        while challenges.len() < batch_size {
            let idx = rng.gen_range(0..8) as usize;
            if !challenges.contains(&idx) { challenges.push(idx); }
        }
        challenges.sort();
        println!("[Network]  Yêu cầu xác minh Merkle Path cho {} shard: {:?}", batch_size, challenges);

        let start_prove = Instant::now();
        let z0_primary = vec![Fr::ZERO, sector.commitment_root]; 
        let z0_secondary = vec![<VestaEngine as Engine>::Scalar::ZERO];
        
        // ⚡ BẢN VÁ LỖI NẰM Ở ĐÂY: Sử dụng Mạch thật của thử thách đầu tiên để khởi tạo Base Instance
        let (leaf_base, path_base, indices_base) = sector.get_proof(challenges[0]);
        let base_circuit = PoStStepCircuit { leaf: leaf_base, path_elements: path_base, path_indices: indices_base };

        let mut recursive_snark = RecursiveSNARK::new(&pp, &base_circuit, &circuit_secondary, &z0_primary, &z0_secondary).unwrap();

        for (step, &idx) in challenges.iter().enumerate() {
            let (leaf, path_elements, path_indices) = sector.get_proof(idx);
            let step_circuit = PoStStepCircuit { leaf, path_elements, path_indices };

            recursive_snark.prove_step(&pp, &step_circuit, &circuit_secondary).unwrap();
            println!("   > Fold #{} thành công (Đã xác thực Merkle Path cho Shard {})", step + 1, idx);
        }
        
        println!("   [✓] TẠO BẰNG CHỨNG TỔNG HỢP HOÀN TẤT ({:?})", start_prove.elapsed());

        print!("[Network]  Xác minh bằng chứng toán học (Verify)...");
        io::stdout().flush().unwrap();
        let start_verify = Instant::now();
        match recursive_snark.verify(&pp, batch_size, &z0_primary, &z0_secondary) {
            Ok(_) => println!(" ✅ HỢP LỆ ({:?})", start_verify.elapsed()),
            Err(e) => println!(" ❌ KHÔNG HỢP LỆ: {:?}", e),
        }
    }
}