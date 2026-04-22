use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError, LinearCombination};
use bellpepper_core::test_cs::TestConstraintSystem;
use nova_snark::{
    traits::{circuit::{StepCircuit, TrivialCircuit}, Engine}, 
    provider::{PallasEngine, VestaEngine, ipa_pc::EvaluationEngine}, 
    spartan::snark::RelaxedR1CSSNARK,
    RecursiveSNARK, CompressedSNARK, PublicParams,
};
use pasta_curves::pallas::Scalar as Fr;
use ff::{Field, PrimeField}; 
use rand::Rng;
use std::time::Instant;
use std::io::{self, Write};
use std::thread;
use std::time::Duration;
use bincode;

mod constants;
use constants::{MAT_FULL, MAT_PARTIAL, RC, R_F, R_P, T};

// ==========================================
// MÔ PHỎNG LỚP OUTER WRAPPER (GROTH16 / ON-CHAIN)
// ==========================================
pub mod groth16_wrapper {
    #[derive(Clone, Debug)]
    pub struct Groth16Proof {
        pub pi_a: [u8; 64],  // Điểm G1
        pub pi_b: [u8; 128], // Điểm G2
        pub pi_c: [u8; 64],  // Điểm G1
    }

    pub struct Groth16Wrapper;

    impl Groth16Wrapper {
        pub fn mock_prove() -> Groth16Proof {
            // Trong thực tế, quá trình này gọi mạch Circom/Halo2 để verify proof của Nova
            // và sinh ra 3 điểm trên đường cong BN254.
            Groth16Proof {
                pi_a: [1u8; 64],
                pi_b: [2u8; 128],
                pi_c: [3u8; 64],
            }
        }
    }
}
use groth16_wrapper::*;

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

// ==========================================
// 3. CẤU TRÚC DỮ LIỆU & MẠCH BẰNG CHỨNG
// ==========================================
#[derive(Clone, Debug)]
pub struct DataSector {
    pub raw_data: Vec<Fr>, 
    pub leaves: Vec<Fr>,
    pub tree: Vec<Vec<Fr>>,
    pub commitment_root: Fr,
}

impl DataSector {
    pub fn new(raw_shards: Vec<&str>) -> Self {
        let mut raw_data: Vec<Fr> = raw_shards.iter().map(|s| {
            let mut bytes = [0u8; 32];
            let s_bytes = s.as_bytes();
            let len = std::cmp::min(s_bytes.len(), 31);
            bytes[..len].copy_from_slice(&s_bytes[..len]);
            Option::from(Fr::from_repr(bytes)).expect("Lỗi chuyển đổi dữ liệu")
        }).collect();
        
        while raw_data.len() < 8 { raw_data.push(Fr::ZERO); }

        let leaves: Vec<Fr> = raw_data.iter().map(|&data| {
            native_poseidon2(data, Fr::ZERO)
        }).collect();

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

        for level in 0..3 {
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

            cs.enforce(
                || format!("boolean_index_safe_{}", i),
                |lc| lc + index.get_variable(),
                |lc| lc + index.get_variable(),
                |lc| lc + index.get_variable(),
            );

            reconstructed_index_lc = reconstructed_index_lc + (multiplier, index.get_variable());
            multiplier = multiplier * Fr::from(2u64);

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
            || "enforce_challenge_index_match",
            |lc| lc + &reconstructed_index_lc,
            |lc| lc + CS::one(),
            |lc| lc + expected_index_var.get_variable(),
        );

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
    if let Err(_) = io::stdin().read_line(&mut input) {
        println!("\n⚠️ Không thể đọc UTF-8 từ Terminal. Tự động dùng dữ liệu mặc định!");
        input = String::from("ofengieoeng,ogennnnnnnnnnnnnnnn,owngfdoqnfoqienfiqe,qooegnoqeng,igowngon,oiengonq,oiqnegioqneg");
    }
    
    let mut raw_shards: Vec<&str> = input.trim().split(',').filter(|s| !s.is_empty()).collect();
    if raw_shards.is_empty() {
        raw_shards = vec!["shard1", "shard2", "shard3", "shard4"];
    }

    print!("\n[Provider] Đang băm dữ liệu bằng Native Poseidon2 và dựng cây Merkle...");
    io::stdout().flush().unwrap();
    let sector = DataSector::new(raw_shards);
    
    let dummy_sector = DataSector::new(vec!["dummy"]);
    let (dummy_data, dummy_path, dummy_indices) = dummy_sector.get_proof(0);
    let circuit_primary = PoStStepCircuit { 
        raw_data: dummy_data, 
        challenge_index: Fr::ZERO, 
        path_elements: dummy_path.clone(), 
        path_indices: dummy_indices.clone() 
    };

    let mut cs = TestConstraintSystem::<Fr>::new();
    let z_in_test = vec![
        AllocatedNum::alloc(cs.namespace(|| "z0"), || Ok(Fr::ZERO)).unwrap(),
        AllocatedNum::alloc(cs.namespace(|| "z1"), || Ok(Fr::ZERO)).unwrap()
    ];
    circuit_primary.synthesize(&mut cs, &z_in_test).unwrap();
    let num_constraints = cs.num_constraints();

    println!("\n\n[ BÁO CÁO CAM KẾT - PHASE 1 ]");
    println!("- Mã cam kết (Root) : {:?}", sector.commitment_root);
    println!("- Kích thước mạch   : {} Constraints (Chính xác)", num_constraints); 

    print!("\n[Network] Đang thiết lập Nova Public Params...");
    io::stdout().flush().unwrap();
    
    type C1 = PoStStepCircuit;
    type C2 = TrivialCircuit<<VestaEngine as Engine>::Scalar>;
    type EE1 = EvaluationEngine<PallasEngine>;
    type EE2 = EvaluationEngine<VestaEngine>;
    type S1 = RelaxedR1CSSNARK<PallasEngine, EE1>;
    type S2 = RelaxedR1CSSNARK<VestaEngine, EE2>;

    let circuit_secondary = C2::default(); 
    let pp = PublicParams::<PallasEngine, VestaEngine, C1, C2>::setup(
        &circuit_primary, &circuit_secondary, &*nova_snark::traits::snark::default_ck_hint(), &*nova_snark::traits::snark::default_ck_hint()
    );
    println!(" ✅ Xong");

    print!("[Network] Đang tạo Prover/Verifier Key cho Spartan Compression...");
    io::stdout().flush().unwrap();
    let (pk, vk) = CompressedSNARK::<PallasEngine, VestaEngine, C1, C2, S1, S2>::setup(&pp).unwrap();
    println!(" ✅ Xong");

    print!("\n[Hệ thống] Bạn muốn chạy bao nhiêu vòng kiểm tra (Epochs)?\n> ");
    io::stdout().flush().unwrap();
    
    let mut epoch_input = String::new();
    let num_epochs: usize = match io::stdin().read_line(&mut epoch_input) {
        Ok(_) => epoch_input.trim().parse().unwrap_or(1),
        Err(_) => 1
    };

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

        let z0_primary = vec![Fr::ZERO, sector.commitment_root]; 
        let z0_secondary = vec![<VestaEngine as Engine>::Scalar::ZERO];
        
        let challenge_index_base_fr = Fr::from(challenges[0] as u64);
        let (raw_data_base, path_base, indices_base) = sector.get_proof(challenges[0]);
        let base_circuit = PoStStepCircuit { 
            raw_data: raw_data_base, 
            challenge_index: challenge_index_base_fr,
            path_elements: path_base, 
            path_indices: indices_base 
        };

        // ==========================================
        // GIAI ĐOẠN 1: NOVA FOLDING (IVC)
        // ==========================================
        let start_prove_ivc = Instant::now();
        let mut recursive_snark = RecursiveSNARK::new(&pp, &base_circuit, &circuit_secondary, &z0_primary, &z0_secondary).unwrap();

        for (step, &idx) in challenges.iter().enumerate() {
            let challenge_index_fr = Fr::from(idx as u64); 
            let (raw_data, path_elements, path_indices) = sector.get_proof(idx);
            
            let step_circuit = PoStStepCircuit { 
                raw_data, 
                challenge_index: challenge_index_fr, 
                path_elements, 
                path_indices 
            };

            recursive_snark.prove_step(&pp, &step_circuit, &circuit_secondary).unwrap();
        }
        let total_prove_ivc_time = start_prove_ivc.elapsed();
        
        let ivc_ram_size = std::mem::size_of_val(&recursive_snark);
        let serialized_ivc = bincode::serialize(&recursive_snark).expect("Lỗi Serialize IVC");
        let ivc_serialize_size = serialized_ivc.len();

        // ==========================================
        // GIAI ĐOẠN 2: SPARTAN COMPRESSION (NÉN)
        // ==========================================
        print!("   [Đang nén] Khởi chạy Spartan Compression...");
        io::stdout().flush().unwrap();
        
        let start_compress = Instant::now();
        let compressed_snark = CompressedSNARK::<PallasEngine, VestaEngine, C1, C2, S1, S2>::prove(&pp, &pk, &recursive_snark).unwrap();
        let total_compress_time = start_compress.elapsed();
        println!(" ✅ Xong");

        let serialized_compressed = bincode::serialize(&compressed_snark).expect("Lỗi Serialize Compressed");
        let compressed_serialize_size = serialized_compressed.len();

        print!("   [Network] Xác minh bằng chứng Spartan...");
        io::stdout().flush().unwrap();
        let start_verify = Instant::now();
        let verify_result = compressed_snark.verify(&vk, batch_size, &z0_primary, &z0_secondary);
        let total_verify_time = start_verify.elapsed();

        match verify_result {
            Ok(_) => println!(" ✅ HỢP LỆ"),
            Err(e) => println!(" ❌ KHÔNG HỢP LỆ: {:?}", e),
        }

        // ==========================================
        // GIAI ĐOẠN 3: ON-CHAIN SUBMISSION (MÔ PHỎNG GROTH16 WRAPPER)
        // ==========================================
        print!("   [On-Chain] Mô phỏng bọc bằng Groth16 Cross-curve...");
        io::stdout().flush().unwrap();
        let start_groth16 = Instant::now();
        
        // Mô phỏng độ trễ tạo siêu bằng chứng (Super-proof) của hệ thống thật
        thread::sleep(Duration::from_millis(150)); 
        let onchain_proof = Groth16Wrapper::mock_prove();
        let total_groth16_time = start_groth16.elapsed();
        
        let onchain_size = onchain_proof.pi_a.len() + onchain_proof.pi_b.len() + onchain_proof.pi_c.len();
        println!(" ✅ Xong");

        // ==========================================
        // BÁO CÁO HIỆU NĂNG TỔNG THỂ
        // ==========================================
        println!("\n📊 BÁO CÁO HIỆU NĂNG THỰC TẾ (EPOCH {}):", epoch);
        println!("  1. Giai đoạn Nova Folding (Lưu nội bộ - Off-chain):");
        println!("     - Thời gian Proving       : {:?}", total_prove_ivc_time);
        println!("     - Dung lượng 'Vỏ' trên RAM: {} bytes", ivc_ram_size);
        println!("     - Dung lượng Serialize    : {} bytes (~{:.2} KB)", ivc_serialize_size, ivc_serialize_size as f64 / 1024.0);
        
        println!("\n  2. Giai đoạn Spartan Compression (Truyền mạng P2P):");
        println!("     - Thời gian Nén (Prove)   : {:?}", total_compress_time);
        println!("     - Thời gian Xác minh      : {:?}", total_verify_time);
        println!("     - Dung lượng Nén Thực Tế  : {} bytes (~{:.2} KB)", compressed_serialize_size, compressed_serialize_size as f64 / 1024.0);

        println!("\n  3. Giai đoạn Outer Wrapper (Ghi lên On-chain):");
        println!("     - Thời gian Bọc Groth16   : {:?} (Mô phỏng)", total_groth16_time);
        println!("     - Kích thước gửi lên Chain: {} bytes (Sẵn sàng gắn vào Bitcoin/EVM)", onchain_size);
    }
}