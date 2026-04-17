use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
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
mod poseidon2_gadget;
use poseidon2_gadget::Poseidon2Gadget;
use constants::{MAT_FULL, MAT_PARTIAL, RC, R_F, R_P, T};

// ==========================================
// 1. HÀM POSEIDON2 NATIVE (DÀNH CHO HOST)
// ==========================================
// Cần hàm này để Host tự dựng cây Merkle bằng Poseidon2 giống hệt mạch ZK
fn sbox(x: Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x // x^5
}

pub fn native_poseidon2(left: Fr, right: Fr) -> Fr {
    let mut state = [left, right, Fr::ZERO];
    let half_f = R_F / 2;

    // First matrix multiplication
    let mut new_state = [Fr::ZERO; 3];
    for i in 0..T {
        for j in 0..T { new_state[i] += MAT_FULL[i][j] * state[j]; }
    }
    state = new_state;

    // Rounds
    for r in 0..(R_F + R_P) {
        let is_full = r < half_f || r >= half_f + R_P;
        
        // Add Round Constants
        for i in 0..T { state[i] += RC[r][i]; }

        // S-Box
        for i in 0..T {
            if is_full || i == 0 { state[i] = sbox(state[i]); }
        }

        // Matrix Multiplication
        let matrix = if is_full { &*MAT_FULL } else { &*MAT_PARTIAL };
        let mut new_state = [Fr::ZERO; 3];
        for i in 0..T {
            for j in 0..T { new_state[i] += matrix[i][j] * state[j]; }
        }
        state = new_state;
    }
    state[0] // Trả về phần tử đầu tiên làm kết quả hash
}

// ==========================================
// 2. MÔ PHỎNG DỮ LIỆU & MERKLE TREE (HOST)
// ==========================================
#[derive(Clone, Debug)]
pub struct DataSector {
    pub leaves: Vec<Fr>,
    pub tree: Vec<Vec<Fr>>,
    pub commitment_root: Fr,
}

impl DataSector {
    pub fn new(raw_shards: Vec<&str>) -> Self {
        // Chuyển string thành Fr và padding lên 8 leaves
        let mut leaves: Vec<Fr> = raw_shards.iter().map(|s| {
            let mut bytes = [0u8; 32];
            let s_bytes = s.as_bytes();
            let len = std::cmp::min(32, s_bytes.len());
            bytes[..len].copy_from_slice(&s_bytes[..len]);
            Option::from(Fr::from_repr(bytes)).unwrap_or(Fr::ZERO)
        }).collect();
        
        while leaves.len() < 8 { leaves.push(Fr::ZERO); }

        // Dựng cây Merkle bằng native_poseidon2
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

    // Lấy Merkle Path (Witness)
    pub fn get_proof(&self, index: usize) -> (Fr, Vec<Fr>, Vec<Fr>) {
        let mut path_elements = vec![];
        let mut path_indices = vec![];
        let mut current_idx = index;

        for level in 0..3 {
            let is_right = current_idx % 2 == 1;
            let sibling_idx = if is_right { current_idx - 1 } else { current_idx + 1 };
            
            path_elements.push(self.tree[level][sibling_idx]);
            path_indices.push(if is_right { Fr::ONE } else { Fr::ZERO }); // 1 = Left sibling, 0 = Right sibling
            current_idx /= 2;
        }
        (self.leaves[index], path_elements, path_indices)
    }
}

// ==========================================
// 3. MẠCH ZK BƯỚC ĐƠN: KIỂM TRA MERKLE PATH
// ==========================================
#[derive(Clone, Debug)]
pub struct PoStStepCircuit {
    pub leaf: Fr,
    pub path_elements: Vec<Fr>,
    pub path_indices: Vec<Fr>,
    pub expected_root: Fr,
}

impl StepCircuit<Fr> for PoStStepCircuit {
    fn arity(&self) -> usize { 1 }

    fn synthesize<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<Fr>],
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        
        // z_in[0] có thể dùng làm bộ đếm số lần fold (Counter), hiện ta bỏ qua
        let z_prev = z_in[0].clone(); 
        let expected_root_var = AllocatedNum::alloc(cs.namespace(|| "expected_root"), || Ok(self.expected_root))?;
        let zero_var = AllocatedNum::alloc(cs.namespace(|| "zero_cap"), || Ok(Fr::ZERO))?;

        let mut current_hash = AllocatedNum::alloc(cs.namespace(|| "leaf"), || Ok(self.leaf))?;

        // ---------------------------------------------------------
        // MERKLE INCLUSION PROOF LOGIC (Mô phỏng MUX)
        // ---------------------------------------------------------
        for i in 0..self.path_elements.len() {
            let sibling = AllocatedNum::alloc(cs.namespace(|| format!("sibling_{}", i)), || Ok(self.path_elements[i]))?;
            let index = AllocatedNum::alloc(cs.namespace(|| format!("index_{}", i)), || Ok(self.path_indices[i]))?;

            // Ràng buộc boolean: index * (1 - index) = 0
            cs.enforce(
                || format!("boolean_index_{}", i),
                |lc| lc + index.get_variable(),
                |lc| lc + CS::one() - index.get_variable(),
                |lc| lc,
            );

            // Logic MUX Toán học: 
            // left = current - index * (current - sibling)
            // right = sibling + index * (current - sibling)
            let diff_val = current_hash.get_value().zip(sibling.get_value()).map(|(c, s)| c - s);
            let left_val = current_hash.get_value().zip(index.get_value()).zip(diff_val).map(|((c, idx), diff)| c - idx * diff);
            let right_val = sibling.get_value().zip(index.get_value()).zip(diff_val).map(|((s, idx), diff)| s + idx * diff);

            let left = AllocatedNum::alloc(cs.namespace(|| format!("left_{}", i)), || left_val.ok_or(SynthesisError::AssignmentMissing))?;
            let right = AllocatedNum::alloc(cs.namespace(|| format!("right_{}", i)), || right_val.ok_or(SynthesisError::AssignmentMissing))?;

            // Ràng buộc MUX Left
            cs.enforce(
                || format!("mux_left_{}", i),
                |lc| lc + index.get_variable(),
                |lc| lc + current_hash.get_variable() - sibling.get_variable(),
                |lc| lc + current_hash.get_variable() - left.get_variable(),
            );

            // Ràng buộc MUX Right
            cs.enforce(
                || format!("mux_right_{}", i),
                |lc| lc + index.get_variable(),
                |lc| lc + current_hash.get_variable() - sibling.get_variable(),
                |lc| lc + right.get_variable() - sibling.get_variable(),
            );

            // Tính Poseidon2(left, right, 0)
            let hash_inputs = vec![left, right, zero_var.clone()];
            let mut ns = cs.namespace(|| format!("poseidon_{}", i));
            let mut hasher = Poseidon2Gadget::new(&mut ns, hash_inputs);
            let hash_out = hasher.hash()?;
            current_hash = hash_out[0].clone();
        }

        // ---------------------------------------------------------
        // RÀNG BUỘC TỐI THƯỢNG: Hash cuối cùng PHẢI BẰNG Root cam kết
        // ---------------------------------------------------------
        cs.enforce(
            || "enforce_merkle_root",
            |lc| lc + current_hash.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + expected_root_var.get_variable(),
        );

        Ok(vec![z_prev]) // Trả về z_prev để mạch duy trì trạng thái đệ quy
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
    // Depth = 3 -> 3 lần băm Poseidon2 (~720 constraints) + Constraints cho Mux/Boolean
    println!("- Kích thước mạch   : ~750 Constraints (Mạch đã bao gồm Merkle Inclusion!)"); 

    print!("\n[Network] Đang thiết lập Nova Public Params...");
    io::stdout().flush().unwrap();
    
    let circuit_primary = PoStStepCircuit {
        leaf: Fr::ZERO,
        path_elements: vec![Fr::ZERO; 3],
        path_indices: vec![Fr::ZERO; 3],
        expected_root: Fr::ZERO,
    };
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
        let z0_primary = vec![Fr::ZERO];
        let z0_secondary = vec![<VestaEngine as Engine>::Scalar::ZERO];
        
        let mut recursive_snark = RecursiveSNARK::new(&pp, &circuit_primary, &circuit_secondary, &z0_primary, &z0_secondary).unwrap();

        for (step, &idx) in challenges.iter().enumerate() {
            let (leaf, path_elements, path_indices) = sector.get_proof(idx);
            let step_circuit = PoStStepCircuit { leaf, path_elements, path_indices, expected_root: sector.commitment_root };

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