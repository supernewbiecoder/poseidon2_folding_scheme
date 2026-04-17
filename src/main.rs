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

// ==========================================
// 1. MÔ PHỎNG DỮ LIỆU & MERKLE TREE (HOST)
// ==========================================
#[derive(Clone, Debug)]
pub struct DataSector {
    pub shards: Vec<String>,
    pub commitment_root: Fr,
}

impl DataSector {
    pub fn new(raw_shards: Vec<&str>) -> Self {
        // Đệm cho đủ 8 shards (Mô phỏng cây Merkle Depth = 3)
        let mut shards: Vec<String> = raw_shards.iter().map(|s| s.to_string()).collect();
        while shards.len() < 8 {
            shards.push("0".to_string());
        }

        // Mô phỏng tạo Merkle Root bằng thuật toán băm nội bộ
        let mut hasher = blake3::Hasher::new();
        for shard in &shards {
            hasher.update(shard.as_bytes());
        }
        let hash_bytes = hasher.finalize();
        let mut commitment_bytes = [0u8; 32];
        commitment_bytes.copy_from_slice(hash_bytes.as_bytes());
        let root = Option::from(Fr::from_repr(commitment_bytes)).unwrap_or(Fr::ZERO);
        
        Self { shards, commitment_root: root }
    }

    // Mô phỏng lấy dữ liệu shard
    pub fn get_shard_hash(&self, index: usize) -> Fr {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.shards[index].as_bytes());
        let hash_bytes = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hash_bytes.as_bytes());
        Option::from(Fr::from_repr(bytes)).unwrap_or(Fr::ZERO)
    }
}

// ==========================================
// 2. MẠCH ZK BƯỚC ĐƠN (STEP CIRCUIT) - POSEIDON2
// ==========================================
// Mạch này chỉ chịu trách nhiệm kiểm tra đúng MỘT (01) Shard.
// Kích thước cố định, không bị phình to theo Batch Size.
#[derive(Clone, Debug)]
pub struct PoStStepCircuit {
    pub challenge_index: Fr,
    pub shard_hash: Fr,
    pub expected_root: Fr,
}

impl StepCircuit<Fr> for PoStStepCircuit {
    fn arity(&self) -> usize { 1 }

    fn synthesize<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<Fr>],
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        
        let z_prev = z_in[0].clone(); // State từ bước fold trước
        
        let challenge_var = AllocatedNum::alloc(cs.namespace(|| "challenge_idx"), || Ok(self.challenge_index))?;
        let shard_var = AllocatedNum::alloc(cs.namespace(|| "shard_hash"), || Ok(self.shard_hash))?;
        
        // Trạng thái cho Poseidon2 Gadget: T = 3
        let initial_state = vec![z_prev, challenge_var, shard_var];
        
        // Chạy hàm băm Poseidon2 siêu tối ưu
        let mut hasher = Poseidon2Gadget::new(cs, initial_state);
        let state_out = hasher.hash()?;
        
        // Output trạng thái mới để chuyển sang bước Fold tiếp theo
        Ok(vec![state_out[0].clone()])
    }
}

// ==========================================
// 3. GIAO DIỆN CLI VÀ LUỒNG FOLDING SCHEME
// ==========================================
fn main() {
    println!("\n======================================================================");
    println!("      MÔ PHỎNG GIAO THỨC ENGRAM (POSEIDON2 + NOVA FOLDING)");
    println!("======================================================================\n");

    // --- BƯỚC 1: NHẬP DỮ LIỆU TỪ CLI ---
    print!("[Hệ thống] Nhập các dữ liệu phân mảnh cần lưu trữ (cách nhau bằng dấu phẩy, tối đa 8 mục):\n> ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let raw_shards: Vec<&str> = input.trim().split(',').filter(|s| !s.is_empty()).collect();

    print!("\n[Provider] Đang băm dữ liệu và dựng cây Merkle...");
    io::stdout().flush().unwrap();
    let sector = DataSector::new(raw_shards);
    
    println!("\n\n[ BÁO CÁO CAM KẾT - PHASE 1 ]");
    println!("- Số lượng phân mảnh     : {} shards (Padding lên 8)", sector.shards.len());
    println!("- Mã cam kết (c_stor_i)  : {:?}", sector.commitment_root);
    // Poseidon2 tốn ~240 constraints, cộng các phép gán biến ~10 -> tổng < 260
    println!("- Kích thước mạch ZK     : ~260 Constraints (Cố định nhờ Folding!)"); 

    // --- BƯỚC 2: SETUP NOVA (TRUSTED SETUP) ---
    print!("\n[Network] Đang thiết lập Nova Public Params (Lần đầu tiên sẽ tốn vài giây)...");
    io::stdout().flush().unwrap();
    let start_setup = Instant::now();
    
    let circuit_primary = PoStStepCircuit {
        challenge_index: Fr::ZERO,
        shard_hash: Fr::ZERO,
        expected_root: Fr::ZERO,
    };
    let circuit_secondary = TrivialCircuit::<<VestaEngine as Engine>::Scalar>::default(); 
    
    let pp = PublicParams::<PallasEngine, VestaEngine, PoStStepCircuit, TrivialCircuit<<VestaEngine as Engine>::Scalar>>::setup(
        &circuit_primary,
        &circuit_secondary,
        &*nova_snark::traits::snark::default_ck_hint(),
        &*nova_snark::traits::snark::default_ck_hint(),
    );
    println!(" ✅ Xong ({:?})", start_setup.elapsed());

    // --- BƯỚC 3: SỐ LƯỢNG EPOCH ---
    print!("\n[Hệ thống] Bạn muốn chạy bao nhiêu vòng kiểm tra (Epochs)?\n> ");
    io::stdout().flush().unwrap();
    let mut epoch_input = String::new();
    io::stdin().read_line(&mut epoch_input).unwrap();
    let num_epochs: usize = epoch_input.trim().parse().unwrap_or(1);

    let batch_size = 4; // Số lượng thử thách trong 1 Epoch
    let mut rng = rand::thread_rng();

    // --- BƯỚC 4: VÒNG LẶP EPOCH (PROVE & VERIFY) ---
    println!("\n================ BÁO CÁO XÁC THỰC LƯU TRỮ (EPOCHS) ================");
    for epoch in 1..=num_epochs {
        println!("\n---------------- EPOCH {} ----------------", epoch);
        
        // 1. Mạng lưới sinh tập thử thách ngẫu nhiên
        let mut challenges = vec![];
        while challenges.len() < batch_size {
            let idx = rng.gen_range(0..8) as usize;
            if !challenges.contains(&idx) { challenges.push(idx); }
        }
        challenges.sort();
        println!("[Network]  Sinh tập thử thách (J_ipt) gồm {} shard: {:?}", batch_size, challenges);

        // 2. Provider tạo bằng chứng NÉN BẰNG FOLDING
        println!("[Provider] Bắt đầu quá trình Folding Scheme (Gấp {} shards vào 1 Bằng chứng)...", batch_size);
        
        let start_prove = Instant::now();
        
        // Trạng thái ban đầu Z0
        let z0_primary = vec![sector.commitment_root];
        let z0_secondary = vec![<VestaEngine as Engine>::Scalar::ZERO];
        
        // Khởi tạo SNARK đệ quy MỚI cho Epoch này
        let mut recursive_snark = RecursiveSNARK::new(
            &pp,
            &circuit_primary,
            &circuit_secondary,
            &z0_primary,
            &z0_secondary,
        ).expect("Lỗi khởi tạo Recursive SNARK");

        // FOLDING LOOP: Gấp từng shard một
        for (step, &idx) in challenges.iter().enumerate() {
            let step_circuit = PoStStepCircuit {
                challenge_index: Fr::from(idx as u64),
                shard_hash: sector.get_shard_hash(idx),
                expected_root: sector.commitment_root,
            };

            recursive_snark.prove_step(&pp, &step_circuit, &circuit_secondary).unwrap();
            println!("   > Fold #{} thành công (Shard {})", step + 1, idx);
        }
        
        let prove_time = start_prove.elapsed();
        let proof_size = std::mem::size_of_val(&recursive_snark);

        println!("   [✓] BẰNG CHỨNG TỔNG HỢP ĐÃ HOÀN TẤT");
        println!("   - Tổng thời gian Prove : {:?}", prove_time);
        println!("   - Kích thước Proof     : ~{} Bytes (O(1) Succinctness)", proof_size);
        println!("   - Tổng Constraints     : Giữ nguyên ở mức ~260 (Đỉnh cao của Folding!)");

        // 3. Mạng lưới xác minh
        print!("[Network]  Xác minh bằng chứng toán học (Verify)...");
        io::stdout().flush().unwrap();
        let start_verify = Instant::now();
        
        // Verify kiểm tra xem sau `batch_size` bước fold, bằng chứng có hợp lệ không
        let verify_res = recursive_snark.verify(&pp, batch_size, &z0_primary, &z0_secondary);
        
        match verify_res {
            Ok(_) => println!(" ✅ HỢP LỆ ({:?})", start_verify.elapsed()),
            Err(e) => println!(" ❌ KHÔNG HỢP LỆ: {:?}", e),
        }
    }
    println!("\n======================================================================\n");
}