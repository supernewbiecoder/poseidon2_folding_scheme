use nova_snark::{
    traits::{circuit::{StepCircuit, TrivialCircuit}, Group},
    provider::ipa_pc::EvaluationEngine,
    spartan::snark::RelaxedR1CSSNARK,
    RecursiveSNARK, CompressedSNARK, PublicParams,
    ProverKey,
};
use pasta_curves::{pallas, vesta};
use ff::{Field, PrimeField};
use serde_json::json;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::env;
use sha2::{Digest, Sha256};
use std::time::Instant;

use super::power_monitor::{print_stage_power_report, stage_average_watts};

type G1 = pallas::Point;
type G2 = vesta::Point;
type EE1 = EvaluationEngine<G1>;
type EE2 = EvaluationEngine<G2>;
type S1 = RelaxedR1CSSNARK<G1, EE1>;
type S2 = RelaxedR1CSSNARK<G2, EE2>;

pub struct PostProofEngine<C1: StepCircuit<<G1 as Group>::Scalar>> {
    pub pp: PublicParams<G1, G2, C1, TrivialCircuit<<G2 as Group>::Scalar>>,
    pub pk: ProverKey<G1, G2, C1, TrivialCircuit<<G2 as Group>::Scalar>, S1, S2>,
}

impl<C1: StepCircuit<<G1 as Group>::Scalar>> PostProofEngine<C1> {
    pub fn from_params(pp_path: &Path, pk_path: &Path) -> Self {
        println!("[Engine] Đang nạp Public Params từ Layer 0...");
        let pp_bytes = std::fs::read(pp_path).expect("❌ Không tìm thấy pp.bin");
        
        println!("[Engine] Đang nạp Prover Key từ Layer 0...");
        let pk_bytes = std::fs::read(pk_path).expect("❌ Không tìm thấy pk.bin");
        
        let pp = bincode::deserialize(&pp_bytes).expect("Lỗi giải mã pp");
        let pk = bincode::deserialize(&pk_bytes).expect("Lỗi giải mã pk");

        Self { pp, pk } 
    }

    pub fn run_pipeline(
    &self,
    steps: Vec<C1>,
    z0: Vec<<G1 as Group>::Scalar>,
    metadata: serde_json::Value,
) {
    let circuit_secondary = TrivialCircuit::default();
    let z0_secondary = vec![<G2 as Group>::Scalar::ZERO];

    // 1. Debug constraints (giữ nguyên để kiểm tra mạch)
    println!("\n--- 🕵️ MÁY SOI RÀNG BUỘC TẤT CẢ CÁC BƯỚC ---");
    use bellpepper_core::test_cs::TestConstraintSystem;
    use bellpepper_core::num::AllocatedNum;
    use bellpepper_core::ConstraintSystem;

    let mut current_z = z0.clone();
    for (i, step) in steps.iter().enumerate() {
        let mut cs = TestConstraintSystem::<<G1 as Group>::Scalar>::new();
        let mut z_allocated = Vec::new();
        for (j, val) in current_z.iter().enumerate() {
            let a = AllocatedNum::alloc(cs.namespace(|| format!("z_in_{}", j)), || Ok(*val)).unwrap();
            z_allocated.push(a);
        }
        let z_out = step.synthesize(&mut cs, &z_allocated).unwrap();
        if !cs.is_satisfied() {
            println!("❌ PHÁT HIỆN LỖI TẠI STEP {}: Mạch KHÔNG thỏa mãn!", i + 1);
            println!("Chi tiết: {:?}", cs.which_is_unsatisfied().unwrap());
            panic!("Dừng chương trình - mạch logic sai!");
        } else {
            println!("✅ Step {} thỏa mãn hoàn hảo! (Constraints: {})", i + 1, cs.num_constraints());
            current_z = z_out.iter().map(|v| v.get_value().unwrap()).collect();
        }
    }
    
    let expected_zi = current_z.clone(); 
    println!("   Output cuối cùng (zi): {:?}", expected_zi);
    println!("------------------------------------------\n");

    // 2. Folding bằng Nova
    println!("   [Folding] Đang tích lũy các Epoch bằng Nova...");

    let mut recursive_snark = RecursiveSNARK::new(
        &self.pp,
        &steps[0],
        &circuit_secondary,
        z0.clone(),
        z0_secondary.clone(),
    );



    for (i, step) in steps.iter().enumerate() {
        
        print!("\r     -> Đang Fold step {}/{}...", i + 1, steps.len());
        std::io::stdout().flush().unwrap();

        recursive_snark
            .prove_step(
                &self.pp,
                step,
                &circuit_secondary,
                z0.clone(),           // ✅ LUÔN TRUYỀN z0 GỐC
                z0_secondary.clone(), // ✅ LUÔN TRUYỀN z0_secondary GỐC
            )
            .expect(&format!("Failed to prove step {}", i + 1));
    }
    println!("\n   ✅ Folding hoàn tất!");

    // 3. Compression bằng Spartan
    println!("   [Nén] Khởi chạy Spartan Compression...");
    let prove_start = Instant::now();
    
    let compressed_proof = CompressedSNARK::<_, _, _, _, S1, S2>::prove(
        &self.pp,
        &self.pk,
        &recursive_snark,
    )
    .unwrap();
    
    let prove_elapsed_ms = prove_start.elapsed().as_millis();
    print_stage_power_report("Spartan Prove", prove_elapsed_ms, stage_average_watts("Spartan Prove"));

    // 🔑 KHÔNG VERIFY Ở ĐÂY - ĐỂ LAYER 2 LÀM VIỆC ĐÓ
    println!("✅ Bằng chứng Spartan đã được tạo thành công!");
    println!("   (Việc xác minh sẽ được Layer 2 DVN thực hiện)");

    // 4. Xuất kết quả
    self.export_for_wrapper(&compressed_proof, &z0, &expected_zi, metadata);
}

    fn export_for_wrapper(
        &self,
        proof: &CompressedSNARK<G1, G2, C1, TrivialCircuit<<G2 as Group>::Scalar>, S1, S2>,
        z0: &Vec<<G1 as Group>::Scalar>,
        zi: &Vec<<G1 as Group>::Scalar>,
        metadata: serde_json::Value,
    ) {
        let to_safe_hex = |scalar: &<G1 as Group>::Scalar| -> String {
            let mut bytes = scalar.to_repr().as_ref().to_vec();
            let mut hex_str = String::from("0x");
            for b in bytes.iter().rev() {
                hex_str.push_str(&format!("{:02x}", b));
            }
            hex_str
        };

        let proof_bytes = bincode::serialize(proof).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&proof_bytes);
        let digest = hasher.finalize();
        let mut hash_hex = String::from("0x");
        for byte in digest.iter().take(31) {
            hash_hex.push_str(&format!("{:02x}", byte));
        }

        let safe_z0 = to_safe_hex(&z0[1]);
        let safe_zi = to_safe_hex(&zi[1]);

        let root_dir = env::var("ENGRAM_ROOT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let cwd = env::current_dir().unwrap();
                if cwd.file_name().and_then(|name| name.to_str()) == Some("prover-rust") {
                    cwd.parent().unwrap().to_path_buf()
                } else {
                    cwd
                }
            });

        let prover_id = env::var("ENGRAM_PROVER_ID").unwrap_or_else(|_| "unknown".to_string());
        let prover_output_dir = root_dir.join("output").join(format!("prover_{}", prover_id));
        std::fs::create_dir_all(&prover_output_dir).expect("failed to create prover output dir");

        // 🌟 LẤY EPOCH TỪ METADATA VÀ TẠO TÊN FILE MỚI
        let epoch = metadata.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0);
        let proof_filename = format!("compressed_proof_{}.bin", epoch);
        let input_filename = format!("input_{}.json", epoch);

        // 1. Lưu file Proof
        let proof_path = prover_output_dir.join(&proof_filename);
        let mut proof_file = File::create(&proof_path).expect("failed to create proof artifact");
        proof_file.write_all(&proof_bytes).expect("failed to write proof artifact");

        // 2. Lưu file JSON (Cập nhật trường proof_artifact trỏ tới tên file mới)
        let data = json!({
            "expected_z0": safe_z0,
            "expected_zi": safe_zi,
            "spartan_proof_hash": hash_hex,
            "engram_metadata": metadata,
            "proof_artifact": proof_filename 
        });

        let input_path = prover_output_dir.join(&input_filename);
        let mut file = File::create(&input_path).unwrap();
        file.write_all(data.to_string().as_bytes()).unwrap();
        
        println!("✅ Exported proof artifact: {}", proof_path.display());
        println!("✅ Exported metadata: {}", input_path.display());
    }
}