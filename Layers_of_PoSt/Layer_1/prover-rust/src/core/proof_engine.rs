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
use std::fs; // Đã thêm thư viện fs
use std::path::{Path, PathBuf};
use std::env;
use sha2::{Digest, Sha256};

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
    
    // Lấy kích thước mạch
    pub fn get_circuit_sizes(&self) -> (usize, usize) {
        let (n_primary, n_secondary) = self.pp.num_constraints();
        (n_primary, n_secondary)
    }

    pub fn from_params(pp_path: &Path, pk_path: &Path) -> Self {
        println!("[Engine] Đang nạp Public Params từ Layer 0...");
        let pp_bytes = std::fs::read(pp_path).expect("❌ Không tìm thấy pp.bin");
        println!("[Engine] Đang nạp Prover Key từ Layer 0...");
        let pk_bytes = std::fs::read(pk_path).expect("❌ Không tìm thấy pk.bin");
        
        let pp = bincode::deserialize(&pp_bytes).expect("Lỗi giải mã pp");
        let pk = bincode::deserialize(&pk_bytes).expect("Lỗi giải mã pk");
        Self { pp, pk } 
    }

    pub fn run_pipeline(&self, steps: Vec<C1>, z0: Vec<<G1 as Group>::Scalar>, metadata: serde_json::Value) {
        let circuit_secondary = TrivialCircuit::default();
        let z0_secondary = vec![<G2 as Group>::Scalar::ZERO];

        // 1. Debug constraints
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
            println!("✅ Step {} thỏa mãn! (Constraints: {})", i + 1, cs.num_constraints());
            current_z = z_out.iter().map(|v| v.get_value().unwrap()).collect();
        }
        let expected_zi = current_z.clone(); 

        // 2. Folding
        let mut recursive_snark = RecursiveSNARK::new(&self.pp, &steps[0], &circuit_secondary, z0.clone(), z0_secondary.clone());
        // Sửa warning unused variable `i` bằng cách dùng `_i`
        for (_i, step) in steps.iter().enumerate() {
            recursive_snark.prove_step(&self.pp, step, &circuit_secondary, z0.clone(), z0_secondary.clone()).expect("Folding failed");
        }

        // 3. Spartan Compression
        let compressed_proof = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&self.pp, &self.pk, &recursive_snark).unwrap();

        // 4. Xuất kết quả
        self.export_for_wrapper(&compressed_proof, &z0, &expected_zi, metadata);
    }

    fn export_for_wrapper(&self, proof: &CompressedSNARK<G1, G2, C1, TrivialCircuit<<G2 as Group>::Scalar>, S1, S2>, z0: &Vec<<G1 as Group>::Scalar>, zi: &Vec<<G1 as Group>::Scalar>, metadata: serde_json::Value) {
        let to_safe_hex = |scalar: &<G1 as Group>::Scalar| -> String {
            let mut bytes = scalar.to_repr().as_ref().to_vec();
            let mut hex_str = String::from("0x");
            for b in bytes.iter().rev() { hex_str.push_str(&format!("{:02x}", b)); }
            hex_str
        };

        let proof_bytes = bincode::serialize(proof).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&proof_bytes);
        let digest = hasher.finalize();
        let mut hash_hex = String::from("0x");
        for byte in digest.iter().take(31) { hash_hex.push_str(&format!("{:02x}", byte)); }

        let root_dir = env::var("ENGRAM_ROOT_DIR").map(PathBuf::from).unwrap_or_else(|_| {
            let cwd = env::current_dir().unwrap();
            if cwd.file_name().and_then(|name| name.to_str()) == Some("prover-rust") { cwd.parent().unwrap().to_path_buf() } else { cwd }
        });

        // Ưu tiên lấy ID từ metadata, nếu không có mới dùng env (tránh lỗi prover_unknown)
        let prover_id = metadata.get("prover_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| env::var("ENGRAM_PROVER_ID").unwrap_or_else(|_| "unknown".to_string()));
            
        let prover_output_dir = root_dir.join("output").join(format!("prover_{}", prover_id));
        fs::create_dir_all(&prover_output_dir).expect("failed to create prover output dir");

        let epoch = metadata.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0);
        let proof_filename = format!("compressed_proof_{}.bin", epoch);
        let input_filename = format!("input_{}.json", epoch);

        fs::write(prover_output_dir.join(&proof_filename), &proof_bytes).expect("Write proof failed");
        let data = json!({
            "expected_z0": to_safe_hex(&z0[1]),
            "expected_zi": to_safe_hex(&zi[1]),
            "spartan_proof_hash": hash_hex,
            "engram_metadata": metadata,
            "proof_artifact": proof_filename 
        });
        fs::write(prover_output_dir.join(&input_filename), data.to_string()).unwrap();
        
        println!("✅ Exported proof artifact: output/prover_{}/{}", prover_id, proof_filename);
    }
}