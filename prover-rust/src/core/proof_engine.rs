use nova_snark::{
    traits::{circuit::{StepCircuit, TrivialCircuit}, Group},
    provider::ipa_pc::EvaluationEngine,
    spartan::snark::RelaxedR1CSSNARK,
    RecursiveSNARK, CompressedSNARK, PublicParams,
};
use pasta_curves::{pallas, vesta};
use ff::{Field, PrimeField};
use serde_json::json;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::env;
use sha2::{Digest, Sha256};
use std::time::Instant;

use super::power_monitor::{estimate_energy_joules, print_stage_power_report, stage_average_watts};

// Định nghĩa các Type Alias tương thích chuẩn với nova-snark 0.24.0
type G1 = pallas::Point;
type G2 = vesta::Point;
type EE1 = EvaluationEngine<G1>;
type EE2 = EvaluationEngine<G2>;
type S1 = RelaxedR1CSSNARK<G1, EE1>;
type S2 = RelaxedR1CSSNARK<G2, EE2>;

pub struct PostProofEngine<C1: StepCircuit<<G1 as Group>::Scalar>> {
    pp: PublicParams<G1, G2, C1, TrivialCircuit<<G2 as Group>::Scalar>>,
}

impl<C1: StepCircuit<<G1 as Group>::Scalar>> PostProofEngine<C1> {
    pub fn new(primary_circuit: &C1) -> Self {
        let circuit_secondary = TrivialCircuit::default();
        
        let pp = PublicParams::setup(
            primary_circuit, 
            &circuit_secondary, 
        );
        Self { pp }
    }

    // Sửa lại chữ ký hàm: Xóa bỏ tham số base_circuit
    pub fn run_pipeline(&self, steps: Vec<C1>, z0: Vec<<G1 as Group>::Scalar>) {
        let circuit_secondary = TrivialCircuit::default();
        let z0_secondary = vec![<G2 as Group>::Scalar::ZERO];

        println!("   [Folding] Đang tích lũy các Epoch bằng Nova...");
        let pipeline_start = Instant::now();

        // Dùng chính mạch thật đầu tiên (steps[0]) để khởi tạo.
        let mut recursive_snark = RecursiveSNARK::new(
            &self.pp, &steps[0], &circuit_secondary, z0.clone(), z0_secondary.clone()
        );

        let init_elapsed_ms = pipeline_start.elapsed().as_millis();
        print_stage_power_report("Nova Init", init_elapsed_ms, stage_average_watts("Nova Init"));

        let folding_start = Instant::now();
        for (i, step) in steps.iter().enumerate() {
            print!("\r     -> Đang Fold step {}/{}...", i + 1, steps.len());
            std::io::stdout().flush().unwrap();
            
            recursive_snark.prove_step(
                &self.pp, step, &circuit_secondary, z0.clone(), z0_secondary.clone()
            ).unwrap();
        }
        let folding_elapsed_ms = folding_start.elapsed().as_millis();
        println!("\n   ✅ Folding hoàn tất!");
        print_stage_power_report("Nova Folding", folding_elapsed_ms, stage_average_watts("Nova Folding"));

        println!("   [Nén] Khởi chạy Spartan Compression...");
        let setup_start = Instant::now();
        let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&self.pp).unwrap();
        let setup_elapsed_ms = setup_start.elapsed().as_millis();
        print_stage_power_report("Spartan Setup", setup_elapsed_ms, stage_average_watts("Spartan Setup"));

        let prove_start = Instant::now();
        let compressed_proof = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&self.pp, &pk, &recursive_snark).unwrap();
        let prove_elapsed_ms = prove_start.elapsed().as_millis();
        print_stage_power_report("Spartan Prove", prove_elapsed_ms, stage_average_watts("Spartan Prove"));

        let num_steps = steps.len(); 
        
        let verify_start = Instant::now();
        let (zi_primary, _) = compressed_proof.verify(&vk, num_steps, z0.clone(), z0_secondary.clone()).unwrap();
        let verify_elapsed_ms = verify_start.elapsed().as_millis();
        print_stage_power_report("Spartan Verify", verify_elapsed_ms, stage_average_watts("Spartan Verify"));

        // 3. EXPORT TO JSON 
        let export_start = Instant::now();
        self.export_for_wrapper(&compressed_proof, &z0, &zi_primary);
        let export_elapsed_ms = export_start.elapsed().as_millis();
        print_stage_power_report("Export + Attestation", export_elapsed_ms, stage_average_watts("Export + Attestation"));

        let total_elapsed_ms = pipeline_start.elapsed().as_millis();
        let total_energy = estimate_energy_joules(total_elapsed_ms, stage_average_watts("Pipeline Total"));
        println!("[Power][Pipeline Total] elapsed={} ms | estimated={:.3} J | avg={:.1} W", total_elapsed_ms, total_energy, stage_average_watts("Pipeline Total"));
    }

    fn export_for_wrapper(
        &self, 
        proof: &CompressedSNARK<G1, G2, C1, TrivialCircuit<<G2 as Group>::Scalar>, S1, S2>, 
        z0: &Vec<<G1 as Group>::Scalar>, 
        zi: &Vec<<G1 as Group>::Scalar>
    ) {
        // 1. Ép kiểu Pallas (255 bit) sang BN254 (254 bit) an toàn cho Circom
        let to_safe_hex = |scalar: &<G1 as Group>::Scalar| -> String {
            let mut bytes = scalar.to_repr().as_ref().to_vec();
            bytes[31] &= 0x1F; // Cắt các bit cao nhất để chống tràn số trong SnarkJS
            let mut hex_str = String::from("0x");
            for b in bytes.iter().rev() {
                hex_str.push_str(&format!("{:02x}", b));
            }
            hex_str
        };

        // 2. Băm bằng chứng Spartan thực tế thành một mã duy nhất
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

        // 3. EXPORT PROOF ARTIFACT: write compressed_proof to file so independent
        // committee nodes can fetch and verify it. Do NOT self-sign here.
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

        // Write compressed proof artifact
        let proof_path = root_dir.join("circuits-circom").join("compressed_proof.bin");
        let mut proof_file = File::create(&proof_path).expect("failed to create proof artifact");
        proof_file.write_all(&proof_bytes).expect("failed to write proof artifact");

        // 4. Package JSON WITHOUT signatures. Committee signs independently after
        // fetching `compressed_proof.bin` and verifying it.
        let data = json!({
            "expected_z0": safe_z0.clone(),
            "expected_zi": safe_zi.clone(),
            "spartan_z0": safe_z0.clone(), 
            "spartan_zi": safe_zi.clone(),
            "spartan_proof_hash": hash_hex.clone(),
            "proof_artifact": proof_path.strip_prefix(&root_dir).unwrap_or(&proof_path).to_string_lossy(),
            "committee": {
                "size": 0,
                "pubkeys": [],
                "pubkeys_hash": null,
                "signatures": []
            },
            "attestation": {
                "epoch": 1,
                "domain_sep": "ENGRAM_SPARTAN_PROOF"
            }
        });
        
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
        let input_path = root_dir.join("circuits-circom").join("input.json");
        let mut file = File::create(&input_path).unwrap();
        file.write_all(data.to_string().as_bytes()).unwrap();

        println!("✅ Exported proof artifact: {}", proof_path.display());
        println!("✅ Exported input.json (no committee signatures yet): {}", input_path.display());
        println!("🔐 spartan_proof_hash: {}", &hash_hex[..20]);
        println!("ℹ️  Next: distribute '{}' to committee nodes for independent verify+signing.", proof_path.display());
    }
}