use nova_snark::{
    traits::{circuit::TrivialCircuit, Group},
    provider::ipa_pc::EvaluationEngine,
    spartan::snark::RelaxedR1CSSNARK,
    CompressedSNARK, VerifierKey,
};
use pasta_curves::{pallas, vesta};
use ff::Field;
use sha2::{Digest, Sha256};
use chrono::{DateTime, Utc, TimeZone};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use configparser::ini::Ini;

fn get_network_config() -> (u64, String) {
    let mut config = Ini::new();
    match config.load("../CURRENT_EPOCH_IN_BITCOIN.conf") {
        Ok(_) => {},
        Err(_) => panic!("❌ Không tìm thấy file CURRENT_EPOCH_IN_BITCOIN.conf ở thư mục gốc (../../)"),
    }
    
    let current_epoch = config.get("DEFAULT", "CURRENT_EPOCH").unwrap().parse::<u64>().unwrap();
    let current_bitcoin_hash = config.get("DEFAULT", "LATEST_BITCOIN_HASH").unwrap();
    
    (current_epoch, current_bitcoin_hash)
}

use serde::Deserialize;
use prover_rust::constants::from_hex;
use prover_rust::core::circuit::PoStStepCircuit;

type G1 = pallas::Point;
type G2 = vesta::Point;
type EE1 = EvaluationEngine<G1>;
type EE2 = EvaluationEngine<G2>;
type S1 = RelaxedR1CSSNARK<G1, EE1>;
type S2 = RelaxedR1CSSNARK<G2, EE2>;

#[derive(Debug, Deserialize)]
struct ProofMetadata {
    expected_z0: String,
    expected_zi: String,
    spartan_proof_hash: String,
    engram_metadata: EngramMetadata,
    proof_artifact: String,
}

#[derive(Debug, Deserialize)]
struct EngramMetadata {
    prover_id: String,
    epoch: u64,
    bitcoin_hash_used: String,
    shards_proven: Vec<usize>,
    total_shards_stored: usize,
    merkle_depth: usize,
}

#[derive(Debug)]
struct MetadataCheckResult {
    passed: bool,
    errors: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Debug)]
struct VerificationResult {
    verifier_id: String,
    prover_id: String,
    epoch: u64,
    success: bool,
    timestamp: u64,
    verification_time_ms: u64,
    metadata_check: MetadataCheckResult,
    spartan_verified: bool,
    root_match: bool,
    error_msg: Option<String>,
    proof_hash: String,
    num_steps: usize,
    expected_z0: String,
    expected_zi: String,
    computed_zi: Option<String>,
}

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                    ENGRAM LAYER 2 - DVN VERIFIER NODE                         ║");
    println!("║         Middleware: Kiểm duyệt Proof-of-Spacetime & Aggregation              ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");

    // ==================== PHẦN 1: ĐỌC THAM SỐ CLI ====================
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("❌ Cách sử dụng: cargo run -- <DVN_NODE_ID> <EPOCH> [PROVER_ID]");
        eprintln!("\nVí dụ:");
        eprintln!("  cargo run -- DVN_001 494087                   # Kiểm tra tất cả prover ở epoch 494087");
        eprintln!("  cargo run -- DVN_001 494087 1001              # Kiểm tra riêng prover 1001 ở epoch 494087");
        std::process::exit(1);
    }

    let dvn_id = &args[1];
    let verify_epoch: u64 = args[2].parse().expect("❌ Lỗi: Tham số EPOCH phải là một số nguyên!");
    let target_prover = if args.len() >= 4 { Some(&args[3]) } else { None };

    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Lấy config gốc để so sánh (đặc biệt là bitcoin_hash)
    let (network_epoch, current_bitcoin_hash) = get_network_config();

    println!("🔍 DVN Node ID: {}", dvn_id);
    println!("📅 Epoch Yêu Cầu Xác Minh: {}", verify_epoch);
    if verify_epoch != network_epoch {
        println!("   ⚠️ (Lưu ý: Khác với epoch hiện tại của mạng lưới là {})", network_epoch);
    }
    println!("🔗 Bitcoin Hash: {}...", &current_bitcoin_hash[..20]);
    
    if let Some(pid) = target_prover {
        println!("🎯 Lọc Prover ID: {}", pid);
    }
    println!();

    // ==================== PHẦN 2: NẠP VERIFIER KEY TỪ GENESIS ====================
    let vk_path = PathBuf::from("../Layer_0_genesis_setup/network_params/vk.bin");
    
    println!("📂 [1/4] Nạp Verifier Key từ Genesis...");
    if !vk_path.exists() {
        eprintln!("\n❌ KHÔNG TÌM THẤY VERIFIER KEY tại: {}", vk_path.display());
        std::process::exit(1);
    }

    let vk_bytes = fs::read(&vk_path).expect("❌ Lỗi đọc file vk.bin");
    let vk: VerifierKey<G1, G2, PoStStepCircuit, TrivialCircuit<<G2 as Group>::Scalar>, S1, S2> = 
        bincode::deserialize(&vk_bytes).expect("❌ Lỗi giải mã Verifier Key");
    
    println!("   ✅ Verifier Key đã nạp thành công!\n");

    // ==================== PHẦN 3: TÌM BẰNG CHỨNG TỪ LAYER 1 ====================
    let layer1_output_dir = PathBuf::from("../Layer_1/output");
    
    println!("📂 [2/4] Tìm bằng chứng từ Layer 1...");
    if !layer1_output_dir.exists() {
        eprintln!("\n❌ KHÔNG TÌM THẤY THƯ MỤC OUTPUT CỦA LAYER 1!");
        std::process::exit(1);
    }

    let prover_dirs: Vec<PathBuf> = fs::read_dir(&layer1_output_dir)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.is_dir() && path.file_name()?.to_str()?.starts_with("prover_") {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    if prover_dirs.is_empty() {
        println!("   ⚠️ Không tìm thấy thư mục prover_ nào!\n");
        std::process::exit(0);
    }

    println!("   📊 Tìm thấy {} thư mục prover\n", prover_dirs.len());

    // ==================== PHẦN 4: KIỂM TRA TỪNG BẰNG CHỨNG ====================
    let mut results = Vec::new();

    for prover_dir in prover_dirs {
        let prover_id = prover_dir.file_name().unwrap().to_str().unwrap().strip_prefix("prover_").unwrap();

        if let Some(target) = target_prover {
            if prover_id != target { continue; }
        }

        println!("┌─────────────────────────────────────────────────────────────────────────────┐");
        println!("│ 🔍 KIỂM TRA PROVER: {} (Dành cho Epoch: {})", prover_id, verify_epoch);
        println!("│ 📁 Đường dẫn: {}", prover_dir.display());
        println!("└─────────────────────────────────────────────────────────────────────────────┘");

        // Tìm file input theo EPOCH được yêu cầu
        let json_filename = format!("input_{}.json", verify_epoch);
        let json_path = prover_dir.join(&json_filename);
        if !json_path.exists() {
            println!("   ⚠️ Bỏ qua: Không tìm thấy {} (Chưa có bằng chứng cho Epoch này)\n", json_filename);
            continue;
        }

        let metadata_str = fs::read_to_string(&json_path).unwrap();
        let metadata: ProofMetadata = match serde_json::from_str(&metadata_str) {
            Ok(m) => m,
            Err(e) => {
                println!("   ❌ Lỗi parse metadata: {}\n", e);
                continue;
            }
        };

        // KIỂM TRA METADATA VỚI EPOCH YÊU CẦU
        let metadata_check = check_metadata(&metadata, verify_epoch, &current_bitcoin_hash);
        
        let proof_filename = &metadata.proof_artifact;
        let proof_path = prover_dir.join(proof_filename);
        
        if !proof_path.exists() {
            println!("   ❌ Không tìm thấy file: {}", proof_filename);
            results.push(create_failed_result(dvn_id, prover_id, &metadata, "Không tìm thấy file bằng chứng".to_string()));
            continue;
        }

        let proof_bytes = fs::read(&proof_path).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&proof_bytes);
        let digest = hasher.finalize();
        let proof_hash = format!("0x{}", hex::encode(&digest[..31]));

        if proof_hash != metadata.spartan_proof_hash {
            results.push(create_failed_result(dvn_id, prover_id, &metadata, "Hash bằng chứng bị sai lệch".to_string()));
            continue;
        }

        let proof: CompressedSNARK<G1, G2, PoStStepCircuit, TrivialCircuit<<G2 as Group>::Scalar>, S1, S2> = 
            bincode::deserialize(&proof_bytes).expect("❌ Lỗi giải mã");

        let z0_clean = metadata.expected_z0.trim_start_matches("0x");
        let z0_scalar = from_hex(z0_clean);
        
        let zi_clean = metadata.expected_zi.trim_start_matches("0x");
        let expected_zi_scalar = from_hex(zi_clean);
        
        let z0_primary = vec![<G1 as Group>::Scalar::ZERO, z0_scalar];
        let z0_secondary = vec![<G2 as Group>::Scalar::ZERO];
        let num_steps = metadata.engram_metadata.shards_proven.len();

        let verify_result = proof.verify(&vk, num_steps, z0_primary, z0_secondary);

        let (spartan_verified, root_match, computed_zi_str, error_msg) = match verify_result {
            Ok((zi_computed, _)) => {
                let computed_root = format!("{:?}", zi_computed[1]);
                let match_root = zi_computed[1] == expected_zi_scalar;
                if match_root {
                    println!("   ✅ SPARTAN XÁC MINH THÀNH CÔNG!");
                    (true, true, Some(computed_root), None)
                } else {
                    println!("   ❌ ROOT KHÔNG KHỚP!");
                    (true, false, Some(computed_root), Some("Root mismatch".to_string()))
                }
            },
            Err(e) => {
                println!("   ❌ SPARTAN XÁC MINH THẤT BẠI: {:?}", e);
                (false, false, None, Some(format!("{:?}", e)))
            }
        };

        let final_success = metadata_check.passed && spartan_verified && root_match;
        
        results.push(VerificationResult {
            verifier_id: dvn_id.to_string(),
            prover_id: prover_id.to_string(),
            epoch: metadata.engram_metadata.epoch,
            success: final_success,
            timestamp: current_timestamp,
            verification_time_ms: 0,
            metadata_check,
            spartan_verified,
            root_match,
            error_msg,
            proof_hash,
            num_steps,
            expected_z0: metadata.expected_z0,
            expected_zi: metadata.expected_zi,
            computed_zi: computed_zi_str,
        });
        println!();
    }

    // ==================== PHẦN 5: XUẤT KẾT QUẢ ====================
    export_results(dvn_id, &results, current_timestamp, verify_epoch);
    print_summary(&results, verify_epoch);
}

fn check_metadata(metadata: &ProofMetadata, verify_epoch: u64, expected_bitcoin_hash: &str) -> MetadataCheckResult {
    let mut errors = Vec::new();
    let meta = &metadata.engram_metadata;
    
    if meta.epoch != verify_epoch {
        errors.push(format!("Epoch không khớp! Bằng chứng là {}, đang verify {}", meta.epoch, verify_epoch));
    }
    if meta.bitcoin_hash_used != expected_bitcoin_hash {
        errors.push("Bitcoin Hash bị sai lệch".to_string());
    }
    
    MetadataCheckResult { passed: errors.is_empty(), errors, warnings: vec![] }
}

fn create_failed_result(dvn_id: &str, prover_id: &str, metadata: &ProofMetadata, error: String) -> VerificationResult {
    VerificationResult {
        verifier_id: dvn_id.to_string(), prover_id: prover_id.to_string(), epoch: metadata.engram_metadata.epoch,
        success: false, timestamp: 0, verification_time_ms: 0,
        metadata_check: MetadataCheckResult { passed: false, errors: vec![], warnings: vec![] },
        spartan_verified: false, root_match: false, error_msg: Some(error),
        proof_hash: "".to_string(), num_steps: 0, expected_z0: "".to_string(), expected_zi: "".to_string(), computed_zi: None,
    }
}

fn export_results(dvn_id: &str, results: &[VerificationResult], timestamp: u64, current_epoch: u64) {
    let results_dir = PathBuf::from("verifier_results");
    fs::create_dir_all(&results_dir).unwrap();
    let output_file = results_dir.join(format!("dvn_{}_epoch_{}.txt", dvn_id, current_epoch));
    let mut content = format!("BÁO CÁO DVN {} - EPOCH {}\n", dvn_id, current_epoch);
    for r in results { content.push_str(&format!("Prover {}: {}\n", r.prover_id, if r.success {"PASS"} else {"FAIL"})); }
    fs::write(&output_file, content).unwrap();
}

fn print_summary(results: &[VerificationResult], current_epoch: u64) {
    let success = results.iter().filter(|r| r.success).count();
    println!("🏁 EPOCH: {} | TỔNG SỐ PROVER: {} | PASS: {} | FAIL: {}", current_epoch, results.len(), success, results.len() - success);
}

fn format_timestamp(secs: u64) -> String {
    let dt: DateTime<Utc> = Utc.timestamp_opt(secs as i64, 0).unwrap();
    dt.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}