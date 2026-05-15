use nova_snark::{
    traits::{circuit::TrivialCircuit, Group},
    provider::ipa_pc::EvaluationEngine,
    spartan::snark::RelaxedR1CSSNARK,
    CompressedSNARK, VerifierKey,
};
use pasta_curves::{pallas, vesta};
use ff::Field;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use configparser::ini::Ini;
use serde::{Deserialize, Serialize};

// --- THƯ VIỆN ĐO RAM (SỬA LỖI CHO API 0.30) ---
use sysinfo::{System, Pid};

use prover_rust::constants::from_hex;
use prover_rust::core::circuit::PoStStepCircuit;

// --- CẤU HÌNH ĐO LƯỜNG ĐIỆN NĂNG (GIẢ LẬP) ---
const ASSUMED_CPU_WATTAGE: f64 = 65.0; 

fn calc_energy_joules(time_ms: f64) -> f64 {
    (time_ms / 1000.0) * ASSUMED_CPU_WATTAGE
}

// Hàm lấy RAM hiện tại của tiến trình (Megabytes)
fn get_current_ram_mb(sys: &mut System, pid: Pid) -> f64 {
    sys.refresh_process(pid); // API 0.30 dùng refresh_process(pid)
    if let Some(process) = sys.process(pid) {
        process.memory() as f64 / (1024.0 * 1024.0)
    } else {
        0.0
    }
}

// =========================================================================

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
    bitcoin_hash_used: Option<String>,
    shards_proven: Vec<usize>,
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    dvn_id: String,
    epoch: u64,
    assumed_cpu_wattage: f64,
    setup_time_ms: f64,
    setup_ram_mb: f64,
    total_verify_time_ms: f64,
    total_energy_joules: f64,
    peak_ram_mb: f64,
    provers_metrics: Vec<ProverMetric>,
}

#[derive(Debug, Serialize)]
struct ProverMetric {
    prover_id: String,
    success: bool,
    deserialize_time_ms: f64,
    deserialize_energy_j: f64,
    deserialize_ram_mb: f64,
    verify_math_time_ms: f64,
    verify_math_energy_j: f64,
    verify_math_ram_mb: f64,
    total_prover_time_ms: f64,
    total_prover_energy_j: f64,
}

struct PreloadedTask {
    prover_id: String,
    metadata: ProofMetadata,
    proof_bytes: Vec<u8>,
}

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║              ENGRAM LAYER 2 - DVN BENCHMARK VERIFIER                 ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("❌ Tham số: cargo run -- <DVN_NODE_ID> <EPOCH> [PROVER_ID]");
        std::process::exit(1);
    }
    let dvn_id = &args[1];
    let verify_epoch: u64 = args[2].parse().unwrap();
    let target_prover = if args.len() >= 4 { Some(&args[3]) } else { None };

    let mut sys = System::new_all();
    let pid = sysinfo::get_current_pid().unwrap();
    let mut peak_ram = 0.0;

    // ============================================================================
    // GIAI ĐOẠN 1: SETUP - NẠP DỮ LIỆU VÀO RAM (Không tính vào Verify Time)
    // ============================================================================
    let setup_start = Instant::now();
    let base_ram = get_current_ram_mb(&mut sys, pid);

    // Nạp VK
    let vk_path = PathBuf::from("../Layer_0_genesis_setup/network_params/vk.bin");
    let vk_bytes = fs::read(&vk_path).expect("Lỗi đọc vk.bin");
    let vk: VerifierKey<G1, G2, PoStStepCircuit, TrivialCircuit<<G2 as Group>::Scalar>, S1, S2> = bincode::deserialize(&vk_bytes).unwrap();
    
    // Nạp Proofs
    let layer1_output_dir = PathBuf::from("../Layer_1/output");
    let mut preloaded_tasks = Vec::new();
    if let Ok(entries) = fs::read_dir(&layer1_output_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(folder_name) = path.file_name().and_then(|n| n.to_str()) {
                    if folder_name.starts_with("prover_") {
                        let pid_str = folder_name.strip_prefix("prover_").unwrap().to_string();
                        if let Some(target) = target_prover { if pid_str != *target { continue; } }
                        let json_path = path.join(format!("input_{}.json", verify_epoch));
                        if !json_path.exists() { continue; }
                        let metadata: ProofMetadata = serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).unwrap();
                        let proof_path = path.join(&metadata.proof_artifact);
                        if proof_path.exists() {
                            preloaded_tasks.push(PreloadedTask { prover_id: pid_str, metadata, proof_bytes: fs::read(&proof_path).unwrap() });
                        }
                    }
                }
            }
        }
    }

    let setup_time_ms = setup_start.elapsed().as_secs_f64() * 1000.0;
    let setup_ram_mb = f64::max(0.0, get_current_ram_mb(&mut sys, pid) - base_ram);
    peak_ram = get_current_ram_mb(&mut sys, pid);

    // ============================================================================
    // GIAI ĐOẠN 2: BENCHMARK - XÁC MINH (Chỉ tính toán CPU & RAM)
    // ============================================================================
    let benchmark_start = Instant::now();
    let mut provers_metrics = Vec::new();

    for task in preloaded_tasks {
        let prover_start = Instant::now();
        let mut success = false;
        
        let mut deserialize_time_ms = 0.0;
        let mut deserialize_ram_mb = 0.0;
        let mut verify_math_time_ms = 0.0;
        let mut verify_math_ram_mb = 0.0;

        // Hash Check
        let mut hasher = Sha256::new();
        hasher.update(&task.proof_bytes);
        if format!("0x{}", hex::encode(&hasher.finalize()[..31])) == task.metadata.spartan_proof_hash {
            
            // Deserialize RAM & Time
            let ram_before_des = get_current_ram_mb(&mut sys, pid);
            let des_start = Instant::now();
            let proof_result: Result<CompressedSNARK<G1, G2, PoStStepCircuit, TrivialCircuit<<G2 as Group>::Scalar>, S1, S2>, _> = bincode::deserialize(&task.proof_bytes);
            deserialize_time_ms = des_start.elapsed().as_secs_f64() * 1000.0;
            deserialize_ram_mb = f64::max(0.0, get_current_ram_mb(&mut sys, pid) - ram_before_des);
            if get_current_ram_mb(&mut sys, pid) > peak_ram { peak_ram = get_current_ram_mb(&mut sys, pid); }

            if let Ok(proof) = proof_result {
                // Public Inputs
                let z0_scalar = from_hex(task.metadata.expected_z0.trim_start_matches("0x"));
                let expected_zi_scalar = from_hex(task.metadata.expected_zi.trim_start_matches("0x"));
                let z0_primary = vec![<G1 as Group>::Scalar::ZERO, z0_scalar];
                let z0_secondary = vec![<G2 as Group>::Scalar::ZERO];
                let num_steps = task.metadata.engram_metadata.shards_proven.len();

                // Math Verify RAM & Time
                let ram_before_math = get_current_ram_mb(&mut sys, pid);
                let verify_start = Instant::now();
                let verify_result = proof.verify(&vk, num_steps, z0_primary, z0_secondary);
                verify_math_time_ms = verify_start.elapsed().as_secs_f64() * 1000.0;
                verify_math_ram_mb = f64::max(0.0, get_current_ram_mb(&mut sys, pid) - ram_before_math);
                if get_current_ram_mb(&mut sys, pid) > peak_ram { peak_ram = get_current_ram_mb(&mut sys, pid); }

                if let Ok((zi_computed, _)) = verify_result {
                    if zi_computed[1] == expected_zi_scalar { success = true; }
                }
            }
        }

        provers_metrics.push(ProverMetric {
            prover_id: task.prover_id,
            success,
            deserialize_time_ms,
            deserialize_energy_j: calc_energy_joules(deserialize_time_ms),
            deserialize_ram_mb,
            verify_math_time_ms,
            verify_math_energy_j: calc_energy_joules(verify_math_time_ms),
            verify_math_ram_mb,
            total_prover_time_ms: prover_start.elapsed().as_secs_f64() * 1000.0,
            total_prover_energy_j: calc_energy_joules(prover_start.elapsed().as_secs_f64() * 1000.0),
        });
    }

    let total_verify_time_ms = benchmark_start.elapsed().as_secs_f64() * 1000.0;

    // ============================================================================
    // GIAI ĐOẠN 3: XUẤT FILE - TÁCH BIỆT 2 THƯ MỤC
    // ============================================================================
    
    // 1. Thư mục Verifier (giữ nguyên cho Layer 3)
    let verifier_dir = PathBuf::from("verifier_results");
    fs::create_dir_all(&verifier_dir).unwrap();
    let txt_path = verifier_dir.join(format!("dvn_{}_epoch_{}.txt", dvn_id, verify_epoch));
    let mut txt_content = format!("BÁO CÁO DVN {} - EPOCH {}\n", dvn_id, verify_epoch);
    for r in &provers_metrics { txt_content.push_str(&format!("Prover {}: {}\n", r.prover_id, if r.success {"PASS"} else {"FAIL"})); }
    fs::write(&txt_path, txt_content).unwrap();

    // 2. Thư mục Benchmark (File JSON mới)
    let bench_dir = PathBuf::from("benchmark_result");
    fs::create_dir_all(&bench_dir).unwrap();
    let report = BenchmarkReport {
        dvn_id: dvn_id.to_string(),
        epoch: verify_epoch,
        assumed_cpu_wattage: ASSUMED_CPU_WATTAGE,
        setup_time_ms,
        setup_ram_mb,
        total_verify_time_ms,
        total_energy_joules: calc_energy_joules(total_verify_time_ms),
        peak_ram_mb: peak_ram,
        provers_metrics,
    };
    let json_path = bench_dir.join(format!("metrics_dvn_{}_epoch_{}.json", dvn_id, verify_epoch));
    fs::write(&json_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();

    println!("📊 Đã xuất TXT tại: verifier_results/");
    println!("📊 Đã xuất JSON tại: benchmark_result/");
}