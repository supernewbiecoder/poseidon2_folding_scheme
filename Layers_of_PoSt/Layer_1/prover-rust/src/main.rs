use pasta_curves::pallas::Scalar as Fr;
use ff::{Field, PrimeField}; 
use sha2::{Digest, Sha256};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use serde::Serialize;
use sysinfo::{System, Pid, get_current_pid};
use configparser::ini::Ini;

mod constants;
mod core;

use crate::core::circuit::{DataSector, PoStStepCircuit};
use crate::core::proof_engine::PostProofEngine;
// Lấy các hằng số chuẩn từ file thiết kế của bạn
use engram_common::{MERKLE_DEPTH, NUM_CHALLENGES};

const ASSUMED_CPU_WATTAGE: f64 = 65.0; 

fn calc_energy_joules(time_ms: f64) -> f64 {
    (time_ms / 1000.0) * ASSUMED_CPU_WATTAGE
}

fn get_current_ram_mb(sys: &mut System, pid: Pid) -> f64 {
    sys.refresh_process(pid);
    if let Some(process) = sys.process(pid) {
        process.memory() as f64 / (1024.0 * 1024.0)
    } else {
        0.0
    }
}

#[derive(Serialize)]
struct ProverBenchmarkReport {
    prover_id: String,
    epoch: u64,
    primary_constraints: usize,
    secondary_constraints: usize,
    setup_time_ms: f64,
    setup_ram_mb: f64,
    sealing_time_ms: f64,
    sealing_energy_j: f64,
    sealing_ram_mb: f64,
    proving_time_ms: f64,
    proving_energy_j: f64,
    proving_ram_mb: f64,
    peak_ram_mb: f64,
}

fn get_network_config() -> (u64, String) {
    let mut config = Ini::new();
    config.load("../../CURRENT_EPOCH_IN_BITCOIN.conf").expect("❌ Thiếu file config");
    let current_epoch = config.get("DEFAULT", "CURRENT_EPOCH").unwrap().parse::<u64>().unwrap();
    let current_bitcoin_hash = config.get("DEFAULT", "LATEST_BITCOIN_HASH").unwrap();
    (current_epoch, current_bitcoin_hash)
}

fn load_specific_shards(indices: &[usize], dir: &Path) -> Vec<String> {
    indices.iter().map(|&idx| {
        let path = dir.join(format!("shard_{}.txt", idx));
        fs::read_to_string(&path).unwrap_or_else(|_| String::from("0")) // Nếu không có file thì coi như data trống
    }).collect()
}

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║              ENGRAM LAYER 1 - PROVER BENCHMARK SYSTEM                ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Sử dụng: cargo run --release -- <PROVER_ID> <CHỈ_SỐ_SHARD>");
        std::process::exit(1);
    }

    let prover_id_raw = &args[1];
    let shard_indices: Vec<usize> = args[2].split(',').map(|s| s.trim().parse().unwrap()).collect();

    let mut sys = System::new_all();
    let pid = get_current_pid().unwrap();
    let initial_ram = get_current_ram_mb(&mut sys, pid);
    let mut peak_ram = initial_ram;

    // ============================================================================
    // GIAI ĐOẠN 1: SETUP
    // ============================================================================
    println!("🚀 [Giai đoạn 1] Setup: Nạp Public Parameters & Proving Key...");
    let setup_start = Instant::now();
    let (current_epoch, current_bitcoin_hash) = get_network_config();
    let params_dir = PathBuf::from("../../Layer_0_genesis_setup/network_params");
    
    let engine = PostProofEngine::from_params(&params_dir.join("pp.bin"), &params_dir.join("pk.bin"));
    let (p_cons, s_cons) = engine.get_circuit_sizes();

    let setup_time_ms = setup_start.elapsed().as_secs_f64() * 1000.0;
    let setup_ram_mb = f64::max(0.0, get_current_ram_mb(&mut sys, pid) - initial_ram);
    if get_current_ram_mb(&mut sys, pid) > peak_ram { peak_ram = get_current_ram_mb(&mut sys, pid); }

    // ============================================================================
    // GIAI ĐOẠN 2: SEALING (Poseidon2-CBC)
    // ============================================================================
    println!("⚡ [Giai đoạn 2] Sealing Sector (Khởi tạo cây Merkle {} tầng)...", MERKLE_DEPTH);
    let sealing_start = Instant::now();
    let ram_pre_sealing = get_current_ram_mb(&mut sys, pid);

    let prover_id_fr = Fr::from_str_vartime(prover_id_raw).unwrap();
    let shard_dir = PathBuf::from("sample_shards");
    let raw_shards = load_specific_shards(&shard_indices, &shard_dir);
    let sector = DataSector::new(raw_shards, prover_id_fr, Fr::from(current_epoch));

    let sealing_time_ms = sealing_start.elapsed().as_secs_f64() * 1000.0;
    let sealing_ram_mb = f64::max(0.0, get_current_ram_mb(&mut sys, pid) - ram_pre_sealing);
    if get_current_ram_mb(&mut sys, pid) > peak_ram { peak_ram = get_current_ram_mb(&mut sys, pid); }

    // ============================================================================
    // GIAI ĐOẠN 3: PROVING (Nova Folding + Spartan)
    // ============================================================================
    println!("🌀 [Giai đoạn 3] ZK Proving Pipeline (Thực hiện {} thử thách)...", NUM_CHALLENGES);
    let proving_start = Instant::now();
    let ram_pre_proving = get_current_ram_mb(&mut sys, pid);

    let mut seed_hasher = Sha256::new();
    seed_hasher.update(current_bitcoin_hash.as_bytes());
    seed_hasher.update(prover_id_fr.to_repr());
    let mut prng = ChaCha8Rng::from_seed(seed_hasher.finalize().into());
    
    // Tự động random ra 460 thử thách phủ khắp cây Merkle
    let target_leaves = 1 << MERKLE_DEPTH;
    let mut challenges = vec![];
    while challenges.len() < NUM_CHALLENGES {
        let r = prng.gen_range(0..target_leaves);
        if !challenges.contains(&r) { challenges.push(r); }
    }

    let mut steps = vec![];
    for &idx in &challenges {
        // Lấy đường dẫn Merkle cho lá thứ `idx` bất kỳ
        let (raw_data, prev_s, path_elements, path_indices) = sector.get_proof(idx);
        steps.push(PoStStepCircuit { raw_data, prev_s, challenge_index: Fr::from(idx as u64), path_elements, path_indices });
    }

    let metadata = serde_json::json!({
        "prover_id": prover_id_raw,
        "epoch": current_epoch,
        "shards_proven": challenges,
    });

    let z0 = vec![Fr::ZERO, sector.commitment_root];
    engine.run_pipeline(steps, z0, metadata);

    let proving_time_ms = proving_start.elapsed().as_secs_f64() * 1000.0;
    let proving_ram_mb = f64::max(0.0, get_current_ram_mb(&mut sys, pid) - ram_pre_proving);
    if get_current_ram_mb(&mut sys, pid) > peak_ram { peak_ram = get_current_ram_mb(&mut sys, pid); }

    // ============================================================================
    // GIAI ĐOẠN 4: XUẤT BENCHMARK
    // ============================================================================
    let report = ProverBenchmarkReport {
        prover_id: prover_id_raw.to_string(),
        epoch: current_epoch,
        primary_constraints: p_cons,
        secondary_constraints: s_cons,
        setup_time_ms,
        setup_ram_mb,
        sealing_time_ms,
        sealing_energy_j: calc_energy_joules(sealing_time_ms),
        sealing_ram_mb,
        proving_time_ms,
        proving_energy_j: calc_energy_joules(proving_time_ms),
        proving_ram_mb,
        peak_ram_mb: peak_ram,
    };

    let bench_dir = PathBuf::from("benchmark_results");
    fs::create_dir_all(&bench_dir).unwrap();
    let json_path = bench_dir.join(format!("metrics_prover_{}_epoch_{}.json", prover_id_raw, current_epoch));
    fs::write(&json_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();

    println!("\n📊 Đã xuất kết quả Benchmark tại: {}", json_path.display());
}