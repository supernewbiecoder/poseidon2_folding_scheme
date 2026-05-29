use core_primitives::config::EngramConfig;
use core_primitives::merkle_tree::verify_merkle_proof;
use core_primitives::Fr;
use ff::{Field, PrimeField};
use nova_snark::provider::PallasEngine;
use nova_snark::traits::Engine;
use prover::benchmark::elapsed_ms_f64;
use prover::{ChallengeMetrics, ProverStorage, Sealer, EngramStepCircuit, ProvingPipeline};
use serde::Deserialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::process::Command;
use std::time::Instant;
use sysinfo::{CpuExt, System, SystemExt};

macro_rules! logln {
    ($log_file:expr, $($arg:tt)*) => {{
        let line = format!($($arg)*);
        println!("{}", line);
        writeln!($log_file, "{}", line).expect("Lỗi ghi transcript log");
    }};
}

#[derive(Debug, Deserialize)]
struct MockMetadata {
    client_id: String,
    deal_id: String,
    sector_id: u64,
    copy_index: u8,
    nonce: u64,
}

// ---------------------------------------------------------------------------
// 1. Khai báo kịch bản tấn công
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum AttackMode {
    /// Happy path — không tấn công.
    None,
    /// KB1: xóa ngẫu nhiên `pct`% raw_chunks.
    DropRawRandomPct(f64),
    /// KB1d: xóa đúng 1 chunk tại index challenge đầu tiên (test fail path của KB1).
    DropRawOneChallenge,
    /// KB2: xóa raw_chunks tại đúng các index challenge (chỉ giữ S_i).
    DropRawAtChallenges,
    /// KB3: xóa state S_{j_i - 1} tại các vị trí challenge cần dùng.
    DropStatesAtChallengePrev,
    /// KB4: được mô phỏng thông qua proof_epoch != verify_epoch.
    EpochMismatch,
}

impl AttackMode {
    fn label(&self) -> &'static str {
        match self {
            AttackMode::None => "no_attack",
            AttackMode::DropRawRandomPct(_) => "drop_raw_random_pct",
            AttackMode::DropRawOneChallenge => "drop_raw_one_challenge",
            AttackMode::DropRawAtChallenges => "drop_raw_at_challenges",
            AttackMode::DropStatesAtChallengePrev => "drop_states_at_prev",
            AttackMode::EpochMismatch => "epoch_mismatch",
        }
    }
}

// ---------------------------------------------------------------------------
// 2. I/O helpers
// ---------------------------------------------------------------------------

fn read_first_existing_file(paths: &[&str]) -> Option<Vec<u8>> {
    // Single-source behavior: only attempt the first provided path.
    if let Some(path) = paths.first() {
        if let Ok(bytes) = fs::read(path) {
            return Some(bytes);
        }
    }
    None
}

fn read_first_existing_text(paths: &[&str]) -> Option<String> {
    // Single-source behavior: only attempt the first provided path.
    if let Some(path) = paths.first() {
        if let Ok(text) = fs::read_to_string(path) {
            return Some(text);
        }
    }
    None
}

fn load_mock_sector_data(config: &EngramConfig) -> Vec<u8> {
    // Single-source: expect mockdata under `mockdata/data` in repository root.
    let path = "mockdata/data/client_raw_data.bin";
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.len() as usize == config.sector_size_bytes {
            return std::fs::read(path).expect("Không thể đọc file client_raw_data.bin");
        } else {
            panic!(
                "client_raw_data.bin tồn tại nhưng kích thước không đúng: {} bytes (cần {})",
                metadata.len(),
                config.sector_size_bytes
            );
        }
    }
    panic!("Không tìm thấy client_raw_data.bin trong mockdata/data — hãy chạy data_generator để tạo file đúng kích thước.");
}

fn load_mock_metadata() -> MockMetadata {
    let metadata_text = read_first_existing_text(&["mockdata/metadata/metadata.json"]) .expect("Không thể đọc mock metadata.json");
    serde_json::from_str(&metadata_text).expect("Không thể parse mock metadata.json")
}

fn load_bitcoin_epoch_hashes() -> Vec<String> {
    let text = read_first_existing_text(&["mockdata/bitcoin_mocks/bitcoin_blocks.txt"]) .expect("Không thể đọc mock bitcoin_blocks.txt");
    text.lines()
        .filter_map(|line| line.split_once(':').map(|(_, hash)| hash.trim().to_string()))
        .collect()
}

fn bytes_to_fr(bytes: &[u8]) -> Fr {
    let mut repr = [0u8; 32];
    let len = bytes.len().min(32);
    repr[..len].copy_from_slice(&bytes[..len]);
    repr[31] &= 0x3f;
    Fr::from_repr(repr).unwrap()
}

fn string_to_fr(value: &str) -> Fr {
    bytes_to_fr(value.as_bytes())
}

fn poseidon2_chain(values: &[Fr]) -> Fr {
    let mut acc = Fr::ZERO;
    for value in values {
        acc = core_primitives::poseidon2::hash_2(acc, *value);
    }
    acc
}

fn select_epoch_hash(hashes: &[String], epoch: usize) -> String {
    if hashes.is_empty() {
        return "fallback-epoch-hash".to_string();
    }
    hashes[epoch % hashes.len()].clone()
}

fn derive_replica_id(metadata: &MockMetadata) -> Fr {
    let client_id = string_to_fr(&metadata.client_id);
    let deal_id = string_to_fr(&metadata.deal_id);
    let sector_id = Fr::from(metadata.sector_id);
    let copy_index = Fr::from(metadata.copy_index as u64);
    let nonce = Fr::from(metadata.nonce);
    poseidon2_chain(&[client_id, deal_id, sector_id, copy_index, nonce])
}

fn derive_challenge_index(
    beacon: &str,
    sector_id: u64,
    epoch: usize,
    challenge_no: usize,
    num_chunks: usize,
) -> usize {
    let beacon_fr = string_to_fr(beacon);
    let sector_fr = Fr::from(sector_id);
    let epoch_fr = Fr::from(epoch as u64);
    let challenge_fr = Fr::from(challenge_no as u64);
    let seed = poseidon2_chain(&[beacon_fr, sector_fr, epoch_fr, challenge_fr]);
    let seed_bytes = seed.to_repr();
    (usize::from(seed_bytes.as_ref()[0]) % num_chunks).saturating_add(1)
}

// FIX: z0 giờ có 4 phần tử (arity=4): [epoch, 0, D_ji, S_ji-1]
// Hàm này chỉ dùng để build initial z0 khi verify — cần D_ji và S_ji-1 của challenge đầu.
type NovaFr = <PallasEngine as Engine>::Scalar;

fn public_input_for_epoch(epoch: usize, d_ji_first: NovaFr, s_ji_minus_1_first: NovaFr) -> Vec<NovaFr> {
    vec![NovaFr::from(epoch as u64), NovaFr::ZERO, d_ji_first, s_ji_minus_1_first]
}

fn nova_fr_from_core(f: Fr) -> NovaFr {
    let bytes = f.to_repr();
    NovaFr::from_repr(bytes.into()).unwrap_or(NovaFr::ZERO)
}

fn build_reference_challenge(
    storage: &ProverStorage,
    bitcoin_hashes: &[String],
    proof_epoch: usize,
    num_chunks_total: usize,
    sector_id: u64,
    replica_id: Fr,
) -> EngramStepCircuit {
    let proof_epoch_hash = select_epoch_hash(bitcoin_hashes, proof_epoch);
    let beacon = string_to_fr(&proof_epoch_hash);
    let sealed_root = storage
        .merkle_tree
        .as_ref()
        .expect("Không thể tạo challenge mẫu vì thiếu Merkle tree")
        .root;
    let j_i = derive_challenge_index(&proof_epoch_hash, sector_id, proof_epoch, 1, num_chunks_total);
    let d_ji = storage
        .get_raw_chunk(j_i)
        .map(bytes_to_fr)
        .unwrap_or_else(|| Fr::ZERO);
    let s_ji_minus_1 = storage
        .get_state(j_i.saturating_sub(1))
        .cloned()
        .expect("Không thể tạo challenge mẫu vì thiếu state");
    let s_ji = storage
        .get_state(j_i)
        .cloned()
        .expect("Không thể tạo challenge mẫu vì thiếu state S_ji");
    let proof = storage
        .merkle_tree
        .as_ref()
        .expect("Không thể tạo challenge mẫu vì thiếu Merkle tree")
        .generate_proof(j_i - 1);

    EngramStepCircuit {
        epoch: proof_epoch,
        sector_id: Fr::from(sector_id),
        sealed_root,
        beacon,
        j_i,
        d_ji,
        s_ji_minus_1,
        s_ji,
        replica_id,
        path_ji_siblings: proof.siblings,
        path_ji_indices: proof.path_indices,
    }
}

// ---------------------------------------------------------------------------
// 3. Deterministic drop helper
// ---------------------------------------------------------------------------

fn lcg_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn deterministic_drop_random_pct(drop_pct: f64, seed: u64, num_chunks: usize) -> Vec<usize> {
    if num_chunks == 0 || drop_pct <= 0.0 {
        return Vec::new();
    }
    let drop_count = ((num_chunks as f64) * drop_pct / 100.0).round() as usize;
    let drop_count = drop_count.min(num_chunks);

    let mut keys: Vec<usize> = (1..=num_chunks).collect();
    let mut rng_state = seed.wrapping_add(0x9E3779B97F4A7C15);
    for i in (1..keys.len()).rev() {
        let r = (lcg_next(&mut rng_state) as usize) % (i + 1);
        keys.swap(i, r);
    }
    let mut removed: Vec<usize> = keys.into_iter().take(drop_count).collect();
    removed.sort_unstable();
    removed
}

// ---------------------------------------------------------------------------
// 4. main
// ---------------------------------------------------------------------------

fn main() {
    let config = EngramConfig::mock_dev();
    let num_chunks_total = config.sector_size_bytes / config.chunk_size_bytes;
    let current_epoch: usize = 0;
    let next_epoch: usize = 1;

    // Setup transcript log
    let mut transcript_log = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("benchmark_terminal.log")
        .expect("Không thể tạo file transcript log");

    // Setup CSV output
    let mut log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("benchmark_results.csv")
        .expect("Không thể tạo file benchmark");

    // Ghi metadata môi trường
    let mut sys = System::new_all();
    sys.refresh_all();
    let cpu_brand = sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_default();
    let cpu_physical_cores = sys.physical_core_count().unwrap_or(0);
    let cpu_logical_threads = sys.cpus().len();
    let total_memory_kib = sys.total_memory();
    let host_name = sys.host_name().unwrap_or_default();
    let os_name = sys.name().unwrap_or_default();
    let os_version = sys.os_version().unwrap_or_default();
    let kernel_version = sys.kernel_version().unwrap_or_default();

    let git_commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "unknown".to_string())
        .trim()
        .to_string();

    let rustc_version = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_else(|| "unknown".to_string())
        .trim()
        .to_string();

    let metadata_json = serde_json::json!({
        "config": {
            "sector_size_bytes": config.sector_size_bytes,
            "chunk_size_bytes": config.chunk_size_bytes,
            "num_chunks_total": num_chunks_total,
            "tree_height": config.tree_height,
            "challenges_per_epoch": config.challenges_per_epoch,
            "epochs_per_window": config.epochs_per_window,
        },
        "platform": {
            "cpu_brand": cpu_brand,
            "cpu_physical_cores": cpu_physical_cores,
            "cpu_logical_threads": cpu_logical_threads,
            "total_memory_kib": total_memory_kib,
            "host_name": host_name,
            "os_name": os_name,
            "os_version": os_version,
            "kernel_version": kernel_version,
        },
        "toolchain": {
            "rustc_version": rustc_version,
            "git_commit": git_commit,
            "nova_snark": "0.71.1",
        }
    });
    fs::write(
        "benchmark_metadata.json",
        serde_json::to_string_pretty(&metadata_json).unwrap(),
    )
    .expect("Không thể ghi benchmark_metadata.json");

    logln!(
        transcript_log,
        "========================================================\n🚀 BẮT ĐẦU SIMULATION ENGRAM: TEST RUNNER (BENCHMARK)\n========================================================"
    );
    logln!(
        transcript_log,
        "\n📝 Đã ghi benchmark_metadata.json:\n{}",
        serde_json::to_string_pretty(&metadata_json).unwrap()
    );

    let metadata = load_mock_metadata();
    logln!(transcript_log, "\n📦 Mock metadata: {:?}", metadata);

    let bitcoin_hashes = load_bitcoin_epoch_hashes();
    for (i, h) in bitcoin_hashes.iter().take(2).enumerate() {
        logln!(transcript_log, "⛏️  Epoch {} bitcoin hash: {}", i, h);
    }

    let mock_sector_data = load_mock_sector_data(&config);
    let sealer = Sealer::new(config.clone());

    // Header CSV
    writeln!(
        log_file,
        "Scenario,Run_ID,Status,Attack_Mode,Drop_Targets,Sector_Size_Bytes,Chunk_Size_Bytes,Challenges_Per_Epoch,\
         Proof_Epoch,Verify_Epoch,Epoch_Status,Proof_Epoch_Hash,Verify_Epoch_Hash,Challenge_Seed,Challenge_Indices,\
         Setup_PublicParams_ms,Setup_PkVk_ms,Setup_RAM_peak_KiB,\
         Seal_C_chunk_absorb_4KB_ms,Seal_C_hash_poseidon2_ms,Seal_C_merkle_build_ms,Seal_RAM_peak_KiB,\
         Challenge_C_hash_poseidon2_ms,Challenge_C_merkle_path_ms,Challenge_RAM_peak_KiB,\
         C_step_total_ms,C_augmented_nova_ms,prove_time_per_step_ms,fold_time_per_step_ms,\
         compressed_proof_size_bytes,Prove_RAM_peak_KiB,Verify_VK_Setup_ms,verify_time_ms,Verify_RAM_peak_KiB"
    )
    .expect("Lỗi ghi header CSV");

    // =====================================================================
    // GIAI ĐOẠN 0: MASTER SEALING (1 lần duy nhất)
    // =====================================================================
    logln!(
        transcript_log,
        "📦 [MASTER] Đang mã hóa và Seal dữ liệu gốc từ mockdata..."
    );
    let mut master_storage = ProverStorage::new();
    let seal_start = Instant::now();
    let seal_metrics = sealer.seal_sector(
        derive_replica_id(&metadata),
        &mock_sector_data,
        &mut master_storage,
    );
    logln!(
        transcript_log,
        "✅ Đã Seal xong {} chunks trong {:.3} ms",
        master_storage.num_chunks,
        elapsed_ms_f64(seal_start)
    );
    logln!(transcript_log, "📊 Sealing metrics: {:?}", seal_metrics);
    logln!(
        transcript_log,
        "🌳 Master Merkle Root: {:?}\n",
        master_storage.merkle_tree.as_ref().unwrap().root
    );

    drop(mock_sector_data);

    let replica_id = derive_replica_id(&metadata);

    let reference_challenge = build_reference_challenge(
        &master_storage,
        &bitcoin_hashes,
        current_epoch,
        num_chunks_total,
        metadata.sector_id,
        replica_id,
    );
    let (shared_pipeline, shared_setup_metrics) = ProvingPipeline::setup(reference_challenge);

    // =====================================================================
    // GIAI ĐOẠN 1: CHẠY CÁC KỊCH BẢN
    // =====================================================================
    let runs_per_scenario = 5;

    let scenarios: &[(&str, AttackMode, usize, usize)] = &[
        ("KB0_HappyPath",                 AttackMode::None,                          current_epoch, current_epoch),
        ("KB1a_DropRaw_1pct_Random",      AttackMode::DropRawRandomPct(1.0),         current_epoch, current_epoch),
        ("KB1b_DropRaw_5pct_Random",      AttackMode::DropRawRandomPct(5.0),         current_epoch, current_epoch),
        ("KB1c_DropRaw_10pct_Random",     AttackMode::DropRawRandomPct(10.0),        current_epoch, current_epoch),
        // FIX: KB1d — test fail path của KB1 (xóa đúng 1 chunk challenge)
        ("KB1d_DropRaw_OneChallenge",     AttackMode::DropRawOneChallenge,           current_epoch, current_epoch),
        ("KB2_DropRaw_AtChallenge",       AttackMode::DropRawAtChallenges,           current_epoch, current_epoch),
        ("KB3_DropState_AtChallengePrev", AttackMode::DropStatesAtChallengePrev,     current_epoch, current_epoch),
        ("KB4_OldProof_NewEpoch",         AttackMode::EpochMismatch,                 current_epoch, next_epoch),
    ];

    for (name, attack, proof_epoch, verify_epoch) in scenarios {
        run_scenario(
            name,
            *attack,
            &config,
            num_chunks_total,
            metadata.sector_id,
            replica_id,
            &master_storage,
            &shared_pipeline,
            &shared_setup_metrics,
            &seal_metrics,
            &bitcoin_hashes,
            *proof_epoch,
            *verify_epoch,
            runs_per_scenario,
            &mut transcript_log,
            &mut log_file,
        );
    }

    logln!(
        transcript_log,
        "\n🎉 HOÀN TẤT! Kết quả Benchmark đã được xuất ra file 'benchmark_results.csv'"
    );
    logln!(
        transcript_log,
        "📋 Metadata môi trường đã được xuất ra file 'benchmark_metadata.json'"
    );
}

// ---------------------------------------------------------------------------
// 5. run_scenario
// ---------------------------------------------------------------------------

fn run_scenario(
    name: &str,
    attack: AttackMode,
    config: &EngramConfig,
    num_chunks_total: usize,
    sector_id: u64,
    replica_id: Fr,
    master_storage: &ProverStorage,
    pipeline: &ProvingPipeline,
    setup_metrics: &prover::SetupMetrics,
    seal_metrics: &prover::SealingMetrics,
    bitcoin_hashes: &[String],
    proof_epoch: usize,
    verify_epoch: usize,
    num_runs: usize,
    transcript_log: &mut std::fs::File,
    log_file: &mut std::fs::File,
) {
    logln!(transcript_log, "\n========================================================");
    logln!(
        transcript_log,
        "🔥 ĐANG CHẠY: {} ({} Lần) — attack={}",
        name,
        num_runs,
        attack.label()
    );
    logln!(transcript_log, "========================================================");

    for run in 1..=num_runs {
        logln!(transcript_log, "\n--- LẦN CHẠY {}/{} ---", run, num_runs);
        let proof_epoch_hash = select_epoch_hash(bitcoin_hashes, proof_epoch);
        let verify_epoch_hash = select_epoch_hash(bitcoin_hashes, verify_epoch);
        let beacon = string_to_fr(&proof_epoch_hash);
        let sealed_root = master_storage
            .merkle_tree
            .as_ref()
            .expect("Thiếu Merkle tree ở master storage")
            .root;

        let challenge_indices: Vec<usize> = (1..=config.challenges_per_epoch)
            .map(|i| derive_challenge_index(&proof_epoch_hash, sector_id, proof_epoch, i, num_chunks_total))
            .collect();
        let challenge_indices_str = challenge_indices
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(";");
        let challenge_seed = format!("beacon:{}|sector:{}|epoch:{}", proof_epoch_hash, sector_id, proof_epoch);
        logln!(
            transcript_log,
            "🎯 Challenge indices (j_i): {}",
            challenge_indices_str
        );

        // Determine attack targets (lightweight, không clone master_storage)
        let mut drop_raw_targets: Vec<usize> = Vec::new();
        let mut drop_state_targets: Vec<usize> = Vec::new();

        match attack {
            AttackMode::None | AttackMode::EpochMismatch => {}
            AttackMode::DropRawRandomPct(pct) => {
                let seed = (proof_epoch as u64)
                    .wrapping_mul(1_000_003)
                    .wrapping_add(run as u64)
                    .wrapping_add(
                        name.bytes()
                            .fold(0u64, |acc, b| acc.wrapping_mul(131).wrapping_add(b as u64)),
                    );
                drop_raw_targets = deterministic_drop_random_pct(pct, seed, num_chunks_total);
                logln!(
                    transcript_log,
                    "   [Mô phỏng] Xóa ngẫu nhiên {} chunks ({}%) — seed={}",
                    drop_raw_targets.len(),
                    pct,
                    seed
                );
            }
            // FIX KB1d: xóa đúng 1 chunk tại index challenge đầu tiên
            AttackMode::DropRawOneChallenge => {
                if let Some(&first_challenge) = challenge_indices.first() {
                    drop_raw_targets = vec![first_challenge];
                    logln!(
                        transcript_log,
                        "   [Mô phỏng KB1d] Xóa D_i tại index challenge đầu tiên: {}",
                        first_challenge
                    );
                }
            }
            AttackMode::DropRawAtChallenges => {
                drop_raw_targets = challenge_indices.clone();
                logln!(
                    transcript_log,
                    "   [Mô phỏng] Xóa D_i tại các index challenge: {:?}",
                    drop_raw_targets
                );
            }
            AttackMode::DropStatesAtChallengePrev => {
                drop_state_targets = challenge_indices
                    .iter()
                    .map(|j| j.saturating_sub(1))
                    .collect();
                logln!(
                    transcript_log,
                    "   [Mô phỏng] Xóa S_{{j_i - 1}} tại các index: {:?}",
                    drop_state_targets
                );
            }
        }

        // Build challenge circuits
        let mut challenge_metrics = ChallengeMetrics::default();
        let mut challenges = Vec::new();
        let mut early_fail = false;
        let mut early_fail_reason = String::new();

        for &j_i in &challenge_indices {
            // Kiểm tra D_ji
            let raw_present = master_storage.has_raw_chunk(j_i) && !drop_raw_targets.contains(&j_i);
            if !raw_present {
                early_fail = true;
                early_fail_reason = format!("missing_D_at_{}", j_i);
                logln!(
                    transcript_log,
                    "❌ LỖI: Prover không thể tạo Proof vì làm mất D_ji tại index {}!",
                    j_i
                );
                break;
            }

            let hash_start = Instant::now();
            let d_ji = master_storage
                .get_raw_chunk(j_i)
                .map(bytes_to_fr)
                .expect("raw chunk phải tồn tại khi raw_present=true");
            challenge_metrics.c_hash_poseidon2_ms += elapsed_ms_f64(hash_start);

            // Kiểm tra S_{j_i - 1}
            let state_prev_index = j_i.saturating_sub(1);
            let s_ji_minus_1 = match master_storage.get_state(state_prev_index) {
                Some(s) if !drop_state_targets.contains(&state_prev_index) => *s,
                _ => {
                    early_fail = true;
                    early_fail_reason = format!("missing_S_at_{}", state_prev_index);
                    logln!(
                        transcript_log,
                        "❌ LỖI: Prover không thể tạo Merkle Path vì làm mất State S_{}!",
                        state_prev_index
                    );
                    break;
                }
            };

            // Kiểm tra S_{j_i}
            let s_ji = match master_storage.get_state(j_i) {
                Some(s) if !drop_state_targets.contains(&j_i) => *s,
                _ => {
                    early_fail = true;
                    early_fail_reason = format!("missing_S_at_{}", j_i);
                    logln!(
                        transcript_log,
                        "❌ LỖI: Prover không thể lấy State S_{} theo mô tả challenge!",
                        j_i
                    );
                    break;
                }
            };

            let merkle_start = Instant::now();
            let proof = master_storage
                .merkle_tree
                .as_ref()
                .unwrap()
                .generate_proof(j_i - 1);
            challenge_metrics.c_merkle_path_ms += elapsed_ms_f64(merkle_start);

            let leaf_r = match master_storage.get_replica(j_i) {
                Some(r) => *r,
                _ => {
                    early_fail = true;
                    early_fail_reason = format!("missing_R_at_{}", j_i);
                    logln!(
                        transcript_log,
                        "❌ LỖI: Prover không thể verify Merkle Path vì làm mất Replica R_{}!",
                        j_i
                    );
                    break;
                }
            };
            let leaf_s = match master_storage.get_state(j_i) {
                Some(s) => *s,
                _ => unreachable!("S_ji đã được kiểm tra ở trên"),
            };
            let merkle_root = master_storage
                .merkle_tree
                .as_ref()
                .unwrap()
                .root;
            if !verify_merkle_proof(merkle_root, leaf_r, leaf_s, &proof) {
                early_fail = true;
                early_fail_reason = format!("invalid_merkle_at_{}", j_i);
                logln!(
                    transcript_log,
                    "❌ LỖI: Merkle path không hợp lệ tại index {}!",
                    j_i
                );
                break;
            }

            challenges.push(EngramStepCircuit {
                epoch: proof_epoch,
                sector_id: Fr::from(sector_id),
                sealed_root,
                beacon,
                j_i,
                d_ji,
                s_ji_minus_1,
                s_ji,
                replica_id,
                path_ji_siblings: proof.siblings,
                path_ji_indices: proof.path_indices,
            });
        }

        if early_fail {
            write_csv_row_fail(
                log_file,
                name,
                run,
                &early_fail_reason,
                attack.label(),
                &drop_raw_targets,
                &drop_state_targets,
                config,
                proof_epoch,
                verify_epoch,
                &proof_epoch_hash,
                &verify_epoch_hash,
                &challenge_seed,
                &challenge_indices_str,
                seal_metrics,
                &challenge_metrics,
            );
            continue;
        }

        logln!(
            transcript_log,
            "⚙️  Chuẩn bị mạch ZK thành công. Bắt đầu Proving..."
        );
        let (spartan_proof, z0, proving_metrics) = pipeline.prove_epoch(challenges);

        let epoch_status = if proof_epoch == verify_epoch {
            "Epoch_Valid"
        } else {
            "Epoch_Mismatch"
        };

        if proof_epoch != verify_epoch {
            logln!(
                transcript_log,
                "❌ [EPOCH CHECK] Proof sinh ở epoch {} nhưng đang verify ở epoch {} (hash cũ: {}, hash mới: {})",
                proof_epoch, verify_epoch, proof_epoch_hash, verify_epoch_hash
            );
        }

        let (is_valid, verification_metrics) = verifier::EngramVerifier::verify_proof(
            &pipeline.pp,
            &spartan_proof,
            config.challenges_per_epoch,
            z0.clone(),
        );

        let steps = config.challenges_per_epoch.max(1) as f64;
        let step_total_ms = (challenge_metrics.c_hash_poseidon2_ms
            + challenge_metrics.c_merkle_path_ms
            + proving_metrics.fold_total_ms)
            / steps;

        let status = if is_valid { "Valid" } else { "Invalid" };
        let mut drop_list: Vec<String> = Vec::new();
        drop_list.extend(drop_raw_targets.iter().map(|i| format!("R{}", i)));
        drop_list.extend(drop_state_targets.iter().map(|i| format!("S{}", i)));
        let drop_str = drop_list.join(";");

        let csv_row = [
            name.to_string(),
            run.to_string(),
            status.to_string(),
            attack.label().to_string(),
            drop_str,
            config.sector_size_bytes.to_string(),
            config.chunk_size_bytes.to_string(),
            config.challenges_per_epoch.to_string(),
            proof_epoch.to_string(),
            verify_epoch.to_string(),
            epoch_status.to_string(),
            proof_epoch_hash.clone(),
            verify_epoch_hash.clone(),
            challenge_seed.clone(),
            challenge_indices_str.clone(),
            format!("{:.3}", setup_metrics.public_params_ms),
            format!("{:.3}", setup_metrics.pk_vk_ms),
            setup_metrics.ram_peak_kib.to_string(),
            format!("{:.3}", seal_metrics.c_chunk_absorb_4kb_ms),
            format!("{:.3}", seal_metrics.c_hash_poseidon2_ms),
            format!("{:.3}", seal_metrics.c_merkle_build_ms),
            seal_metrics.ram_peak_kib.to_string(),
            format!("{:.3}", challenge_metrics.c_hash_poseidon2_ms),
            format!("{:.3}", challenge_metrics.c_merkle_path_ms),
            challenge_metrics.ram_peak_kib.to_string(),
            format!("{:.3}", step_total_ms),
            format!("{:.3}", proving_metrics.c_augmented_nova_ms),
            format!("{:.3}", proving_metrics.prove_time_per_step_ms),
            format!("{:.3}", proving_metrics.fold_time_per_step_ms),
            proving_metrics.compressed_proof_size_bytes.to_string(),
            proving_metrics.ram_peak_kib.to_string(),
            format!("{:.3}", verification_metrics.vk_setup_ms),
            format!("{:.3}", verification_metrics.verify_time_ms),
            verification_metrics.ram_peak_kib.to_string(),
        ]
        .join(",");
        writeln!(log_file, "{}", csv_row).expect("Lỗi ghi file");
    }
}

fn write_csv_row_fail(
    log_file: &mut std::fs::File,
    name: &str,
    run: usize,
    fail_reason: &str,
    attack_label: &str,
    drop_raw: &[usize],
    drop_state: &[usize],
    config: &EngramConfig,
    proof_epoch: usize,
    verify_epoch: usize,
    proof_epoch_hash: &str,
    verify_epoch_hash: &str,
    challenge_seed: &str,
    challenge_indices_str: &str,
    seal_metrics: &prover::SealingMetrics,
    challenge_metrics: &ChallengeMetrics,
) {
    let mut drop_list: Vec<String> = Vec::new();
    drop_list.extend(drop_raw.iter().map(|i| format!("R{}", i)));
    drop_list.extend(drop_state.iter().map(|i| format!("S{}", i)));
    let drop_str = drop_list.join(";");

    let csv_row = [
        name.to_string(),
        run.to_string(),
        format!("Prover_Failed({})", fail_reason),
        attack_label.to_string(),
        drop_str,
        config.sector_size_bytes.to_string(),
        config.chunk_size_bytes.to_string(),
        config.challenges_per_epoch.to_string(),
        proof_epoch.to_string(),
        verify_epoch.to_string(),
        "Epoch_Not_Checked".to_string(),
        proof_epoch_hash.to_string(),
        verify_epoch_hash.to_string(),
        challenge_seed.to_string(),
        challenge_indices_str.to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        format!("{:.3}", seal_metrics.c_chunk_absorb_4kb_ms),
        format!("{:.3}", seal_metrics.c_hash_poseidon2_ms),
        format!("{:.3}", seal_metrics.c_merkle_build_ms),
        seal_metrics.ram_peak_kib.to_string(),
        format!("{:.3}", challenge_metrics.c_hash_poseidon2_ms),
        format!("{:.3}", challenge_metrics.c_merkle_path_ms),
        challenge_metrics.ram_peak_kib.to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
        "0".to_string(),
    ]
    .join(",");
    writeln!(log_file, "{}", csv_row).expect("Lỗi ghi file");
}
