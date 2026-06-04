//! Simulator runner
//!
//! Đây là binary chịu trách nhiệm điều phối toàn bộ simulation/benchmark:
//! - Gọi `Sealer` để seal dữ liệu mock
//! - Sinh challenges, áp dụng kịch bản tấn công (drop raw/state)
//! - Xây EngramStepCircuit cho mỗi challenge và chạy Proving/Verification
//! - Ghi kết quả benchmark ra CSV
//!
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

type NovaFr = Fr;

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

/// Đọc file text đầu tiên tồn tại trong `paths`.
fn read_first_existing_text(paths: &[&str]) -> Option<String> {
    // Single-source behavior: only attempt the first provided path.
    if let Some(path) = paths.first() {
        if let Ok(text) = fs::read_to_string(path) {
            return Some(text);
        }
    }
    None
}

fn get_raw_data_path(config: &EngramConfig) -> std::path::PathBuf {
    let path = std::path::PathBuf::from("mockdata/data/client_raw_data.bin");
    if let Ok(metadata) = std::fs::metadata(&path) {
        if metadata.len() as usize == config.sector_size_bytes {
            return path;
        }
        panic!(
            "client_raw_data.bin sai kích thước: {} bytes (cần {})",
            metadata.len(), config.sector_size_bytes
        );
    }
    panic!("Không tìm thấy client_raw_data.bin — chạy data_generator trước.");
}

/// Load mock metadata từ `mockdata/metadata/metadata.json`.
fn load_mock_metadata() -> MockMetadata {
    let metadata_text = read_first_existing_text(&["mockdata/metadata/metadata.json"]) .expect("Không thể đọc mock metadata.json");
    serde_json::from_str(&metadata_text).expect("Không thể parse mock metadata.json")
}

/// Load danh sách bitcoin epoch hashes từ mock file.
fn load_bitcoin_epoch_hashes() -> Vec<String> {
    let text = read_first_existing_text(&["mockdata/bitcoin_mocks/bitcoin_blocks.txt"]) .expect("Không thể đọc mock bitcoin_blocks.txt");
    text.lines()
        .filter_map(|line| line.split_once(':').map(|(_, hash)| hash.trim().to_string()))
        .collect()
}

/// Chuyển đổi bytes tùy ý thành Fr bằng cách fold từng lát 31-byte.
/// PHẢI đồng nhất với chunk_to_fr() trong sealing.rs để witness D_ji khớp.
/// Chuyển `bytes` thành `Fr` theo cùng quy tắc fold 31-byte như `chunk_to_fr`.
///
/// Phải giữ cùng thuật toán với `sealing.rs` để D_ji khớp khi build witness.
fn bytes_to_fr(bytes: &[u8]) -> Fr {
    use core_primitives::poseidon2::hash_2 as p2_hash_2;
    const SLICE_SIZE: usize = 31;

    let mut acc = core_primitives::Fr::from(bytes.len() as u64);

    for window in bytes.chunks(SLICE_SIZE) {
        let mut repr = [0u8; 32];
        repr[..window.len()].copy_from_slice(window);
        let slice_fr = Fr::from_repr(repr.into()).unwrap_or_else(|| {
            repr[31] = 0;
            Fr::from_repr(repr.into()).unwrap_or(Fr::ZERO)
        });
        acc = p2_hash_2(acc, slice_fr);
    }

    acc
}

/// Chuyển chuỗi thành `Fr` (sử dụng `bytes_to_fr`).
fn string_to_fr(value: &str) -> Fr {
    bytes_to_fr(value.as_bytes())
}

/// Gộp một dãy `Fr` bằng `hash_2` liên tiếp (dùng làm PRF/seed).
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

/// Derive replica id từ metadata (domain-specific Poseidon chain).
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

/// Tạo public input vector dạng `NovaFr` cho một epoch (z0 format).
// z0 giờ có 7 phần tử (arity=7): [epoch, 0, sector_id, sealed_root, beacon, replica_id, z_acc]
// z_acc khởi tạo = replica_id theo spec Demo.md (z_0 = Replica_id).
fn public_input_for_epoch(epoch: usize, sector_id: NovaFr, sealed_root: NovaFr, beacon: NovaFr, replica_id: NovaFr) -> Vec<NovaFr> {
    vec![
        NovaFr::from(epoch as u64),
        NovaFr::ZERO,
        sector_id,
        sealed_root,
        beacon,
        replica_id,
        replica_id, // z_acc = replica_id tại bước khởi tạo
    ]
}

/// Chuyển `core` Fr sang `NovaFr` an toàn.
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
    // Tính j_i_seed: giá trị hash_chain đầy đủ TRƯỚC khi % N — để truyền vào circuit
    let j_i_seed = {
        let beacon_fr = string_to_fr(&proof_epoch_hash);
        let sector_fr = Fr::from(sector_id);
        let epoch_fr = Fr::from(proof_epoch as u64);
        let challenge_fr = Fr::from(1u64); // challenge_no = 1 (1-based)
        poseidon2_chain(&[beacon_fr, sector_fr, epoch_fr, challenge_fr])
    };
    let d_ji = storage
        .get_raw_chunk(j_i)
        .as_deref()
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
        j_i_seed,
        d_ji,
        s_ji_minus_1,
        s_ji,
        replica_id,
        path_ji_siblings: proof.siblings,
        path_ji_indices: proof.path_indices,
    }
}

/// LCG helper (deterministic pseudo-random) dùng cho drop simulations.
fn lcg_next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

/// Deterministic helper để chọn danh sách indices cần drop.
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

    let raw_data_path = get_raw_data_path(&config);
    let sealer = Sealer::new(config.clone());

    // Header CSV
    writeln!(
        log_file,
        "Scenario,Run_ID,Status,Attack_Mode,Drop_Targets,Sector_Size_Bytes,Chunk_Size_Bytes,Challenges_Per_Epoch,\
         Proof_Epoch,Verify_Epoch,Epoch_Status,Proof_Epoch_Hash,Verify_Epoch_Hash,Challenge_Seed,Challenge_Indices,\
         Setup_PublicParams_ms,Setup_PkVk_ms,Setup_RAM_peak_KiB,\
         Seal_C_chunk_absorb_4KB_ms,Seal_C_hash_poseidon2_ms,Seal_C_merkle_build_ms,Seal_IO_read_ms,Seal_IO_read_count,Seal_RAM_peak_KiB,\
         Challenge_C_hash_poseidon2_ms,Challenge_C_merkle_path_ms,Challenge_IO_read_ms,Challenge_IO_read_count,Challenge_RAM_peak_KiB,\
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
    let seal_metrics = sealer.seal_sector_streaming(
        derive_replica_id(&metadata),
        &raw_data_path,
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

    let replica_id = derive_replica_id(&metadata);

    // FIX (Vấn đề 3): Giải phóng raw_chunks ngay sau khi seal xong và đã build Merkle tree.
    // raw_chunks chiếm ~1GB (262144 chunks × 4KB), không cần thiết cho proving (chỉ cần R_i, S_i, Merkle tree).
    // Nếu không drop, RAM metric của proving phase sẽ bị lạm phát 1GB và không phản ánh overhead thực.
    // QUAN TRỌNG: raw_chunks vẫn CÒN DÙNG khi build challenges trong run_scenario (đọc D_ji).
    // Do đó chúng ta chỉ có thể clear sau khi đã build reference_challenge (dùng để setup pp).
    let reference_challenge = build_reference_challenge(
        &master_storage,
        &bitcoin_hashes,
        current_epoch,
        num_chunks_total,
        metadata.sector_id,
        replica_id,
    );
    let (shared_pipeline, shared_setup_metrics) = ProvingPipeline::setup(reference_challenge);

    // Sau khi setup() đã chạy xong (PublicParams không phụ thuộc raw data),
    // và TRƯỚC khi vào vòng lặp run_scenario — tại đây chúng ta CẦN raw_chunks
    // cho từng challenge build, nên KHÔNG được clear ở đây.
    // raw_chunks sẽ được đọc theo từng j_i trong run_scenario.
    // Nếu muốn tối ưu RAM hơn nữa, có thể dùng lazy-read từ disk thay vì giữ trong memory,
    // nhưng cho mục đích benchmark Phase 1 thì đây là trade-off hợp lý.
    logln!(
        transcript_log,
        "ℹ️  [RAM NOTE] raw_chunks (~{}MB) vẫn còn trong memory để phục vụ challenge building.\n   → RAM metric của proving phase phản ánh tổng process (seal + prove).\n   → Để đo RAM proving thuần, cần thêm lazy-load từ disk (sẽ thực hiện ở Phase 2).",
        (master_storage.num_chunks * 4096) / (1024 * 1024)
    );

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

        // Clone storage cho scenario này (rẻ: không còn raw_chunks 32GB)
        let mut scenario_storage = master_storage.clone_for_attack();

        // Apply drops vào scenario_storage
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
                let dropped = scenario_storage.attack_drop_raw_chunks_random_pct(pct, seed);
                logln!(transcript_log,
                    "   [Mô phỏng] Xóa ngẫu nhiên {} chunks ({}%) — seed={}",
                    dropped.len(), pct, seed);
            }
            AttackMode::DropRawOneChallenge => {
                if let Some(&first_challenge) = challenge_indices.first() {
                    scenario_storage.attack_drop_raw_chunks_at(&[first_challenge]);
                    logln!(transcript_log,
                        "   [Mô phỏng KB1d] Xóa D_i tại index challenge đầu tiên: {}", first_challenge);
                }
            }
            AttackMode::DropRawAtChallenges => {
                scenario_storage.attack_drop_raw_chunks_at(&challenge_indices);
                logln!(transcript_log,
                    "   [Mô phỏng] Xóa D_i tại các index challenge: {:?}", challenge_indices);
            }
            AttackMode::DropStatesAtChallengePrev => {
                let state_targets: Vec<usize> = challenge_indices.iter()
                    .map(|j| j.saturating_sub(1)).collect();
                scenario_storage.attack_drop_states_at(&state_targets);
                logln!(transcript_log,
                    "   [Mô phỏng KB3] Xóa S_{{j_i-1}} tại: {:?}", state_targets);
            }
            _ => {}
        }
        let drop_raw_targets: Vec<usize> = scenario_storage.dropped_raw_indices.iter().cloned().collect();
        let drop_state_targets: Vec<usize> = Vec::new(); // đã xử lý trong scenario_storage

        // Build challenge circuits
        let mut challenge_metrics = ChallengeMetrics::default();
        let mut challenges = Vec::new();
        let mut early_fail = false;
        let mut early_fail_reason = String::new();
        let mut challenge_peak = prover::benchmark::PeakMemoryTracker::new();

        // Snapshot IO counters before building challenges for this scenario
        let io_ns_before = prover::benchmark::io_get_ns_total();
        let io_count_before = prover::benchmark::io_get_count();

        for (challenge_no, &j_i) in challenge_indices.iter().enumerate().map(|(i, v)| (i + 1, v)) {
            // Kiểm tra D_ji từ scenario_storage (đã có drop info)
            let raw_present = scenario_storage.has_raw_chunk(j_i);
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
            let d_ji = scenario_storage
                .get_raw_chunk(j_i)
                .as_deref()
                .map(bytes_to_fr)
                .expect("raw chunk phải tồn tại khi raw_present=true");
            challenge_metrics.c_hash_poseidon2_ms += elapsed_ms_f64(hash_start);

            // Kiểm tra S_{j_i - 1}
            let state_prev_index = j_i.saturating_sub(1);
            let s_ji_minus_1 = match scenario_storage.get_state(state_prev_index) {
                Some(s) => *s,
                None => {
                    early_fail = true;
                    early_fail_reason = format!("missing_S_at_{}", state_prev_index);
                    logln!(transcript_log,
                        "❌ LỖI: Prover không thể tạo Merkle Path vì làm mất State S_{}!",
                        state_prev_index);
                    break;
                }
            };

            // Kiểm tra S_{j_i}
            let s_ji = match scenario_storage.get_state(j_i) {
                Some(s) => *s,
                None => {
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

            // Tính j_i_seed: hash_chain đầy đủ tương ứng với challenge_no này
            let j_i_seed = {
                let beacon_fr_local = string_to_fr(&proof_epoch_hash);
                let sector_fr_local = Fr::from(sector_id);
                let epoch_fr_local = Fr::from(proof_epoch as u64);
                let challenge_fr_local = Fr::from(challenge_no as u64);
                poseidon2_chain(&[beacon_fr_local, sector_fr_local, epoch_fr_local, challenge_fr_local])
            };

            challenges.push(EngramStepCircuit {
                epoch: proof_epoch,
                sector_id: Fr::from(sector_id),
                sealed_root,
                beacon,
                j_i,
                j_i_seed,
                d_ji,
                s_ji_minus_1,
                s_ji,
                replica_id,
                path_ji_siblings: proof.siblings,
                path_ji_indices: proof.path_indices,
            });
            // Challenge loop nhỏ, vẫn giữ sample mỗi bước để bắt peak của witness build.
            challenge_peak.sample();
        }
        // compute IO delta for challenge building
        let io_ns_after_build = prover::benchmark::io_get_ns_total();
        let io_count_after_build = prover::benchmark::io_get_count();
        challenge_metrics.io_read_ms = (io_ns_after_build.saturating_sub(io_ns_before) as f64) / 1_000_000.0;
        challenge_metrics.io_read_count = io_count_after_build.saturating_sub(io_count_before);
        challenge_metrics.ram_peak_kib = challenge_peak.peak_delta_kib();

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
                "⚠️  [KB4 EPOCH CHECK] Proof sinh ở epoch {} (beacon: {}...) nhưng verifier dùng epoch {} (beacon: {}...)",
                proof_epoch,
                &proof_epoch_hash[..16],
                verify_epoch,
                &verify_epoch_hash[..16]
            );
            logln!(
                transcript_log,
                "   → Verifier tự tính z0 từ verify_epoch — nếu proof dùng epoch cũ sẽ bị reject."
            );
        }

        // FIX KB4: Verifier phải tự build z0 từ verify_epoch_hash,
        // KHÔNG được dùng z0_primary từ prover (đó là replay attack).
        // Nếu epoch không khớp, beacon trong z0_verify sẽ khác beacon trong proof
        // → verify thất bại vì epoch_binding constraint sẽ reject.
        let verify_beacon = string_to_fr(&verify_epoch_hash);
        let verify_z0 = vec![
            NovaFr::from(verify_epoch as u64),          // epoch từ verify side
            NovaFr::ZERO,                                // step counter bắt đầu từ 0
            nova_fr_from_core(Fr::from(sector_id)),
            nova_fr_from_core(sealed_root),
            nova_fr_from_core(verify_beacon),            // beacon của verify_epoch, không phải proof_epoch
            nova_fr_from_core(replica_id),
            nova_fr_from_core(replica_id),               // z_acc khởi tạo = replica_id
        ];

        let (is_valid, verification_metrics) = verifier::EngramVerifier::verify_proof(
            &pipeline.pp,
            &spartan_proof,
            config.challenges_per_epoch,
            verify_z0,
            Some(&pipeline.vk),  // FIX: dùng vk cached, không gọi setup() lần 3
        );

        let steps = config.challenges_per_epoch.max(1) as f64;
        let step_total_ms = (challenge_metrics.c_hash_poseidon2_ms
            + challenge_metrics.c_merkle_path_ms
            + proving_metrics.fold_total_ms)
            / steps;

        let status = if is_valid { "Valid" } else { "Invalid" };
        logln!(
            transcript_log,
            "{}  [VERIFY RESULT] Kịch bản {} — {}{}",
            if is_valid { "✅" } else { "❌" },
            name,
            status,
            if proof_epoch != verify_epoch && is_valid {
                " ← BUG: epoch mismatch nhưng vẫn Valid!"
            } else if proof_epoch != verify_epoch && !is_valid {
                " ← ĐÚNG: epoch mismatch bị bắt chính xác."
            } else {
                ""
            }
        );
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
            format!("{:.3}", seal_metrics.io_read_ms),
            seal_metrics.io_read_count.to_string(),
            seal_metrics.ram_peak_kib.to_string(),
            format!("{:.3}", challenge_metrics.c_hash_poseidon2_ms),
            format!("{:.3}", challenge_metrics.c_merkle_path_ms),
            format!("{:.3}", challenge_metrics.io_read_ms),
            challenge_metrics.io_read_count.to_string(),
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
        format!("{:.3}", seal_metrics.io_read_ms),
        seal_metrics.io_read_count.to_string(),
        seal_metrics.ram_peak_kib.to_string(),
        format!("{:.3}", challenge_metrics.c_hash_poseidon2_ms),
        format!("{:.3}", challenge_metrics.c_merkle_path_ms),
        format!("{:.3}", challenge_metrics.io_read_ms),
        challenge_metrics.io_read_count.to_string(),
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
