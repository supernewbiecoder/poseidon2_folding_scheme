use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use pasta_curves::{pallas, vesta};
use ff::Field;
use engram_common::{MERKLE_DEPTH, dummy_path_elements, dummy_path_indices};
use nova_snark::{
    traits::{circuit::TrivialCircuit, Group},
    provider::ipa_pc::EvaluationEngine,
    spartan::snark::RelaxedR1CSSNARK,
    CompressedSNARK, PublicParams,
};
use prover_rust::core::circuit::PoStStepCircuit;
use serde::Serialize;
use sysinfo::{System, Pid, get_current_pid};

// 1. Định nghĩa các kiểu dữ liệu chuẩn
type G1 = pallas::Point;
type G2 = vesta::Point;
type EE1 = EvaluationEngine<G1>;
type EE2 = EvaluationEngine<G2>;
type S1 = RelaxedR1CSSNARK<G1, EE1>;
type S2 = RelaxedR1CSSNARK<G2, EE2>;

// --- CẤU HÌNH ĐO LƯỜNG ---
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

// --- CẤU TRÚC BÁO CÁO BENCHMARK ---
#[derive(Serialize)]
struct GenesisBenchmarkReport {
    merkle_depth: usize,
    primary_constraints: usize,
    secondary_constraints: usize,
    
    // Thời gian và năng lượng
    pp_setup_time_ms: f64,
    pp_setup_energy_j: f64,
    pk_vk_setup_time_ms: f64,
    pk_vk_setup_energy_j: f64,
    serialization_time_ms: f64,

    // Chỉ số RAM
    peak_ram_mb: f64,
    total_setup_time_ms: f64,
}

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║              ENGRAM LAYER 0 - GENESIS BENCHMARK SYSTEM               ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════╝\n");

    let params_dir = PathBuf::from("network_params");
    fs::create_dir_all(&params_dir).expect("Không thể tạo thư mục params");

    // Khởi tạo đo RAM
    let mut sys = System::new_all();
    let pid = get_current_pid().unwrap();
    let initial_ram = get_current_ram_mb(&mut sys, pid);
    let mut peak_ram = initial_ram;

    let start_all = Instant::now();

    // 1. Chuẩn bị mạch giả lập
    let dummy_circuit = PoStStepCircuit {
        raw_data: <G1 as Group>::Scalar::ZERO,
        prev_s: <G1 as Group>::Scalar::ZERO,
        challenge_index: <G1 as Group>::Scalar::ZERO,
        path_elements: dummy_path_elements(),
        path_indices: dummy_path_indices(),
    };

    // 2. Tính toán Public Parameters (PP)
    println!("🚀 [Bước 1/3] Đang tính toán Public Parameters (PP)...");
    let pp_start = Instant::now();
    
    let pp = PublicParams::<G1, G2, PoStStepCircuit, TrivialCircuit<<G2 as Group>::Scalar>>::setup(
        &dummy_circuit, 
        &TrivialCircuit::default()
    );
    
    let pp_setup_time_ms = pp_start.elapsed().as_secs_f64() * 1000.0;
    if get_current_ram_mb(&mut sys, pid) > peak_ram { peak_ram = get_current_ram_mb(&mut sys, pid); }

    // 3. Trích xuất Constraints (RÀNG BUỘC)
    let (p_cons, s_cons) = pp.num_constraints();
    println!("   📏 Constraints: Primary = {}, Secondary = {}", p_cons, s_cons);

    // 4. Trích xuất PK và VK
    println!("\n🔑 [Bước 2/3] Đang trích xuất Prover Key (PK) và Verifier Key (VK)...");
    let keys_start = Instant::now();
    
    let (pk, vk) = CompressedSNARK::<G1, G2, PoStStepCircuit, TrivialCircuit<<G2 as Group>::Scalar>, S1, S2>::setup(&pp).unwrap();

    let pk_vk_setup_time_ms = keys_start.elapsed().as_secs_f64() * 1000.0;
    if get_current_ram_mb(&mut sys, pid) > peak_ram { peak_ram = get_current_ram_mb(&mut sys, pid); }

    // 5. Lưu trữ nhị phân (Serialization)
    println!("\n💾 [Bước 3/3] Đang lưu trữ tham số mạng lưới (Serialization)...");
    let ser_start = Instant::now();
    
    fs::write(params_dir.join("pp.bin"), bincode::serialize(&pp).unwrap()).unwrap();
    fs::write(params_dir.join("pk.bin"), bincode::serialize(&pk).unwrap()).unwrap();
    fs::write(params_dir.join("vk.bin"), bincode::serialize(&vk).unwrap()).unwrap();
    
    let serialization_time_ms = ser_start.elapsed().as_secs_f64() * 1000.0;
    if get_current_ram_mb(&mut sys, pid) > peak_ram { peak_ram = get_current_ram_mb(&mut sys, pid); }

    // ============================================================================
    // TỔNG HỢP VÀ XUẤT BÁO CÁO JSON
    // ============================================================================
    let total_time_ms = start_all.elapsed().as_secs_f64() * 1000.0;

    let report = GenesisBenchmarkReport {
        merkle_depth: MERKLE_DEPTH,
        primary_constraints: p_cons,
        secondary_constraints: s_cons,
        pp_setup_time_ms,
        pp_setup_energy_j: calc_energy_joules(pp_setup_time_ms),
        pk_vk_setup_time_ms,
        pk_vk_setup_energy_j: calc_energy_joules(pk_vk_setup_time_ms),
        serialization_time_ms,
        peak_ram_mb: peak_ram,
        total_setup_time_ms: total_time_ms,
    };

    // Tạo thư mục benchmark_results ngang hàng với network_params
    let bench_dir = PathBuf::from("benchmark_results");
    fs::create_dir_all(&bench_dir).unwrap();
    
    let json_path = bench_dir.join("genesis_metrics.json");
    fs::write(&json_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();

    println!("\n✅ THÀNH CÔNG: Tham số mạng lưới đã được khởi tạo.");
    println!("📊 Báo cáo Benchmark JSON: {}", json_path.display());
    println!("📦 Chìa khóa mạng lưới đã lưu tại: network_params/");
}