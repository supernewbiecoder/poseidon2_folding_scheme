use pasta_curves::pallas::Scalar as Fr;
use ff::Field;
use ff::PrimeField;
use sha2::{Digest, Sha256};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use configparser::ini::Ini; // Import đúng theo phong cách Rust

fn get_network_config() -> (u64, String) {
    let mut config = Ini::new();
    
    // SỬA Ở ĐÂY: Thêm 1 cấp "../" nữa để lùi ra đúng thư mục gốc Layers_of_PoSt
    match config.load("../../CURRENT_EPOCH_IN_BITCOIN.conf") {
        Ok(_) => {},
        Err(_) => panic!("❌ Không tìm thấy file CURRENT_EPOCH_IN_BITCOIN.conf ở thư mục gốc (../../)"),
    }
    
    // Truy xuất giá trị
    let current_epoch = config.get("DEFAULT", "CURRENT_EPOCH").unwrap().parse::<u64>().unwrap();
    let current_bitcoin_hash = config.get("DEFAULT", "LATEST_BITCOIN_HASH").unwrap();
    
    (current_epoch, current_bitcoin_hash)
}

// Khai báo các module con từ cấu trúc thư mục của bạn
mod constants;
mod core;

use crate::core::circuit::{DataSector, PoStStepCircuit};
use crate::core::proof_engine::PostProofEngine;

/// 1. Hàm xác định thư mục chứa dữ liệu sample_shards
fn get_shard_dir() -> PathBuf {
    let mut dir = env::current_dir().unwrap();
    // Nếu đang đứng ở thư mục gốc Engram, đi vào prover-rust
    if dir.ends_with("Engram") {
        dir = dir.join("prover-rust");
    }
    dir.join("sample_shards")
}

/// 2. Hàm đọc chính xác danh sách file shard mà Prover này cam kết lưu trữ
fn load_specific_shards(indices: &[usize], dir: &Path) -> Vec<String> {
    let mut shards = Vec::new();
    for &idx in indices {
        let file_name = format!("shard_{}.txt", idx);
        let path = dir.join(&file_name);
        let content = fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!("❌ Không tìm thấy file: {}. Hãy kiểm tra thư mục sample_shards!", path.display())
        });
        println!("[Input] Prover đã nạp {}: ({} bytes)", file_name, content.len());
        shards.push(content);
    }
    shards
}

fn main() {
    println!("\n======================================================================");
    println!("  MÔ PHỎNG ENGRAM LAYER 1: PROVER COMMITMENT & POST FLOW");
    println!("======================================================================\n");

    // 3. Phân tích tham số CLI: cargo run -- <PROVER_ID> <SHARD_INDICES>
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("❌ Thiếu tham số!");
        eprintln!("Sử dụng: cargo run -- <PROVER_ID> <CHỈ_SỐ_SHARD_PHÂN_CÁCH_BỞI_DẤU_PHẨY>");
        eprintln!("Ví dụ: cargo run -- 1001 0,1,2");
        std::process::exit(1);
    }

    let prover_id_raw = &args[1];
    let prover_id = Fr::from_str_vartime(prover_id_raw).expect("Prover ID không hợp lệ");
    env::set_var("ENGRAM_PROVER_ID", prover_id_raw);
    
    let shard_indices: Vec<usize> = args[2]
        .split(',')
        .map(|s| s.trim().parse().expect("Chỉ số shard phải là số nguyên"))
        .collect();

    // 4. Lấy Epoch và Hash hiện tại từ file đồng bộ mạng lưới (CURRENT_EPOCH_IN_BITCOIN.conf)
    let (current_epoch, current_bitcoin_hash) = get_network_config();
    let epoch_fr = Fr::from(current_epoch);

    println!("[Trạng thái] Prover ID: {} | Epoch Đồng Bộ: {}", prover_id_raw, current_epoch);

    // 5. Niêm phong dữ liệu (Poseidon2-CBC Sealing)
    let shard_dir = get_shard_dir();
    let raw_shards = load_specific_shards(&shard_indices, &shard_dir);
    
    print!("[Sealing] Đang thực hiện CBC Sealing và dựng Merkle Tree...");
    io::stdout().flush().unwrap();
    let sector = DataSector::new(raw_shards, prover_id, epoch_fr);
    println!(" ✅ Xong. Root: {:?}", sector.commitment_root);

    // 6. Tạo Challenge Seed từ Bitcoin Block Hash thực tế
    let mut seed_hasher = Sha256::new();
    seed_hasher.update(current_bitcoin_hash.as_bytes()); // Sử dụng hash lấy từ config
    seed_hasher.update(prover_id.to_repr());
    let seed_bytes: [u8; 32] = seed_hasher.finalize().into();

    // 7. Ánh xạ Shard thử thách bằng PRNG (ChaCha8) từ Seed
    let mut prng = ChaCha8Rng::from_seed(seed_bytes);
    let mut challenges = vec![];
    let num_challenges = 2.min(shard_indices.len()); // Thử thách 2 shard ngẫu nhiên trong danh sách đã lưu
    
    while challenges.len() < num_challenges {
        let rand_idx = prng.gen_range(0..shard_indices.len());
        if !challenges.contains(&shard_indices[rand_idx]) {
            challenges.push(shard_indices[rand_idx]);
        }
    }
    println!("[Network] Bitcoin Seed chỉ định Prover {} chứng minh các Shard: {:?}", prover_id_raw, challenges);

    // 8. Khởi tạo Nova Proof Engine
    print!("[Engine] Đang khởi tạo Nova Public Params...");
    io::stdout().flush().unwrap();
    
    // Lấy shard đầu tiên để làm mẫu khởi tạo mạch
    let (data0, prev_s0, path0, indices0) = sector.get_proof(0);
    let init_circuit = PoStStepCircuit {
        raw_data: data0,
        prev_s: prev_s0,
        challenge_index: Fr::from(shard_indices[0] as u64),
        path_elements: path0,
        path_indices: indices0,
    };
    
    // Nạp tham số từ Layer 0 (Đã xóa vk_path dư thừa)
    let params_dir = PathBuf::from("../../Layer_0_genesis_setup/network_params");
    let pp_path = params_dir.join("pp.bin");
    let pk_path = params_dir.join("pk.bin");

    let engine = PostProofEngine::from_params(&pp_path, &pk_path);
    println!(" ✅ Đã nạp tham số mạng lưới thành công.");
    println!(" ✅ Xong");

    // 9. Tạo các bước Folding (Steps) cho từng thử thách
    let mut steps = vec![];
    for &idx_in_storage in &challenges {
        // Tìm vị trí tương đối trong mảng local của Prover
        let local_pos = shard_indices.iter().position(|&x| x == idx_in_storage).unwrap();
        let (raw_data, prev_s, path_elements, path_indices) = sector.get_proof(local_pos);
        
        steps.push(PoStStepCircuit {
            raw_data,
            prev_s,
            challenge_index: Fr::from(idx_in_storage as u64),
            path_elements,
            path_indices,
        });
    }
    
    // Lấy kích thước path từ chứng minh đầu tiên
    let merkle_depth = init_circuit.path_elements.len();
    
    // 10. Chạy Pipeline: Folding (Nova) -> Compression (Spartan) -> Export (JSON)
    let metadata = serde_json::json!({
        "prover_id": prover_id_raw,
        "epoch": current_epoch,
        "bitcoin_hash_used": current_bitcoin_hash,
        "shards_proven": challenges,
        "total_shards_stored": shard_indices.len(),
        "merkle_depth": merkle_depth 
    });

    let z0 = vec![Fr::ZERO, sector.commitment_root];
    engine.run_pipeline(steps, z0, metadata);

    println!("\n[Kết thúc] Prover {} đã hoàn thành nhiệm vụ Epoch {}.", prover_id_raw, current_epoch);
}