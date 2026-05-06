use pasta_curves::pallas::Scalar as Fr;
use ff::Field;
use rand::Rng;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// Khai báo các module con
mod constants;
mod core;

use crate::core::circuit::{DataSector, PoStStepCircuit};
use crate::core::proof_engine::PostProofEngine;

fn parse_shard_count() -> usize {
    if let Ok(value) = env::var("ENGRAM_SHARD_COUNT") {
        if let Ok(count) = value.trim().parse::<usize>() {
            return count;
        }
    }

    if let Some(arg) = env::args().nth(1) {
        if let Ok(count) = arg.trim().parse::<usize>() {
            return count;
        }
    }

    print!("[Hệ thống] Nhập số lượng file shard cần đọc (shard_0.txt..shard_n.txt):\n> ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_ok() {
        input.trim().parse::<usize>().unwrap_or(4)
    } else {
        4
    }
}

fn parse_challenge_count(shard_count: usize) -> usize {
    if let Ok(value) = env::var("ENGRAM_CHALLENGE_COUNT") {
        if let Ok(count) = value.trim().parse::<usize>() {
            return count.max(1).min(shard_count);
        }
    }

    if let Some(arg) = env::args().nth(2) {
        if let Ok(count) = arg.trim().parse::<usize>() {
            return count.max(1).min(shard_count);
        }
    }

    print!("[Hệ thống] Nhập số challenge cần chứng minh trong 1 batch (mặc định 4):\n> ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    let parsed = if io::stdin().read_line(&mut input).is_ok() {
        input.trim().parse::<usize>().ok()
    } else {
        None
    };

    parsed.unwrap_or(4).max(1).min(shard_count)
}

fn shard_dir() -> PathBuf {
    let raw_dir = env::var("ENGRAM_SHARD_DIR").ok().map(PathBuf::from);
    let root_dir = env::var("ENGRAM_ROOT_DIR").ok().map(PathBuf::from);

    if let Some(dir) = raw_dir {
        if dir.is_absolute() {
            return dir;
        }

        if let Some(root) = &root_dir {
            let repo_relative = root.join(&dir);
            if repo_relative.exists() {
                return repo_relative;
            }

            let prover_relative = root.join("prover-rust").join(&dir);
            if prover_relative.exists() {
                return prover_relative;
            }
        }

        if let Ok(current_dir) = env::current_dir() {
            let cwd_relative = current_dir.join(&dir);
            if cwd_relative.exists() {
                return cwd_relative;
            }
        }

        return dir;
    }

    env::current_dir().unwrap()
}

fn load_shard_files(count: usize, dir: &Path) -> Vec<String> {
    let mut shards = Vec::with_capacity(count);

    for index in 0..count {
        let file_name = format!("shard_{}.txt", index);
        let file_path = dir.join(&file_name);
        let content = fs::read_to_string(&file_path).unwrap_or_else(|_| {
            panic!("Không tìm thấy hoặc không đọc được file shard: {}", file_path.display())
        });
        println!("[Input] Loaded {} ({} bytes)", file_path.display(), content.as_bytes().len());
        shards.push(content);
    }

    shards
}

fn main() {
    println!("\n======================================================================");
    println!("  MÔ PHỎNG GIAO THỨC ENGRAM (KIẾN TRÚC PIPELINE CHUẨN PRODUCT)");
    println!("======================================================================\n");

    let requested_shard_count = parse_shard_count();
    if requested_shard_count == 0 {
        eprintln!("[Input] Số lượng shard phải lớn hơn 0");
        std::process::exit(1);
    }

    let shard_directory = shard_dir();
    println!("[Input] Đọc {} file từ {}", requested_shard_count, shard_directory.display());
    let raw_shards = load_shard_files(requested_shard_count, &shard_directory);

    print!("\n[Provider] Đang băm dữ liệu và dựng cây Merkle...");
    io::stdout().flush().unwrap();
    let sector = DataSector::new(raw_shards);
    println!(" ✅ Xong. Mã cam kết: {:?}", sector.commitment_root);

    print!("[Engine] Đang khởi tạo Nova Public Params và Spartan Keys...");
    io::stdout().flush().unwrap();

    let (init_data, init_path, init_indices) = sector.get_proof(0);
    let init_circuit = PoStStepCircuit {
        raw_data: init_data,
        challenge_index: Fr::ZERO,
        path_elements: init_path,
        path_indices: init_indices,
    };

    let engine = PostProofEngine::new(&init_circuit);
    println!(" ✅ Xong");

    // Khởi tạo batch thử thách (Epoch mô phỏng)
    let batch_size = parse_challenge_count(requested_shard_count);
    let mut rng = rand::thread_rng();
    let mut challenges = vec![];
    while challenges.len() < batch_size {
        let idx = rng.gen_range(0..requested_shard_count) as usize;
        if !challenges.contains(&idx) { challenges.push(idx); }
    }
    challenges.sort();
    println!("[Network] Yêu cầu xác minh {} shard: {:?}", batch_size, challenges);

    // Tạo các bước (steps) để Folding
    let mut steps = vec![];
    for &idx in &challenges {
        let (raw_data, path_elements, path_indices) = sector.get_proof(idx);
        steps.push(PoStStepCircuit {
            raw_data, challenge_index: Fr::from(idx as u64),
            path_elements, path_indices
        });
    }

    let z0 = vec![Fr::ZERO, sector.commitment_root];
    
    // Gọi luồng thực thi chính!
    engine.run_pipeline(steps, z0);
}