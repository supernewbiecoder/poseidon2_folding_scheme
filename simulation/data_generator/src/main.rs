//Đoạn code này sẽ tự động tạo thư mục mockdata và sinh ra 3 thành phần bạn yêu cầu: 
// Block hash giả lập của Bitcoin, dữ liệu client (giả lập 1GB để khớp sector/padding),
//  và file metadata.
//Cách chạy thử
//Từ thư mục gốc simulation, bạn mở terminal và chạy lệnh:
//Bash
//cargo run --bin data_generator

//----------------------------------------------------------
use rand::{Rng, RngCore};
use core_primitives::config::EngramConfig;
use serde::Serialize;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

// Cấu trúc Metadata của Client
#[derive(Serialize)]
struct Metadata {
    client_id: String,
    deal_id: String,
    sector_id: u64,
    copy_index: u8,
    nonce: u64,
}

// Hằng số cho mô phỏng
const MOCK_DATA_DIR: &str = "./mockdata";
const BITCOIN_EPOCHS: usize = 10;

fn main() -> io::Result<()> {
    println!("🚀 Khởi tạo Engram Simulation - Data Generator");

    // 1. Tạo cấu trúc thư mục
    let dirs = [
        format!("{}/bitcoin_mocks", MOCK_DATA_DIR),
        format!("{}/data", MOCK_DATA_DIR),
        format!("{}/metadata", MOCK_DATA_DIR),
    ];

    for dir in &dirs {
        fs::create_dir_all(dir)?;
        println!("📁 Đã tạo thư mục: {}", dir);
    }

    // 2. Sinh Bitcoin mockdata (Block hash cho Challenge)
    generate_bitcoin_mocks(Path::new(&dirs[0]))?;

    // 3. Sinh Client Data ngẫu nhiên
    generate_client_data(Path::new(&dirs[1]))?;

    // 4. Sinh Metadata
    generate_metadata(Path::new(&dirs[2]))?;

    println!("✅ Hoàn tất sinh Mock Data!");
    Ok(())
}

fn generate_bitcoin_mocks(dir: &Path) -> io::Result<()> {
    let mut rng = rand::thread_rng();
    let file_path = dir.join("bitcoin_blocks.txt");
    let mut file = File::create(&file_path)?;

    for epoch in 0..BITCOIN_EPOCHS {
        let mut hash = [0u8; 32];
        rng.fill_bytes(&mut hash);
        let hex_hash = hex::encode(hash);
        
        writeln!(file, "Epoch {}: {}", epoch, hex_hash)?;
    }
    
    println!("   -> Đã sinh {} epoch Bitcoin hashes tại {:?}", BITCOIN_EPOCHS, file_path);
    Ok(())
}

fn generate_client_data(dir: &Path) -> io::Result<()> {
    let mut rng = rand::thread_rng();
    let file_path = dir.join("client_raw_data.bin");
    let mut file = File::create(&file_path)?;

    let size_in_bytes = EngramConfig::mock_dev().sector_size_bytes as usize;
    let mut buffer = vec![0u8; 1024 * 1024]; // write in 1 MiB chunks

    let mut bytes_written = 0usize;
    while bytes_written < size_in_bytes {
        let remaining = size_in_bytes - bytes_written;
        let write_size = remaining.min(buffer.len());
        rng.fill_bytes(&mut buffer[..write_size]);
        file.write_all(&buffer[..write_size])?;
        bytes_written += write_size;
    }

    println!(
        "   -> Đã sinh {} bytes client data tại {:?}",
        size_in_bytes,
        file_path
    );
    Ok(())
}

fn generate_metadata(dir: &Path) -> io::Result<()> {
    let mut rng = rand::thread_rng();
    
    let metadata = Metadata {
        client_id: format!("client_{}", hex::encode(rng.gen::<[u8; 4]>())),
        deal_id: format!("deal_{}", hex::encode(rng.gen::<[u8; 4]>())),
        sector_id: rng.gen_range(1000..9999),
        copy_index: 1,
        nonce: rng.gen::<u64>(),
    };

    let file_path = dir.join("metadata.json");
    let file = File::create(&file_path)?;
    serde_json::to_writer_pretty(file, &metadata)?;

    println!("   -> Đã sinh metadata JSON tại {:?}", file_path);
    Ok(())
}