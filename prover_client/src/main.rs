mod api_client;
mod sealer;
mod circuit;
mod folding;

use core::types::{DealMetadata, SectorData};
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Khởi động Prover Client Node...");

    // 1. Nạp public parameters và proving key (pp, pk)
    // Thực tế sẽ đọc từ file do tiến trình setup_phase sinh ra
    let (pp, pk) = core::setup_phase::load_keys("prover_keys.bin");

    // 2. Lấy dữ liệu thô D và thông tin S_info từ ổ cứng/Client
    let raw_data = SectorData::load_from_disk("raw_sector_32gb.dat");
    let metadata = DealMetadata::new("client_01", "deal_001", "sector_100", 1, 12345);

    // 3. Quá trình Sealing dữ liệu
    println!("🔒 Bắt đầu quá trình Sealing...");
    let (r_sealed, merkle_root, aux) = sealer::seal_sector(&raw_data, &metadata);

    // 4. Gửi Commit lên Verifier API
    println!("📡 Gửi cam kết lên Verifier...");
    api_client::commit_sector(r_sealed, metadata.clone()).await?;

    // 5. Lấy Challenge từ Verifier
    let challenge_indices = api_client::get_challenge("epoch_10", "random_beacon_hex", &metadata.sector_id).await?;

    // 6. Chạy Folding Scheme (IVC/Nova) để tạo Proof
    println!("🧠 Đang tính toán ZK-SNARK Proof...");
    let proof = folding::generate_proof(&raw_data, &aux, challenge_indices, &pp, &pk);

    // 7. Gửi Proof để Verify
    let is_valid = api_client::verify_proof(proof, r_sealed).await?;
    
    if is_valid {
        println!("✅ Bằng chứng hợp lệ. Lưu trữ thành công!");
    } else {
        println!("❌ Bằng chứng bị từ chối.");
    }

    Ok(())
}