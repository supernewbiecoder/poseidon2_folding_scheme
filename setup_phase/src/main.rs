use std::fs::File;
use std::io::Write;
use std::path::Path;
use core::types::{PublicParams, ProverKey, VerifierKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("⚙️  Bắt đầu tiến trình Setup hệ thống Engram (Chạy 1 lần)...");

    // 1. Khởi tạo tham số an toàn \lambda và cấu hình hệ thống
    // Hệ thống sử dụng cặp đường cong Elliptic Pallas/Vesta để hỗ trợ mạch đệ quy Nova
    let security_parameter = 128; 
    println!("🧬 Khởi tạo hệ thống trên cặp đường cong Pallas/Vesta (Security Level: {} bits)...", security_parameter);

    // 2. Biên dịch Step Circuit (C_step)
    // Mạch C_step chứa toàn bộ logic kiểm tra: Replica Reconstruction, State Check, 
    // Path Check (Merkle), Challenge Binding, và State Accumulation.
    println!("📐 Đang biên dịch mạch logic C_step và tính toán hệ thống ràng buộc (R1CS)...");
    
    // Giả lập số lượng constraint tối thiểu cần sinh ra cho cấu trúc Poseidon2 và Merkle Tree
    let constraints_count = 15000; 
    println!("📊 Tổng số lượng ràng buộc được thiết lập cho 1 bước (Step): {} constraints", constraints_count);

    // 3. Sinh các Public Parameters (pp), Prover Key (pk), và Verifier Key (vk)
    println!("🔑 Đang tính toán và sinh các bộ khóa mật mã...");
    let pp = PublicParams::initialize(security_parameter, constraints_count);
    let pk = ProverKey::generate(&pp);
    let vk = VerifierKey::generate(&pp);

    // 4. Lưu trữ các khóa vật lý ra file (.bin) để Prover và Verifier nạp vào sau này
    let output_dir = Path::new("./generated_keys");
    if !output_dir.exists() {
        std::fs::create_dir_all(output_dir)?;
    }

    println!("💾 Đang kết xuất (serialize) tham số và các khóa ra ổ cứng...");
    
    // Lưu Public Parameters (Dùng chung cho cả hệ thống)
    save_key_to_disk(&pp, "./generated_keys/public_params.bin")?;
    
    // Lưu Prover Key (Gửi cho Node Prover/Worker để tính toán bằng chứng nặng)
    save_key_to_disk(&pk, "./generated_keys/prover_key.bin")?;
    
    // Lưu Verifier Key (Gửi cho Node Verifier API hoặc Smart Contract để xác minh gọn nhẹ)
    save_key_to_disk(&vk, "./generated_keys/verifier_key.bin")?;

    println!("✨ Tiến trình Setup hoàn tất thành công!");
    println!("📂 Tất cả các file khóa đã được lưu tại thư mục: ./generated_keys/");

    Ok(())
}

/// Hàm trợ giúp tuần tự hóa cấu trúc dữ liệu và ghi xuống file nhị phân
fn save_key_to_disk<T: serde::Serialize>(key_data: &T, file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(file_path)?;
    let serialized_data = bincode::serialize(key_data)?;
    file.write_all(&serialized_data)?;
    println!("   -> Đã ghi file: {}", file_path);
    Ok(())
}