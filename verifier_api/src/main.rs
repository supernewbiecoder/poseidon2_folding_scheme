mod state;
mod routes;

use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🖥️  Khởi động Node Verifier API Server...");

    // 1. Nạp khóa xác minh vk từ file vật lý do setup_phase sinh ra
    // Điều này đảm bảo tính độc lập dữ liệu giữa Prover và Verifier
    let vk = core::setup_phase::load_verifier_key("../setup_phase/generated_keys/verifier_key.bin")
        .expect("⚠️ Không thể nạp verifier_key.bin. Vui lòng chạy setup_phase trước!");

    // 2. Khởi tạo trạng thái ứng dụng dùng chung
    let shared_state = Arc::new(AppState::new(vk));

    // 3. Thiết lập hệ thống Router nối các endpoint định sẵn
    let app = Router::new()
        .route("/deal", post(routes::create_deal))          // Tiếp nhận deal và R_sealed 
        .route("/challenge", get(routes::get_challenge))    // Cấp phát thử thách ngẫu nhiên 
        .route("/verify", post(routes::verify_proof))       // Thực thi xác minh zk-proof 
        .with_state(shared_state);

    // 4. Liên kết Server vào Port nội bộ 8080 để lắng nghe Request
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    println!("📡 Server đang lắng nghe tín hiệu tại địa chỉ: http://{}", listener.local_addr()?);
    println!("💡 Bạn có thể dùng Postman để kiểm thử độc lập các luồng /deal và /challenge lúc này.");

    axum::serve(listener, app).await?;

    Ok(())
}