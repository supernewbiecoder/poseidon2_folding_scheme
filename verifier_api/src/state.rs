use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use core::types::{DealMetadata, VerifierKey};

// Định nghĩa trạng thái chia sẻ toàn cục cho Server (In-memory DB)
pub struct AppState {
    // Lưu trữ cặp khóa xác minh (vk) được nạp từ setup_phase
    pub verifier_key: VerifierKey,
    // Ánh xạ từ sector_id sang dữ liệu R_sealed đã cam kết
    pub sealed_sectors: RwLock<HashMap<String, Vec<u8>>>,
    // Ánh xạ lưu trữ metadata của từng deal
    pub deals_metadata: RwLock<HashMap<String, DealMetadata>>,
}

impl AppState {
    pub fn new(vk: VerifierKey) -> Self {
        Self {
            verifier_key: vk,
            sealed_sectors: RwLock::new(HashMap::new()),
            deals_metadata: RwLock::new(HashMap::new()),
        }
    }
}

// Bọc bằng Arc để chia sẻ an toàn giữa các luồng xử lý của Axum Server
pub type SharedState = Arc<AppState>;