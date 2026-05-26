use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use core::types::{DealMetadata, Proof};
use crate::state::SharedState;

// --- Cấu trúc dữ liệu cho các Request/Response ---

#[derive(Deserialize)]
pub struct DealRequest {
    pub r_sealed: Vec<u8>,
    pub metadata: DealMetadata,
}

#[derive(Deserialize)]
pub struct ChallengeQuery {
    pub epoch: String,
    pub beacon: String,
    pub sector_id: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub sector_id: String,
    pub proof: Proof,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub challenges: Vec<u64>,
}

// --- Các hàm xử lý Endpoint ---

/// POST /deal: Tiếp nhận R_sealed và metadata của deal lưu trữ
pub async fn create_deal(
    State(state): State<SharedState>,
    Json(payload): Json<DealRequest>,
) -> StatusCode {
    let sector_id = payload.metadata.sector_id.clone();
    
    // Lưu thông tin vào In-memory DB
    let mut sectors = state.sealed_sectors.write().await;
    let mut deals = state.deals_metadata.write().await;
    
    sectors.insert(sector_id.clone(), payload.r_sealed);
    deals.insert(sector_id, payload.metadata);
    
    println!("📥 [POST /deal] Đã lưu trữ metadata và cam kết R_sealed thành công.");
    StatusCode::CREATED
}

/// GET /challenge: Thuật toán sinh tập hợp thử thách ngẫu nhiên ràng buộc (Challenge Binding)
pub async fn get_challenge(
    State(state): State<SharedState>,
    Query(query): Query<ChallengeQuery>,
) -> Result<Json<ChallengeResponse>, StatusCode> {
    // Kiểm tra xem sector_id này đã được đăng ký thông qua endpoint /deal chưa
    let sectors = state.sealed_sectors.read().await;
    if !sectors.contains_key(&query.sector_id) {
        return Err(StatusCode::NOT_FOUND);
    }

    let mut challenges = Vec::new();
    let num_challenges = 10; // Giả định hệ thống yêu cầu c = 10 thử thách cho mỗi epoch

    // Thực hiện vòng lặp sinh thử thách: j_i = Poseidon2(Beacon, Sector_id, Epoch, i) mod N
    for i in 0..num_challenges {
        let j_i = core::poseidon2::poseidon2_hash(&[
            query.beacon.as_bytes(),
            query.sector_id.as_bytes(),
            query.epoch.as_bytes(),
            &[i as u8],
        ]) % core::constants::N;
        
        challenges.push(j_i);
    }

    println!("🎲 [GET /challenge] Đã sinh {} thử thách ngẫu nhiên cho Sector: {}", num_challenges, query.sector_id);
    Ok(Json(ChallengeResponse { challenges }))
}

/// POST /verify: Thuật toán xác minh Verify(\pi, R_sealed, J, vk) -> accept/reject
pub async fn verify_proof(
    State(state): State<SharedState>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<bool>, StatusCode> {
    let sectors = state.sealed_sectors.read().await;
    
    // Tìm kiếm R_sealed tương ứng trong DB để đối chiếu bảo mật
    let r_sealed = match sectors.get(&payload.sector_id) {
        Some(data) => data,
        None => return Err(StatusCode::NOT_FOUND),
    };

    println!("🔍 [POST /verify] Tiến hành chạy thuật toán xác minh ZK-Proof...");
    
    // Gọi hàm verify cốt lõi từ thư viện SNARK với Verifier Key (vk) đã nạp
    let is_valid = core::verifier::verify_snark(
        &payload.proof,
        r_sealed,
        &state.verifier_key
    );

    if is_valid {
        println!("✅ [Xác minh] Bằng chứng hợp lệ! Chấp nhận lưu trữ (Accept).");
    } else {
        println!("❌ [Xác minh] Bằng chứng không hợp lệ! Từ chối lưu trữ (Reject).");
    }

    Ok(Json(is_valid))
}