use pasta_curves::pallas::Scalar as Fr;

/// Định danh Replica duy nhất, khóa chặt dữ liệu với thông tin hợp đồng
#[derive(Debug, Clone)]
pub struct ReplicaId {
    pub client_id: Fr,
    pub deal_id: Fr,
    pub sector_id: Fr,
    pub copy_index: Fr,
    pub nonce: Fr,
}

/// Thông tin Metadata cơ bản của một Sector
#[derive(Debug, Clone)]
pub struct Metadata {
    pub sector_id: Fr,
    pub epoch: Fr,
    pub beacon: Fr,
}

/// Struct đại diện cho Bằng chứng ZK (zk-SNARK proof)
#[derive(Debug, Clone)]
pub struct Proof {
    // Placeholder cho dữ liệu byte của proof sinh ra từ Nova/Spartan
    pub pi: Vec<u8>, 
}

/// Trạng thái tích lũy cho cơ chế đệ quy (Folding Scheme IVC)
#[derive(Debug, Clone)]
pub struct IVCState {
    pub z_i: Fr,
}