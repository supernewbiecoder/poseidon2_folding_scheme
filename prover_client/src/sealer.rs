use core::poseidon2::poseidon2_hash;
use core::merkle::MerkleTree;
use core::types::{DealMetadata, SectorData};

/// Trả về R_sealed (File mã hóa), Root (Merkle Root), và Aux (dữ liệu phụ trợ)
pub fn seal_sector(data: &SectorData, meta: &DealMetadata) -> (Vec<u8>, [u8; 32], Vec<u8>) {
    // Sinh định danh duy nhất cho Replica dựa trên metadata của hợp đồng
    let replica_id = poseidon2_hash(&[
        meta.client_id, meta.deal_id, meta.sector_id, meta.copy_index, meta.nonce
    ]);

    let mut s_prev = replica_id.clone(); // S_0 = Replica_id
    let mut sealed_chunks = Vec::new();
    let mut aux_data = Vec::new(); // Lưu trữ trạng thái trung gian S_i để làm witness

    // Lặp qua từng chunk dữ liệu D_i
    for (i, chunk) in data.chunks().enumerate() {
        // 1. Replica encoding: R_i = Poseidon2(D_i, S_{i-1}, i, Replica_id)
        let r_i = poseidon2_hash(&[chunk, &s_prev, i as u64, &replica_id]);
        
        // 2. State transition: S_i = Poseidon2(S_{i-1}, R_i)
        let s_i = poseidon2_hash(&[&s_prev, &r_i]);

        sealed_chunks.push(r_i);
        aux_data.push(s_i.clone());
        s_prev = s_i;
    }

    // 3. Merkle commitment: R_sealed = MerkleRoot(R_1, R_2, ... R_n)
    let merkle_tree = MerkleTree::build(&sealed_chunks);
    let root = merkle_tree.get_root();

    // R_sealed trong thực tế sẽ được ghi thẳng ra ổ cứng thành file mới
    (sealed_chunks.into_iter().flatten().collect(), root, aux_data.into_iter().flatten().collect())
}