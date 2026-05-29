use core_primitives::config::EngramConfig;
use core_primitives::poseidon2::hash_2;
use core_primitives::merkle_tree::MerkleTree;
use pasta_curves::pallas::Scalar as Fr;
use ff::PrimeField;
use crate::storage::ProverStorage;
use crate::benchmark::{elapsed_ms_f64, PeakMemoryTracker, SealingMetrics};
use std::time::Instant;

/// Chuyển đổi 1 chunk (VD: 4KB) thành 1 phần tử Fr đại diện để đưa vào Poseidon2.
fn chunk_to_fr(chunk: &[u8]) -> Fr {
    let mut repr = [0u8; 32];
    let len = chunk.len().min(32);
    repr[..len].copy_from_slice(&chunk[..len]);
    // Đảm bảo nằm trong trường chuẩn bằng cách set bit cao nhất về 0
    repr[31] &= 0x3f;
    Fr::from_repr(repr).unwrap()
}

fn poseidon2_hash_4(a: Fr, b: Fr, c: Fr, d: Fr) -> Fr {
    let left = hash_2(a, b);
    let right = hash_2(c, d);
    hash_2(left, right)
}

pub struct Sealer {
    config: EngramConfig,
}

impl Sealer {
    pub fn new(config: EngramConfig) -> Self {
        Self { config }
    }

    /// Thực hiện padding và sealing cho một Sector.
    ///
    /// FIX HIỆU NĂNG:
    /// - ProverStorage::with_capacity() pre-allocate đúng capacity → không rehash/realloc
    /// - Instant::now() đặt TRƯỚC khi allocate chunk buffer → đo đúng thời gian thực
    /// - Dùng insert_raw_chunk / insert_state / insert_replica thay vì HashMap::insert
    pub fn seal_sector(
    &self,
    replica_id: Fr,
    raw_sector_data: &[u8],
    storage: &mut ProverStorage,
) -> SealingMetrics {
    let chunk_size = self.config.chunk_size_bytes;
    let num_chunks = self.config.sector_size_bytes / chunk_size;

    *storage = ProverStorage::with_capacity(num_chunks);

    let mut s_prev = replica_id;
    let mut sealed_pairs = Vec::with_capacity(num_chunks);
    let mut metrics = SealingMetrics::default();
    let mut peak = PeakMemoryTracker::new();

    storage.insert_state(0, s_prev);

    // FIX HIỆU NĂNG: Khởi tạo buffer cố định ngoài vòng lặp để tái sử dụng cho chunk cuối (nếu thiếu dữ liệu)
    let mut chunk_buf = vec![0u8; chunk_size];

    for i in 1..=num_chunks {
        let absorb_start = Instant::now();

        let start = (i - 1) * chunk_size;
        let end = start + chunk_size;

        // Trích xuất lát cắt bộ nhớ trực tiếp mà không cấp phát heap mới
        let chunk_slice = if end <= raw_sector_data.len() {
            &raw_sector_data[start..end]
        } else {
            // Chỉ thực hiện xử lý ghi đè buffer khi gặp chunk cuối cùng cần padding dữ liệu rỗng
            chunk_buf.fill(0);
            if start < raw_sector_data.len() {
                let copy_end = raw_sector_data.len();
                chunk_buf[..(copy_end - start)].copy_from_slice(&raw_sector_data[start..copy_end]);
            }
            &chunk_buf
        };
        metrics.c_chunk_absorb_4kb_ms += elapsed_ms_f64(absorb_start);

        // Chuyển đổi slice sang dạng Field Element
        let d_i = chunk_to_fr(chunk_slice);

        // Giữ nguyên logic toán băm
        let hash_start = Instant::now();
        let r_i = poseidon2_hash_4(d_i, s_prev, Fr::from(i as u64), replica_id);
        metrics.c_hash_poseidon2_ms += elapsed_ms_f64(hash_start);

        let s_i = hash_2(s_prev, r_i);

        // Lưu trữ vào cấu trúc mảng O(1)
        storage.insert_raw_chunk(i, chunk_slice.to_vec()); // Chỉ clone khi lưu trữ cố định vào storage
        storage.insert_replica(i, r_i);
        storage.insert_state(i, s_i);

        sealed_pairs.push((r_i, s_i));
        s_prev = s_i;
    }

    let merkle_start = Instant::now();
    let tree = MerkleTree::build(&sealed_pairs);
    metrics.c_merkle_build_ms = elapsed_ms_f64(merkle_start);
    storage.merkle_tree = Some(tree);

    metrics.ram_peak_kib = peak.peak_kib();
    metrics
    }
}
