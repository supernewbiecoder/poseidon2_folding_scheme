//! Sealing module
//!
//! Đây là module chịu trách nhiệm "sealing" (niêm phong) một sector dữ liệu.
//! Nó chuyển các chunk bytes sang phần tử trường (`Fr`), tính replica chunks `R_i` và state `S_i`,
//! lưu vào `ProverStorage` và xây Merkle tree từ cặp `(R_i, S_i)`.
//! Thiết kế hiện tại seal theo kiểu streaming (đọc file on-demand, không giữ raw chunks trong RAM).
//!
use core_primitives::config::EngramConfig;
use core_primitives::poseidon2::hash_2;
use core_primitives::merkle_tree::MerkleTree;
use core_primitives::Fr;
use ff::Field;
use ff::PrimeField;
use crate::storage::ProverStorage;
use crate::benchmark::{elapsed_ms_f64, PeakMemoryTracker, SealingMetrics};
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::Instant;

/// Chuyển đổi một slice bytes thành một phần tử trường `Fr`.
///
/// Cách hoạt động: chia input thành lát 31-byte, chuyển từng lát thành `Fr` rồi
/// fold vào một accumulator bằng `hash_2`. Kết quả đảm bảo mọi bit ảnh hưởng.
fn chunk_to_fr(chunk: &[u8]) -> Fr {
    const SLICE_SIZE: usize = 31; // 31 bytes < Pallas field order → luôn hợp lệ
    let mut acc = Fr::from(chunk.len() as u64);
    for window in chunk.chunks(SLICE_SIZE) {
        let mut repr = [0u8; 32];
        repr[..window.len()].copy_from_slice(window);
        let slice_fr = Fr::from_repr(repr.into()).unwrap_or_else(|| {
            repr[31] = 0;
            Fr::from_repr(repr.into()).unwrap_or(Fr::ZERO)
        });
        acc = hash_2(acc, slice_fr);
    }
    acc
}

/// Hỗ trợ: hash gộp 4 phần tử bằng hai lần `hash_2`.
/// Dùng làm biến thể tiện lợi khi cần trộn 4 inputs vào một giá trị.
fn poseidon2_hash_4(a: Fr, b: Fr, c: Fr, d: Fr) -> Fr {
    hash_2(hash_2(a, b), hash_2(c, d))
}

pub struct Sealer {
    config: EngramConfig,
}

impl Sealer {
    pub fn new(config: EngramConfig) -> Self {
        Self { config }
    }

    /// Seal sector từ FILE — không load raw data vào RAM.
    ///
    /// # RAM profile
    /// - BufReader: chunk_size * 256 bytes buffer (1MB cho chunk 4KB)
    /// - sealed_pairs: num_chunks × 64 bytes (~512MB cho 32GB sector)
    /// - states + replicas: num_chunks × 64 bytes (~512MB)
    /// - Merkle tree: ~512MB
    /// - Tổng: ~1.5GB thay vì 64GB của phiên bản cũ
    ///
    /// # Sealing time
    /// 32GB sector = 8M chunks × 2 Poseidon2 ≈ 27 phút single-thread.
    /// Đây là con số thực tế của thuật toán PoSt — không phải bug.
    /// Sequential S_i dependency ngăn full parallelization.
    pub fn seal_sector_streaming(
        &self,
        replica_id: Fr,
        raw_data_path: &Path,
        storage: &mut ProverStorage,
    ) -> SealingMetrics {
        const RAM_SAMPLE_EVERY: usize = 256;
        // Snapshot IO counters before sealing to compute delta owned by this call
        let io_ns_before = crate::benchmark::io_get_ns_total();
        let io_count_before = crate::benchmark::io_get_count();
        let chunk_size  = self.config.chunk_size_bytes;
        let num_chunks  = self.config.sector_size_bytes / chunk_size;
        let buf_chunks  = 256usize;           // đọc 256 chunks/lần = 1MB buffer
        let buf_size    = chunk_size * buf_chunks;

        *storage = ProverStorage::with_capacity(num_chunks, chunk_size);
        storage.set_raw_data_path(raw_data_path.to_path_buf());

        let file   = std::fs::File::open(raw_data_path)
            .unwrap_or_else(|e| panic!("Không mở được {}: {}", raw_data_path.display(), e));
        let mut reader  = BufReader::with_capacity(buf_size, file);

        let mut s_prev       = replica_id;
        let mut sealed_pairs = Vec::with_capacity(num_chunks);
        let mut metrics      = SealingMetrics::default();
        let mut peak         = PeakMemoryTracker::new();
        let mut chunk_buf    = vec![0u8; chunk_size];

        storage.insert_state(0, s_prev);

        for i in 1..=num_chunks {
            // ── Đọc chunk từ file (streaming, không giữ lại) ─────────────
            let absorb_start = Instant::now();
            // Xử lý EOF gracefully bằng zero-padding
            let bytes_read = fill_chunk(&mut reader, &mut chunk_buf);
            if bytes_read < chunk_size {
                chunk_buf[bytes_read..].fill(0);
            }
            metrics.c_chunk_absorb_4kb_ms += elapsed_ms_f64(absorb_start);
            // record to global IO counters (treat one chunk read as one IO op)
            let ns = absorb_start.elapsed().as_nanos() as u64;
            crate::benchmark::io_add_ns(ns);
            crate::benchmark::io_inc_count(1);

            // ── Sealing ──────────────────────────────────────────────────
            let hash_start = Instant::now();
            let d_i = chunk_to_fr(&chunk_buf);
            let r_i = poseidon2_hash_4(d_i, s_prev, Fr::from(i as u64), replica_id);
            metrics.c_hash_poseidon2_ms += elapsed_ms_f64(hash_start);

            let s_i = hash_2(s_prev, r_i);

            // ── Lưu sealed data (không lưu raw chunk) ────────────────────
            storage.insert_replica(i, r_i);
            storage.insert_state(i, s_i);
            sealed_pairs.push((r_i, s_i));
            s_prev = s_i;

            if i % RAM_SAMPLE_EVERY == 0 || i == num_chunks {
                peak.sample();
            }
        }

        let merkle_start = Instant::now();
        let tree = MerkleTree::build(&sealed_pairs);
        metrics.c_merkle_build_ms = elapsed_ms_f64(merkle_start);
        storage.merkle_tree = Some(tree);

        metrics.ram_peak_kib = peak.peak_delta_kib();
        // compute IO delta for this sealing call
        let io_ns_after = crate::benchmark::io_get_ns_total();
        let io_count_after = crate::benchmark::io_get_count();
        metrics.io_read_ms = (io_ns_after.saturating_sub(io_ns_before) as f64) / 1_000_000.0;
        metrics.io_read_count = io_count_after.saturating_sub(io_count_before);
        metrics
    }
}

/// Đọc đúng `buf.len()` bytes vào `buf` từ reader.
/// Trả về số bytes thực tế đọc được (có thể nhỏ hơn khi EOF).
fn fill_chunk<R: Read>(reader: &mut R, buf: &mut [u8]) -> usize {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0)   => break,
            Ok(n)   => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_)  => break,
        }
    }
    total
}
