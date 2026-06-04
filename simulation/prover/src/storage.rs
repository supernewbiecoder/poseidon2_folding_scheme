//! Prover storage
//!
//! File-backed storage cho Prover:
//! - Lưu `states` và `replicas` trong RAM (vì cần truy cập nhanh trong proving).
//! - `raw_data` không lưu trong RAM; `get_raw_chunk()` đọc on-demand từ file path được gán.
//! - Hỗ trợ kịch bản tấn công bằng `dropped_raw_indices` và các hàm `attack_*`.
//!
use core_primitives::Fr;
use core_primitives::merkle_tree::MerkleTree;
use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

/// ProverStorage — file-backed storage cho raw chunk data.
///
/// # Thay đổi so với phiên bản cũ
/// Phiên bản cũ lưu toàn bộ raw_chunks: Vec<Option<Vec<u8>>> vào RAM.
/// Với 32GB sector (8M chunks × 4KB) = 32GB RAM chỉ riêng cho raw data.
/// Cộng thêm 32GB raw_sector_data load vào trước = tổng 64GB — không chấp nhận được.
///
/// # Thiết kế mới
/// - raw_chunks KHÔNG lưu trong RAM. Đọc từ file on-demand khi cần.
/// - dropped_raw_indices: HashSet<usize> đánh dấu chunk nào bị "xóa" (attack simulation).
/// - states + replicas vẫn giữ trong RAM (~512MB cho 32GB sector) — unavoidable.
/// - Merkle tree giữ trong RAM (~512MB) — unavoidable.
///
/// # RAM sau fix
/// 32GB sector: states(256MB) + replicas(256MB) + merkle(512MB) ≈ 1.0GB total.
#[derive(Default, Clone)]
pub struct ProverStorage {
    /// Đường dẫn file raw data gốc — đọc on-demand, không load vào RAM.
    pub raw_data_path: Option<PathBuf>,
    /// Kích thước mỗi chunk (bytes), cần để tính offset khi seek.
    pub chunk_size: usize,
    /// Set các chunk index bị "dropped" (attack simulation).
    /// Khi has_raw_chunk(i) → false nếu i ∈ dropped_raw_indices.
    pub dropped_raw_indices: HashSet<usize>,
    /// states[i] = S_i (0-based: states[0] = replica_id, states[i] = S_i sau chunk i)
    pub states: Vec<Option<Fr>>,
    /// replicas[i] = R_i (1-based, index 0 unused)
    pub replicas: Vec<Option<Fr>>,
    pub merkle_tree: Option<MerkleTree>,
    pub num_chunks: usize,
}

impl ProverStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Khởi tạo với capacity biết trước.
    /// chunk_size cần thiết để tính offset khi đọc file.
    pub fn with_capacity(num_chunks: usize, chunk_size: usize) -> Self {
        Self {
            raw_data_path: None,
            chunk_size,
            dropped_raw_indices: HashSet::new(),
            states:   vec![None; num_chunks + 1],
            replicas: vec![None; num_chunks + 1],
            merkle_tree: None,
            num_chunks,
        }
    }

    /// Gắn đường dẫn file raw data. Gọi sau khi sealing xong.
    pub fn set_raw_data_path(&mut self, path: PathBuf) {
        self.raw_data_path = Some(path);
    }

    // ── State ───────────────────────────────────────────────────────────────

    #[inline]
    pub fn insert_state(&mut self, i: usize, s: Fr) {
        if i < self.states.len() { self.states[i] = Some(s); }
    }

    #[inline]
    pub fn get_state(&self, i: usize) -> Option<&Fr> {
        self.states.get(i)?.as_ref()
    }

    // ── Replica ─────────────────────────────────────────────────────────────

    #[inline]
    pub fn insert_replica(&mut self, i: usize, r: Fr) {
        if i < self.replicas.len() { self.replicas[i] = Some(r); }
    }

    #[inline]
    pub fn get_replica(&self, i: usize) -> Option<&Fr> {
        self.replicas.get(i)?.as_ref()
    }

    // ── Raw chunk (file-backed) ──────────────────────────────────────────────

    /// Kiểm tra chunk i có "tồn tại" không.
    /// Trả về false nếu bị dropped (attack) hoặc không có file.
    #[inline]
    pub fn has_raw_chunk(&self, i: usize) -> bool {
        if self.dropped_raw_indices.contains(&i) { return false; }
        i >= 1 && i <= self.num_chunks && self.raw_data_path.is_some()
    }

    /// Đọc chunk i từ file (on-demand, O(1) RAM).
    /// Seek đến offset = (i-1) * chunk_size rồi đọc chunk_size bytes.
    pub fn get_raw_chunk(&self, i: usize) -> Option<Vec<u8>> {
        if self.dropped_raw_indices.contains(&i) { return None; }
        let path = self.raw_data_path.as_ref()?;
        let offset = ((i - 1) as u64) * (self.chunk_size as u64);
        let start = std::time::Instant::now();
        let mut file = std::fs::File::open(path).ok()?;
        file.seek(SeekFrom::Start(offset)).ok()?;
        let mut buf = vec![0u8; self.chunk_size];
        file.read_exact(&mut buf).ok()?;
        // record IO metrics (nanoseconds)
        let ns = start.elapsed().as_nanos() as u64;
        crate::benchmark::io_add_ns(ns);
        crate::benchmark::io_inc_count(1);
        Some(buf)
    }

    // ── Attack scenarios ─────────────────────────────────────────────────────

    /// Sinh chuỗi pseudo-random từ seed (LCG deterministic).
    fn lcg_next(state: &mut u64) -> u64 {
        *state = state.wrapping_mul(6364136223846793005)
                      .wrapping_add(1442695040888963407);
        *state
    }

    /// Attack 1: Drop ngẫu nhiên drop_pct% raw chunks.
    /// Đánh dấu vào dropped_raw_indices thay vì xóa Vec.
    pub fn attack_drop_raw_chunks_random_pct(&mut self, drop_pct: f64, seed: u64) -> Vec<usize> {
        if self.num_chunks == 0 || drop_pct <= 0.0 { return Vec::new(); }
        let drop_count = ((self.num_chunks as f64) * drop_pct / 100.0).round() as usize;
        let drop_count = drop_count.min(self.num_chunks);

        let mut keys: Vec<usize> = (1..=self.num_chunks)
            .filter(|i| !self.dropped_raw_indices.contains(i))
            .collect();

        let mut rng = seed.wrapping_add(0x9E3779B97F4A7C15);
        for i in (1..keys.len()).rev() {
            let r = (Self::lcg_next(&mut rng) as usize) % (i + 1);
            keys.swap(i, r);
        }

        let removed: Vec<usize> = keys.into_iter().take(drop_count).collect();
        for &k in &removed { self.dropped_raw_indices.insert(k); }
        let mut out = removed;
        out.sort_unstable();
        out
    }

    /// Attack 2: Drop đúng các index được chỉ định.
    pub fn attack_drop_raw_chunks_at(&mut self, indices: &[usize]) -> Vec<usize> {
        let mut removed = Vec::new();
        for &idx in indices {
            if idx >= 1 && idx <= self.num_chunks {
                self.dropped_raw_indices.insert(idx);
                removed.push(idx);
            }
        }
        removed
    }

    /// Attack 3: Drop state S_{j_i-1} tại các vị trí challenge.
    pub fn attack_drop_states_at(&mut self, state_indices: &[usize]) -> Vec<usize> {
        let mut removed = Vec::new();
        for &idx in state_indices {
            if idx < self.states.len() {
                if self.states[idx].take().is_some() { removed.push(idx); }
            }
        }
        removed
    }

    /// Clone storage để chạy từng kịch bản tấn công độc lập.
    pub fn clone_for_attack(&self) -> Self {
        Self {
            raw_data_path: self.raw_data_path.clone(),
            chunk_size: self.chunk_size,
            dropped_raw_indices: HashSet::new(), // reset drops cho mỗi scenario
            states:   self.states.clone(),
            replicas: self.replicas.clone(),
            merkle_tree: self.merkle_tree.clone(),
            num_chunks: self.num_chunks,
        }
    }
}
