use pasta_curves::pallas::Scalar as Fr;
use core_primitives::merkle_tree::MerkleTree;

/// ProverStorage dùng Vec thay vì HashMap để tránh overhead allocation trên WSL2.
/// Index i tương ứng trực tiếp với chunk/state i (1-based cho chunks, 0-based cho states).
/// Vec được pre-allocate với capacity đúng từ đầu → không rehash, không realloc.
#[derive(Default, Clone)]
pub struct ProverStorage {
    /// raw_chunks[i] = raw bytes của chunk thứ i (index 1..=num_chunks)
    /// Dùng Option để simulate "missing" mà không cần xóa
    pub raw_chunks: Vec<Option<Vec<u8>>>,
    /// states[i] = S_i (index 0..=num_chunks)
    pub states: Vec<Option<Fr>>,
    /// replicas[i] = R_i (index 1..=num_chunks)
    pub replicas: Vec<Option<Fr>>,
    pub merkle_tree: Option<MerkleTree>,
    /// Số chunks tổng (để biết capacity)
    pub num_chunks: usize,
}

impl ProverStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// Khởi tạo với capacity biết trước — dùng cái này thay vì new() khi biết num_chunks
    pub fn with_capacity(num_chunks: usize) -> Self {
        Self {
            raw_chunks: vec![None; num_chunks + 1], // index 0 unused, 1..=num_chunks
            states: vec![None; num_chunks + 1],     // index 0..=num_chunks
            replicas: vec![None; num_chunks + 1],
            merkle_tree: None,
            num_chunks,
        }
    }

    /// Insert raw chunk tại index i (1-based)
    #[inline]
    pub fn insert_raw_chunk(&mut self, i: usize, chunk: Vec<u8>) {
        if i < self.raw_chunks.len() {
            self.raw_chunks[i] = Some(chunk);
        }
    }

    /// Insert state tại index i (0-based)
    #[inline]
    pub fn insert_state(&mut self, i: usize, s: Fr) {
        if i < self.states.len() {
            self.states[i] = Some(s);
        }
    }

    /// Insert replica tại index i (1-based)
    #[inline]
    pub fn insert_replica(&mut self, i: usize, r: Fr) {
        if i < self.replicas.len() {
            self.replicas[i] = Some(r);
        }
    }

    /// Kiểm tra raw_chunk tại index i có tồn tại không
    #[inline]
    pub fn has_raw_chunk(&self, i: usize) -> bool {
        self.raw_chunks.get(i).and_then(|x| x.as_ref()).is_some()
    }

    /// Lấy raw chunk tại index i.
    #[inline]
    pub fn get_raw_chunk(&self, i: usize) -> Option<&[u8]> {
        self.raw_chunks.get(i).and_then(|x| x.as_deref())
    }

    /// Lấy state tại index i
    #[inline]
    pub fn get_state(&self, i: usize) -> Option<&Fr> {
        self.states.get(i)?.as_ref()
    }

    /// Lấy replica tại index i
    #[inline]
    pub fn get_replica(&self, i: usize) -> Option<&Fr> {
        self.replicas.get(i)?.as_ref()
    }

    /// Sinh chuỗi pseudo-random từ một seed (LCG đơn giản, deterministic)
    fn lcg_next(state: &mut u64) -> u64 {
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *state
    }

    /// Kịch bản tấn công 1 (% drop): Simulate xóa ngẫu nhiên một phần trăm raw_chunks.
    /// Trả về danh sách index bị "xóa" (đánh dấu None) để ghi log.
    pub fn attack_drop_raw_chunks_random_pct(&mut self, drop_pct: f64, seed: u64) -> Vec<usize> {
        let total = self.num_chunks;
        if total == 0 || drop_pct <= 0.0 {
            return Vec::new();
        }

        let drop_count = ((total as f64) * drop_pct / 100.0).round() as usize;
        let drop_count = drop_count.min(total);

        // Lấy danh sách index có dữ liệu (1..=num_chunks), shuffle bằng Fisher-Yates LCG
        let mut keys: Vec<usize> = (1..=self.num_chunks)
            .filter(|&i| self.raw_chunks.get(i).and_then(|x| x.as_ref()).is_some())
            .collect();

        let mut rng_state = seed.wrapping_add(0x9E3779B97F4A7C15);
        for i in (1..keys.len()).rev() {
            let r = (Self::lcg_next(&mut rng_state) as usize) % (i + 1);
            keys.swap(i, r);
        }

        let mut removed: Vec<usize> = keys.into_iter().take(drop_count).collect();
        removed.sort_unstable();
        for &k in &removed {
            if k < self.raw_chunks.len() {
                self.raw_chunks[k] = None;
            }
        }
        removed
    }

    /// Kịch bản tấn công 2 (target): Xóa raw_chunks tại đúng các index challenge.
    pub fn attack_drop_raw_chunks_at(&mut self, indices: &[usize]) -> Vec<usize> {
        let mut removed = Vec::new();
        for &idx in indices {
            if idx < self.raw_chunks.len() {
                if self.raw_chunks[idx].take().is_some() {
                    removed.push(idx);
                }
            }
        }
        removed
    }

    /// Kịch bản tấn công 3 (target): Xóa state S_{j_i - 1} tại các vị trí challenge.
    pub fn attack_drop_states_at(&mut self, state_indices: &[usize]) -> Vec<usize> {
        let mut removed = Vec::new();
        for &idx in state_indices {
            if idx < self.states.len() {
                if self.states[idx].take().is_some() {
                    removed.push(idx);
                }
            }
        }
        removed
    }
}
