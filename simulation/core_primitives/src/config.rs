// file này để đặt các cấu hình mặc định cho Engram, có thể mở rộng thêm sau này

#[derive(Clone, Debug)]
pub struct EngramConfig {
    pub sector_size_bytes: usize,
    pub chunk_size_bytes: usize,
    pub tree_height: usize,
    pub challenges_per_epoch: usize,
    pub epochs_per_window: usize,
}

impl EngramConfig {
    /// Cấu hình dùng để chạy Simulation và Test kịch bản tấn công (nhanh, nhẹ)
    pub fn mock_dev() -> Self {
        Self {
            sector_size_bytes: 1 * 1024 * 1024 * 1024, // Tự động set 1GB
            chunk_size_bytes: 4096,                // 4KB (1 shard/chunk)
            tree_height: 18,                       // Tự động set height 18
            challenges_per_epoch: 50,
            epochs_per_window: 5, // chuẩn bị cho tương lai simulation
        }
    }

    /// Cấu hình thực tế theo báo cáo (benchmark thời gian thật)
    pub fn production() -> Self {
        Self {
            sector_size_bytes: 32 * 1024 * 1024 * 1024, // 32GB
            chunk_size_bytes: 4096,
            tree_height: 23,                            // 2^23 lá = 32GB
            challenges_per_epoch: 100,
            epochs_per_window: 48,
        }
    }
}
