use std::time::Instant;

use sysinfo::{get_current_pid, ProcessExt, System, SystemExt};

pub fn current_process_memory_kib() -> u64 {
    let pid = match get_current_pid() {
        Ok(pid) => pid,
        Err(_) => return 0,
    };

    let mut system = System::new_all();
    system.refresh_process(pid);

    // On some platforms (Windows) sysinfo::ProcessExt::memory() returns bytes,
    // while on others it returns kilobytes. Normalize to KiB.
    match system.process(pid).map(|process| process.memory()) {
        Some(val) => {
            if val > 10_000_000 {
                val / 1024
            } else {
                val
            }
        }
        None => 0,
    }
}

#[derive(Clone, Debug, Default)]
pub struct PeakMemoryTracker {
    peak_kib: u64,
}

impl PeakMemoryTracker {
    pub fn new() -> Self {
        let mut tracker = Self::default();
        tracker.sample();
        tracker
    }

    pub fn sample(&mut self) {
        self.peak_kib = self.peak_kib.max(current_process_memory_kib());
    }

    pub fn peak_kib(&self) -> u64 {
        self.peak_kib
    }
}

#[derive(Clone, Debug, Default)]
pub struct SetupMetrics {
    pub public_params_ms: f64,
    pub pk_vk_ms: f64,
    pub ram_peak_kib: u64,
}

#[derive(Clone, Debug, Default)]
pub struct SealingMetrics {
    pub c_chunk_absorb_4kb_ms: f64,
    pub c_hash_poseidon2_ms: f64,
    pub c_merkle_build_ms: f64,
    pub ram_peak_kib: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ChallengeMetrics {
    pub c_hash_poseidon2_ms: f64,
    pub c_merkle_path_ms: f64,
    pub ram_peak_kib: u64,
}

#[derive(Clone, Debug, Default)]
pub struct ProvingMetrics {
    pub c_step_total_ms: f64,
    pub c_augmented_nova_ms: f64,
    pub prove_time_per_step_ms: f64,
    pub fold_time_per_step_ms: f64,
    pub compressed_proof_size_bytes: usize,
    pub fold_total_ms: f64,
    pub compression_ms: f64,
    pub ram_peak_kib: u64,
}

#[derive(Clone, Debug, Default)]
pub struct VerificationMetrics {
    pub verify_time_ms: f64,
    pub vk_setup_ms: f64,
    pub ram_peak_kib: u64,
}

/// Trả về thời gian đã trôi qua tính bằng millisecond ở dạng f64
/// (dùng nano-second để giữ độ chính xác sub-millisecond).
pub fn elapsed_ms_f64(start: Instant) -> f64 {
    start.elapsed().as_nanos() as f64 / 1_000_000.0
}

/// Giữ lại để tương thích ngược với code cũ
pub fn elapsed_ms(start: Instant) -> u128 {
    start.elapsed().as_millis()
}
