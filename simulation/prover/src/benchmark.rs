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
    baseline_kib: u64,
    peak_kib: u64,
}

impl PeakMemoryTracker {
    pub fn new() -> Self {
        let baseline_kib = current_process_memory_kib();
        Self {
            baseline_kib,
            peak_kib: baseline_kib,
        }
    }

    pub fn sample(&mut self) {
        self.peak_kib = self.peak_kib.max(current_process_memory_kib());
    }

    pub fn peak_kib(&self) -> u64 {
        self.peak_kib
    }

    pub fn peak_delta_kib(&self) -> u64 {
        self.peak_kib.saturating_sub(self.baseline_kib)
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
    pub io_read_ms: f64,
    pub io_read_count: u64,
}
// Global IO counters (nanoseconds total and read count)
use std::sync::atomic::{AtomicU64, Ordering};

static IO_READ_NS_TOTAL: AtomicU64 = AtomicU64::new(0);
static IO_READ_COUNT: AtomicU64 = AtomicU64::new(0);

/// Add nanoseconds to the global IO read counter.
pub fn io_add_ns(ns: u64) {
    IO_READ_NS_TOTAL.fetch_add(ns, Ordering::Relaxed);
}

/// Increment the global IO read count by `n`.
pub fn io_inc_count(n: u64) {
    IO_READ_COUNT.fetch_add(n, Ordering::Relaxed);
}

/// Get total IO read nanoseconds so far.
pub fn io_get_ns_total() -> u64 {
    IO_READ_NS_TOTAL.load(Ordering::Relaxed)
}

/// Get total IO read operations so far.
pub fn io_get_count() -> u64 {
    IO_READ_COUNT.load(Ordering::Relaxed)
}

/// Reset the global IO counters to zero.
/// Use with care in concurrent contexts; here it's only used for local snapshots.
pub fn io_reset() {
    IO_READ_NS_TOTAL.store(0, Ordering::Relaxed);
    IO_READ_COUNT.store(0, Ordering::Relaxed);
}

#[derive(Clone, Debug, Default)]
pub struct ChallengeMetrics {
    pub c_hash_poseidon2_ms: f64,
    pub c_merkle_path_ms: f64,
    pub ram_peak_kib: u64,
    pub io_read_ms: f64,
    pub io_read_count: u64,
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
