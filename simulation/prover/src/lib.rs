pub mod storage;
pub mod benchmark;
pub mod sealing;
pub mod proving;

pub use benchmark::{ChallengeMetrics, PeakMemoryTracker, ProvingMetrics, SealingMetrics, SetupMetrics, VerificationMetrics};
pub use storage::ProverStorage;
pub use sealing::Sealer;

pub use proving::{EngramStepCircuit, EngramVerifierKey, ProvingPipeline};
// Re-export type aliases cần thiết cho verifier crate
pub use proving::{G1, G2, SpartanPrimary, SpartanSecondary};