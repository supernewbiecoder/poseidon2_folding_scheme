use std::time::Instant;

use nova_snark::{
    nova::{CompressedSNARK, PublicParams},
    provider::{ipa_pc::EvaluationEngine, PallasEngine, VestaEngine},
    traits::Engine,
};
use prover::EngramStepCircuit;
use prover::{PeakMemoryTracker, VerificationMetrics};
use prover::benchmark::elapsed_ms_f64;

type G1 = PallasEngine;
type G2 = VestaEngine;

type NovaFr = <G1 as Engine>::Scalar;

type SpartanPrimary = nova_snark::spartan::ppsnark::RelaxedR1CSSNARK<G1, EvaluationEngine<G1>>;
type SpartanSecondary = nova_snark::spartan::ppsnark::RelaxedR1CSSNARK<G2, EvaluationEngine<G2>>;

pub struct EngramVerifier;

impl EngramVerifier {
    /// FIX: z0_primary giờ có 4 phần tử phù hợp với arity=4 của circuit.
    /// Caller (simulator_runner) truyền đúng z0 từ prove_epoch().
    pub fn verify_proof(
        pp: &PublicParams<G1, G2, EngramStepCircuit>,
        proof: &CompressedSNARK<G1, G2, EngramStepCircuit, SpartanPrimary, SpartanSecondary>,
        num_steps: usize,
        z0_primary: Vec<NovaFr>,
    ) -> (bool, VerificationMetrics) {
        println!("========================================================");
        println!("🔍 [VERIFIER] Bắt đầu xác minh bằng chứng Spartan...");

        let mut metrics = VerificationMetrics::default();
        let mut peak = PeakMemoryTracker::new();

        let vk_setup_start = Instant::now();
        let (_pk, vk) = CompressedSNARK::<G1, G2, EngramStepCircuit, SpartanPrimary, SpartanSecondary>::setup(pp).unwrap();
        metrics.vk_setup_ms = elapsed_ms_f64(vk_setup_start);
        peak.sample();

        let start = Instant::now();
        let verification_result = proof.verify(&vk, num_steps, &z0_primary);
        let verify_time = elapsed_ms_f64(start);

        println!("⏱️  Metric - Verify Time (verify_time): {:.3} ms", verify_time);
        metrics.verify_time_ms = verify_time;
        metrics.ram_peak_kib = peak.peak_kib();

        let is_valid = match verification_result {
            Ok(zn_primary) => {
                println!("✅ KẾT QUẢ: Bằng chứng HỢP LỆ!");
                println!("   -> Trạng thái tích lũy cuối cùng (z_n): {:?}", zn_primary[0]);
                true
            }
            Err(e) => {
                println!("❌ KẾT QUẢ: Bằng chứng KHÔNG HỢP LỆ!");
                println!("   -> Lỗi từ hệ thống chứng minh: {:?}", e);
                false
            }
        };

        (is_valid, metrics)
    }
}
