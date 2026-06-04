use std::time::Instant;

use nova_snark::{
    nova::{CompressedSNARK, PublicParams},
    provider::{ipa_pc::EvaluationEngine, PallasEngine, VestaEngine},
    traits::Engine,
};
use prover::{EngramStepCircuit, EngramVerifierKey};
use prover::{G1, G2, SpartanPrimary, SpartanSecondary};
use prover::{PeakMemoryTracker, VerificationMetrics};
use prover::benchmark::elapsed_ms_f64;

type NovaFr = <G1 as Engine>::Scalar;

pub struct EngramVerifier;

impl EngramVerifier {
    /// FIX (Vấn đề 4 — Verifier): Nhận vk được cache từ ProvingPipeline thay vì
    /// gọi CompressedSNARK::setup() lần thứ 3, tránh lãng phí vài giây và lạm phát metric.
    ///
    /// Nếu caller không có vk (VD: verifier độc lập, on-chain), có thể truyền None —
    /// hàm sẽ tự derive vk từ pp (tốn thêm thời gian, được tính vào vk_setup_ms).
    pub fn verify_proof(
        pp: &PublicParams<G1, G2, EngramStepCircuit>,
        proof: &CompressedSNARK<G1, G2, EngramStepCircuit, SpartanPrimary, SpartanSecondary>,
        num_steps: usize,
        z0_primary: Vec<NovaFr>,
        vk_opt: Option<&EngramVerifierKey>,
    ) -> (bool, VerificationMetrics) {
        println!("========================================================");
        println!("🔍 [VERIFIER] Bắt đầu xác minh bằng chứng Spartan...");

        let mut metrics = VerificationMetrics::default();
        let mut peak = PeakMemoryTracker::new();

        // Dùng vk được truyền vào nếu có; nếu không thì derive từ pp (tốn thêm thời gian)
        let vk_setup_start = Instant::now();
        let derived_vk;
        let vk = match vk_opt {
            Some(v) => v,
            None => {
                let (_pk, v) = CompressedSNARK::<G1, G2, EngramStepCircuit, SpartanPrimary, SpartanSecondary>::setup(pp).unwrap();
                derived_vk = v;
                &derived_vk
            }
        };
        metrics.vk_setup_ms = elapsed_ms_f64(vk_setup_start);
        peak.sample();

        let start = Instant::now();
        let verification_result = proof.verify(vk, num_steps, &z0_primary);
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
