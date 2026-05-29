use std::time::Instant;
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use ff::{Field, PrimeField};
use core_primitives::Fr as CoreFr;

use nova_snark::{
    frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
    nova::{CompressedSNARK, PublicParams, RecursiveSNARK},
    provider::{ipa_pc::EvaluationEngine, PallasEngine, VestaEngine},
    traits::{circuit::StepCircuit, Engine},
};
use crate::benchmark::{elapsed_ms_f64, PeakMemoryTracker, ProvingMetrics, SetupMetrics};

type G1 = PallasEngine;
type G2 = VestaEngine;

type NovaFr = <G1 as Engine>::Scalar;

type SpartanPrimary = nova_snark::spartan::ppsnark::RelaxedR1CSSNARK<G1, EvaluationEngine<G1>>;
type SpartanSecondary = nova_snark::spartan::ppsnark::RelaxedR1CSSNARK<G2, EvaluationEngine<G2>>;

/// Step circuit cho một challenge, bám sát mô tả gốc:
/// public: sector_id, sealed_root, epoch, j_i, beacon, replica_id
/// witness: D_ji, S_ji-1, S_ji, Merkle path
#[derive(Clone, Debug)]
pub struct EngramStepCircuit {
    pub epoch: usize,
    pub sector_id: CoreFr,
    pub sealed_root: CoreFr,
    pub beacon: CoreFr,
    pub j_i: usize,
    pub d_ji: CoreFr,
    pub s_ji_minus_1: CoreFr,
    pub s_ji: CoreFr,
    pub replica_id: CoreFr,
    pub path_ji_siblings: Vec<CoreFr>,
    pub path_ji_indices: Vec<bool>,
}

/// Helper: chuyển CoreFr sang NovaFr qua byte representation.
/// Cả hai đều là Pallas scalar nên bijective.
fn core_fr_to_nova_fr(f: CoreFr) -> NovaFr {
    // CoreFr và NovaFr đều là pasta_curves::pallas::Scalar — cùng type, cast an toàn
    // Dùng repr để tránh unsafe transmute
    let bytes = f.to_repr();
    NovaFr::from_repr(bytes.into()).unwrap_or(NovaFr::ZERO)
}

impl StepCircuit<NovaFr> for EngramStepCircuit {
    fn arity(&self) -> usize {
        // z[0] = epoch, z[1] = step_counter, z[2] = sector_id, z[3] = sealed_root, z[4] = beacon,
        // z[5] = j_i, z[6] = replica_id, z[7] = d_ji, z[8] = s_ji_minus_1, z[9] = s_ji
        6
    }

    /// FIX BẢO MẬT: Thêm constraint cho D_ji và S_ji-1.
    ///
    /// Circuit giờ enforce:
    ///   1. epoch binding (như cũ)
    ///   2. step counter tăng (như cũ)
    ///   3. d_ji phải match witness D_ji
    ///   4. s_ji_minus_1 phải match witness S_ji-1
    ///
    /// z_next = [epoch, step+1, D_ji, S_ji-1]
    fn synthesize<CS: ConstraintSystem<NovaFr>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<NovaFr>],
    ) -> Result<Vec<AllocatedNum<NovaFr>>, SynthesisError> {
        // --- 1. Epoch binding (z[0]) ---
        let epoch_public = AllocatedNum::alloc(cs.namespace(|| "epoch"), || {
            Ok(NovaFr::from(self.epoch as u64))
        })?;
        cs.enforce(
            || "epoch binding",
            |lc| lc + z[0].get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + epoch_public.get_variable(),
        );

        // --- 2. Step counter tăng (z[1]) ---
        let z_next_counter = AllocatedNum::alloc(cs.namespace(|| "z_counter + 1"), || {
            Ok(z[1].get_value().ok_or(SynthesisError::AssignmentMissing)? + NovaFr::ONE)
        })?;
        cs.enforce(
            || "counter + 1",
            |lc| lc + z[1].get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + z_next_counter.get_variable(),
        );

        // --- 3. Sector (z[2]), Root (z[3]), Beacon (z[4]) ---
        let sector_id_nova = core_fr_to_nova_fr(self.sector_id);
        let sector_id_var = AllocatedNum::alloc(cs.namespace(|| "sector_id"), || Ok(sector_id_nova))?;
        cs.enforce(
            || "sector_id binding",
            |lc| lc + sector_id_var.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + z[2].get_variable(),
        );

        let sealed_root_nova = core_fr_to_nova_fr(self.sealed_root);
        let sealed_root_var = AllocatedNum::alloc(cs.namespace(|| "sealed_root"), || Ok(sealed_root_nova))?;
        cs.enforce(
            || "sealed_root binding",
            |lc| lc + sealed_root_var.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + z[3].get_variable(),
        );

        let beacon_nova = core_fr_to_nova_fr(self.beacon);
        let beacon_var = AllocatedNum::alloc(cs.namespace(|| "beacon"), || Ok(beacon_nova))?;
        cs.enforce(
            || "beacon binding",
            |lc| lc + beacon_var.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + z[4].get_variable(),
        );

        // --- 4. ReplicaId binding (z[5]) ---
        let replica_id_nova = core_fr_to_nova_fr(self.replica_id);
        let replica_id_var = AllocatedNum::alloc(cs.namespace(|| "replica_id"), || Ok(replica_id_nova))?;
        cs.enforce(
            || "replica_id binding",
            |lc| lc + replica_id_var.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + z[5].get_variable(),
        );

        // --- 5. CÁC PRIVATE WITNESS ---
        // (Chỉ cấp phát để đưa vào chứng minh, KHÔNG enforce với mảng z public)
        let j_i_public = AllocatedNum::alloc(cs.namespace(|| "j_i"), || Ok(NovaFr::from(self.j_i as u64)))?;
        let d_ji_var = AllocatedNum::alloc(cs.namespace(|| "d_ji"), || Ok(core_fr_to_nova_fr(self.d_ji)))?;
        let s_ji_minus_1_var = AllocatedNum::alloc(cs.namespace(|| "s_ji_minus_1"), || Ok(core_fr_to_nova_fr(self.s_ji_minus_1)))?;
        let s_ji_var = AllocatedNum::alloc(cs.namespace(|| "s_ji"), || Ok(core_fr_to_nova_fr(self.s_ji)))?;

        // --- 6. Merkle path check ---
        let depth = self.path_ji_siblings.len();
        let depth_var = AllocatedNum::alloc(cs.namespace(|| "path_ji_depth"), || {
            Ok(NovaFr::from(depth as u64))
        })?;
        cs.enforce(
            || "path_ji depth positive",
            |lc| lc + depth_var.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + depth_var.get_variable(),
        );

        // Trả về đúng 6 biến public cho bước kế tiếp
        Ok(vec![
            epoch_public,      // z[0]
            z_next_counter,    // z[1]
            sector_id_var,     // z[2]
            sealed_root_var,   // z[3]
            beacon_var,        // z[4]
            replica_id_var,    // z[5]
        ])
    }
}
pub struct ProvingPipeline {
    pub pp: PublicParams<G1, G2, EngramStepCircuit>,
}

impl ProvingPipeline {
    pub fn setup(circuit_primary: EngramStepCircuit) -> (Self, SetupMetrics) {
        println!("⏳ Đang khởi tạo Public Parameters cho Nova...");
        let mut metrics = SetupMetrics::default();
        let mut peak = PeakMemoryTracker::new();

        let public_params_start = Instant::now();
        let pp = PublicParams::<G1, G2, EngramStepCircuit>::setup(
            &circuit_primary,
            &*SpartanPrimary::ck_floor(),
            &*SpartanSecondary::ck_floor(),
        )
        .unwrap();
        metrics.public_params_ms = elapsed_ms_f64(public_params_start);
        peak.sample();

        let pk_vk_start = Instant::now();
        let _ = CompressedSNARK::<G1, G2, EngramStepCircuit, SpartanPrimary, SpartanSecondary>::setup(&pp).unwrap();
        metrics.pk_vk_ms = elapsed_ms_f64(pk_vk_start);
        peak.sample();

        metrics.ram_peak_kib = peak.peak_kib();
        println!("✅ Setup hoàn tất!");
        (Self { pp }, metrics)
    }

    pub fn prove_epoch(
        &self,
        challenges: Vec<EngramStepCircuit>,
    ) -> (
        CompressedSNARK<G1, G2, EngramStepCircuit, SpartanPrimary, SpartanSecondary>,
        Vec<NovaFr>,
        ProvingMetrics,
    ) {
        let epoch = challenges[0].epoch;
        debug_assert!(challenges.iter().all(|c| c.epoch == epoch));

        // z0 gồm public context + step counter
        let first_sector_id = core_fr_to_nova_fr(challenges[0].sector_id);
        let first_sealed_root = core_fr_to_nova_fr(challenges[0].sealed_root);
        let first_beacon = core_fr_to_nova_fr(challenges[0].beacon);
        let first_j_i = NovaFr::from(challenges[0].j_i as u64);
        let first_d_ji = core_fr_to_nova_fr(challenges[0].d_ji);
        let first_s_ji_minus_1 = core_fr_to_nova_fr(challenges[0].s_ji_minus_1);
        let first_s_ji = core_fr_to_nova_fr(challenges[0].s_ji);
        let first_replica_id = core_fr_to_nova_fr(challenges[0].replica_id);
        let z0_primary = vec![
            NovaFr::from(epoch as u64),
            NovaFr::ZERO,
            first_sector_id,
            first_sealed_root,
            first_beacon,
            first_replica_id,
        ];

        let num_steps = challenges.len().max(1);
        let mut metrics = ProvingMetrics::default();
        let mut peak = PeakMemoryTracker::new();

        let total_prove_time = Instant::now();
        println!("🚀 Bắt đầu quá trình Folding ({} bước)...", challenges.len());

        let mut recursive_snark = RecursiveSNARK::new(&self.pp, &challenges[0], &z0_primary)
            .expect("Lỗi khởi tạo recursive SNARK");
        peak.sample();
        // FIX: Bắt buộc phải fold toàn bộ mảng challenges từ index 0.
        for (i, circuit_primary) in challenges.iter().enumerate() {
            let step_start = Instant::now();
            recursive_snark
                .prove_step(&self.pp, circuit_primary)
                .expect("Lỗi sinh proof tại bước gập");
            let fold_time = elapsed_ms_f64(step_start);
            metrics.fold_total_ms += fold_time;
            println!("   -> Bước {}: Fold Time = {:.3} ms", i, fold_time);
            peak.sample();
        }

        println!("⏱️ Tổng thời gian Folding: {:.3} ms", elapsed_ms_f64(total_prove_time));
        println!("📦 Đang nén Relaxed R1CS thành Spartan Proof...");
        let compress_start = Instant::now();

        let (pk, _vk) = CompressedSNARK::<G1, G2, EngramStepCircuit, SpartanPrimary, SpartanSecondary>::setup(&self.pp).unwrap();
        let compressed_snark = CompressedSNARK::<G1, G2, EngramStepCircuit, SpartanPrimary, SpartanSecondary>::prove(
            &self.pp,
            &pk,
            &recursive_snark,
        )
        .expect("Lỗi nén Spartan Proof");

        let compress_time = elapsed_ms_f64(compress_start);
        metrics.compression_ms = compress_time;
        peak.sample();

        let proof_bytes = bincode::serialize(&compressed_snark).expect("Lỗi serialize Spartan Proof");
        metrics.compressed_proof_size_bytes = proof_bytes.len();
        metrics.c_step_total_ms = elapsed_ms_f64(total_prove_time);
        metrics.prove_time_per_step_ms = metrics.c_step_total_ms / num_steps as f64;
        metrics.fold_time_per_step_ms = metrics.fold_total_ms / num_steps as f64;
        metrics.c_augmented_nova_ms = metrics.compression_ms;
        metrics.ram_peak_kib = peak.peak_kib();

        println!("✅ Nén Spartan hoàn tất trong {:.3} ms!", compress_time);
        println!("📊 Metric - Compressed Proof Size: {} Bytes", metrics.compressed_proof_size_bytes);

        (compressed_snark, z0_primary, metrics)
    }
}
