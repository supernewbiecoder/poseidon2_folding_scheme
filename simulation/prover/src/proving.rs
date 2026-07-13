use std::time::Instant;
use nova_snark::traits::snark::RelaxedR1CSSNARKTrait;
use ff::{Field, PrimeField};
use core_primitives::Fr as CoreFr;
use core_primitives::poseidon2_gadget::{hash_2_gadget, hash_4_gadget, hash_chain_gadget, conditional_swap_gadget};
use nova_snark::{
    frontend::{num::AllocatedNum, ConstraintSystem, SynthesisError},
    nova::{CompressedSNARK, ProverKey, PublicParams, RecursiveSNARK, VerifierKey},
    provider::{ipa_pc::EvaluationEngine, PallasEngine, VestaEngine},
    traits::{circuit::StepCircuit, Engine},
};
use crate::benchmark::{elapsed_ms_f64, PeakMemoryTracker, ProvingMetrics, SetupMetrics};

pub type G1 = PallasEngine;
pub type G2 = VestaEngine;

pub type NovaFr = <G1 as Engine>::Scalar;

pub type SpartanPrimary = nova_snark::spartan::ppsnark::RelaxedR1CSSNARK<G1, EvaluationEngine<G1>>;
pub type SpartanSecondary = nova_snark::spartan::ppsnark::RelaxedR1CSSNARK<G2, EvaluationEngine<G2>>;

/// Type alias công khai cho VerifierKey — để verifier crate dùng được mà không cần khai báo lại.
pub type EngramVerifierKey = VerifierKey<G1, G2, EngramStepCircuit, SpartanPrimary, SpartanSecondary>;

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
    // j_i_seed field đã bị xóa — circuit tự tính seed qua hash_chain_gadget,
    // không cần prover cung cấp riêng (tránh confusion và lãng phí witness).
    pub d_ji: CoreFr,
    pub s_ji_minus_1: CoreFr,
    pub s_ji: CoreFr,
    pub replica_id: CoreFr,
    pub path_ji_siblings: Vec<CoreFr>,
    pub path_ji_indices: Vec<bool>,
    pub tree_height: usize,
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
        // z[0] = epoch
        // z[1] = step_counter (tăng 1 mỗi bước fold)
        // z[2] = sector_id
        // z[3] = sealed_root
        // z[4] = beacon
        // z[5] = replica_id
        // z[6] = z_acc  (IVC state tích lũy: Poseidon2(z_acc_prev, Poseidon2(j_i, S_ji)))
        // Tổng: 7 phần tử.
        // Lưu ý: D_ji, S_{j_i-1}, S_ji, j_i là Private Witness — không nằm trong z.
        7
    }

    /// Circuit enforce:
    ///   1. epoch binding
    ///   2. step counter tăng
    ///   3. sector_id / sealed_root / beacon / replica_id binding
    ///   4. Challenge Binding: seed = hash_chain(beacon, sector, epoch, challenge_no),
    ///      rã H bit thấp làm r, ép r + 1 == j_i_var (modulo N = 2^H, đóng Soundness Gap)
    ///   5. Replica Reconstruction + State Transition check
    ///   6. Merkle Path verification — path_indices[l] bound với bit_l(j_i - 1)
    ///      (leaf index 0-based) để ngăn Prover cung cấp proof của vị trí khác j_i
    ///   7. IVC State Accumulation: z_acc_next = Poseidon2(z_acc, hash_4(j_i, S_ji, R_ji, 0))
    ///      theo spec Demo.md §State Accumulation — bao gồm đầy đủ j_i, S_ji, R_sealed
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

        // --- 5. PRIVATE WITNESS: j_i, D_ji, S_{j_i-1}, S_ji ---
        // j_i: challenge index — allocated as witness
        let j_i_var = AllocatedNum::alloc(cs.namespace(|| "j_i"), || {
            Ok(NovaFr::from(self.j_i as u64))
        })?;

        // D_ji: raw data chunk tại vị trí challenge
        let d_ji_var = AllocatedNum::alloc(cs.namespace(|| "d_ji"), || {
            Ok(core_fr_to_nova_fr(self.d_ji))
        })?;

        // S_{j_i-1}: state trước chunk challenge
        let s_ji_minus_1_var = AllocatedNum::alloc(cs.namespace(|| "s_ji_minus_1"), || {
            Ok(core_fr_to_nova_fr(self.s_ji_minus_1))
        })?;

        // S_ji: state sau chunk challenge
        let s_ji_var = AllocatedNum::alloc(cs.namespace(|| "s_ji"), || {
            Ok(core_fr_to_nova_fr(self.s_ji))
        })?;

        // --- 6. R1CS GADGETS: REPLICA, STATE & CHALLENGE ---

        // a. Replica Reconstruction: Tính R_ji = Poseidon2(D_ji, S_{j_i-1}, j_i, Replica_id)
        let r_ji_var = hash_4_gadget(
            cs.namespace(|| "calc_r_ji"),
            &d_ji_var,
            &s_ji_minus_1_var,
            &j_i_var,
            &replica_id_var,
        )?;

        // b. State Transition Check: Ép S_ji == Poseidon2(S_{j_i-1}, R_ji)
        let expected_s_ji = hash_2_gadget(
            cs.namespace(|| "calc_s_ji"),
            &s_ji_minus_1_var,
            &r_ji_var,
        )?;
        cs.enforce(
            || "enforce_state_transition",
            |lc| lc + expected_s_ji.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + s_ji_var.get_variable(),
        );

        // c. Challenge Binding Check: j_i phải được derive từ (beacon, sector_id, epoch, challenge_no)
        //
        // NGUYÊN NHÂN BUG CŨ:
        //   - Host dùng poseidon2_chain([beacon, sector, epoch, challenge_no]) — hash TUẦN TỰ
        //   - Circuit cũ dùng hash_4_gadget(beacon, sector, epoch, z[1])   — hash CÂY NHỊ PHÂN
        //   → Hai hàm cho output khác nhau → constraint luôn fail → InvalidSumcheckProof
        //
        // FIX: dùng hash_chain_gadget để khớp chính xác với poseidon2_chain() ở host.
        //
        // ĐỒNG NHẤT INDEXING:
        //   Host gọi derive_challenge_index với challenge_no = 1, 2, 3... (1-based).
        //   z[1] là step counter = 0, 1, 2... TRƯỚC khi bước này synthesize.
        //   → challenge_no = z[1] + 1.
        let challenge_no_var = AllocatedNum::alloc(cs.namespace(|| "challenge_no"), || {
            // z[1] là giá trị counter TRƯỚC khi tăng (0-based) → challenge_no = z[1] + 1
            Ok(z[1].get_value().ok_or(SynthesisError::AssignmentMissing)? + NovaFr::ONE)
        })?;
        // Enforce: challenge_no = z[1] + 1
        cs.enforce(
            || "challenge_no = counter + 1",
            |lc| lc + z[1].get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + challenge_no_var.get_variable(),
        );

        // hash_chain([beacon, sector_id, epoch, challenge_no]) khớp với poseidon2_chain() ở host
        let pseudo_j_i_full = hash_chain_gadget(
            cs.namespace(|| "calc_j_i_binding"),
            &[&beacon_var, &sector_id_var, &epoch_public, &challenge_no_var],
        )?;

        if let Some(val) = pseudo_j_i_full.get_value() {
            println!("circuit pseudo_j_i_full: {:?}", val);
            println!("circuit challenge_no_var: {:?}", challenge_no_var.get_value().unwrap());
        }
        // Circuit không thể enforce modulo trong R1CS (đắt và phức tạp).
        // Thay vào đó: rã pseudo_j_i_full thành bit, lấy H bit thấp làm r,
        // rồi enforce r + 1 == j_i_var (modulo với N=2^H public không ảnh
        // hưởng soundness — Prover không thể fake seed mà vẫn qua được
        // constraint này).
        //
        // VÁ LỖ HỔNG SOUNDNESS (Challenge Binding Modulo):
        // N = 2^H. Vậy r = (j_i_seed % N) chính là H bit thấp nhất của j_i_seed.
        // Ta sử dụng to_bits_le_strict() để rã pseudo_j_i_full thành 255 bit nhị phân an toàn (< p).
        // Sau đó tổng hợp lại H bit đầu tiên thành r_var, và ép r_var == j_i_var - 1.
        let seed_bits = pseudo_j_i_full.to_bits_le_strict(cs.namespace(|| "seed_bits"))?;
        
        let h = self.tree_height;
        let mut lc_r = nova_snark::frontend::LinearCombination::zero();
        let mut factor = NovaFr::ONE;
        
        for i in 0..h {
            lc_r = lc_r + &seed_bits[i].lc(CS::one(), factor);
            factor *= NovaFr::from(2u64);
        }
        
        // Tạo biến r_var lưu giá trị của modulo (H bits thấp)
        let r_val = match pseudo_j_i_full.get_value() {
            Some(v) => {
                let bytes = v.to_repr();
                let bytes_ref: &[u8; 32] = bytes.as_ref().try_into().unwrap();
                let mut tmp_r = NovaFr::ZERO;
                let mut tmp_factor = NovaFr::ONE;
                for i in 0..h {
                    let byte_idx = i / 8;
                    let bit_idx = i % 8;
                    if (bytes_ref[byte_idx] >> bit_idx) & 1 == 1 {
                        tmp_r += tmp_factor;
                    }
                    tmp_factor *= NovaFr::from(2u64);
                }
                Some(tmp_r)
            },
            None => None,
        };
        
        let r_var = AllocatedNum::alloc(cs.namespace(|| "r_var"), || {
            r_val.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        cs.enforce(
            || "r_var == sum(H bits)",
            |_| lc_r,
            |lc| lc + CS::one(),
            |lc| lc + r_var.get_variable(),
        );
        
        // Ép r_var == j_i_var - 1 (vì host dùng: j_i = r + 1)
        cs.enforce(
            || "j_i binding: r_var + 1 == j_i_var",
            |lc| lc + r_var.get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + j_i_var.get_variable(),
        );

        // --- 7. MERKLE PATH VERIFICATION (SEALING VERIFY) ---
        
        // a. Tính giá trị lá Merkle (Leaf = Poseidon2(R_ji, S_ji))
        let mut current_hash = hash_2_gadget(
            cs.namespace(|| "calc_leaf_hash"),
            &r_ji_var,
            &s_ji_var,
        )?;

        // b. Vòng lặp băm ngược lên gốc (Root)
        // FIX SOUNDNESS: Ngoài việc enforce is_right_var là boolean, cần phải enforce
        // is_right_var[level] == bit_level(leaf_idx). Nếu không, Prover có thể cung cấp
        // Merkle proof của leaf khác j_i mà không bị phát hiện.
        //
        // QUAN TRỌNG — OFFSET 1-based/0-based:
        //   Host build Merkle tree với leaf index 0-based, và luôn gọi
        //   generate_proof(j_i - 1) (xem merkle_tree.rs::generate_proof +
        //   simulator_runner/main.rs). Tức path_ji_indices[level] = bit_level(j_i - 1),
        //   KHÔNG PHẢI bit_level(j_i). j_i_var ở đây là 1-based (host: j_i = r + 1),
        //   nên phải rã (j_i_var - 1) chứ không phải rã thẳng j_i_var — nếu không,
        //   constraint sẽ luôn unsatisfied với MỌI prover trung thực (lệch 1 bit
        //   ở vị trí thấp nhất trở lên do phép trừ 1 gây carry/borrow).
        let leaf_idx_var = AllocatedNum::alloc(cs.namespace(|| "leaf_idx"), || {
            Ok(j_i_var.get_value().ok_or(SynthesisError::AssignmentMissing)? - NovaFr::ONE)
        })?;
        cs.enforce(
            || "leaf_idx_plus_1_eq_j_i",
            |lc| lc + leaf_idx_var.get_variable() + CS::one(),
            |lc| lc + CS::one(),
            |lc| lc + j_i_var.get_variable(),
        );
        let j_i_bits = leaf_idx_var.to_bits_le_strict(cs.namespace(|| "j_i_bits"))?;

        for (i, (sibling_val, is_right_val)) in self.path_ji_siblings.iter().zip(self.path_ji_indices.iter()).enumerate() {
            // Cấp phát chứng nhân cho sibling node
            let sibling_var = AllocatedNum::alloc(cs.namespace(|| format!("sibling_{}", i)), || Ok(core_fr_to_nova_fr(*sibling_val)))?;

            // Cấp phát chứng nhân cho boolean (1 = node phải, 0 = node trái)
            let is_right_fr = if *is_right_val { NovaFr::ONE } else { NovaFr::ZERO };
            let is_right_var = AllocatedNum::alloc(cs.namespace(|| format!("is_right_{}", i)), || Ok(is_right_fr))?;

            // Ép is_right_var bắt buộc phải là số nhị phân: x * (1 - x) == 0
            cs.enforce(
                || format!("enforce_bool_is_right_{}", i),
                |lc| lc + is_right_var.get_variable(),
                |lc| lc + CS::one() - is_right_var.get_variable(),
                |lc| lc,
            );

            // FIX SOUNDNESS: Ép is_right_var[i] phải khớp với bit i của leaf_idx (= j_i - 1)
            // (Merkle tree index là 0-based, j_i là 1-based)
            // is_right_var == j_i_bits[i]: Enforce bằng cách dùng LC từ Boolean bit.
            cs.enforce(
                || format!("merkle_bit_binding_{}", i),
                |lc| lc + is_right_var.get_variable(),
                |lc| lc + CS::one(),
                |_| j_i_bits[i].lc(CS::one(), NovaFr::ONE),
            );

            // Sắp xếp đúng vị trí Trái/Phải trước khi băm
            let (left, right) = conditional_swap_gadget(
                cs.namespace(|| format!("swap_{}", i)),
                &current_hash,
                &sibling_var,
                &is_right_var,
            )?;

            // Băm lên tầng tiếp theo
            current_hash = hash_2_gadget(
                cs.namespace(|| format!("hash_level_{}", i)),
                &left,
                &right,
            )?;
        }

        // c. CHỐT CHẶN CUỐI: Ép kết quả băm cuối cùng phải BẰNG ĐÚNG public sealed_root
        cs.enforce(
            || "enforce_merkle_root",
            |lc| lc + current_hash.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + sealed_root_var.get_variable(), // z[3] chính là sealed_root public
        );

        // --- 8. IVC STATE ACCUMULATION ---
        // Spec (Demo.md §State Accumulation):
        //   z_i = Poseidon2(z_{i-1}, j_i, S_ji, R_sealed)
        //
        // FIX: Trước đây thiếu R_ji trong accumulation. Bây giờ dùng hash_4_gadget
        // để commit đầy đủ (j_i, S_ji, R_ji, 0_pad) vào inner hash:
        //   inner = hash_4(j_i, S_ji, R_ji, 0)
        //   z_acc_next = hash_2(z_acc_prev, inner)
        //
        // Điều này đảm bảo z_acc tích lũy toàn bộ bằng chứng: index + state + replica.
        // 0_pad dùng để fill slot thứ 4 của hash_4 (binary tree composition).
        let zero_pad = AllocatedNum::alloc(cs.namespace(|| "zero_pad_acc"), || Ok(NovaFr::ZERO))?;
        cs.enforce(
            || "enforce_zero_pad_acc",
            |lc| lc + zero_pad.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc,
        );
        let inner_acc = hash_4_gadget(
            cs.namespace(|| "acc_inner_hash"),
            &j_i_var,
            &s_ji_var,
            &r_ji_var,
            &zero_pad,
        )?;
        let z_acc_next = hash_2_gadget(
            cs.namespace(|| "acc_z_next"),
            &z[6],
            &inner_acc,
        )?;

        // Trả về đúng 7 biến public cho bước kế tiếp
        Ok(vec![
            epoch_public,      // z[0]
            z_next_counter,    // z[1]
            sector_id_var,     // z[2]
            sealed_root_var,   // z[3]
            beacon_var,        // z[4]
            replica_id_var,    // z[5]
            z_acc_next,        // z[6] — IVC state tích lũy mới
        ])
    }
}
pub struct ProvingPipeline {
    pub pp: PublicParams<G1, G2, EngramStepCircuit>,
    /// Cache (pk, vk) để tránh gọi CompressedSNARK::setup() 2 lần.
    /// Lần đầu tính trong setup(), prove_epoch() dùng lại trực tiếp.
    pub pk: ProverKey<G1, G2, EngramStepCircuit, SpartanPrimary, SpartanSecondary>,
    pub vk: EngramVerifierKey,
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
        // FIX (Vấn đề 4): Gọi setup() 1 lần duy nhất tại đây và cache kết quả.
        // prove_epoch() sẽ dùng lại self.pk thay vì gọi lại lần nữa.
        let (pk, vk) = CompressedSNARK::<G1, G2, EngramStepCircuit, SpartanPrimary, SpartanSecondary>::setup(&pp).unwrap();
        metrics.pk_vk_ms = elapsed_ms_f64(pk_vk_start);
        peak.sample();

        metrics.ram_peak_kib = peak.peak_delta_kib();
        println!("✅ Setup hoàn tất!");
        (Self { pp, pk, vk }, metrics)
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
        let first_replica_id = core_fr_to_nova_fr(challenges[0].replica_id);
        // z0 gồm public context + step counter + z_acc khởi tạo bằng replica_id
        // (theo spec: z_0 = Replica_id cho IVC state tích lũy)
        let z0_primary = vec![
            NovaFr::from(epoch as u64),
            NovaFr::ZERO,
            first_sector_id,
            first_sealed_root,
            first_beacon,
            first_replica_id,
            first_replica_id, // z[6] = z_acc khởi tạo = replica_id (theo Demo.md: z_0 = Replica_id)
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

        // FIX (Vấn đề 4): Dùng self.pk đã cache — KHÔNG gọi CompressedSNARK::setup() lại.
        // Gọi lại ở đây tốn vài giây và làm lạm phát compression_ms trong CSV.
        let compressed_snark = CompressedSNARK::<G1, G2, EngramStepCircuit, SpartanPrimary, SpartanSecondary>::prove(
            &self.pp,
            &self.pk,
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
        metrics.ram_peak_kib = peak.peak_delta_kib();

        println!("✅ Nén Spartan hoàn tất trong {:.3} ms!", compress_time);
        println!("📊 Metric - Compressed Proof Size: {} Bytes", metrics.compressed_proof_size_bytes);

        (compressed_snark, z0_primary, metrics)
    }
}