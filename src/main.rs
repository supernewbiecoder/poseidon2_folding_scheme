//=============================================================================
// NOVA Folding Scheme - Proof of Space-Time (PoSt) Example
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use nova_snark::{
    traits::{circuit::{StepCircuit, TrivialCircuit}, Group},
    // CẬP NHẬT 1: Sử dụng Engine do chính Nova cung cấp thay vì pasta_curves
    provider::{PallasEngine, VestaEngine}, 
    RecursiveSNARK, PublicParams,
};
use pasta_curves::pallas::Scalar as Fr;
use ff::Field; // CẬP NHẬT 2: Thêm Field để gọi hàm ZERO

mod constants;
mod poseidon2_gadget;
use poseidon2_gadget::Poseidon2Gadget;

#[derive(Clone, Debug)]
pub struct PoStStepCircuit {
    pub challenge: Fr, 
    pub data_leaf: Fr, 
}

impl StepCircuit<Fr> for PoStStepCircuit {
    fn arity(&self) -> usize {
        1 
    }

    fn synthesize<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
        z_in: &[AllocatedNum<Fr>], 
    ) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        
        let z_prev = &z_in[0];
        
        let challenge_var = AllocatedNum::alloc(cs.namespace(|| "challenge"), || Ok(self.challenge))?;
        let data_var = AllocatedNum::alloc(cs.namespace(|| "data"), || Ok(self.data_leaf))?;

        let initial_state = vec![z_prev.clone(), challenge_var, data_var];
        
        let mut hasher = Poseidon2Gadget::new(cs, initial_state);
        let state_out = hasher.hash()?;

        Ok(vec![state_out[0].clone()])
    }
}

fn main() {
    println!("=== KHỞI ĐỘNG HỆ THỐNG NOVA FOLDING SCHEME ===");

    let circuit_primary = PoStStepCircuit { challenge: Fr::ZERO, data_leaf: Fr::ZERO };
    let circuit_secondary = TrivialCircuit::default();

    println!("1. Đang thiết lập Tham số Công khai (Public Params)... (Có thể mất vài giây)");
    
    // CẬP NHẬT 3: Thay G1, G2 bằng PallasEngine và VestaEngine
    let pp = PublicParams::<
        PallasEngine, VestaEngine,
        PoStStepCircuit,
        TrivialCircuit<<VestaEngine as nova_snark::traits::Engine>::Scalar>,
    >::setup(
        &circuit_primary, 
        &circuit_secondary, 
        &*nova_snark::traits::snark::default_ck_hint(), 
        &*nova_snark::traits::snark::default_ck_hint()
    );

    let z0_primary = vec![Fr::from(12345u64)]; 
    // CẬP NHẬT 4: Gọi Scalar của VestaEngine cho điểm khởi tạo
    let z0_secondary = vec![<VestaEngine as nova_snark::traits::Engine>::Scalar::ZERO];

    let mut recursive_snark = RecursiveSNARK::new(
        &pp, 
        &circuit_primary, 
        &circuit_secondary, 
        &z0_primary, 
        &z0_secondary,
    ).expect("Lỗi khởi tạo SNARK đệ quy");

    let num_slots = 5;
    println!("2. Bắt đầu quá trình Folding qua {} chu kỳ thời gian:", num_slots);

    for i in 0..num_slots {
        let step_circuit = PoStStepCircuit {
            challenge: Fr::from(i as u64 * 10),
            data_leaf: Fr::from(9999 + i as u64),
        };

        let res = recursive_snark.prove_step(
            &pp, 
            &step_circuit, 
            &circuit_secondary
        );
        
        match res {
            Ok(_) => println!("   [+] Gập thành công Slot thứ {}", i + 1),
            Err(e) => panic!("   [-] Lỗi Folding ở Slot {}: {:?}", i + 1, e),
        }
    }

    println!("3. Quá trình Proving hoàn tất! Đang tiến hành Xác minh (Verify)...");
    let res = recursive_snark.verify(
        &pp, 
        num_slots, 
        &z0_primary, 
        &z0_secondary
    );

    if res.is_ok() {
        println!("=== ✅ XÁC MINH THÀNH CÔNG! Bằng chứng PoSt hợp lệ! ===");
        let (z_final_primary, _) = res.unwrap();
        println!("Mã Hash tích lũy cuối cùng: {:?}", z_final_primary[0]);
    } else {
        println!("=== ❌ XÁC MINH THẤT BẠI! ===");
    }
}

//========================================
//========================================
// Mạch Gadget Poseidon2 R1CS Test
// use bellpepper_core::{num::AllocatedNum, ConstraintSystem, test_cs::TestConstraintSystem};
// use pasta_curves::pallas::Scalar as Fr;

// mod constants;
// mod poseidon2_gadget;
// use poseidon2_gadget::Poseidon2Gadget;
// use constants::from_hex;

// fn main() {
//     println!("Bắt đầu Test Mạch Poseidon2...");

//     // Khởi tạo Constraint System giả lập để test mạch
//     let mut cs = TestConstraintSystem::<Fr>::new();

//     // Đầu vào giống hệt Test Vector của SageMath [0, 1, 2]
//     let in_0 = AllocatedNum::alloc(cs.namespace(|| "in_0"), || Ok(Fr::from(0u64))).unwrap();
//     let in_1 = AllocatedNum::alloc(cs.namespace(|| "in_1"), || Ok(Fr::from(1u64))).unwrap();
//     let in_2 = AllocatedNum::alloc(cs.namespace(|| "in_2"), || Ok(Fr::from(2u64))).unwrap();
    
//     let initial_state = vec![in_0, in_1, in_2];

//     // Chạy Mạch
//     let mut hasher = Poseidon2Gadget::new(&mut cs, initial_state);
//     let out_state = hasher.hash().unwrap();

//     // ĐÃ CẬP NHẬT: Kết quả đầu ra dự kiến từ SageMath (Đường cong Vesta Base / Pallas Scalar)
//     let expected_0 = from_hex("0x261ecbdfd62c617b82d297705f18c788fc9831b14a6a2b8f61229bef68ce2792");
//     let expected_1 = from_hex("0x2c76327e0b7653873263158cf8545c282364b183880fcdea93ca8526d518c66f");
//     let expected_2 = from_hex("0x262316c0ce5244838c75873299b59d763ae0849d2dd31bdc95caf7db1c2901bf");

//     assert!(cs.is_satisfied());
//     println!("Trạng thái mạch R1CS: Thỏa mãn (Satisfied)");
//     println!("Số lượng ràng buộc (Constraints): {}", cs.num_constraints());

//     let val_0 = out_state[0].get_value().unwrap();
//     let val_1 = out_state[1].get_value().unwrap();
//     let val_2 = out_state[2].get_value().unwrap();

//     assert_eq!(val_0, expected_0, "Sai lệch giá trị state[0]");
//     assert_eq!(val_1, expected_1, "Sai lệch giá trị state[1]");
//     assert_eq!(val_2, expected_2, "Sai lệch giá trị state[2]");

//     println!("KIỂM TRA THÀNH CÔNG: Mạch Gadget tạo ra Hash hoàn toàn khớp với SageMath/Python!");
// }