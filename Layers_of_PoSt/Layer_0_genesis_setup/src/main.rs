use std::fs;
use std::path::PathBuf;
use pasta_curves::{pallas, vesta};
use ff::Field;
use engram_common::{MERKLE_DEPTH, dummy_path_elements, dummy_path_indices};
use nova_snark::{
    traits::{circuit::TrivialCircuit, Group},
    provider::ipa_pc::EvaluationEngine,
    spartan::snark::RelaxedR1CSSNARK, // Chỉ định rõ ràng dùng loại snark thường
    CompressedSNARK, PublicParams,
};
use prover_rust::core::circuit::PoStStepCircuit;

// 1. Định nghĩa các kiểu dữ liệu chuẩn của mạng lưới
type G1 = pallas::Point;
type G2 = vesta::Point;
type EE1 = EvaluationEngine<G1>;
type EE2 = EvaluationEngine<G2>;
type S1 = RelaxedR1CSSNARK<G1, EE1>;
type S2 = RelaxedR1CSSNARK<G2, EE2>;

fn main() {
    println!("--- 🛠️ ENGRAM GENESIS: KHỞI TẠO THAM SỐ MẠNG LƯỚI ---");

    let params_dir = PathBuf::from("network_params");
    fs::create_dir_all(&params_dir).expect("Không thể tạo thư mục params");

    let depth = MERKLE_DEPTH; 
    let dummy_circuit = PoStStepCircuit {
        raw_data: <G1 as Group>::Scalar::ZERO,
        prev_s: <G1 as Group>::Scalar::ZERO,
        challenge_index: <G1 as Group>::Scalar::ZERO,
        path_elements: dummy_path_elements(),
        path_indices: dummy_path_indices(),
    };

    // 3. Tính toán Public Parameters (PP)
    println!("[1/2] Đang tính toán Public Parameters (PP)...");
    let pp = PublicParams::<G1, G2, PoStStepCircuit, TrivialCircuit<<G2 as Group>::Scalar>>::setup(
        &dummy_circuit, 
        &TrivialCircuit::default()
    );
    
    // 4. Trích xuất PK và VK với định nghĩa kiểu cụ thể
    println!("[2/2] Đang trích xuất Prover Key (PK) và Verifier Key (VK)...");
    let (pk, vk) = CompressedSNARK::<G1, G2, PoStStepCircuit, TrivialCircuit<<G2 as Group>::Scalar>, S1, S2>::setup(&pp).unwrap();

    // 5. Lưu trữ nhị phân để các Layer sau nạp vào
    fs::write(params_dir.join("pp.bin"), bincode::serialize(&pp).unwrap()).unwrap();
    fs::write(params_dir.join("pk.bin"), bincode::serialize(&pk).unwrap()).unwrap();
    fs::write(params_dir.join("vk.bin"), bincode::serialize(&vk).unwrap()).unwrap();

    println!("✅ THÀNH CÔNG: Chìa khóa mạng lưới đã được lưu tại 'network_params/'");
}