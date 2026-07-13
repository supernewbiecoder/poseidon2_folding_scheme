use nova_snark::frontend::{test_cs::TestConstraintSystem, ConstraintSystem, num::AllocatedNum};
use prover::{EngramStepCircuit, G1};
use core_primitives::poseidon2::hash_2;
use core_primitives::Fr;
use nova_snark::traits::{circuit::StepCircuit, Engine};
use ff::{Field, PrimeField};

type NovaFr = <G1 as Engine>::Scalar;

fn poseidon2_chain(values: &[Fr]) -> Fr {
    let mut acc = Fr::ZERO;
    for value in values {
        acc = hash_2(acc, *value);
    }
    acc
}

fn poseidon2_hash_4(a: Fr, b: Fr, c: Fr, d: Fr) -> Fr {
    hash_2(hash_2(a, b), hash_2(c, d))
}

fn string_to_fr(s: &str) -> Fr {
    let bytes = s.as_bytes();
    let mut acc = Fr::from(bytes.len() as u64);
    for window in bytes.chunks(31) {
        let mut repr = [0u8; 32];
        repr[..window.len()].copy_from_slice(window);
        let slice_fr = Fr::from_repr(repr.into()).unwrap_or_else(|| {
            repr[31] = 0;
            Fr::from_repr(repr.into()).unwrap_or(Fr::ZERO)
        });
        acc = hash_2(acc, slice_fr);
    }
    acc
}

fn main() {
    println!("🔍 Testing constraint system...");
    // Khởi tạo các giá trị giả lập
    let beacon_str = "test_beacon_1234567890";
    let beacon = string_to_fr(beacon_str);
    let beacon_nova = NovaFr::from_repr(beacon.to_repr().into()).unwrap_or(NovaFr::ZERO);
    
    let sector_id = 1000u64;
    let epoch = 0usize;
    let challenge_no = 1usize;
    let num_chunks = 262144;
    
    // Derived values
    let challenge_fr = Fr::from(challenge_no as u64);
    let j_i_seed = poseidon2_chain(&[beacon, Fr::from(sector_id), Fr::from(epoch as u64), challenge_fr]);
    
    let seed_bytes = j_i_seed.to_repr();
    let j_i_u64 = u64::from_le_bytes(seed_bytes.as_ref()[0..8].try_into().unwrap());
    let j_i = (j_i_u64 as usize % num_chunks).saturating_add(1);
    // j_i_seed field đã bị xóa khỏi struct, chỉ dùng locally để derive j_i
    let _ = j_i_seed;
    
    println!("Generated j_i: {}", j_i);

    // Dummy data
    let d_ji = Fr::ZERO;
    let s_ji_minus_1 = Fr::ZERO;
    let replica_id = Fr::ZERO;
    let r_ji = poseidon2_hash_4(d_ji, s_ji_minus_1, Fr::from(j_i as u64), replica_id);
    let s_ji = core_primitives::poseidon2::hash_2(s_ji_minus_1, r_ji);

    // Tree path
    // Tree path: indices phải khớp với bit từng cấp của (j_i - 1) để qua Merkle bit binding constraint
    let j_i_minus_1 = j_i.saturating_sub(1);
    let path_ji_indices: Vec<bool> = (0..18).map(|bit| (j_i_minus_1 >> bit) & 1 == 1).collect();
    let path_ji_siblings = vec![Fr::ZERO; 18];
    
    // Root
    let mut current_hash = hash_2(r_ji, s_ji);
    for _ in 0..18 {
        current_hash = hash_2(current_hash, Fr::ZERO);
    }
    let sealed_root = current_hash;
    let sealed_root_nova = NovaFr::from_repr(sealed_root.to_repr().into()).unwrap_or(NovaFr::ZERO);

    let circuit = EngramStepCircuit {
        epoch,
        sector_id: Fr::from(sector_id),
        sealed_root,
        beacon,
        replica_id,
        j_i,
        d_ji,
        s_ji_minus_1,
        s_ji,
        path_ji_siblings,
        path_ji_indices,
        tree_height: 18,
    };

    let mut cs = TestConstraintSystem::<NovaFr>::new();
    
    let z = vec![
        AllocatedNum::alloc(cs.namespace(|| "z0"), || Ok(NovaFr::from(epoch as u64))).unwrap(),
        AllocatedNum::alloc(cs.namespace(|| "z1"), || Ok(NovaFr::ZERO)).unwrap(),
        AllocatedNum::alloc(cs.namespace(|| "z2"), || Ok(NovaFr::from(sector_id))).unwrap(),
        AllocatedNum::alloc(cs.namespace(|| "z3"), || Ok(sealed_root_nova)).unwrap(),
        AllocatedNum::alloc(cs.namespace(|| "z4"), || Ok(beacon_nova)).unwrap(),
        AllocatedNum::alloc(cs.namespace(|| "z5"), || Ok(NovaFr::ZERO)).unwrap(),
        AllocatedNum::alloc(cs.namespace(|| "z6"), || Ok(NovaFr::ZERO)).unwrap(),
    ];
    
    let _z_out = circuit.synthesize(&mut cs, z.as_slice()).unwrap();
    
    let is_satisfied = cs.is_satisfied();
    println!("Is satisfied: {}", is_satisfied);
    if !is_satisfied {
        println!("Failing constraints:");
        println!("{:?}", cs.which_is_unsatisfied());
    }
}
