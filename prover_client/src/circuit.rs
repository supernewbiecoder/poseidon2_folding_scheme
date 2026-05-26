use core::types::{PublicInputs, PrivateWitness};

pub struct EngramStepCircuit;

impl EngramStepCircuit {
    /// Hàm này mô phỏng việc sinh constraints cho ZK-Circuit
    pub fn synthesize(public: &PublicInputs, witness: &PrivateWitness) -> Result<(), String> {
        
        // 1. Replica Reconstruction: R_{j_i} = Poseidon2(D_{j_i}, S_{j_i-1}, j_i, Replica_id)
        let expected_r_ji = core::poseidon2::circuit_hash(&[
            witness.d_ji, witness.s_prev, public.j_i, public.replica_id
        ]);
        
        // 2. State Check: S_{j_i} = Poseidon2(S_{j_i-1}, R_{j_i})
        let expected_s_ji = core::poseidon2::circuit_hash(&[witness.s_prev, expected_r_ji]);
        if expected_s_ji != witness.s_ji {
            return Err("State Check Constraint Failed".into());
        }

        // 3. Path Check: MerkleVerify(R_{j_i}, path, j_i, R_sealed) == 1
        let is_valid_path = core::merkle::circuit_verify_path(
            expected_r_ji, &witness.path, public.j_i, public.r_sealed
        );
        if !is_valid_path {
            return Err("Merkle Path Check Failed".into());
        }

        // 4. Challenge Binding: j_i = Poseidon2(beacon, sector_id, epoch, i) mod N
        let expected_j_i = core::poseidon2::circuit_hash(&[
            public.beacon, public.sector_id, public.epoch, witness.step_index
        ]) % core::constants::N;
        if expected_j_i != public.j_i {
            return Err("Challenge Binding Constraint Failed (Prover cheated!)".into());
        }

        // 5. State Accumulation (Dành cho Nova Folding): z_i = Poseidon2(z_{i-1}, j_i, S_{j_i}, R_sealed)
        let z_i = core::poseidon2::circuit_hash(&[
            witness.z_prev, public.j_i, witness.s_ji, public.r_sealed
        ]);
        
        // Output trạng thái tích lũy cho bước tiếp theo
        println!("Generated Folded State (z_i): {:?}", z_i);

        Ok(())
    }
}