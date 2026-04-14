use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError, LinearCombination};
use pasta_curves::pallas::Scalar as Fr;
use ff::Field;
use crate::constants::*;

pub struct Poseidon2Gadget<'a, CS: ConstraintSystem<Fr>> {
    cs: &'a mut CS,
    state: Vec<AllocatedNum<Fr>>,
}

impl<'a, CS: ConstraintSystem<Fr>> Poseidon2Gadget<'a, CS> {
    pub fn new(cs: &'a mut CS, initial_state: Vec<AllocatedNum<Fr>>) -> Self {
        assert_eq!(initial_state.len(), T, "State phải có kích thước t={}", T);
        Self { cs, state: initial_state }
    }

    fn sbox(&mut self, x: &AllocatedNum<Fr>, name: &str) -> Result<AllocatedNum<Fr>, SynthesisError> {
        let x_sq = x.square(self.cs.namespace(|| format!("{}_sq", name)))?;
        let x_quad = x_sq.square(self.cs.namespace(|| format!("{}_quad", name)))?;
        x_quad.mul(self.cs.namespace(|| format!("{}_penta", name)), x)
    }

    fn apply_matrix(&mut self, is_full_round: bool, namespace_prefix: &str) -> Result<(), SynthesisError> {
        let matrix = if is_full_round { &*MAT_FULL } else { &*MAT_PARTIAL };
        let mut new_state = vec![];

        for i in 0..T {
            let mut lc = LinearCombination::zero();
            let mut val = Some(Fr::ZERO); // Dùng ZERO của bản 0.13

            for j in 0..T {
                lc = lc + (matrix[i][j], self.state[j].get_variable());
                if let (Some(mut v), Some(state_val)) = (val, self.state[j].get_value()) {
                    v += matrix[i][j] * state_val;
                    val = Some(v);
                } else { val = None; }
            }

            let sum_var = AllocatedNum::alloc(
                self.cs.namespace(|| format!("{}_matrix_mul_i{}", namespace_prefix, i)),
                || val.ok_or(SynthesisError::AssignmentMissing),
            )?;
            
            self.cs.enforce(
                || format!("{}_enforce_matrix_i{}", namespace_prefix, i),
                |lc_a| lc_a + &lc,
                |lc_b| lc_b + CS::one(),
                |lc_c| lc_c + sum_var.get_variable(),
            );
            new_state.push(sum_var);
        }
        self.state = new_state;
        Ok(())
    }

    pub fn hash(&mut self) -> Result<Vec<AllocatedNum<Fr>>, SynthesisError> {
        let half_f = R_F / 2;
        self.apply_matrix(true, "initial_premix")?;

        for r in 0..(R_F + R_P) {
            let is_full = r < half_f || r >= half_f + R_P;

            let mut state_after_rc = vec![];
            for i in 0..T {
                let rc = RC[r][i];
                let val = self.state[i].get_value().map(|v| v + rc);
                let added_var = AllocatedNum::alloc(
                    self.cs.namespace(|| format!("r{}_add_rc_i{}", r, i)),
                    || val.ok_or(SynthesisError::AssignmentMissing),
                )?;
                self.cs.enforce(
                    || format!("r{}_enforce_rc_i{}", r, i),
                    |lc| lc + self.state[i].get_variable() + (rc, CS::one()),
                    |lc| lc + CS::one(),
                    |lc| lc + added_var.get_variable(),
                );
                state_after_rc.push(added_var);
            }
            
            self.state = state_after_rc;

            let mut state_after_sbox = vec![];
            for i in 0..T {
                if is_full || i == 0 {
                    let current_var = self.state[i].clone();
                    let sboxed_var = self.sbox(&current_var, &format!("r{}_sbox_i{}", r, i))?;
                    state_after_sbox.push(sboxed_var);
                } else {
                    state_after_sbox.push(self.state[i].clone());
                }
            }

            self.state = state_after_sbox;
            self.apply_matrix(is_full, &format!("r{}", r))?;
        }

        Ok(self.state.clone())
    }
}