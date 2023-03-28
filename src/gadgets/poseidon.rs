use crate::constraint_builder::{AdviceColumn, ConstraintBuilder, Query};
use halo2_proofs::{arithmetic::FieldExt, circuit::Region, plonk::ConstraintSystem, halo2curves::bn256::Fr};

pub trait PoseidonLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3];
}

#[derive(Clone, Copy)]
pub struct PoseidonConfig {
    left: AdviceColumn,
    right: AdviceColumn,
    hash: AdviceColumn,
}

impl PoseidonConfig {
    pub fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
    ) -> Self {
        let [left, right, hash] = cb.advice_columns(cs);
        Self { left, right, hash }
    }

    pub fn assign(&self, region: &mut Region<'_, Fr>, hash_traces: &[(Fr, Fr, Fr)]) {
        for (offset, hash_trace) in hash_traces.iter().enumerate() {
            for (column, value) in [
                (self.left, hash_trace.0),
                (self.right, hash_trace.1),
                (self.hash, hash_trace.2),
            ] {
                column.assign(region, offset, value);
            }
        }
    }
}

impl PoseidonLookup for PoseidonConfig {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3] {
        [
            self.left.current(),
            self.right.current(),
            self.hash.current(),
        ]
    }
}
