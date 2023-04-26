use crate::constraint_builder::{AdviceColumn, ConstraintBuilder, Query};
use crate::util::hash as poseidon_hash;
use halo2_proofs::{
    arithmetic::FieldExt, circuit::Region, halo2curves::bn256::Fr, plonk::ConstraintSystem,
};

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
            // TODO: probably has to do with 0, 0?
            // assert_eq!(poseidon_hash(hash_trace.0, hash_trace.1), hash_trace.2);
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
