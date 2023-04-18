use crate::constraint_builder::{AdviceColumn, ConstraintBuilder, Query};
use halo2_proofs::{
    arithmetic::FieldExt, circuit::Region, halo2curves::bn256::Fr, plonk::ConstraintSystem,
};

pub trait SegmentProofLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3];
}

#[derive(Clone, Copy)]
pub struct SegmentProofConfig {
    segment_type: AdviceColumn,
    proof_type: AdviceColumn,
    direction: AdviceColumn,
}

impl SegmentProofConfig {
    pub fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
    ) -> Self {
        let [segment_type, proof_type, direction] = cb.advice_columns(cs);
        Self {
            segment_type,
            proof_type,
            direction,
        }
    }

    pub fn assign(&self, region: &mut Region<'_, Fr>, traces: &[(Fr, Fr, Fr)]) {
        for (offset, trace) in traces.iter().enumerate() {
            for (column, value) in [
                (self.segment_type, trace.0),
                (self.proof_type, trace.1),
                (self.direction, trace.2),
            ] {
                column.assign(region, offset, value);
            }
        }
    }
}

impl SegmentProofLookup for SegmentProofConfig {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3] {
        [
            self.segment_type.current(),
            self.proof_type.current(),
            self.direction.current(),
        ]
    }
}
