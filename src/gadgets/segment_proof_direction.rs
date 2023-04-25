use super::mpt_update::SegmentType;
use crate::{
    constraint_builder::{FixedColumn, Query},
    MPTProofType,
};
use halo2_proofs::{
    arithmetic::FieldExt, circuit::Region, halo2curves::bn256::Fr, plonk::ConstraintSystem,
};

// TODO: need to check and update when implementing the corresponding proof type.
const SEGMENT_PROOF_DIRECTIONS: [(SegmentType, MPTProofType, u64); 27] = [
    // AccountLeaf0
    (SegmentType::AccountLeaf0, MPTProofType::BalanceChanged, 0),
    (SegmentType::AccountLeaf0, MPTProofType::CodeHashExists, 0),
    (SegmentType::AccountLeaf0, MPTProofType::CodeSizeExists, 0),
    (SegmentType::AccountLeaf0, MPTProofType::NonceChanged, 0),
    (
        SegmentType::AccountLeaf0,
        MPTProofType::PoseidonCodeHashExists,
        0,
    ),
    (SegmentType::AccountLeaf0, MPTProofType::StorageChanged, 0),
    (
        SegmentType::AccountLeaf0,
        MPTProofType::StorageDoesNotExist,
        0,
    ),
    // AccountLeaf1
    (SegmentType::AccountLeaf1, MPTProofType::BalanceChanged, 0),
    (SegmentType::AccountLeaf1, MPTProofType::CodeHashExists, 0),
    (SegmentType::AccountLeaf1, MPTProofType::CodeSizeExists, 0),
    (SegmentType::AccountLeaf1, MPTProofType::NonceChanged, 0),
    (SegmentType::AccountLeaf1, MPTProofType::StorageChanged, 0),
    (
        SegmentType::AccountLeaf1,
        MPTProofType::StorageDoesNotExist,
        0,
    ),
    (
        SegmentType::AccountLeaf1,
        MPTProofType::PoseidonCodeHashExists,
        1,
    ),
    // AccountLeaf2
    (SegmentType::AccountLeaf2, MPTProofType::BalanceChanged, 0),
    (SegmentType::AccountLeaf2, MPTProofType::CodeSizeExists, 0),
    (SegmentType::AccountLeaf2, MPTProofType::NonceChanged, 0),
    (SegmentType::AccountLeaf2, MPTProofType::CodeHashExists, 1),
    (SegmentType::AccountLeaf2, MPTProofType::StorageChanged, 1),
    (
        SegmentType::AccountLeaf2,
        MPTProofType::StorageDoesNotExist,
        1,
    ),
    // AccountLeaf3
    (SegmentType::AccountLeaf3, MPTProofType::BalanceChanged, 1),
    (SegmentType::AccountLeaf3, MPTProofType::CodeSizeExists, 0),
    (SegmentType::AccountLeaf3, MPTProofType::NonceChanged, 0),
    (SegmentType::AccountLeaf3, MPTProofType::CodeHashExists, 1),
    (SegmentType::AccountLeaf3, MPTProofType::StorageChanged, 0),
    // AccountLeaf4
    (SegmentType::AccountLeaf4, MPTProofType::CodeHashExists, 0),
    (SegmentType::AccountLeaf4, MPTProofType::CodeHashExists, 1),
];

pub trait SegmentProofDirectionLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3];
}

#[derive(Clone, Copy)]
pub struct SegmentProofDirectionConfig {
    segment_type: FixedColumn,
    proof_type: FixedColumn,
    direction: FixedColumn,
}

impl SegmentProofDirectionConfig {
    pub fn configure<F: FieldExt>(cs: &mut ConstraintSystem<F>) -> Self {
        let [segment_type, proof_type, direction] = [0; 3].map(|_| FixedColumn(cs.fixed_column()));

        Self {
            segment_type,
            proof_type,
            direction,
        }
    }

    pub fn assign(&self, region: &mut Region<'_, Fr>) {
        for (offset, tuple) in SEGMENT_PROOF_DIRECTIONS.iter().enumerate() {
            for (column, value) in [
                (self.segment_type, Fr::from(tuple.0 as u64)),
                (self.proof_type, Fr::from(tuple.1 as u64)),
                (self.direction, Fr::from(tuple.2)),
            ] {
                column.assign(region, offset, value);
            }
        }
    }
}

impl SegmentProofDirectionLookup for SegmentProofDirectionConfig {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3] {
        [
            self.segment_type.current(),
            self.proof_type.current(),
            self.direction.current(),
        ]
    }
}
