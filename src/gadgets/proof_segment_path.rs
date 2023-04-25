use super::mpt_update::SegmentType;
use crate::{
    constraint_builder::{FixedColumn, Query},
    MPTProofType,
};
use halo2_proofs::{
    arithmetic::FieldExt, circuit::Region, halo2curves::bn256::Fr, plonk::ConstraintSystem,
};

/// Segment type path as `previous -> current`.
struct SegmentPath {
    previous: SegmentType,
    current: SegmentType,
}

impl SegmentPath {
    const fn new(previous: SegmentType, current: SegmentType) -> Self {
        Self { previous, current }
    }
}

// TODO: need to check and update when implementing the corresponding proof type.
const PROOF_SEGMENT_PATHS: [(MPTProofType, SegmentPath); 47] = [
    // Nonce
    (
        MPTProofType::NonceChanged,
        SegmentPath::new(SegmentType::Start, SegmentType::AccountTrie),
    ),
    (
        MPTProofType::NonceChanged,
        SegmentPath::new(SegmentType::AccountTrie, SegmentType::AccountTrie),
    ),
    (
        MPTProofType::NonceChanged,
        SegmentPath::new(SegmentType::Start, SegmentType::AccountLeaf0),
    ),
    (
        MPTProofType::NonceChanged,
        SegmentPath::new(SegmentType::AccountTrie, SegmentType::AccountLeaf0),
    ),
    (
        MPTProofType::NonceChanged,
        SegmentPath::new(SegmentType::AccountLeaf0, SegmentType::AccountLeaf1),
    ),
    (
        MPTProofType::NonceChanged,
        SegmentPath::new(SegmentType::AccountLeaf1, SegmentType::AccountLeaf2),
    ),
    (
        MPTProofType::NonceChanged,
        SegmentPath::new(SegmentType::AccountLeaf2, SegmentType::AccountLeaf3),
    ),
    (
        MPTProofType::NonceChanged,
        SegmentPath::new(SegmentType::AccountLeaf3, SegmentType::Start),
    ),
    // Balance
    (
        MPTProofType::BalanceChanged,
        SegmentPath::new(SegmentType::Start, SegmentType::AccountTrie),
    ),
    (
        MPTProofType::BalanceChanged,
        SegmentPath::new(SegmentType::AccountTrie, SegmentType::AccountTrie),
    ),
    (
        MPTProofType::BalanceChanged,
        SegmentPath::new(SegmentType::Start, SegmentType::AccountLeaf0),
    ),
    (
        MPTProofType::BalanceChanged,
        SegmentPath::new(SegmentType::AccountTrie, SegmentType::AccountLeaf0),
    ),
    (
        MPTProofType::BalanceChanged,
        SegmentPath::new(SegmentType::AccountLeaf0, SegmentType::AccountLeaf1),
    ),
    (
        MPTProofType::BalanceChanged,
        SegmentPath::new(SegmentType::AccountLeaf1, SegmentType::AccountLeaf2),
    ),
    (
        MPTProofType::BalanceChanged,
        SegmentPath::new(SegmentType::AccountLeaf2, SegmentType::AccountLeaf3),
    ),
    (
        MPTProofType::BalanceChanged,
        SegmentPath::new(SegmentType::AccountLeaf3, SegmentType::Start),
    ),
    // Keccak code hash
    (
        MPTProofType::CodeHashExists,
        SegmentPath::new(SegmentType::Start, SegmentType::AccountTrie),
    ),
    (
        MPTProofType::CodeHashExists,
        SegmentPath::new(SegmentType::AccountTrie, SegmentType::AccountTrie),
    ),
    (
        MPTProofType::CodeHashExists,
        SegmentPath::new(SegmentType::Start, SegmentType::AccountLeaf0),
    ),
    (
        MPTProofType::CodeHashExists,
        SegmentPath::new(SegmentType::AccountTrie, SegmentType::AccountLeaf0),
    ),
    (
        MPTProofType::CodeHashExists,
        SegmentPath::new(SegmentType::AccountLeaf0, SegmentType::AccountLeaf1),
    ),
    (
        MPTProofType::CodeHashExists,
        SegmentPath::new(SegmentType::AccountLeaf1, SegmentType::AccountLeaf2),
    ),
    (
        MPTProofType::CodeHashExists,
        SegmentPath::new(SegmentType::AccountLeaf2, SegmentType::AccountLeaf3),
    ),
    (
        MPTProofType::CodeHashExists,
        SegmentPath::new(SegmentType::AccountLeaf3, SegmentType::AccountLeaf4),
    ),
    (
        MPTProofType::CodeHashExists,
        SegmentPath::new(SegmentType::AccountLeaf4, SegmentType::Start),
    ),
    // poseidon code hash
    (
        MPTProofType::PoseidonCodeHashExists,
        SegmentPath::new(SegmentType::Start, SegmentType::AccountTrie),
    ),
    (
        MPTProofType::PoseidonCodeHashExists,
        SegmentPath::new(SegmentType::AccountTrie, SegmentType::AccountTrie),
    ),
    (
        MPTProofType::PoseidonCodeHashExists,
        SegmentPath::new(SegmentType::Start, SegmentType::AccountLeaf0),
    ),
    (
        MPTProofType::PoseidonCodeHashExists,
        SegmentPath::new(SegmentType::AccountTrie, SegmentType::AccountLeaf0),
    ),
    (
        MPTProofType::PoseidonCodeHashExists,
        SegmentPath::new(SegmentType::AccountLeaf0, SegmentType::AccountLeaf1),
    ),
    (
        MPTProofType::PoseidonCodeHashExists,
        SegmentPath::new(SegmentType::AccountLeaf1, SegmentType::Start),
    ),
    // Code size
    (
        MPTProofType::CodeSizeExists,
        SegmentPath::new(SegmentType::Start, SegmentType::AccountTrie),
    ),
    (
        MPTProofType::CodeSizeExists,
        SegmentPath::new(SegmentType::AccountTrie, SegmentType::AccountTrie),
    ),
    (
        MPTProofType::CodeSizeExists,
        SegmentPath::new(SegmentType::Start, SegmentType::AccountLeaf0),
    ),
    (
        MPTProofType::CodeSizeExists,
        SegmentPath::new(SegmentType::AccountTrie, SegmentType::AccountLeaf0),
    ),
    (
        MPTProofType::CodeSizeExists,
        SegmentPath::new(SegmentType::AccountLeaf0, SegmentType::AccountLeaf1),
    ),
    (
        MPTProofType::CodeSizeExists,
        SegmentPath::new(SegmentType::AccountLeaf1, SegmentType::AccountLeaf2),
    ),
    (
        MPTProofType::CodeSizeExists,
        SegmentPath::new(SegmentType::AccountLeaf2, SegmentType::AccountLeaf3),
    ),
    (
        MPTProofType::CodeSizeExists,
        SegmentPath::new(SegmentType::AccountLeaf3, SegmentType::Start),
    ),
    // Storage
    (
        MPTProofType::StorageChanged,
        SegmentPath::new(SegmentType::Start, SegmentType::AccountTrie),
    ),
    (
        MPTProofType::StorageChanged,
        SegmentPath::new(SegmentType::AccountTrie, SegmentType::AccountTrie),
    ),
    (
        MPTProofType::StorageChanged,
        SegmentPath::new(SegmentType::Start, SegmentType::AccountLeaf0),
    ),
    (
        MPTProofType::StorageChanged,
        SegmentPath::new(SegmentType::AccountTrie, SegmentType::AccountLeaf0),
    ),
    (
        MPTProofType::StorageChanged,
        SegmentPath::new(SegmentType::AccountLeaf0, SegmentType::AccountLeaf1),
    ),
    (
        MPTProofType::StorageChanged,
        SegmentPath::new(SegmentType::AccountLeaf1, SegmentType::AccountLeaf2),
    ),
    (
        MPTProofType::StorageChanged,
        SegmentPath::new(SegmentType::AccountLeaf2, SegmentType::AccountLeaf3),
    ),
    (
        MPTProofType::StorageChanged,
        SegmentPath::new(SegmentType::AccountLeaf3, SegmentType::Start),
    ),
];

pub trait ProofSegmentPathLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3];
}

#[derive(Clone, Copy)]
pub struct ProofSegmentPathConfig {
    proof_type: FixedColumn,
    previous_segment_type: FixedColumn,
    current_segment_type: FixedColumn,
}

impl ProofSegmentPathConfig {
    pub fn configure<F: FieldExt>(cs: &mut ConstraintSystem<F>) -> Self {
        let [proof_type, previous_segment_type, current_segment_type] =
            [0; 3].map(|_| FixedColumn(cs.fixed_column()));

        Self {
            proof_type,
            previous_segment_type,
            current_segment_type,
        }
    }

    pub fn assign(&self, region: &mut Region<'_, Fr>) {
        for (offset, (proof_type, segment_path)) in PROOF_SEGMENT_PATHS.iter().enumerate() {
            for (column, value) in [
                (self.proof_type, Fr::from(*proof_type as u64)),
                (
                    self.previous_segment_type,
                    Fr::from(segment_path.previous as u64),
                ),
                (
                    self.current_segment_type,
                    Fr::from(segment_path.current as u64),
                ),
            ] {
                column.assign(region, offset, value);
            }
        }
    }
}

impl ProofSegmentPathLookup for ProofSegmentPathConfig {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3] {
        [
            self.proof_type.current(),
            self.previous_segment_type.current(),
            self.current_segment_type.current(),
        ]
    }
}
