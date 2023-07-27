use crate::types::HashDomain;
use crate::MPTProofType;
use std::collections::HashMap;
use strum_macros::EnumIter;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, EnumIter, Hash)]
pub enum SegmentType {
    Start, // Boundary marker between updates
    AccountTrie,
    AccountLeaf0,
    AccountLeaf1,
    AccountLeaf2,
    AccountLeaf3,
    StorageTrie,
    StorageLeaf0,
}

// Allowed transitions between current and next segment type, as a function of the proof type.
pub fn transitions(proof: MPTProofType) -> HashMap<SegmentType, Vec<SegmentType>> {
    match proof {
        MPTProofType::NonceChanged
        | MPTProofType::BalanceChanged
        | MPTProofType::CodeSizeExists
        | MPTProofType::CodeHashExists => [
            (
                SegmentType::Start,
                vec![
                    SegmentType::AccountTrie,  // mpt has > 1 account
                    SegmentType::AccountLeaf0, // mpt has <= 1 account
                ],
            ),
            (
                SegmentType::AccountTrie,
                vec![
                    SegmentType::AccountTrie,
                    SegmentType::AccountLeaf0,
                    SegmentType::Start, // empty account proof
                ],
            ),
            (SegmentType::AccountLeaf0, vec![SegmentType::AccountLeaf1]),
            (SegmentType::AccountLeaf1, vec![SegmentType::AccountLeaf2]),
            (SegmentType::AccountLeaf2, vec![SegmentType::AccountLeaf3]),
            (SegmentType::AccountLeaf3, vec![SegmentType::Start]),
        ]
        .into(),
        MPTProofType::PoseidonCodeHashExists => [
            (
                SegmentType::Start,
                vec![
                    SegmentType::AccountTrie,  // mpt has more than one account
                    SegmentType::AccountLeaf0, // mpt has only one account
                ],
            ),
            (
                SegmentType::AccountTrie,
                vec![SegmentType::AccountTrie, SegmentType::AccountLeaf0],
            ),
            (SegmentType::AccountLeaf0, vec![SegmentType::AccountLeaf1]),
            (SegmentType::AccountLeaf1, vec![SegmentType::Start]),
        ]
        .into(),
        MPTProofType::StorageChanged => [
            (
                SegmentType::Start,
                vec![
                    SegmentType::AccountTrie,  // mpt has > 1 account
                    SegmentType::AccountLeaf0, // mpt has 1 account
                ],
            ),
            (
                SegmentType::AccountTrie,
                vec![SegmentType::AccountTrie, SegmentType::AccountLeaf0],
            ),
            (SegmentType::AccountLeaf0, vec![SegmentType::AccountLeaf1]),
            (SegmentType::AccountLeaf1, vec![SegmentType::AccountLeaf2]),
            (SegmentType::AccountLeaf2, vec![SegmentType::AccountLeaf3]),
            (
                SegmentType::AccountLeaf3,
                vec![
                    SegmentType::StorageTrie,  // existing storage has > 1 entry
                    SegmentType::StorageLeaf0, // existing storage <= 1 entry
                ],
            ),
            (
                SegmentType::StorageTrie,
                vec![SegmentType::StorageTrie, SegmentType::StorageLeaf0],
            ),
            (SegmentType::StorageLeaf0, vec![SegmentType::Start]),
        ]
        .into(),
        MPTProofType::AccountDoesNotExist => [
            (
                SegmentType::Start,
                vec![
                    SegmentType::AccountTrie, // mpt has more > 1 account
                    SegmentType::Start,       // mpt has <= 1 account
                ],
            ),
            (
                SegmentType::AccountTrie,
                vec![SegmentType::AccountTrie, SegmentType::Start],
            ),
        ]
        .into(),
        MPTProofType::StorageDoesNotExist => [
            (
                SegmentType::Start,
                vec![
                    SegmentType::AccountTrie,  // mpt has > 1 account
                    SegmentType::AccountLeaf0, // mpt has 1 account
                ],
            ),
            (
                SegmentType::AccountTrie,
                vec![
                    SegmentType::Start, // empty storage proof for empty account
                    SegmentType::AccountTrie,
                    SegmentType::AccountLeaf0, // empty storage proof for existing account
                ],
            ),
            (SegmentType::AccountLeaf0, vec![SegmentType::AccountLeaf1]),
            (SegmentType::AccountLeaf1, vec![SegmentType::AccountLeaf2]),
            (SegmentType::AccountLeaf2, vec![SegmentType::AccountLeaf3]),
            (
                SegmentType::AccountLeaf3,
                vec![
                    SegmentType::StorageTrie, // existing storage > 1 entry
                    SegmentType::Start,       // storage has <= 1 entry
                ],
            ),
            (
                SegmentType::StorageTrie,
                vec![SegmentType::StorageTrie, SegmentType::Start],
            ),
        ]
        .into(),
        MPTProofType::AccountDestructed => [].into(),
    }
}

pub fn domains(segment_type: SegmentType) -> Vec<HashDomain> {
    match segment_type {
        SegmentType::Start => vec![HashDomain::Pair],

        SegmentType::AccountTrie | SegmentType::StorageTrie => vec![
            HashDomain::NodeTypeBranch0,
            HashDomain::NodeTypeBranch1,
            HashDomain::NodeTypeBranch2,
            HashDomain::NodeTypeBranch3,
        ],
        SegmentType::AccountLeaf0 | SegmentType::StorageLeaf0 => vec![HashDomain::NodeTypeEmpty],
        SegmentType::AccountLeaf1 | SegmentType::AccountLeaf2 | SegmentType::AccountLeaf3 => {
            vec![HashDomain::AccountFields]
        }
    }
}
