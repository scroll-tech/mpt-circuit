use crate::MPTProofType;
use std::collections::HashMap;
use strum_macros::EnumIter;

#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, Hash)]
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

pub fn transitions(proof: MPTProofType) -> HashMap<SegmentType, Vec<SegmentType>> {
    match proof {
        MPTProofType::NonceChanged
        | MPTProofType::BalanceChanged
        | MPTProofType::CodeSizeExists
        | MPTProofType::CodeHashExists => [
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
                    SegmentType::AccountTrie,  // mpt has more than one account
                    SegmentType::AccountLeaf0, // mpt has only one account
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
                vec![SegmentType::StorageTrie, SegmentType::StorageLeaf0],
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
                    SegmentType::AccountTrie, // mpt has more than one account
                    SegmentType::Start,       // mpt has at most 1 account
                ],
            ),
            (
                SegmentType::AccountTrie,
                vec![SegmentType::AccountTrie, SegmentType::Start],
            ),
        ]
        .into(),
        MPTProofType::StorageDoesNotExist | MPTProofType::AccountDestructed => [].into(),
    }
}
