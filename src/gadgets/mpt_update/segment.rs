use crate::MPTProofType;
use std::collections::HashMap;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

// Each row of an mpt update belongs to one of four segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, Hash)]
pub enum SegmentType {
    Start, // Boundary marker between updates
    AccountTrie,
    AccountLeaf0,
    AccountLeaf1,
    AccountLeaf2,
    AccountLeaf3,
    AccountLeaf4,
    StorageTrie,
    StorageLeaf0,
    StorageLeaf1,
}

// TODO: use this
fn transitions(proof: MPTProofType) -> HashMap<SegmentType, Vec<SegmentType>> {
    match proof {
        MPTProofType::NonceChanged => [
            (
                SegmentType::Start,
                vec![
                    SegmentType::Start,        // mpt has no accounts
                    SegmentType::AccountTrie,  // mpt has more than one account
                    SegmentType::AccountLeaf0, // mpt has only one account
                ],
            ),
            (
                SegmentType::AccountTrie,
                vec![
                    SegmentType::AccountTrie, // subtree contains multiple accounts
                    SegmentType::AccountLeaf0,
                    SegmentType::Start, // empty account witness = empty tree
                ],
            ),
            (
                SegmentType::AccountLeaf0,
                vec![
                    SegmentType::Start,        // empty account witness = another leaf
                    SegmentType::AccountLeaf1, // proving existence of a nonce for an existing account
                ],
            ),
            (SegmentType::AccountLeaf1, vec![SegmentType::AccountLeaf2]),
            (SegmentType::AccountLeaf2, vec![SegmentType::AccountLeaf3]),
            (SegmentType::AccountLeaf3, vec![SegmentType::Start]),
        ]
        .into(),
        _ => [].into(),
    }
}

// TODO: use this
fn unreachable_states(proof: MPTProofType) -> Vec<SegmentType> {
    match proof {
        MPTProofType::NonceChanged => vec![
            SegmentType::AccountLeaf4,
            SegmentType::StorageTrie,
            SegmentType::StorageLeaf0,
            SegmentType::StorageLeaf1,
        ],
        _ => vec![],
    }
}

// Allowed transitions within on mpt update. Additionally, every state can
// transition to Start, marking the end of the current update and the start of the next one.
// The is the union of possible transitions over all MPTProofType's. In the mpt update gadget, we conditionally
// disallow certain transitions based on the variant and value.
const INTERNAL_TRANSITIONS: [(SegmentType, SegmentType); 17] = [
    //
    (SegmentType::Start, SegmentType::AccountTrie),
    (SegmentType::Start, SegmentType::AccountLeaf0),
    //
    (SegmentType::AccountTrie, SegmentType::AccountTrie),
    (SegmentType::AccountTrie, SegmentType::AccountLeaf0),
    //
    (SegmentType::AccountLeaf0, SegmentType::AccountLeaf1),
    (SegmentType::AccountLeaf0, SegmentType::StorageTrie),
    //
    (SegmentType::AccountLeaf1, SegmentType::AccountLeaf2),
    (SegmentType::AccountLeaf1, SegmentType::StorageTrie),
    //
    (SegmentType::AccountLeaf2, SegmentType::AccountLeaf3),
    (SegmentType::AccountLeaf2, SegmentType::StorageTrie),
    //
    (SegmentType::AccountLeaf3, SegmentType::AccountLeaf4),
    (SegmentType::AccountLeaf3, SegmentType::StorageTrie),
    (SegmentType::AccountLeaf3, SegmentType::StorageLeaf0),
    //
    (SegmentType::AccountLeaf4, SegmentType::StorageTrie),
    //
    (SegmentType::StorageTrie, SegmentType::StorageTrie),
    (SegmentType::StorageTrie, SegmentType::StorageLeaf0),
    //
    (SegmentType::StorageLeaf0, SegmentType::StorageLeaf1),
];

fn forward_transitions() -> HashMap<SegmentType, Vec<SegmentType>> {
    let mut map = HashMap::new();
    for variant in SegmentType::iter() {
        map.insert(variant, vec![SegmentType::Start]);
    }
    for (source, sink) in INTERNAL_TRANSITIONS {
        map.get_mut(&source).unwrap().push(sink);
    }
    map
}

pub fn backward_transitions() -> HashMap<SegmentType, Vec<SegmentType>> {
    let mut map = HashMap::new();
    for variant in SegmentType::iter() {
        map.insert(variant, vec![]);
        map.get_mut(&SegmentType::Start).unwrap().push(variant);
    }
    for (source, sink) in INTERNAL_TRANSITIONS {
        map.get_mut(&sink).unwrap().push(source);
    }
    map
}
