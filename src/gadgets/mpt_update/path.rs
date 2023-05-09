use std::collections::HashMap;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, Hash)]
pub enum PathType {
    Start,        // Used as boundary marker between updates
    Common,       // Hashes for both the old and new path are being updated.
    ExtensionOld, // The old path is being extended. The new hash doesn't change.
    ExtensionNew, // The new path is being extended. The old hash doesn't change.
}

const PATH_TRANSITIONS: [(PathType, PathType); 12] = [
    // Start -> Anything
    (PathType::Start, PathType::Start),
    (PathType::Start, PathType::Common),
    (PathType::Start, PathType::ExtensionOld),
    (PathType::Start, PathType::ExtensionNew),
    // Common -> Anything
    (PathType::Common, PathType::Common),
    (PathType::Common, PathType::ExtensionOld),
    (PathType::Common, PathType::ExtensionNew),
    (PathType::Common, PathType::Start),
    // ExtensionOld -> ExtensionOld or Start
    (PathType::ExtensionOld, PathType::ExtensionOld),
    (PathType::ExtensionOld, PathType::Start),
    // ExtensionNew -> ExtensionNew or Start
    (PathType::ExtensionNew, PathType::ExtensionNew),
    (PathType::ExtensionNew, PathType::Start),
];

// you should have this take in segment as well.....
fn forward_transitions() -> HashMap<PathType, Vec<PathType>> {
    let mut map = HashMap::new();
    for variant in PathType::iter() {
        map.insert(variant, vec![]);
    }
    for (source, sink) in PATH_TRANSITIONS {
        map.get_mut(&source).unwrap().push(sink);
    }
    map
}

// there are additional requirements on when this transition can change?
// e.g. common -> noncommon can only happen when segment is AccountTrie, AccountLeaf0,
pub fn backward_transitions() -> HashMap<PathType, Vec<PathType>> {
    let mut map = HashMap::new();
    for variant in PathType::iter() {
        map.insert(variant, vec![]);
    }
    for (source, sink) in PATH_TRANSITIONS {
        map.get_mut(&sink).unwrap().push(source);
    }
    map
}
