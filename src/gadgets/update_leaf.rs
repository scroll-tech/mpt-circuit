struct StateRootUpdateGadget {
    selector: SelectorColumn, // always enabled selector for constraints we want always enabled.

    // Lookup columns
    depth: AdviceColumn,
    key: AdviceColumn,
    old: AdviceColumn, // hash of the subtree at the current depth. when depth = 0, this is the state root
    new: AdviceColumn,
    sibling: AdviceColumn, // hash of the common sibling subtree



    index: FixedColumn,  // (0..32).repeat()
    byte: AdviceColumn,  // we need to prove that bytes form the canonical representation of value.

    // Witness columns
    index_is_zero: SelectorColumn, // (0..32).repeat().map(|i| i == 0)
    modulus_byte: FixedColumn,     // (0..32).repeat().map(|i| Fr::MODULUS.to_le_bytes()[i])
    difference: AdviceColumn,      // modulus_byte - byte
    difference_is_zero: IsZeroColumn,
    differences_are_zero_so_far: AdviceColumn, // difference[0] ... difference[index - 1] are all 0.

    byte_lookup: FixedColumn,
}


struct CommonPathGadget {
	depth: AdviceColumn,
    key: AdviceColumn,
    old: AdviceColumn,
    new: AdviceColumn,
    sibling: AdviceColumn,
}

struct ExtensionPathGadget {
	depth: AdviceColumn,
	key: AdviceColumn,
	left: AdviceColumn,
	right: AdviceColumn,
}


// To prove an mpt update:
	// lookup commonpath
	// either root is 0
	// key, old_root, old_value, new_root, new_value in rootupdategadget
	// old value, new value correspond to Extension path | Account | EmptyAccountWitness
	// at most one of old value, new value is Extension
	// new value corresponds to Extention path | Account |
//

// (old root, new root) (old leaf hash new leaf hash) - for common path
// (old leaf hash, new leaf hash) (old ) for extension path
//
