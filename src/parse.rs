#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter)]
enum RowType {
    Common, // Hashes for both the old and new path are being updated
    Old,    // the new hash is not changed. I.e. the new path ends in an non-existence proof.
    New,    // the old hash is not changed. I.e. the old path ends in an non-existence proof.
}

struct MptUpdate {
	account_trie: Vec<MptUpdateRow>
	account_leaf: Vec<MptUpdateRow>
	storage_trie: Vec<MptUpdateRow>
	storage_leaf: Vec<MptUpdateRow>
}

struct MptUpdateRow {
	old_hash: Fr,
	new_hash: Fr,
	sibling: Fr,

	row_type: RowType,
	direction: bool,
}
