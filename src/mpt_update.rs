pub struct MptUpdate {

}


pub struct MptUpdateRow {
	lookup: MptUpdateLookup,

	segment: SegmentType,
	path: PathType,

	old_hash: Fr,
	new_hash: Fr,
	sibling: Fr,

	direction: bool,


}


pub struct MptUpdateLookup {
	proof_type: MPTProofType,
	address: Address,
	storage_key: Word,
	old_root: Fr,
	new_root: Fr,
	old_value: Word,
	new_Value: Word,
}
