pub trait LeafNode {
	fn path(&self) => Fr;
}

enum LeafProof<T> {
	Existing(T),
	EmptyType1 {
		path: Fr,
		leaf_hash: Fr,
	},
	EmptyType2 {
		path: Fr,
	}
}

impl<T: LeafNode> LeafProof<T> {
	pub fn path(&self) -> Fr {
		match self {
			EmptyType1 {path, ..} => path,
			Type2{}
		}
	}
}
