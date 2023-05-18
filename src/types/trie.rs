use crate::{
    gadgets::mpt_update::PathType,
    serde::SMTNode,
    util::{fr, hash, Bit},
};
use halo2_proofs::halo2curves::bn256::Fr;
use itertools::{EitherOrBoth, Itertools};

#[derive(Clone, Debug)]
pub struct TrieRow {
    pub old: Fr,
    pub new: Fr,
    pub sibling: Fr,
    pub direction: bool,
    pub path_type: PathType,
}

#[derive(Clone, Debug)]
pub struct TrieRows(pub Vec<TrieRow>);

impl TrieRow {
    pub fn old_hash(&self) -> Fr {
        if let PathType::ExtensionNew = self.path_type {
            self.old
        } else if self.direction {
            hash(self.sibling, self.old)
        } else {
            hash(self.old, self.sibling)
        }
    }
    pub fn new_hash(&self) -> Fr {
        if let PathType::ExtensionOld = self.path_type {
            self.new
        } else if self.direction {
            hash(self.sibling, self.new)
        } else {
            hash(self.new, self.sibling)
        }
    }
}

impl TrieRows {
    pub fn new(key: Fr, old_nodes: &[SMTNode], new_nodes: &[SMTNode]) -> Self {
        let [old_leaf_hash, new_leaf_hash] = [old_nodes.last(), new_nodes.last()]
            .map(|node| node.map(|x| fr(x.value)).unwrap_or_default());
        Self(
            old_nodes
                .iter()
                .zip_longest(new_nodes.iter())
                .enumerate()
                .map(|(i, pair)| {
                    let direction = key.bit(i);
                    match pair {
                        EitherOrBoth::Both(old, new) => {
                            assert_eq!(old.sibling, new.sibling);
                            TrieRow {
                                direction,
                                old: fr(old.value),
                                new: fr(new.value),
                                sibling: fr(old.sibling),
                                path_type: PathType::Common,
                            }
                        }
                        EitherOrBoth::Left(old) => TrieRow {
                            direction,
                            old: fr(old.value),
                            new: new_leaf_hash,
                            sibling: fr(old.sibling),
                            path_type: PathType::ExtensionOld,
                        },
                        EitherOrBoth::Right(new) => TrieRow {
                            direction,
                            old: old_leaf_hash,
                            new: fr(new.value),
                            sibling: fr(new.sibling),
                            path_type: PathType::ExtensionNew,
                        },
                    }
                })
                .collect(),
        )
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn poseidon_lookups(&self) -> Vec<(Fr, Fr, Fr)> {
        self.0
            .iter()
            .flat_map(|row| {
                let (old_left, old_right) = if row.direction {
                    (row.sibling, row.old)
                } else {
                    (row.old, row.sibling)
                };
                let (new_left, new_right) = if row.direction {
                    (row.sibling, row.new)
                } else {
                    (row.new, row.sibling)
                };
                let old = (old_left, old_right, hash(old_left, old_right));
                let new = (new_left, new_right, hash(new_left, new_right));
                match row.path_type {
                    PathType::Start => vec![],
                    PathType::Common => vec![old, new],
                    PathType::ExtensionOld => vec![old],
                    PathType::ExtensionNew => vec![new],
                }
            })
            .collect()
    }

    pub fn key_bit_lookups(&self, path: Fr) -> Vec<(Fr, usize, bool)> {
        let mut lookups = vec![];
        for (i, row) in self.0.iter().enumerate() {
            match row.path_type {
                PathType::Start => (),
                PathType::Common | PathType::ExtensionOld | PathType::ExtensionNew => {
                    lookups.push((path, i, row.direction));
                }
            }
        }
        lookups
    }

    pub fn old_root(&self) -> Fr {
        self.0.first().map_or_else(Fr::zero, TrieRow::old_hash)
    }

    pub fn new_root(&self) -> Fr {
        self.0.first().map_or_else(Fr::zero, TrieRow::new_hash)
    }
}
