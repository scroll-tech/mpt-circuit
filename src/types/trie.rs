use crate::{
    gadgets::mpt_update::PathType,
    serde::SMTNode,
    types::HashDomain,
    util::{check_domain_consistency, domain_hash, fr, Bit},
};
use halo2_proofs::halo2curves::bn256::Fr;
use itertools::{EitherOrBoth, Itertools};

#[derive(Clone, Debug)]
pub struct TrieRow {
    domain: HashDomain,
    pub old: Fr,
    pub new: Fr,
    pub sibling: Fr,
    pub direction: bool,
    pub path_type: PathType,
}

#[allow(clippy::len_without_is_empty)]
#[derive(Clone, Debug)]
pub struct TrieRows(pub Vec<TrieRow>);

impl TrieRow {
    pub fn old_hash(&self) -> Fr {
        if let PathType::ExtensionNew = self.path_type {
            self.old
        } else if self.direction {
            domain_hash(self.sibling, self.old, self.domain)
        } else {
            domain_hash(self.old, self.sibling, self.domain)
        }
    }
    pub fn new_hash(&self) -> Fr {
        if let PathType::ExtensionOld = self.path_type {
            self.new
        } else if self.direction {
            domain_hash(self.sibling, self.new, self.domain)
        } else {
            domain_hash(self.new, self.sibling, self.domain)
        }
    }
}

impl TrieRows {
    pub fn new(
        key: Fr,
        old_nodes: &[SMTNode],
        new_nodes: &[SMTNode],
        old_leaf: Option<SMTNode>,
        new_leaf: Option<SMTNode>,
    ) -> Self {
        let old_leaf_hash = old_nodes
            .last()
            .map(|node| fr(node.value))
            .unwrap_or_else(|| old_leaf.map(leaf_hash).unwrap_or_default());
        let new_leaf_hash = new_nodes
            .last()
            .map(|node| fr(node.value))
            .unwrap_or_else(|| new_leaf.map(leaf_hash).unwrap_or_default());
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

                            let old_domain = HashDomain::try_from(old.node_type).unwrap();
                            let new_domain = HashDomain::try_from(new.node_type).unwrap();
                            let domain = if old_domain != new_domain {
                                // This can only happen when inserting or deleting a node.
                                assert!(old_nodes.len() != new_nodes.len());
                                assert!(i == std::cmp::min(old_nodes.len(), new_nodes.len()) - 1);

                                if i == old_nodes.len() - 1 {
                                    // Inserting a leaf, so old is before insertion, new is after insertion.
                                    check_domain_consistency(old_domain, new_domain, direction);
                                    old_domain
                                } else {
                                    // Deleting a leaf, so new is after insertion, old is before insertion.
                                    check_domain_consistency(new_domain, old_domain, direction);
                                    new_domain
                                }
                            } else {
                                old_domain
                            };

                            TrieRow {
                                domain,
                                direction,
                                old: fr(old.value),
                                new: fr(new.value),
                                sibling: fr(old.sibling),
                                path_type: PathType::Common,
                            }
                        }
                        EitherOrBoth::Left(old) => TrieRow {
                            domain: HashDomain::try_from(old.node_type).unwrap(),
                            direction,
                            old: fr(old.value),
                            new: new_leaf_hash,
                            sibling: fr(old.sibling),
                            path_type: PathType::ExtensionOld,
                        },
                        EitherOrBoth::Right(new) => TrieRow {
                            domain: HashDomain::try_from(new.node_type).unwrap(),
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
                let old = (
                    old_left,
                    old_right,
                    domain_hash(old_left, old_right, row.domain),
                );
                let new = (
                    new_left,
                    new_right,
                    domain_hash(new_left, new_right, row.domain),
                );
                match row.path_type {
                    PathType::Start => vec![],
                    PathType::Common => vec![old, new],
                    PathType::ExtensionOld => vec![old],
                    PathType::ExtensionNew => vec![new],
                }
            })
            .collect()
    }

    pub fn key_bit_lookups(&self, key: Fr, other_key: Fr) -> Vec<(Fr, usize, bool)> {
        let mut lookups = vec![];
        for (i, row) in self.0.iter().enumerate() {
            match row.path_type {
                PathType::Start => (),
                PathType::Common => {
                    lookups.push((key, i, row.direction));
                    lookups.push((other_key, i, row.direction));
                }
                PathType::ExtensionOld | PathType::ExtensionNew => {
                    lookups.push((key, i, row.direction));
                }
            }
        }
        lookups
    }

    pub fn old_root(&self, leaf_hash: impl FnOnce() -> Fr) -> Fr {
        self.0.first().map_or_else(leaf_hash, TrieRow::old_hash)
    }

    pub fn new_root(&self, leaf_hash: impl FnOnce() -> Fr) -> Fr {
        self.0.first().map_or_else(leaf_hash, TrieRow::new_hash)
    }

    #[cfg(test)]
    pub fn check(&self, old_root: Fr, new_root: Fr) {
        for (i, row) in self.0.iter().enumerate() {
            let [[old_left, old_right], [new_left, new_right]] = if row.direction {
                [[row.sibling, row.old], [row.sibling, row.new]]
            } else {
                [[row.old, row.sibling], [row.new, row.sibling]]
            };

            let [expected_old_hash, expected_new_hash] = if i == 0 {
                [old_root, new_root]
            } else {
                let previous_row = self.0.get(i - 1).unwrap();
                [previous_row.old, previous_row.new]
            };

            match row.path_type {
                PathType::Start => unreachable!(),
                PathType::Common => {
                    let [old_domain, new_domain] = if let Some(next_row) = self.0.get(i + 1) {
                        match next_row.path_type {
                            PathType::Start => unreachable!(),
                            PathType::Common => [row.domain, row.domain],
                            PathType::ExtensionOld => unreachable!(),
                            PathType::ExtensionNew => {
                                match row.domain {
                                    HashDomain::NodeTypeBranch0 => unreachable!(),
                                    HashDomain::NodeTypeBranch1 => [HashDomain::NodeTypeBranch1, HashDomain::NodeTypeBranch3],
                                    HashDomain::NodeTypeBranch2 => unreachable!(),
                                    HashDomain::NodeTypeBranch3 => unreachable!(),
                                    _ => unreachable!(),
                                }
                            },
                        }
                    } else {
                        [row.domain, row.domain]
                    };
                    assert_eq!(
                        domain_hash(old_left, old_right, old_domain),
                        expected_old_hash
                    );
                    assert_eq!(
                        domain_hash(new_left, new_right, new_domain),
                        expected_new_hash
                    );
                }
                PathType::ExtensionOld => {
                    self.0
                        .get(i + 1)
                        .map(|row| assert_eq!(row.path_type, PathType::ExtensionOld));
                    assert_eq!(
                        domain_hash(old_left, old_right, row.domain),
                        expected_old_hash
                    );
                }
                PathType::ExtensionNew => {
                    self.0
                        .get(i + 1)
                        .map(|row| assert_eq!(row.path_type, PathType::ExtensionNew));
                    assert_eq!(
                        domain_hash(new_left, new_right, row.domain),
                        expected_new_hash
                    );
                }
            }
        }
    }
}

fn leaf_hash(leaf: SMTNode) -> Fr {
    domain_hash(fr(leaf.sibling), fr(leaf.value), HashDomain::NodeTypeEmpty)
}
