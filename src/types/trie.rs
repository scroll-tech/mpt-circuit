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
    pub domain: HashDomain,
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
    fn old_hash(&self, next_path_type: Option<PathType>) -> Fr {
        let [domain, _] = self.hash_domains(next_path_type);
        if let PathType::ExtensionNew = self.path_type {
            self.old
        } else if self.direction {
            domain_hash(self.sibling, self.old, domain)
        } else {
            domain_hash(self.old, self.sibling, domain)
        }
    }
    fn new_hash(&self, next_path_type: Option<PathType>) -> Fr {
        let [_, domain] = self.hash_domains(next_path_type);
        if let PathType::ExtensionOld = self.path_type {
            self.new
        } else if self.direction {
            domain_hash(self.sibling, self.new, domain)
        } else {
            domain_hash(self.new, self.sibling, domain)
        }
    }

    fn hash_domains(&self, next_path_type: Option<PathType>) -> [HashDomain; 2] {
        if self.path_type == PathType::Common
            && matches!(
                next_path_type,
                Some(PathType::ExtensionNew) | Some(PathType::ExtensionOld)
            )
        {
            get_domains(next_path_type.unwrap(), self.domain, self.direction)
        } else {
            [self.domain, self.domain]
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

    pub fn poseidon_lookups(&self) -> Vec<(Fr, Fr, HashDomain, Fr)> {
        let mut lookups = vec![];
        for (i, row) in self.0.iter().enumerate() {
            let [[old_left, old_right], [new_left, new_right]] = if row.direction {
                [[row.sibling, row.old], [row.sibling, row.new]]
            } else {
                [[row.old, row.sibling], [row.new, row.sibling]]
            };

            match row.path_type {
                PathType::Start => unreachable!(),
                PathType::Common => {
                    let [old_domain, new_domain] = if let Some(next_row) = self.0.get(i + 1) {
                        get_domains(next_row.path_type, row.domain, row.direction)
                    } else {
                        [row.domain, row.domain]
                    };
                    lookups.push((
                        old_left,
                        old_right,
                        old_domain,
                        domain_hash(old_left, old_right, old_domain),
                    ));
                    lookups.push((
                        new_left,
                        new_right,
                        new_domain,
                        domain_hash(new_left, new_right, new_domain),
                    ));
                }
                PathType::ExtensionOld => {
                    lookups.push((
                        old_left,
                        old_right,
                        row.domain,
                        domain_hash(old_left, old_right, row.domain),
                    ));
                }
                PathType::ExtensionNew => {
                    lookups.push((
                        new_left,
                        new_right,
                        row.domain,
                        domain_hash(new_left, new_right, row.domain),
                    ));
                }
            }
        }
        lookups
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
        let next_path_type = self.0.get(1).map(|row| row.path_type);
        self.0
            .first()
            .map_or_else(leaf_hash, |row| row.old_hash(next_path_type))
    }

    pub fn new_root(&self, leaf_hash: impl FnOnce() -> Fr) -> Fr {
        let next_path_type = self.0.get(1).map(|row| row.path_type);
        self.0
            .first()
            .map_or_else(leaf_hash, |row| row.new_hash(next_path_type))
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
                        get_domains(next_row.path_type, row.domain, row.direction)
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

pub fn next_domain(before_insertion_domain: HashDomain, insertion_direction: bool) -> HashDomain {
    match before_insertion_domain {
        HashDomain::Branch0 => {
            if insertion_direction {
                HashDomain::Branch1
            } else {
                HashDomain::Branch2
            }
        }
        HashDomain::Branch1 | HashDomain::Branch2 => HashDomain::Branch3,
        HashDomain::Branch3 => unreachable!(),
        _ => unreachable!(),
    }
}

fn get_domains(
    next_path_type: PathType,
    before_insertion_domain: HashDomain,
    insertion_direction: bool,
) -> [HashDomain; 2] {
    let mut domains = match next_path_type {
        PathType::Start => unreachable!(),
        PathType::Common => [before_insertion_domain, before_insertion_domain],
        PathType::ExtensionOld | PathType::ExtensionNew => [
            before_insertion_domain,
            next_domain(before_insertion_domain, insertion_direction),
        ],
    };
    if next_path_type == PathType::ExtensionOld {
        domains.reverse();
    }
    domains
}

fn leaf_hash(leaf: SMTNode) -> Fr {
    domain_hash(fr(leaf.sibling), fr(leaf.value), HashDomain::Leaf)
}
