#[cfg(test)]
use crate::types::{Bit, PathType};
use crate::{
    serde::{SMTNode, SMTTrace, StateData},
    types::{trie::TrieRows, HashDomain},
    util::{domain_hash, fr, storage_key_hash, u256_from_hex, u256_hi_lo},
};
use ethers_core::types::U256;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::halo2curves::ff::PrimeField;

#[derive(Clone, Debug)]
pub enum StorageProof {
    Root(Fr), // Not proving a storage update, so we only need the storage root.
    Update {
        storage_key: U256,
        key: Fr,
        trie_rows: TrieRows,
        old_leaf: StorageLeaf,
        new_leaf: StorageLeaf,
    },
}

#[derive(Clone, Copy, Debug)]
pub enum StorageLeaf {
    Empty { mpt_key: Fr },                    // Type 2 empty storage leaf
    Leaf { mpt_key: Fr, value_hash: Fr },     // Type 1 empty storage leaf
    Entry { storage_key: U256, value: U256 }, // Existing storage leaf (value is non-zero)
}

impl StorageProof {
    pub fn n_rows(&self) -> usize {
        match self {
            Self::Root(_) => 0,
            Self::Update {
                trie_rows,
                old_leaf,
                new_leaf,
                ..
            } => trie_rows.len() + std::cmp::max(old_leaf.n_rows(), new_leaf.n_rows()),
        }
    }

    pub fn old_root(&self) -> Fr {
        match self {
            Self::Root(root) => *root,
            Self::Update {
                trie_rows,
                old_leaf,
                ..
            } => trie_rows.old_root(|| old_leaf.hash()),
        }
    }

    pub fn new_root(&self) -> Fr {
        match self {
            Self::Root(root) => *root,
            Self::Update {
                trie_rows,
                new_leaf,
                ..
            } => trie_rows.new_root(|| new_leaf.hash()),
        }
    }

    pub fn poseidon_lookups(&self) -> Vec<(Fr, Fr, HashDomain, Fr)> {
        match self {
            Self::Root(_) => vec![],
            Self::Update {
                storage_key,
                key,
                trie_rows,
                old_leaf,
                new_leaf,
                ..
            } => {
                let (key_high, key_low) = u256_hi_lo(storage_key);
                let mut lookups = vec![(
                    Fr::from_u128(key_high),
                    Fr::from_u128(key_low),
                    HashDomain::Pair,
                    *key,
                )];
                lookups.extend(trie_rows.poseidon_lookups());
                lookups.extend(old_leaf.poseidon_lookups());
                lookups.extend(new_leaf.poseidon_lookups());
                lookups
            }
        }
    }

    pub fn key_lookups(&self) -> Vec<Fr> {
        match self {
            Self::Root(_) => vec![],
            Self::Update { .. } => {
                vec![self.key(), self.other_key()]
            }
        }
    }

    pub fn key_bit_lookups(&self) -> Vec<(Fr, usize, bool)> {
        match self {
            Self::Root(_) => vec![],
            Self::Update { trie_rows, .. } => {
                trie_rows.key_bit_lookups(self.key(), self.other_key())
            }
        }
    }

    pub fn key(&self) -> Fr {
        match self {
            Self::Root(_) => unreachable!(),
            Self::Update { key, .. } => *key,
        }
    }

    pub fn other_key(&self) -> Fr {
        match self {
            Self::Root(_) => unreachable!(),
            Self::Update {
                key,
                old_leaf,
                new_leaf,
                ..
            } => {
                let old_key = old_leaf.key();
                let new_key = new_leaf.key();
                if *key == old_key {
                    new_key
                } else {
                    old_key
                }
            }
        }
    }

    #[cfg(test)]
    pub fn check(&self) {
        if let Self::Update {
            trie_rows,
            old_leaf,
            new_leaf,
            ..
        } = self
        {
            // Check that trie rows are consistent and produce claimed roots.
            trie_rows.check(self.old_root(), self.new_root());

            // Check that directions match old and new keys.
            for (i, row) in trie_rows.0.iter().enumerate() {
                let old_key = old_leaf.key();
                let new_key = new_leaf.key();
                match row.path_type {
                    PathType::Start => unreachable!(),
                    PathType::Common => {
                        assert_eq!(row.direction, old_key.bit(i));
                        assert_eq!(row.direction, new_key.bit(i));
                    }
                    PathType::ExtensionOld => {
                        assert_eq!(row.direction, old_key.bit(i));
                    }
                    PathType::ExtensionNew => {
                        assert_eq!(row.direction, new_key.bit(i));
                    }
                }
            }

            // Check that final trie_row values match leaf hashes
            if let Some(row) = trie_rows.0.last() {
                assert_eq!(old_leaf.hash(), row.old);
                assert_eq!(new_leaf.hash(), row.new);
            }
        }
    }
}

impl StorageLeaf {
    fn new(mpt_key: Fr, node: &Option<SMTNode>, data: &StateData) -> Self {
        let value = u256_from_hex(data.value);
        match (node, value.is_zero()) {
            (None, true) => Self::Empty { mpt_key },
            (Some(node), true) => {
                assert_eq!(mpt_key, storage_key_hash(u256_from_hex(data.key)));
                Self::Leaf {
                    mpt_key: fr(node.sibling),
                    value_hash: fr(node.value),
                }
            }
            (Some(_), false) => Self::Entry {
                storage_key: u256_from_hex(data.key),
                value,
            },
            (None, false) => {
                unreachable!();
            }
        }
    }

    fn n_rows(&self) -> usize {
        match self {
            Self::Empty { .. } | Self::Leaf { .. } => 0,
            Self::Entry { .. } => 1,
        }
    }

    pub fn storage_key(&self) -> Option<U256> {
        match self {
            Self::Empty { .. } | Self::Leaf { .. } => None,
            Self::Entry { storage_key, .. } => Some(*storage_key),
        }
    }

    pub fn key(&self) -> Fr {
        match self {
            Self::Empty { mpt_key } | Self::Leaf { mpt_key, .. } => *mpt_key,
            Self::Entry { storage_key, .. } => storage_key_hash(*storage_key),
        }
    }

    // maybe make this an option?
    pub fn value(&self) -> U256 {
        match self {
            Self::Empty { .. } | Self::Leaf { .. } => U256::zero(),
            Self::Entry { value, .. } => *value,
        }
    }

    fn value_high(&self) -> Fr {
        Fr::from_u128(u256_hi_lo(&self.value()).0)
    }

    fn value_low(&self) -> Fr {
        Fr::from_u128(u256_hi_lo(&self.value()).1)
    }

    pub fn value_hash(&self) -> Fr {
        match self {
            Self::Empty { .. } => unimplemented!(),
            Self::Leaf { value_hash, .. } => *value_hash,
            Self::Entry { .. } => {
                let (high, low) = u256_hi_lo(&self.value());
                domain_hash(Fr::from_u128(high), Fr::from_u128(low), HashDomain::Pair)
            }
        }
    }

    pub fn hash(&self) -> Fr {
        if let Self::Empty { .. } = self {
            Fr::zero()
        } else {
            domain_hash(self.key(), self.value_hash(), HashDomain::Leaf)
        }
    }

    fn poseidon_lookups(&self) -> Vec<(Fr, Fr, HashDomain, Fr)> {
        match self {
            Self::Empty { .. } => vec![],
            Self::Leaf { value_hash, .. } => {
                vec![(self.key(), *value_hash, HashDomain::Leaf, self.hash())]
            }
            Self::Entry { .. } => {
                vec![
                    (
                        self.value_high(),
                        self.value_low(),
                        HashDomain::Pair,
                        self.value_hash(),
                    ),
                    (self.key(), self.value_hash(), HashDomain::Leaf, self.hash()),
                ]
            }
        }
    }
}

impl From<&SMTTrace> for StorageProof {
    fn from(trace: &SMTTrace) -> Self {
        if let Some(root) = trace.common_state_root {
            return Self::Root(fr(root));
        }
        let key = fr(trace.state_key.unwrap());
        let [old_path, new_path] = &trace.state_path;
        let old_leaf = old_path.as_ref().unwrap().leaf;
        let new_leaf = new_path.as_ref().unwrap().leaf;
        let trie_rows = TrieRows::new(
            key,
            &old_path.as_ref().unwrap().path,
            &new_path.as_ref().unwrap().path,
            old_leaf,
            new_leaf,
        );

        let [old_entry, new_entry] = trace.state_update.unwrap().map(Option::unwrap);
        assert_eq!(old_entry.key, new_entry.key);
        let storage_key = u256_from_hex(old_entry.key);
        let old_leaf = StorageLeaf::new(key, &old_leaf, &old_entry);
        let new_leaf = StorageLeaf::new(key, &new_leaf, &new_entry);

        let storage_proof = Self::Update {
            storage_key,
            key,
            trie_rows,
            old_leaf,
            new_leaf,
        };
        assert_eq!(
            storage_proof.old_root(),
            fr(old_path.as_ref().unwrap().root)
        );
        assert_eq!(
            storage_proof.new_root(),
            fr(new_path.as_ref().unwrap().root)
        );
        storage_proof
    }
}
