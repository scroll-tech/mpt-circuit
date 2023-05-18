use crate::serde::{SMTTrace, StateData};
use crate::types::trie::TrieRows;
use crate::util::{fr, hash, u256_from_hex, u256_hi_lo};
use ethers_core::types::U256;
use halo2_proofs::{arithmetic::FieldExt, halo2curves::bn256::Fr};

#[derive(Clone, Debug)]
pub enum StorageProof {
    Root(Fr),
    Update {
        path: Fr,
        trie_rows: TrieRows,
        old_leaf: StorageLeaf,
        new_leaf: StorageLeaf,
    },
}

#[derive(Clone, Debug)]
pub enum StorageLeaf {
    Empty,
    Leaf { key: U256, value_hash: Fr },
    Entry { key: U256, value: U256 },
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

    pub fn poseidon_lookups(&self) -> Vec<(Fr, Fr, Fr)> {
        match self {
            Self::Root(_) => vec![],
            Self::Update {
                trie_rows,
                old_leaf,
                new_leaf,
                ..
            } => {
                let mut lookups = trie_rows.poseidon_lookups();
                match (old_leaf.value().is_zero(), new_leaf.value().is_zero()) {
                    (true, true) => {
                        unimplemented!()
                    }
                    (true, false) => {
                        unimplemented!()
                    }
                    (false, true) => {
                        unimplemented!()
                    }
                    (false, false) => {
                        assert_eq!(old_leaf.key(), new_leaf.key());
                        lookups.push((old_leaf.key_high(), old_leaf.key_low(), old_leaf.path()));
                        lookups.push((Fr::one(), old_leaf.path(), old_leaf.path_hash()));
                        lookups.push((
                            old_leaf.value_high(),
                            old_leaf.value_low(),
                            old_leaf.value_hash(),
                        ));
                        lookups.push((
                            new_leaf.value_high(),
                            new_leaf.value_low(),
                            new_leaf.value_hash(),
                        ));
                    }
                }
                lookups
            }
        }
    }

    pub fn key_bit_lookups(&self) -> Vec<(Fr, usize, bool)> {
        match self {
            Self::Root(_) => vec![],
            Self::Update {
                path, trie_rows, ..
            } => trie_rows.key_bit_lookups(*path),
        }
    }
}

impl StorageLeaf {
    fn n_rows(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Leaf { .. } | Self::Entry { .. } => 1,
        }
    }

    pub fn key(&self) -> U256 {
        match self {
            Self::Empty => U256::zero(),
            Self::Leaf { key, .. } | Self::Entry { key, .. } => *key,
        }
    }

    pub fn key_high(&self) -> Fr {
        match self {
            Self::Empty => Fr::zero(),
            Self::Leaf { key, .. } | Self::Entry { key, .. } => Fr::from_u128(u256_hi_lo(&key).0),
        }
    }

    pub fn key_low(&self) -> Fr {
        match self {
            Self::Empty => Fr::zero(),
            Self::Leaf { key, .. } | Self::Entry { key, .. } => Fr::from_u128(u256_hi_lo(&key).1),
        }
    }

    pub fn path(&self) -> Fr {
        hash(self.key_high(), self.key_low())
    }

    pub fn path_hash(&self) -> Fr {
        hash(Fr::one(), self.path())
    }

    pub fn value(&self) -> U256 {
        match self {
            Self::Empty | Self::Leaf { .. } => U256::zero(),
            Self::Entry { value, .. } => *value,
        }
    }

    pub fn value_high(&self) -> Fr {
        match self {
            Self::Empty | Self::Leaf { .. } => Fr::zero(),
            Self::Entry { value, .. } => Fr::from_u128(u256_hi_lo(&value).0),
        }
    }

    pub fn value_low(&self) -> Fr {
        match self {
            Self::Empty | Self::Leaf { .. } => Fr::zero(),
            Self::Entry { value, .. } => Fr::from_u128(u256_hi_lo(&value).1),
        }
    }

    pub fn value_hash(&self) -> Fr {
        hash(self.value_high(), self.value_low())
    }

    pub fn hash(&self) -> Fr {
        hash(self.path_hash(), self.value_hash())
    }
}

impl From<&SMTTrace> for StorageProof {
    fn from(trace: &SMTTrace) -> Self {
        if let Some(root) = trace.common_state_root {
            return Self::Root(fr(root));
        }
        let path = fr(trace.state_key.unwrap());
        let [old_path, new_path] = &trace.state_path;
        let trie_rows = TrieRows::new(
            path,
            &old_path.as_ref().unwrap().path,
            &new_path.as_ref().unwrap().path,
        );

        let [old_leaf, new_leaf] = trace
            .state_update
            .unwrap()
            .map(|data| StorageLeaf::from(&data.unwrap()));

        let storage_proof = Self::Update {
            path,
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

// TODOOOOOO
impl From<&StateData> for StorageLeaf {
    fn from(data: &StateData) -> Self {
        Self::Entry {
            key: u256_from_hex(data.key),
            value: u256_from_hex(data.value),
        }
    }
}
