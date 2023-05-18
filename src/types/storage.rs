use crate::{
    serde::{SMTTrace, StateData},
    types::trie::TrieRows,
    util::{fr, hash, storage_key_hash, u256_from_hex, u256_hi_lo},
};
use ethers_core::types::U256;
use halo2_proofs::{arithmetic::FieldExt, halo2curves::bn256::Fr};

#[derive(Clone, Debug)]
pub enum StorageProof {
    Root(Fr), // Not proving a storage update, so we only need the storage root.
    Update {
        path: Fr,
        trie_rows: TrieRows,
        old_leaf: StorageLeaf,
        new_leaf: StorageLeaf,
    },
}

#[derive(Clone, Debug)]
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
                lookups.extend(old_leaf.poseidon_lookups());
                lookups.extend(new_leaf.poseidon_lookups());
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
            Self::Empty { .. } => 0,
            Self::Leaf { .. } | Self::Entry { .. } => 1,
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

    pub fn key_hash(&self) -> Fr {
        hash(Fr::one(), self.key())
    }

    pub fn value(&self) -> U256 {
        match self {
            Self::Empty { .. } | Self::Leaf { .. } => U256::zero(),
            Self::Entry { value, .. } => *value,
        }
    }

    pub fn value_high(&self) -> Fr {
        Fr::from_u128(u256_hi_lo(&self.value()).0)
    }

    pub fn value_low(&self) -> Fr {
        Fr::from_u128(u256_hi_lo(&self.value()).1)
    }

    pub fn value_hash(&self) -> Fr {
        hash(self.value_high(), self.value_low())
    }

    pub fn hash(&self) -> Fr {
        hash(self.key_hash(), self.value_hash())
    }

    fn poseidon_lookups(&self) -> Vec<(Fr, Fr, Fr)> {
        let mut lookups = vec![(Fr::one(), self.key(), self.key_hash())];
        if let Self::Entry { storage_key, value } = self {
            let (key_high, key_low) = u256_hi_lo(storage_key);
            lookups.extend(vec![
                (Fr::from_u128(key_high), Fr::from_u128(key_low), self.key()),
                (self.value_high(), self.value_low(), self.value_hash()),
            ]);
        }
        lookups
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
            storage_key: u256_from_hex(data.key),
            value: u256_from_hex(data.value),
        }
    }
}
