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
        old_entry: StorageEntry,
        new_entry: StorageEntry,
    },
}

#[derive(Clone, Debug)]
pub struct StorageEntry {
    pub key: U256,
    pub value: U256,
}

impl StorageProof {
    pub fn n_rows(&self) -> usize {
        match self {
            Self::Root(_) => 0,
            Self::Update {
                trie_rows,
                old_entry,
                new_entry,
                ..
            } => {
                trie_rows.len()
                    + usize::from(!old_entry.value.is_zero() || !new_entry.value.is_zero())
            }
        }
    }
    pub fn old_root(&self) -> Fr {
        match self {
            Self::Root(root) => *root,
            Self::Update { trie_rows, .. } => trie_rows.old_root(),
        }
    }
    pub fn new_root(&self) -> Fr {
        match self {
            Self::Root(root) => *root,
            Self::Update { trie_rows, .. } => trie_rows.new_root(),
        }
    }
    pub fn sanity_check(&self) {}

    pub fn poseidon_lookups(&self) -> Vec<(Fr, Fr, Fr)> {
        match self {
            Self::Root(_) => vec![],
            Self::Update {
                trie_rows,
                old_entry,
                new_entry,
                ..
            } => {
                let mut lookups = trie_rows.poseidon_lookups();
                match (old_entry.value.is_zero(), new_entry.value.is_zero()) {
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
                        assert_eq!(old_entry.key, new_entry.key);
                        lookups.push((old_entry.key_high(), old_entry.key_low(), old_entry.path()));
                        lookups.push((Fr::one(), old_entry.path(), old_entry.path_hash()));
                        lookups.push((
                            old_entry.value_high(),
                            old_entry.value_low(),
                            old_entry.value_hash(),
                        ));
                        lookups.push((
                            new_entry.value_high(),
                            new_entry.value_low(),
                            new_entry.value_hash(),
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
                path,
                trie_rows,
                old_entry,
                new_entry,
                ..
            } => trie_rows.key_bit_lookups(*path),
        }
    }
}

impl StorageEntry {
    pub fn key_high(&self) -> Fr {
        Fr::from_u128(u256_hi_lo(&self.key).0)
    }

    pub fn key_low(&self) -> Fr {
        Fr::from_u128(u256_hi_lo(&self.key).1)
    }

    pub fn path(&self) -> Fr {
        hash(self.key_high(), self.key_low())
    }

    pub fn path_hash(&self) -> Fr {
        hash(Fr::one(), self.path())
    }

    pub fn value_high(&self) -> Fr {
        Fr::from_u128(u256_hi_lo(&self.value).0)
    }

    pub fn value_low(&self) -> Fr {
        Fr::from_u128(u256_hi_lo(&self.value).1)
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

        assert_eq!(trie_rows.old_root(), fr(old_path.as_ref().unwrap().root));
        assert_eq!(trie_rows.new_root(), fr(new_path.as_ref().unwrap().root));

        let [old_entry, new_entry] = trace
            .state_update
            .unwrap()
            .map(|data| StorageEntry::from(&data.unwrap()));
        Self::Update {
            path,
            trie_rows,
            old_entry,
            new_entry,
        }
    }
}

// TODO: think carefully about should (0, 0) be None or (0, 0)
impl From<&StateData> for StorageEntry {
    fn from(data: &StateData) -> Self {
        Self {
            key: u256_from_hex(data.key),
            value: u256_from_hex(data.value),
        }
    }
}
