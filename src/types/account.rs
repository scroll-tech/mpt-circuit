use crate::{
    serde::{AccountData as SerdeAccountData, SMTNode, SMTTrace},
    types::{storage::StorageProof, trie::TrieRows},
    util::{account_key, fr, fr_from_biguint, hash, split_word, u256_from_biguint},
};
use ethers_core::types::{Address, U256};
use halo2_proofs::halo2curves::bn256::Fr;

#[derive(Clone, Debug)]
pub struct AccountProof {
    account_key: Fr,
    trie_rows: TrieRows,
    old_leaf: AccountLeaf,
    new_leaf: AccountLeaf,
    storage: StorageProof,
}

#[derive(Clone, Debug)]
pub enum AccountLeaf {
    Empty {
        account_key: Fr,
    },
    Leaf {
        account_key: Fr,
        account_hash: Fr,
    },
    Account {
        address: Address,
        account_data: AccountData,
    },
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AccountData {
    balance: Fr, // We assume that all account balances can fit into 1 field element.
    keccak_codehash: U256,
    poseidon_codehash: Fr,
    code_size: u64,
    nonce: u64,
}

impl AccountData {
    fn hash(&self, storage_root: Fr) -> Fr {
        hash(
            self.poseidon_codehash_sibling(storage_root),
            self.poseidon_codehash,
        )
    }

    fn packed_nonce_and_codesize(&self) -> Fr {
        Fr::from(self.nonce) + Fr::from(self.code_size) * Fr::from(1 << 32).square()
    }

    fn hashed_nonce_codesize_balance(&self) -> Fr {
        hash(self.packed_nonce_and_codesize(), self.balance)
    }

    fn hashed_keccak_codehash(&self) -> Fr {
        let (high, low) = split_word(self.keccak_codehash);
        hash(high, low)
    }

    fn hashed_storage_root_keccak_codehash(&self, storage_root: Fr) -> Fr {
        hash(storage_root, self.hashed_keccak_codehash())
    }

    fn poseidon_codehash_sibling(&self, storage_root: Fr) -> Fr {
        hash(
            self.hashed_nonce_codesize_balance(),
            self.hashed_storage_root_keccak_codehash(storage_root),
        )
    }
}

impl AccountProof {
    pub fn old_root(&self) -> Fr {
        self.trie_rows
            .old_root(|| self.old_leaf.hash(self.storage.new_root()))
    }

    pub fn new_root(&self) -> Fr {
        self.trie_rows
            .new_root(|| self.new_leaf.hash(self.storage.old_root()))
    }
}

impl AccountLeaf {
    fn new(address: Address, node: &Option<SMTNode>, data: &Option<SerdeAccountData>) -> Self {
        let account_key = account_key(address);
        match (node, data) {
            (None, None) => Self::Empty { account_key },
            (Some(node), Some(data)) => {
                assert_eq!(account_key, fr(node.sibling));
                Self::Account {
                    address,
                    account_data: AccountData {
                        balance: fr_from_biguint(&data.balance),
                        keccak_codehash: u256_from_biguint(&data.code_hash),
                        poseidon_codehash: fr_from_biguint(&data.poseidon_code_hash),
                        code_size: data.code_size,
                        nonce: data.nonce,
                    },
                }
            }
            (Some(node), None) => {
                assert_eq!(account_key, fr(node.sibling));
                Self::Leaf {
                    account_key,
                    account_hash: fr(node.value),
                }
            }
            (None, Some(_)) => {
                unreachable!();
            }
        }
    }

    fn hash(&self, storage_root: Fr) -> Fr {
        match self {
            Self::Empty { .. } => Fr::zero(),
            Self::Leaf {
                account_key,
                account_hash,
            } => hash(hash(Fr::one(), *account_key), *account_hash),
            Self::Account {
                address,
                account_data,
            } => hash(
                hash(Fr::one(), account_key(*address)),
                account_data.hash(storage_root),
            ),
        }
    }
}

impl From<&SMTTrace> for AccountProof {
    fn from(trace: &SMTTrace) -> Self {
        let address = Address::from(trace.address.0);

        let [old_path, new_path] = &trace.account_path;
        let old_leaf = old_path.leaf;
        let new_leaf = new_path.leaf;
        let trie_rows = TrieRows::new(
            account_key(address),
            &new_path.path,
            &new_path.path,
            old_path.leaf,
            new_path.leaf,
        );

        let [old_entry, new_entry] = &trace.account_update;
        let old_leaf = AccountLeaf::new(address, &old_leaf, &old_entry);
        let new_leaf = AccountLeaf::new(address, &new_leaf, &new_entry);

        let account_proof = Self {
            account_key: account_key(address),
            trie_rows,
            old_leaf,
            new_leaf,
            storage: StorageProof::from(trace),
        };
        assert_eq!(account_proof.old_root(), fr(old_path.root));
        assert_eq!(account_proof.new_root(), fr(new_path.root));
        account_proof
    }
}
