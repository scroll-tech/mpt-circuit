use crate::types::{storage::StorageProof, trie::TrieRows};
use ethers_core::types::{Address, U256};
use halo2_proofs::halo2curves::bn256::Fr;

#[derive(Clone, Debug)]
pub struct AccountProof {
    key: Fr,
    trie_rows: TrieRows,
    old_leaf: AccountLeaf,
    new_leaf: AccountLeaf,
}

#[derive(Clone, Debug)]
pub enum AccountLeaf {
    Empty {
        key: Fr,
    },
    Leaf {
        key: Fr,
        account_hash: Fr,
    },
    Account {
        address: Address,
        data: AccountData,
        storage: StorageProof,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct AccountData {
    balance: U256,
    keccak_codehash: U256,
    poseidon_codehash: Fr,
    code_size: u64,
    nonce: u64,
}
