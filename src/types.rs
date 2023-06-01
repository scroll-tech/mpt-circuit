use ethers_core::types::{Address, U256};
use halo2_proofs::{arithmetic::FieldExt, halo2curves::bn256::Fr};
use hash_circuit::hash::Hashable;
use itertools::{EitherOrBoth, Itertools};
use num_bigint::BigUint;
use num_traits::identities::Zero;

use crate::{
    // operation::{Account, SMTPathParse},
    serde::{AccountData, HexBytes, SMTNode, SMTPath, SMTTrace},
    util::{
        account_key, fr_from_biguint, rlc, u256_from_biguint, u256_from_hex, u256_to_big_endian,
    },
    MPTProofType,
};

mod account;
pub mod storage;
pub mod trie;
use storage::StorageProof;

#[derive(Clone, Copy, Debug)]
pub struct Claim {
    pub old_root: Fr,
    pub new_root: Fr,
    pub address: Address,
    pub kind: ClaimKind,
}

#[derive(Clone, Copy, Debug)]
pub enum ClaimKind {
    // TODO: remove Option's and represent type of old and new account elsewhere?
    Nonce {
        old: Option<u64>,
        new: Option<u64>,
    },
    Balance {
        old: Option<U256>,
        new: Option<U256>,
    },
    CodeHash {
        old: Option<U256>,
        new: Option<U256>,
    },
    CodeSize {
        old: Option<u64>,
        new: Option<u64>,
    },
    PoseidonCodeHash {
        old: Option<Fr>,
        new: Option<Fr>,
    },
    Storage {
        key: U256,
        old_value: Option<U256>,
        new_value: Option<U256>,
    },
    IsEmpty(Option<U256>),
}

impl Claim {
    pub fn storage_key(&self) -> U256 {
        match self.kind {
            ClaimKind::Storage { key, .. } | ClaimKind::IsEmpty(Some(key)) => key,
            _ => U256::zero(),
        }
    }

    pub fn old_value_assignment(&self, randomness: Fr) -> Fr {
        match self.kind {
            ClaimKind::Nonce { old, .. } | ClaimKind::CodeSize { old, .. } => {
                Fr::from(old.unwrap_or_default())
            }
            ClaimKind::PoseidonCodeHash { old, .. } => old.unwrap_or_default(),
            ClaimKind::Balance { old, .. } | ClaimKind::CodeHash { old, .. } => {
                rlc(&u256_to_big_endian(&old.unwrap_or_default()), randomness)
            }
            ClaimKind::Storage { old_value, .. } => rlc(
                &u256_to_big_endian(&old_value.unwrap_or_default()),
                randomness,
            ),
            ClaimKind::IsEmpty(_) => Fr::zero(),
        }
    }

    pub fn new_value_assignment(&self, randomness: Fr) -> Fr {
        match self.kind {
            ClaimKind::Nonce { new, .. } | ClaimKind::CodeSize { new, .. } => {
                Fr::from(new.unwrap_or_default())
            }
            ClaimKind::PoseidonCodeHash { new, .. } => new.unwrap_or_default(),
            ClaimKind::Balance { new, .. } | ClaimKind::CodeHash { new, .. } => {
                rlc(&u256_to_big_endian(&new.unwrap_or_default()), randomness)
            }
            ClaimKind::Storage { new_value, .. } => rlc(
                &u256_to_big_endian(&new_value.unwrap_or_default()),
                randomness,
            ),
            ClaimKind::IsEmpty(_) => Fr::zero(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct LeafNode {
    key: Fr,
    value_hash: Fr,
}

impl LeafNode {
    fn hash(&self) -> Fr {
        hash(hash(Fr::one(), self.key), self.value_hash)
    }
}

#[derive(Clone, Debug)]
pub struct Proof {
    pub claim: Claim,
    // direction, open value, close value, sibling, is_padding_open, is_padding_close
    pub address_hash_traces: Vec<(bool, Fr, Fr, Fr, bool, bool)>,

    // TODO: make this optional
    leafs: [Option<LeafNode>; 2],

    pub old_account_hash_traces: [[Fr; 3]; 7],
    pub new_account_hash_traces: [[Fr; 3]; 7],

    pub storage: StorageProof,

    pub old: Path,
    pub new: Path,

    pub old_account: Option<EthAccount>,
    pub new_account: Option<EthAccount>,
}

// TODO: rename to Account
#[derive(Clone, Copy, Debug)]
pub struct EthAccount {
    pub nonce: u64,
    pub code_size: u64,
    poseidon_codehash: Fr,
    pub balance: Fr,
    pub keccak_codehash: U256,
    pub storage_root: Fr,
}

impl From<AccountData> for EthAccount {
    fn from(account_data: AccountData) -> Self {
        Self {
            nonce: account_data.nonce,
            code_size: account_data.code_size,
            poseidon_codehash: fr_from_biguint(&account_data.poseidon_code_hash),
            balance: fr_from_biguint(&account_data.balance),
            keccak_codehash: u256_from_biguint(&account_data.code_hash),
            storage_root: Fr::zero(), // TODO: fixmeeee!!!
        }
    }
}

impl Proof {
    pub fn n_rows(&self) -> usize {
        1 + self.address_hash_traces.len()
            + match self.claim.kind {
                ClaimKind::Nonce { .. } => 4,
                ClaimKind::CodeSize { .. } => 4,
                ClaimKind::Balance { .. } => 4,
                ClaimKind::PoseidonCodeHash { .. } => 2,
                ClaimKind::CodeHash { .. } => 4,
                ClaimKind::Storage { .. } | ClaimKind::IsEmpty(Some(_)) => 4,
                ClaimKind::IsEmpty(None) => 0,
            }
            + self.storage.n_rows()
    }
}

#[derive(Clone, Debug)]
pub struct Path {
    pub key: Fr,
    pub key_hash: Fr, // Hash(1, key) for type 0 and type 1, 0 for type 2.
    pub leaf_data_hash: Option<Fr>, // leaf data hash for type 0 and type 1, None for type 2.
}

impl Path {
    pub fn hash(&self) -> Fr {
        if let Some(data_hash) = self.leaf_data_hash {
            hash(self.key_hash, data_hash)
        } else {
            Fr::zero()
        }
    }
}

impl From<(&MPTProofType, &SMTTrace)> for Claim {
    fn from((proof_type, trace): (&MPTProofType, &SMTTrace)) -> Self {
        let [old_root, new_root] = trace.account_path.clone().map(|path| fr(path.root));
        let address = trace.address.0.into();
        Self {
            new_root,
            old_root,
            address,
            kind: ClaimKind::from((proof_type, trace)),
        }
    }
}

impl From<(&MPTProofType, &SMTTrace)> for ClaimKind {
    fn from((proof_type, trace): (&MPTProofType, &SMTTrace)) -> Self {
        let [account_old, account_new] = &trace.account_update;
        let state_update = &trace.state_update;

        if let Some(update) = state_update {
            match update {
                [None, None] => (),
                [Some(old), Some(new)] => {
                    // The account must exist, because only contracts with bytecode can modify their own storage slots.
                    if !(account_old == account_new || (account_old.is_none() && account_new == &Some(Default::default()))) {
                        assert_eq!(account_old, account_new, "{:?}", state_update);
                    }
                    let old_value = u256_from_hex(old.value);
                    let new_value = u256_from_hex(new.value);

                    assert_eq!(old.key, new.key);
                    let key = u256_from_hex(old.key);
                    if old_value.is_zero() && new_value.is_zero() {
                        return ClaimKind::IsEmpty(Some(key));
                    }
                    return ClaimKind::Storage {
                        key,
                        old_value: if old_value.is_zero() {
                            None
                        } else {
                            Some(old_value)
                        },
                        new_value: if new_value.is_zero() {
                            None
                        } else {
                            Some(new_value)
                        },
                    };
                }
                [None, Some(_)] | [Some(_), None] => unreachable!(),
            }
        }

        match &trace.account_update {
            [None, None] => ClaimKind::IsEmpty(None),
            [None, Some(new)] => {
                if !new.nonce.is_zero() {
                    assert_eq!(*proof_type, MPTProofType::NonceChanged);
                    ClaimKind::Nonce {
                        old: None,
                        new: Some(new.nonce.into()),
                    }
                } else if !new.balance.is_zero() {
                    assert_eq!(*proof_type, MPTProofType::BalanceChanged);
                    ClaimKind::Balance {
                        old: None,
                        new: Some(u256_from_biguint(&new.balance)),
                    }
                } else {
                    unimplemented!("nonce or balance must be first field set on empty account");
                }
            }
            [Some(old), Some(new)] => match *proof_type {
                MPTProofType::NonceChanged => ClaimKind::Nonce {
                    old: Some(old.nonce.into()),
                    new: Some(new.nonce.into()),
                },
                MPTProofType::BalanceChanged => ClaimKind::Balance {
                    old: Some(u256_from_biguint(&old.balance)),
                    new: Some(u256_from_biguint(&new.balance)),
                },
                MPTProofType::AccountDoesNotExist => ClaimKind::IsEmpty(None),
                MPTProofType::CodeHashExists => ClaimKind::CodeHash {
                    old: Some(u256_from_biguint(&old.code_hash)),
                    new: Some(u256_from_biguint(&new.code_hash)),
                },
                MPTProofType::CodeSizeExists => ClaimKind::CodeSize {
                    old: Some(old.code_size.into()),
                    new: Some(new.code_size.into()),
                },
                MPTProofType::PoseidonCodeHashExists => ClaimKind::PoseidonCodeHash {
                    old: Some(big_uint_to_fr(&old.poseidon_code_hash)),
                    new: Some(big_uint_to_fr(&new.poseidon_code_hash)),
                },
                MPTProofType::StorageChanged | MPTProofType::StorageDoesNotExist => unreachable!(),
                MPTProofType::AccountDestructed => unimplemented!(),
            },
            [Some(_old), None] => unimplemented!("SELFDESTRUCT"),
        }
    }
}

impl From<(MPTProofType, SMTTrace)> for Proof {
    fn from((proof, trace): (MPTProofType, SMTTrace)) -> Self {
        let claim = Claim::from((&proof, &trace));

        let storage = StorageProof::from(&trace);

        let key = account_key(claim.address);
        let leafs = trace.account_path.clone().map(get_leaf);
        let [open_hash_traces, close_hash_traces] =
            trace.account_path.clone().map(|path| path.path);
        let leaf_hashes = trace.account_path.clone().map(leaf_hash);
        let address_hash_traces =
            get_internal_hash_traces(key, leaf_hashes, &open_hash_traces, &close_hash_traces);

        let [old_account, new_account] = trace.account_update;
        let old_account_hash_traces = match old_account.clone() {
            None => empty_account_hash_traces(leafs[0]),
            Some(account) => account_hash_traces(claim.address, account, storage.old_root()),
        };
        let new_account_hash_traces = match new_account.clone() {
            None => empty_account_hash_traces(leafs[1]),
            Some(account) => account_hash_traces(claim.address, account, storage.new_root()),
        };

        let [old, new] = trace.account_path.map(|path| {
            // The account_key(address) if the account exists
            // else: path.leaf.sibling if it's a type 1 non-existence proof
            // otherwise account_key(address) if it's a type 2 non-existence proof
            let (key, key_hash) = path.leaf.map_or_else(
                || {
                    let k = account_key(claim.address);
                    (k, hash(Fr::one(), k))
                },
                |l| {
                    let k = fr(l.sibling);
                    (k, hash(Fr::one(), k))
                },
            );

            let leaf_data_hash = path.leaf.map(|leaf| fr(leaf.value));

            Path {
                key,
                key_hash,
                leaf_data_hash,
            }
        });

        let old_account = match old_account {
            Some(account_data) => {
                let mut account = EthAccount::from(account_data);
                account.storage_root = storage.old_root();
                Some(account)
            }
            None => None,
        };
        let new_account = match new_account {
            Some(account_data) => {
                let mut account = EthAccount::from(account_data);
                account.storage_root = storage.new_root();
                Some(account)
            }
            None => None,
        };
        Self {
            claim,
            address_hash_traces,
            old_account_hash_traces,
            new_account_hash_traces,
            leafs,
            storage,
            old,
            new,
            old_account,
            new_account,
        }
    }
}

// This should be an optional
fn get_leaf(path: SMTPath) -> Option<LeafNode> {
    path.leaf.map(|leaf| LeafNode {
        key: fr(leaf.sibling),
        value_hash: fr(leaf.value),
    })
}

fn leaf_hash(path: SMTPath) -> Fr {
    if let Some(leaf) = path.leaf {
        hash(hash(Fr::one(), fr(leaf.sibling)), fr(leaf.value))
    } else {
        // assert_eq!(path, SMTPath::default());
        Fr::zero()
    }
}

fn account_hash_traces(address: Address, account: AccountData, storage_root: Fr) -> [[Fr; 3]; 7] {
    // h5 is sibling of node?
    // let real_account: Account<Fr> = (&account, storage_root).try_into().unwrap();

    let (codehash_hi, codehash_lo) = hi_lo(account.code_hash);
    let h1 = hash(codehash_hi, codehash_lo);
    let h2 = hash(storage_root, h1);

    let nonce_and_codesize =
        Fr::from(account.nonce) + Fr::from(account.code_size) * Fr::from(1 << 32).square();
    let balance = big_uint_to_fr(&account.balance);
    let h3 = hash(nonce_and_codesize, balance);

    let h4 = hash(h3, h2);

    let account_key = account_key(address);
    let h5 = hash(Fr::one(), account_key);

    let poseidon_codehash = big_uint_to_fr(&account.poseidon_code_hash);
    let account_hash = hash(h4, poseidon_codehash);

    let mut account_hash_traces = [[Fr::zero(); 3]; 7];
    account_hash_traces[0] = [codehash_hi, codehash_lo, h1];
    account_hash_traces[1] = [storage_root, h1, h2];
    account_hash_traces[2] = [nonce_and_codesize, balance, h3];
    account_hash_traces[3] = [h3, h2, h4]; //
    account_hash_traces[4] = [h4, poseidon_codehash, account_hash];
    account_hash_traces[5] = [Fr::one(), account_key, h5]; // this should be the sibling?
    account_hash_traces[6] = [h5, account_hash, hash(h5, account_hash)];

    // h4 is value of node?
    // assert_eq!(real_account.account_hash(), account_hash);

    account_hash_traces
}

fn get_internal_hash_traces(
    key: Fr,
    leaf_hashes: [Fr; 2],
    open_hash_traces: &[SMTNode],
    close_hash_traces: &[SMTNode],
) -> Vec<(bool, Fr, Fr, Fr, bool, bool)> {
    let mut address_hash_traces = vec![];
    for (i, e) in open_hash_traces
        .iter()
        .zip_longest(close_hash_traces.iter())
        .enumerate()
    {
        address_hash_traces.push(match e {
            EitherOrBoth::Both(open, close) => {
                assert_eq!(open.sibling, close.sibling);
                (
                    key.bit(i),
                    fr(open.value),
                    fr(close.value),
                    fr(open.sibling),
                    false,
                    false,
                )
            }
            EitherOrBoth::Left(open) => (
                key.bit(i),
                fr(open.value),
                leaf_hashes[1],
                fr(open.sibling),
                false,
                true,
            ),
            EitherOrBoth::Right(close) => (
                key.bit(i),
                leaf_hashes[0],
                fr(close.value),
                fr(close.sibling),
                true,
                false,
            ),
        });
    }
    address_hash_traces.reverse();
    address_hash_traces
}

fn empty_account_hash_traces(leaf: Option<LeafNode>) -> [[Fr; 3]; 7] {
    let mut account_hash_traces = [[Fr::zero(); 3]; 7];

    if let Some(l) = leaf {
        let h5 = hash(Fr::one(), l.key);
        account_hash_traces[5] = [Fr::one(), l.key, h5];
        account_hash_traces[6] = [h5, l.value_hash, hash(h5, l.value_hash)];
    }

    account_hash_traces
}

fn storage_key_value_hash_traces(key: U256, value: U256) -> [[Fr; 3]; 3] {
    let (key_high, key_low) = split_word(key);
    let (value_high, value_low) = split_word(value);
    let h0 = hash(key_high, key_low);
    let h1 = hash(value_high, value_low);
    dbg!(
        hash(key_high, key_low),
        hash(value_high, value_low),
        hash(Fr::one(), hash(key_high, key_low)),
        hash(Fr::one(), hash(value_high, value_low)),
        hash(h0, h1),
        hash(h1, h0),
    );

    let mut hash_traces = [[Fr::zero(); 3]; 3];
    hash_traces[0] = [key_high, key_low, h0];
    hash_traces[1] = [value_high, value_low, h1];
    hash_traces[2] = [h0, h1, hash(h0, h1)];
    hash_traces
}

impl Proof {
    pub fn old_account_leaf_hashes(&self) -> Option<Vec<Fr>> {
        // TODO: make old_account_hash_traces optional
        let old_account_hash_traces = self.old_account_hash_traces;
        match self.claim.kind {
            ClaimKind::Nonce { old, .. } | ClaimKind::CodeSize { old, .. } => old.map(|_| {
                let old_account_hash = old_account_hash_traces[6][1];
                let old_h4 = old_account_hash_traces[4][0];
                let old_h3 = old_account_hash_traces[3][0];
                let old_nonce_and_codesize = old_account_hash_traces[2][0];
                vec![old_account_hash, old_h4, old_h3, old_nonce_and_codesize]
            }),
            ClaimKind::Balance { old, .. } => old.map(|_| {
                let old_account_hash = old_account_hash_traces[6][1];
                let old_h4 = old_account_hash_traces[4][0];
                let old_h3 = old_account_hash_traces[3][0];
                let old_balance = old_account_hash_traces[2][1];
                vec![old_account_hash, old_h4, old_h3, old_balance]
            }),
            ClaimKind::PoseidonCodeHash { old, .. } => old.map(|_| {
                let old_account_hash = old_account_hash_traces[6][1];
                let old_poseidon_code_hash = old_account_hash_traces[4][1];
                vec![old_account_hash, old_poseidon_code_hash]
            }),
            ClaimKind::CodeHash { old, .. } => old.map(|_| {
                let old_account_hash = old_account_hash_traces[6][1];
                let old_h4 = old_account_hash_traces[4][0];
                let old_h2 = old_account_hash_traces[1][2];
                let old_h1 = old_account_hash_traces[0][2];
                vec![old_account_hash, old_h4, old_h2, old_h1]
            }),
            ClaimKind::Storage { .. } | ClaimKind::IsEmpty(Some(_)) => {
                let old_account_hash = old_account_hash_traces[6][1];
                let old_h4 = old_account_hash_traces[4][0];
                let old_h2 = old_account_hash_traces[1][2];
                let old_storage_root = old_account_hash_traces[1][0];
                Some(vec![old_account_hash, old_h4, old_h2, old_storage_root])
            }
            ClaimKind::IsEmpty(None) => self.leafs[0].map(|_| {
                let old_account_hash = old_account_hash_traces[6][1];
                vec![old_account_hash]
            }),
        }
    }

    pub fn new_account_leaf_hashes(&self) -> Option<Vec<Fr>> {
        let new_account_hash_traces = self.new_account_hash_traces;
        match self.claim.kind {
            ClaimKind::Nonce { new, .. } | ClaimKind::CodeSize { new, .. } => new.map(|_| {
                let new_account_hash = new_account_hash_traces[6][1];
                let new_h4 = new_account_hash_traces[4][0];
                let new_h3 = new_account_hash_traces[3][0];
                let new_nonce_and_codesize = new_account_hash_traces[2][0];
                vec![new_account_hash, new_h4, new_h3, new_nonce_and_codesize]
            }),
            ClaimKind::Balance { new, .. } => new.map(|_| {
                let new_account_hash = new_account_hash_traces[6][1];
                let new_h4 = new_account_hash_traces[4][0];
                let new_h3 = new_account_hash_traces[3][0];
                let new_balance = new_account_hash_traces[2][1];
                vec![new_account_hash, new_h4, new_h3, new_balance]
            }),
            ClaimKind::PoseidonCodeHash { new, .. } => new.map(|_| {
                let new_account_hash = new_account_hash_traces[6][1];
                let new_poseidon_code_hash = new_account_hash_traces[4][1];
                vec![new_account_hash, new_poseidon_code_hash]
            }),
            ClaimKind::CodeHash { new, .. } => new.map(|_| {
                let new_account_hash = new_account_hash_traces[6][1];
                let new_h4 = new_account_hash_traces[4][0];
                let new_h2 = new_account_hash_traces[1][2];
                let new_h1 = new_account_hash_traces[0][2];
                vec![new_account_hash, new_h4, new_h2, new_h1]
            }),
            ClaimKind::Storage { .. } | ClaimKind::IsEmpty(Some(_)) => {
                let new_account_hash = new_account_hash_traces[6][1];
                let new_h4 = new_account_hash_traces[4][0];
                let new_h2 = new_account_hash_traces[1][2];
                let new_storage_root = new_account_hash_traces[1][0];
                Some(vec![new_account_hash, new_h4, new_h2, new_storage_root])
            }
            ClaimKind::IsEmpty(None) => self.leafs[1].map(|_| {
                let new_account_hash = new_account_hash_traces[6][1];
                vec![new_account_hash]
            }),
        }
    }

    pub fn account_leaf_siblings(&self) -> Vec<Fr> {
        match self.claim.kind {
            ClaimKind::Nonce { old, new } | ClaimKind::CodeSize { old, new } => {
                let account_hash_traces = match (old, new) {
                    (Some(_), _) => self.old_account_hash_traces,
                    (None, Some(_)) => self.new_account_hash_traces,
                    (None, None) => unimplemented!("reading 0 value from empty account"),
                };
                let balance = account_hash_traces[2][1];
                let h2 = account_hash_traces[3][1];
                let poseidon_codehash = account_hash_traces[4][1];
                let account_key_hash = account_hash_traces[5][2];

                vec![account_key_hash, poseidon_codehash, h2, balance]
            }
            ClaimKind::Balance { old, new } => {
                let account_hash_traces = match (old, new) {
                    (Some(_), _) => self.old_account_hash_traces,
                    (None, Some(_)) => self.new_account_hash_traces,
                    (None, None) => unimplemented!("reading 0 value from empty account"),
                };
                let nonce_and_codesize = account_hash_traces[2][0];
                let h2 = account_hash_traces[3][1];
                let poseidon_codehash = account_hash_traces[4][1];
                let account_key_hash = account_hash_traces[5][2];

                vec![account_key_hash, poseidon_codehash, h2, nonce_and_codesize]
            }
            ClaimKind::PoseidonCodeHash { old, new } => {
                let account_hash_traces = match (old, new) {
                    (Some(_), _) => self.old_account_hash_traces,
                    (None, Some(_)) => self.new_account_hash_traces,
                    (None, None) => unimplemented!("reading 0 value from empty account"),
                };
                let h4 = account_hash_traces[4][0];
                let account_key_hash = account_hash_traces[5][2];

                vec![account_key_hash, h4]
            }
            ClaimKind::CodeHash { old, new } => {
                let account_hash_traces = match (old, new) {
                    (Some(_), _) => self.old_account_hash_traces,
                    (None, Some(_)) => self.new_account_hash_traces,
                    (None, None) => unimplemented!("reading 0 value from empty account"),
                };
                let account_key_hash = account_hash_traces[5][2];
                let poseidon_codehash = account_hash_traces[4][1];
                let h3 = account_hash_traces[3][0];
                let storage_root = account_hash_traces[1][0];
                vec![account_key_hash, poseidon_codehash, h3, storage_root]
            }
            ClaimKind::Storage { .. } | ClaimKind::IsEmpty(Some(_)) => {
                assert_eq!(
                    self.old_account_hash_traces[5][2],
                    self.new_account_hash_traces[5][2]
                );
                assert_eq!(
                    self.old_account_hash_traces[4][1],
                    self.new_account_hash_traces[4][1]
                );
                assert_eq!(
                    self.old_account_hash_traces[3][0],
                    self.new_account_hash_traces[3][0]
                );
                assert_eq!(
                    self.old_account_hash_traces[1][1],
                    self.new_account_hash_traces[1][1]
                );

                let account_key_hash = self.old_account_hash_traces[5][2];
                let poseidon_codehash = self.old_account_hash_traces[4][1];
                let h3 = self.old_account_hash_traces[3][0];
                let keccak_codehash_hash = self.old_account_hash_traces[1][1];
                vec![
                    account_key_hash,
                    poseidon_codehash,
                    h3,
                    keccak_codehash_hash,
                ]
            }
            ClaimKind::IsEmpty(None) => match self.leafs {
                [Some(_), _] => vec![self.old_account_hash_traces[6][1]],
                [None, Some(_)] => {
                    // Wrong proof
                    vec![self.new_account_hash_traces[6][1]]
                }
                [None, None] => vec![],
            },
        }
    }

    // fn new_account_leaf_hashes(&self) -> Vec<Fr> {}
    // fn account_leaf_siblings(&self) -> Vec<Fr> {}
    fn check(&self) {
        // poseidon hashes are correct
        check_hash_traces_new(&self.address_hash_traces);

        // directions match account key.
        let account_key = account_key(self.claim.address);
        for (i, (direction, _, _, _, _, _)) in self.address_hash_traces.iter().enumerate() {
            assert_eq!(
                *direction,
                account_key.bit(self.address_hash_traces.len() - i - 1)
            );
        }

        // old and new roots are correct
        if let Some((direction, open, close, sibling, _is_padding_open, _is_padding_close)) =
            self.address_hash_traces.last()
        {
            if *direction {
                assert_eq!(hash(*sibling, *open), self.claim.old_root);
                assert_eq!(hash(*sibling, *close), self.claim.new_root);
            } else {
                assert_eq!(hash(*open, *sibling), self.claim.old_root);
                assert_eq!(hash(*close, *sibling), self.claim.new_root);
            }
        } else {
            panic!("no hash traces!!!!");
        }

        // this suggests we want something that keeps 1/2 unchanged if something....
        // going to have to add an is padding row or something?
        assert_eq!(
            self.old_account_hash_traces[5][2],
            self.address_hash_traces.get(0).unwrap().1
        );

        assert_eq!(
            self.new_account_hash_traces[5][2],
            self.address_hash_traces.get(0).unwrap().2
        );
        // if this still the case????

        dbg!(self.old_account_hash_traces, self.leafs);

        // TODO: handle none here.
        assert_eq!(
            hash(
                hash(Fr::one(), self.leafs[0].unwrap().key),
                self.leafs[0].unwrap().value_hash
            ),
            self.old_account_hash_traces[5][2],
        );
        assert_eq!(
            hash(
                hash(Fr::one(), self.leafs[1].unwrap().key),
                self.leafs[1].unwrap().value_hash
            ),
            self.new_account_hash_traces[5][2],
        );

        // // storage poseidon hashes are correct
        // self.storage_hash_traces
        //     .as_ref()
        //     .map(|x| check_hash_traces_new(x.as_slice()));

        // // directions match storage key hash.
        // match self.claim.kind {
        //     ClaimKind::Storage { key, .. }
        //     | ClaimKind::Storage { key, .. }
        //     | ClaimKind::IsEmpty(Some(key)) => {
        //         let storage_key_hash = storage_key_hash(key);
        //         for (i, (direction, _, _, _, _, _)) in self
        //             .storage_hash_traces
        //             .as_ref()
        //             .unwrap()
        //             .iter()
        //             .enumerate()
        //         {
        //             assert_eq!(
        //                 *direction,
        //                 storage_key_hash
        //                     .bit(self.storage_hash_traces.as_ref().unwrap().len() - i - 1)
        //             );
        //         }
        //     }
        //     _ => {}
        // }
    }
}

fn check_hash_traces(traces: &[(bool, Fr, Fr, Fr)]) {
    let current_hash_traces = traces.iter();
    let mut next_hash_traces = traces.iter();
    next_hash_traces.next();
    for ((direction, open, close, sibling), (_, next_open, next_close, _)) in
        current_hash_traces.zip(next_hash_traces)
    {
        if *direction {
            assert_eq!(hash(*sibling, *open), *next_open);
            assert_eq!(hash(*sibling, *close), *next_close);
        } else {
            assert_eq!(hash(*open, *sibling), *next_open);
            assert_eq!(hash(*close, *sibling), *next_close);
        }
    }
}

fn check_hash_traces_new(traces: &[(bool, Fr, Fr, Fr, bool, bool)]) {
    let current_hash_traces = traces.iter();
    let mut next_hash_traces = traces.iter();
    next_hash_traces.next();
    for (
        (direction, open, close, sibling, is_padding_open, is_padding_close),
        (_, next_open, next_close, _, is_padding_open_next, is_padding_close_next),
    ) in current_hash_traces.zip(next_hash_traces)
    {
        if *direction {
            if *is_padding_open {

                // TODOOOOOO
            } else {
                assert_eq!(*is_padding_open_next, false);
                assert_eq!(hash(*sibling, *open), *next_open);
            }

            if *is_padding_close {
                // TODOOOOOO
            } else {
                assert_eq!(*is_padding_close_next, false);
                assert_eq!(hash(*sibling, *close), *next_close);
            }
        } else {
            if *is_padding_open {
                // TODOOOOOO
            } else {
                assert_eq!(*is_padding_open_next, false);
                assert_eq!(hash(*open, *sibling), *next_open);
            }

            if *is_padding_close {
                // TODOOOOOO
            } else {
                assert_eq!(*is_padding_close_next, false);
                assert_eq!(hash(*close, *sibling), *next_close);
            }
        }
    }
}

fn path_root(path: SMTPath) -> Fr {
    // let parse: SMTPathParse<Fr> = SMTPathParse::try_from(&path).unwrap();
    // for (a, b, c) in parse.0.hash_traces {
    //     assert_eq!(hash(a, b), c)
    // }

    let account_hash = if let Some(node) = path.clone().leaf {
        hash(hash(Fr::one(), fr(node.sibling)), fr(node.value))
    } else {
        Fr::zero()
    };

    let directions = bits(path.path_part.clone().try_into().unwrap(), path.path.len());
    let mut digest = account_hash;
    for (&bit, node) in directions.iter().zip(path.path.iter().rev()) {
        assert_eq!(digest, fr(node.value));
        digest = if bit {
            hash(fr(node.sibling), digest)
        } else {
            hash(digest, fr(node.sibling))
        };
    }
    assert_eq!(digest, fr(path.root));
    fr(path.root)
}

fn bits(x: usize, len: usize) -> Vec<bool> {
    let mut bits = vec![];
    let mut x = x;
    while x != 0 {
        bits.push(x % 2 == 1);
        x /= 2;
    }
    bits.resize(len, false);
    bits.reverse();
    bits
}

fn fr(x: HexBytes<32>) -> Fr {
    Fr::from_bytes(&x.0).unwrap()
}

pub fn hash(x: Fr, y: Fr) -> Fr {
    Hashable::hash([x, y])
}

fn storage_key_hash(key: U256) -> Fr {
    let (high, low) = split_word(key);
    hash(high, low)
}

fn split_word(x: U256) -> (Fr, Fr) {
    let mut bytes = [0; 32];
    x.to_big_endian(&mut bytes);
    let high_bytes: [u8; 16] = bytes[..16].try_into().unwrap();
    let low_bytes: [u8; 16] = bytes[16..].try_into().unwrap();

    let high = Fr::from_u128(u128::from_be_bytes(high_bytes));
    let low = Fr::from_u128(u128::from_be_bytes(low_bytes));
    (high, low)

    // TODO: what's wrong with this?
    // let [limb_0, limb_1, limb_2, limb_3] = key.0;
    // let key_high = Fr::from_u128(u128::from(limb_2) + u128::from(limb_3) << 64);
    // let key_low = Fr::from_u128(u128::from(limb_0) + u128::from(limb_1) << 64);
    // hash(key_high, key_low)
}

fn big_uint_to_fr(i: &BigUint) -> Fr {
    i.to_u64_digits()
        .iter()
        .rev() // to_u64_digits has least significant digit is first
        .fold(Fr::zero(), |a, b| {
            a * Fr::from(1 << 32).square() + Fr::from(*b)
        })
}

fn hi_lo(x: BigUint) -> (Fr, Fr) {
    let mut u64_digits = x.to_u64_digits();
    u64_digits.resize(4, 0);
    (
        Fr::from_u128((u128::from(u64_digits[3]) << 64) + u128::from(u64_digits[2])),
        Fr::from_u128((u128::from(u64_digits[1]) << 64) + u128::from(u64_digits[0])),
    )
}

pub trait Bit {
    fn bit(&self, i: usize) -> bool;
}

impl Bit for Fr {
    fn bit(&self, i: usize) -> bool {
        let mut bytes = self.to_bytes();
        bytes.reverse();
        bytes
            .get(31 - i / 8)
            .map_or_else(|| false, |&byte| byte & (1 << (i % 8)) != 0)
    }
}
// bit method is already defined for U256, but is not what you want. you probably want to rename this trait.

#[cfg(test)]
mod test {
    use super::*;

    const EMPTY_ACCOUNT_TRACE: &str = include_str!("../tests/empty_account.json");
    const EMPTY_STORAGE_TRACE: &str = include_str!("../tests/empty_storage.json");
    const TRACES: &str = include_str!("../tests/traces.json");
    const READ_TRACES: &str = include_str!("../tests/read_traces.json");
    const DEPLOY_TRACES: &str = include_str!("../tests/deploy_traces.json");
    const TOKEN_TRACES: &str = include_str!("../tests/token_traces.json");

    #[test]
    fn bit_trait() {
        assert_eq!(Fr::one().bit(0), true);
        assert_eq!(Fr::one().bit(1), false);
    }

    #[test]
    fn check_path_part() {
        // DEPLOY_TRACES(!?!?) has a trace where account nonce and balance change in one trace....
        for s in [TRACES, READ_TRACES, TOKEN_TRACES] {
            let traces: Vec<SMTTrace> = serde_json::from_str::<Vec<_>>(s).unwrap();
            for trace in traces {
                let _address = Address::from(trace.address.0);
                let [open, close] = trace.account_path;

                // not always true for deploy traces because account comes into existence.
                assert_eq!(open.path.len(), close.path.len());
                assert_eq!(open.path_part, close.path_part);

                let directions_1 = bits(open.path_part.try_into().unwrap(), open.path.len());
                let directions_2: Vec<_> = (0..open.path.len())
                    .map(|i| fr(trace.account_key).bit(open.path.len() - 1 - i))
                    .collect();
                assert_eq!(directions_1, directions_2);
            }
        }
    }

    #[test]
    fn check_account_key() {
        for s in [TRACES, READ_TRACES, TOKEN_TRACES] {
            let traces: Vec<SMTTrace> = serde_json::from_str::<Vec<_>>(s).unwrap();
            for trace in traces {
                let address = Address::from(trace.address.0);
                assert_eq!(fr(trace.account_key), account_key(address));
            }
        }
    }

    fn storage_roots(trace: &SMTTrace) -> [Fr; 2] {
        if let Some(root) = trace.common_state_root {
            [root, root].map(fr)
        } else {
            trace.state_path.clone().map(|p| path_root(p.unwrap()))
        }
    }

    #[test]
    fn sanity_check_paths() {
        for s in [READ_TRACES, TRACES, DEPLOY_TRACES, TOKEN_TRACES] {
            let traces: Vec<SMTTrace> = serde_json::from_str::<Vec<_>>(s).unwrap();
            for trace in traces {
                let address = trace.address.0.into();
                for (path, _account) in trace.account_path.iter().zip_eq(trace.account_update) {
                    assert!(
                        contains(
                            &bits(
                                path.clone().path_part.try_into().unwrap(),
                                path.clone().path.len()
                            ),
                            account_key(address)
                        ),
                        "{:?}",
                        (address, path.path_part.clone(), account_key(address))
                    );
                }
            }
        }
    }

    fn contains(path: &[bool], key: Fr) -> bool {
        for (i, direction) in path.iter().rev().enumerate() {
            if key.bit(i) != *direction {
                return false;
            }
        }
        true
    }

    #[test]
    fn test_contains() {
        assert_eq!(contains(&[true, true], Fr::from(0b11)), true);
        assert_eq!(contains(&[], Fr::from(0b11)), true);

        assert_eq!(contains(&[false, false, false], Fr::zero()), true);

        assert_eq!(contains(&[false, false, true], Fr::one()), true);
        assert_eq!(contains(&[false, false, false], Fr::one()), false);
    }
}
