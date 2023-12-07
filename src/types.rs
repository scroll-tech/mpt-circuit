use crate::{
    gadgets::mpt_update::PathType,
    serde::{AccountData, HexBytes, SMTNode, SMTPath, SMTTrace},
    util::{
        account_key, check_domain_consistency, domain_hash, fr_from_biguint, fr_to_u256,
        u256_from_biguint, u256_from_hex,
    },
    MPTProofType,
};
use ethers_core::{
    k256::elliptic_curve::PrimeField,
    types::{Address, U256},
};
use halo2_proofs::halo2curves::bn256::Fr;
use itertools::{EitherOrBoth, Itertools};
use num_bigint::BigUint;
use num_traits::identities::Zero;

pub mod storage;
pub mod trie;
use storage::StorageProof;
use trie::TrieRows;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashDomain {
    Leaf,
    Branch0, // branch node with both children = leaf or empty
    Branch1, // branch node with left child = branch node and right child = leaf or empty
    Branch2, // branch node with left child = leaf or empty and right child = branch node
    Branch3, // branch node with both children = branch node
    Pair,
    AccountFields,
}

impl TryFrom<u64> for HashDomain {
    type Error = &'static str;
    fn try_from(x: u64) -> Result<Self, Self::Error> {
        match x {
            4 => Ok(Self::Leaf),
            6 => Ok(Self::Branch0),
            7 => Ok(Self::Branch1),
            8 => Ok(Self::Branch2),
            9 => Ok(Self::Branch3),
            _ => Err("unreachable u64 for HashDomain"),
        }
    }
}

impl From<HashDomain> for Fr {
    fn from(h: HashDomain) -> Self {
        Self::from(u64::from(h))
    }
}

impl From<HashDomain> for u64 {
    fn from(h: HashDomain) -> Self {
        match h {
            HashDomain::Leaf => 4,
            HashDomain::Branch0 => 6,
            HashDomain::Branch1 => 7,
            HashDomain::Branch2 => 8,
            HashDomain::Branch3 => 9,
            HashDomain::Pair => 2 * 256,
            HashDomain::AccountFields => 5 * 256,
        }
    }
}

impl HashDomain {
    pub fn into_u64(&self) -> u64 {
        (*self).into()
    }
}

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

    pub fn old_value(&self) -> U256 {
        match self.kind {
            ClaimKind::Nonce { old, .. } | ClaimKind::CodeSize { old, .. } => {
                U256::from(old.unwrap_or_default())
            }
            ClaimKind::PoseidonCodeHash { old, .. } => fr_to_u256(old.unwrap_or_default()),
            ClaimKind::Balance { old, .. } | ClaimKind::CodeHash { old, .. } => {
                old.unwrap_or_default()
            }
            ClaimKind::Storage { old_value, .. } => old_value.unwrap_or_default(),
            ClaimKind::IsEmpty(_) => U256::zero(),
        }
    }

    pub fn new_value(&self) -> U256 {
        match self.kind {
            ClaimKind::Nonce { new, .. } | ClaimKind::CodeSize { new, .. } => {
                U256::from(new.unwrap_or_default())
            }
            ClaimKind::PoseidonCodeHash { new, .. } => fr_to_u256(new.unwrap_or_default()),
            ClaimKind::Balance { new, .. } | ClaimKind::CodeHash { new, .. } => {
                new.unwrap_or_default()
            }
            ClaimKind::Storage { new_value, .. } => new_value.unwrap_or_default(),
            ClaimKind::IsEmpty(_) => U256::zero(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct LeafNode {
    key: Fr,
    value_hash: Fr,
}

#[derive(Clone, Debug)]
pub struct Proof {
    pub claim: Claim,
    // direction, open_hash_domain, close_hash_domain, open value, close value, sibling, is_padding_open, is_padding_close
    pub address_hash_traces: Vec<(bool, HashDomain, Fr, Fr, Fr, bool, bool)>,

    // TODO: make this optional
    leafs: [Option<LeafNode>; 2],

    pub old_account_hash_traces: [[Fr; 3]; 6],
    pub new_account_hash_traces: [[Fr; 3]; 6],

    pub storage: StorageProof,

    pub old: Path,
    pub new: Path,

    pub old_account: Option<EthAccount>,
    pub new_account: Option<EthAccount>,

    pub account_trie_rows: TrieRows,
}

// TODO: rename to Account
#[derive(Clone, Copy, Debug)]
pub struct EthAccount {
    pub nonce: u64,
    pub code_size: u64,
    pub poseidon_codehash: Fr,
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
        if self.old_account.is_none() && self.new_account.is_none() {
            return 1 + self.address_hash_traces.len();
        }
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
    pub key: Fr,                    // pair hash of address or storage key
    pub leaf_data_hash: Option<Fr>, // leaf data hash for type 0 and type 1, None for type 2.
}

impl Path {
    pub fn hash(&self) -> Fr {
        match self.leaf_data_hash {
            None => Fr::zero(),
            Some(data_hash) => domain_hash(self.key, data_hash, HashDomain::Leaf),
        }
    }
}

impl From<(&MPTProofType, &SMTTrace)> for Claim {
    fn from((proof_type, trace): (&MPTProofType, &SMTTrace)) -> Self {
        let [old_root, new_root] = trace.account_path.clone().map(|path| fr(path.root));
        let address = trace.address.0.into();
        let kind = ClaimKind::from((proof_type, trace));
        assert_eq!(MPTProofType::from(kind), *proof_type);
        Self {
            new_root,
            old_root,
            address,
            kind,
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
                    // Accesses to the MPT happen in the order defined in the state (aka rw) circuit, which is not the
                    // same as the order they occur in the EVM. In the state circuit, nonce and balance modifications
                    // will precede storage modifications for a given address, which means that the MPT circuit only
                    // needs to handle storage modifications for existing accounts, even though this is not true in the
                    // EVM, where the storage of an account can be modified during its construction.
                    if !(account_old == account_new
                        || (account_old.is_none() && account_new == &Some(Default::default())))
                    {
                        assert_eq!(account_old, account_new, "{state_update:?}");
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
            [None, None] => match *proof_type {
                MPTProofType::NonceChanged => ClaimKind::Nonce {
                    old: Some(0),
                    new: Some(0),
                },
                MPTProofType::BalanceChanged => ClaimKind::Balance {
                    old: Some(U256::zero()),
                    new: Some(U256::zero()),
                },
                MPTProofType::AccountDoesNotExist => ClaimKind::IsEmpty(None),
                MPTProofType::CodeHashExists => ClaimKind::CodeHash {
                    old: Some(U256::zero()),
                    new: Some(U256::zero()),
                },
                MPTProofType::CodeSizeExists => ClaimKind::CodeSize {
                    old: Some(0),
                    new: Some(0),
                },
                MPTProofType::StorageDoesNotExist => {
                    ClaimKind::IsEmpty(Some(u256_from_hex(trace.state_key.unwrap())))
                }
                MPTProofType::PoseidonCodeHashExists => unreachable!(),
                MPTProofType::StorageChanged => unreachable!(),
                MPTProofType::AccountDestructed => unimplemented!(),
            },
            [None, Some(new)] => {
                if !new.nonce.is_zero() {
                    assert_eq!(*proof_type, MPTProofType::NonceChanged);
                    ClaimKind::Nonce {
                        old: None,
                        new: Some(new.nonce),
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
                MPTProofType::NonceChanged => {
                    assert_eq!(old.balance, new.balance);
                    assert_eq!(old.code_size, new.code_size);
                    assert_eq!(old.code_hash, new.code_hash);
                    assert_eq!(old.poseidon_code_hash, new.poseidon_code_hash);
                    ClaimKind::Nonce {
                        old: Some(old.nonce),
                        new: Some(new.nonce),
                    }
                }
                MPTProofType::BalanceChanged => {
                    assert_eq!(old.nonce, new.nonce);
                    assert_eq!(old.code_size, new.code_size);
                    assert_eq!(old.code_hash, new.code_hash);
                    assert_eq!(old.poseidon_code_hash, new.poseidon_code_hash);
                    ClaimKind::Balance {
                        old: Some(u256_from_biguint(&old.balance)),
                        new: Some(u256_from_biguint(&new.balance)),
                    }
                }
                MPTProofType::CodeHashExists => {
                    assert_eq!(old.nonce, new.nonce);
                    assert_eq!(old.balance, new.balance);
                    assert_eq!(old.code_size, new.code_size);
                    assert_eq!(old.poseidon_code_hash, new.poseidon_code_hash);
                    ClaimKind::CodeHash {
                        old: Some(u256_from_biguint(&old.code_hash)),
                        new: Some(u256_from_biguint(&new.code_hash)),
                    }
                }
                MPTProofType::CodeSizeExists => {
                    assert_eq!(old.nonce, new.nonce);
                    assert_eq!(old.balance, new.balance);
                    assert_eq!(old.code_hash, new.code_hash);
                    assert_eq!(old.poseidon_code_hash, new.poseidon_code_hash);
                    ClaimKind::CodeSize {
                        old: Some(old.code_size),
                        new: Some(new.code_size),
                    }
                }
                MPTProofType::PoseidonCodeHashExists => {
                    assert_eq!(old.nonce, new.nonce);
                    assert_eq!(old.balance, new.balance);
                    assert_eq!(old.code_size, new.code_size);
                    assert_eq!(old.code_hash, new.code_hash);
                    ClaimKind::PoseidonCodeHash {
                        old: Some(big_uint_to_fr(&old.poseidon_code_hash)),
                        new: Some(big_uint_to_fr(&new.poseidon_code_hash)),
                    }
                }
                MPTProofType::AccountDoesNotExist
                | MPTProofType::StorageChanged
                | MPTProofType::StorageDoesNotExist => unreachable!(),
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
        assert_eq!(key, fr(trace.account_key));

        let account_trie_rows = TrieRows::new(
            fr(trace.account_key),
            &trace.account_path[0].path,
            &trace.account_path[1].path,
            trace.account_path[0].leaf,
            trace.account_path[1].leaf,
        );

        let leafs = trace.account_path.clone().map(get_leaf);
        let [open_hash_traces, close_hash_traces] =
            trace.account_path.clone().map(|path| path.path);
        let leaf_hashes = trace.account_path.clone().map(leaf_hash);
        let address_hash_traces =
            get_internal_hash_traces(key, leaf_hashes, &open_hash_traces, &close_hash_traces);
        check_hash_traces_new(&address_hash_traces);

        let [old_account, new_account] = trace.account_update;
        let old_account_hash_traces = match old_account.clone() {
            None => empty_account_hash_traces(leafs[0]),
            Some(account) => account_hash_traces(claim.address, account, storage.old_root()),
        };
        let new_account_hash_traces = match new_account.clone() {
            None => empty_account_hash_traces(leafs[1]),
            Some(account) => account_hash_traces(claim.address, account, storage.new_root()),
        };
        assert_eq!(old_account_hash_traces[5][2], leaf_hashes[0]);
        assert_eq!(new_account_hash_traces[5][2], leaf_hashes[1]);

        let [old, new] = trace.account_path.map(|path| {
            // The account_key(address) if the account exists
            // else: path.leaf.sibling if it's a type 1 non-existence proof
            // otherwise account_key(address) if it's a type 2 non-existence proof
            let key = path
                .leaf
                .map_or_else(|| account_key(claim.address), |l| fr(l.sibling));

            let leaf_data_hash = path.leaf.map(|leaf| fr(leaf.value));

            Path {
                key,
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
            account_trie_rows,
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
        domain_hash(fr(leaf.sibling), fr(leaf.value), HashDomain::Leaf)
    } else {
        Fr::zero()
    }
}

fn account_hash_traces(address: Address, account: AccountData, storage_root: Fr) -> [[Fr; 3]; 6] {
    let (codehash_hi, codehash_lo) = hi_lo(account.code_hash);
    let h1 = domain_hash(codehash_hi, codehash_lo, HashDomain::Pair);
    let h2 = domain_hash(storage_root, h1, HashDomain::AccountFields);

    let nonce_and_codesize =
        Fr::from(account.nonce) + Fr::from(account.code_size) * Fr::from(1 << 32).square();
    let balance = big_uint_to_fr(&account.balance);
    let h3 = domain_hash(nonce_and_codesize, balance, HashDomain::AccountFields);

    let h4 = domain_hash(h3, h2, HashDomain::AccountFields);

    let account_key = account_key(address);

    let poseidon_codehash = big_uint_to_fr(&account.poseidon_code_hash);
    let account_hash = domain_hash(h4, poseidon_codehash, HashDomain::AccountFields);

    let mut account_hash_traces = [[Fr::zero(); 3]; 6];
    account_hash_traces[0] = [codehash_hi, codehash_lo, h1];
    account_hash_traces[1] = [storage_root, h1, h2];
    account_hash_traces[2] = [nonce_and_codesize, balance, h3];
    account_hash_traces[3] = [h3, h2, h4]; //
    account_hash_traces[4] = [h4, poseidon_codehash, account_hash];
    account_hash_traces[5] = [
        account_key,
        account_hash,
        domain_hash(account_key, account_hash, HashDomain::Leaf),
    ];
    account_hash_traces
}

fn get_internal_hash_traces(
    key: Fr,
    leaf_hashes: [Fr; 2],
    open_hash_traces: &[SMTNode],
    close_hash_traces: &[SMTNode],
) -> Vec<(bool, HashDomain, Fr, Fr, Fr, bool, bool)> {
    let mut address_hash_traces = vec![];
    for (i, e) in open_hash_traces
        .iter()
        .zip_longest(close_hash_traces.iter())
        .enumerate()
    {
        let direction = key.bit(i);
        address_hash_traces.push(match e {
            EitherOrBoth::Both(open, close) => {
                assert_eq!(open.sibling, close.sibling);
                let open_domain = HashDomain::try_from(open.node_type).unwrap();
                let close_domain = HashDomain::try_from(close.node_type).unwrap();

                let domain = if open_domain != close_domain {
                    // This can only happen when inserting or deleting a node.
                    assert!(open_hash_traces.len() != close_hash_traces.len());
                    assert!(
                        i == std::cmp::min(open_hash_traces.len(), close_hash_traces.len()) - 1
                    );

                    if i == open_hash_traces.len() - 1 {
                        // Inserting a leaf, so open is before insertion, close is after insertion.
                        check_domain_consistency(open_domain, close_domain, direction);
                        open_domain
                    } else {
                        // Deleting a leaf, so open is after insertion, close is before insertion.
                        check_domain_consistency(close_domain, open_domain, direction);
                        close_domain
                    }
                } else {
                    open_domain
                };

                (
                    direction,
                    domain,
                    fr(open.value),
                    fr(close.value),
                    fr(open.sibling),
                    false,
                    false,
                )
            }
            EitherOrBoth::Left(open) => (
                direction,
                HashDomain::try_from(open.node_type).unwrap(),
                fr(open.value),
                leaf_hashes[1],
                fr(open.sibling),
                false,
                true,
            ),
            EitherOrBoth::Right(close) => (
                direction,
                HashDomain::try_from(close.node_type).unwrap(),
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

fn empty_account_hash_traces(leaf: Option<LeafNode>) -> [[Fr; 3]; 6] {
    let mut account_hash_traces = [[Fr::zero(); 3]; 6];
    if let Some(l) = leaf {
        account_hash_traces[5] = [
            l.key,
            l.value_hash,
            domain_hash(l.key, l.value_hash, HashDomain::Leaf),
        ];
    }
    account_hash_traces
}

impl Proof {
    pub fn old_account_leaf_hashes(&self) -> Option<Vec<Fr>> {
        // TODO: make old_account_hash_traces optional
        let old_account_hash_traces = self.old_account_hash_traces;
        match self.claim.kind {
            ClaimKind::Nonce { old, .. } | ClaimKind::CodeSize { old, .. } => old.map(|_| {
                let old_account_hash = old_account_hash_traces[5][1];
                let old_h4 = old_account_hash_traces[4][0];
                let old_h3 = old_account_hash_traces[3][0];
                let old_nonce_and_codesize = old_account_hash_traces[2][0];
                vec![old_account_hash, old_h4, old_h3, old_nonce_and_codesize]
            }),
            ClaimKind::Balance { old, .. } => old.map(|_| {
                let old_account_hash = old_account_hash_traces[5][1];
                let old_h4 = old_account_hash_traces[4][0];
                let old_h3 = old_account_hash_traces[3][0];
                let old_balance = old_account_hash_traces[2][1];
                vec![old_account_hash, old_h4, old_h3, old_balance]
            }),
            ClaimKind::PoseidonCodeHash { old, .. } => old.map(|_| {
                let old_account_hash = old_account_hash_traces[5][1];
                let old_poseidon_code_hash = old_account_hash_traces[4][1];
                vec![old_account_hash, old_poseidon_code_hash]
            }),
            ClaimKind::CodeHash { old, .. } => old.map(|_| {
                let old_account_hash = old_account_hash_traces[5][1];
                let old_h4 = old_account_hash_traces[4][0];
                let old_h2 = old_account_hash_traces[1][2];
                let old_h1 = old_account_hash_traces[0][2];
                vec![old_account_hash, old_h4, old_h2, old_h1]
            }),
            ClaimKind::Storage { .. } | ClaimKind::IsEmpty(Some(_)) => self.old_account.map(|_| {
                let old_account_hash = old_account_hash_traces[5][1];
                let old_h4 = old_account_hash_traces[4][0];
                let old_h2 = old_account_hash_traces[1][2];
                let old_storage_root = old_account_hash_traces[1][0];
                vec![old_account_hash, old_h4, old_h2, old_storage_root]
            }),
            ClaimKind::IsEmpty(None) => self.leafs[0].map(|_| {
                let old_account_hash = old_account_hash_traces[5][1];
                vec![old_account_hash]
            }),
        }
    }

    pub fn new_account_leaf_hashes(&self) -> Option<Vec<Fr>> {
        let new_account_hash_traces = self.new_account_hash_traces;
        match self.claim.kind {
            ClaimKind::Nonce { new, .. } | ClaimKind::CodeSize { new, .. } => new.map(|_| {
                let new_account_hash = new_account_hash_traces[5][1];
                let new_h4 = new_account_hash_traces[4][0];
                let new_h3 = new_account_hash_traces[3][0];
                let new_nonce_and_codesize = new_account_hash_traces[2][0];
                vec![new_account_hash, new_h4, new_h3, new_nonce_and_codesize]
            }),
            ClaimKind::Balance { new, .. } => new.map(|_| {
                let new_account_hash = new_account_hash_traces[5][1];
                let new_h4 = new_account_hash_traces[4][0];
                let new_h3 = new_account_hash_traces[3][0];
                let new_balance = new_account_hash_traces[2][1];
                vec![new_account_hash, new_h4, new_h3, new_balance]
            }),
            ClaimKind::PoseidonCodeHash { new, .. } => new.map(|_| {
                let new_account_hash = new_account_hash_traces[5][1];
                let new_poseidon_code_hash = new_account_hash_traces[4][1];
                vec![new_account_hash, new_poseidon_code_hash]
            }),
            ClaimKind::CodeHash { new, .. } => new.map(|_| {
                let new_account_hash = new_account_hash_traces[5][1];
                let new_h4 = new_account_hash_traces[4][0];
                let new_h2 = new_account_hash_traces[1][2];
                let new_h1 = new_account_hash_traces[0][2];
                vec![new_account_hash, new_h4, new_h2, new_h1]
            }),
            ClaimKind::Storage { .. } | ClaimKind::IsEmpty(Some(_)) => {
                let new_account_hash = new_account_hash_traces[5][1];
                let new_h4 = new_account_hash_traces[4][0];
                let new_h2 = new_account_hash_traces[1][2];
                let new_storage_root = new_account_hash_traces[1][0];
                Some(vec![new_account_hash, new_h4, new_h2, new_storage_root])
            }
            ClaimKind::IsEmpty(None) => self.leafs[1].map(|_| {
                let new_account_hash = new_account_hash_traces[5][1];
                vec![new_account_hash]
            }),
        }
    }

    pub fn account_leaf_siblings(&self) -> Vec<Fr> {
        let account_key = account_key(self.claim.address);
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

                vec![account_key, poseidon_codehash, h2, balance]
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

                vec![account_key, poseidon_codehash, h2, nonce_and_codesize]
            }
            ClaimKind::PoseidonCodeHash { old, new } => {
                let account_hash_traces = match (old, new) {
                    (Some(_), _) => self.old_account_hash_traces,
                    (None, Some(_)) => self.new_account_hash_traces,
                    (None, None) => unimplemented!("reading 0 value from empty account"),
                };
                let h4 = account_hash_traces[4][0];

                vec![account_key, h4]
            }
            ClaimKind::CodeHash { old, new } => {
                let account_hash_traces = match (old, new) {
                    (Some(_), _) => self.old_account_hash_traces,
                    (None, Some(_)) => self.new_account_hash_traces,
                    (None, None) => unimplemented!("reading 0 value from empty account"),
                };
                let poseidon_codehash = account_hash_traces[4][1];
                let h3 = account_hash_traces[3][0];
                let storage_root = account_hash_traces[1][0];
                vec![account_key, poseidon_codehash, h3, storage_root]
            }
            ClaimKind::Storage { .. } | ClaimKind::IsEmpty(Some(_)) => {
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

                let poseidon_codehash = self.old_account_hash_traces[4][1];
                let h3 = self.old_account_hash_traces[3][0];
                let keccak_codehash_hash = self.old_account_hash_traces[1][1];
                vec![account_key, poseidon_codehash, h3, keccak_codehash_hash]
            }
            ClaimKind::IsEmpty(None) => vec![],
        }
    }

    // fn new_account_leaf_hashes(&self) -> Vec<Fr> {}
    // fn account_leaf_siblings(&self) -> Vec<Fr> {}
    #[cfg(test)]
    pub fn check(&self) {
        self.storage.check();

        // poseidon hashes are correct
        check_hash_traces_new(&self.address_hash_traces);

        // directions match account key.
        let account_key = account_key(self.claim.address);
        for (i, (direction, _, _, _, _, _, _)) in self.address_hash_traces.iter().enumerate() {
            assert_eq!(
                *direction,
                account_key.bit(self.address_hash_traces.len() - i - 1)
            );
        }

        // old and new roots are correct
        if let Some((
            direction,
            domain,
            open,
            close,
            sibling,
            _is_padding_open,
            _is_padding_close,
        )) = self.address_hash_traces.last()
        {
            if *direction {
                assert_eq!(domain_hash(*sibling, *open, *domain), self.claim.old_root);
                assert_eq!(domain_hash(*sibling, *close, *domain), self.claim.new_root);
            } else {
                assert_eq!(domain_hash(*open, *sibling, *domain), self.claim.old_root);
                assert_eq!(domain_hash(*close, *sibling, *domain), self.claim.new_root);
            }
        } else {
            panic!("no hash traces!!!!");
        }

        // this suggests we want something that keeps 1/2 unchanged if something....
        // going to have to add an is padding row or something?

        assert_eq!(
            self.old_account_hash_traces[5][2],
            self.address_hash_traces.first().unwrap().2
        );

        assert_eq!(
            self.new_account_hash_traces[5][2],
            self.address_hash_traces.first().unwrap().3
        );
        if let Some(old_leaf) = self.leafs[0] {
            assert_eq!(
                domain_hash(old_leaf.key, old_leaf.value_hash, HashDomain::Leaf),
                self.old_account_hash_traces[5][2],
            );
        } else {
            assert_eq!(self.address_hash_traces.first().unwrap().2, Fr::zero())
        }
        if let Some(new_leaf) = self.leafs[1] {
            assert_eq!(
                domain_hash(new_leaf.key, new_leaf.value_hash, HashDomain::Leaf),
                self.new_account_hash_traces[5][2],
            );
        } else {
            assert_eq!(self.address_hash_traces.first().unwrap().3, Fr::zero())
        }

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

fn check_hash_traces_new(traces: &[(bool, HashDomain, Fr, Fr, Fr, bool, bool)]) {
    let mut previous_path_type: Option<PathType> = None;

    let current_hash_traces = traces.iter();
    let mut next_hash_traces = traces.iter();
    next_hash_traces.next();
    for (
        (direction, domain, open, close, sibling, is_padding_open, is_padding_close),
        (_, _, next_open, next_close, _, _, _),
    ) in current_hash_traces.zip(next_hash_traces)
    {
        let path_type = match (is_padding_open, is_padding_close) {
            (false, false) => PathType::Common,
            (false, true) => PathType::ExtensionOld,
            (true, false) => PathType::ExtensionNew,
            (true, true) => unreachable!(),
        };

        match path_type {
            PathType::Start => unreachable!(),
            PathType::Common => {
                let [open_domain, close_domain] =
                    if previous_path_type == Some(PathType::ExtensionOld) {
                        unimplemented!("account leaf deletion");
                    } else if previous_path_type == Some(PathType::ExtensionNew) {
                        match *domain {
                            HashDomain::Branch0 => [
                                HashDomain::Branch0,
                                if *direction {
                                    HashDomain::Branch1
                                } else {
                                    HashDomain::Branch2
                                },
                            ],
                            HashDomain::Branch1 => [HashDomain::Branch1, HashDomain::Branch3],
                            HashDomain::Branch2 => [HashDomain::Branch2, HashDomain::Branch3],
                            HashDomain::Branch3 => {
                                unreachable!("both siblings already present")
                            }
                            _ => unreachable!(),
                        }
                    } else {
                        [*domain, *domain]
                    };

                if *direction {
                    assert_eq!(domain_hash(*sibling, *open, open_domain), *next_open);
                    assert_eq!(domain_hash(*sibling, *close, close_domain), *next_close);
                } else {
                    assert_eq!(domain_hash(*open, *sibling, open_domain), *next_open);
                    assert_eq!(domain_hash(*close, *sibling, close_domain), *next_close);
                }
            }
            PathType::ExtensionOld => {
                assert!(
                    previous_path_type.is_none()
                        || previous_path_type == Some(PathType::ExtensionOld)
                );
                if *direction {
                    assert_eq!(domain_hash(*sibling, *open, *domain), *next_open);
                } else {
                    assert_eq!(domain_hash(*open, *sibling, *domain), *next_open);
                }
            }
            PathType::ExtensionNew => {
                assert!(
                    previous_path_type.is_none()
                        || previous_path_type == Some(PathType::ExtensionNew)
                );
                if *direction {
                    assert_eq!(domain_hash(*sibling, *close, *domain), *next_close);
                } else {
                    assert_eq!(domain_hash(*close, *sibling, *domain), *next_close);
                }
            }
        }

        previous_path_type = Some(path_type);
    }
}

fn fr(x: HexBytes<32>) -> Fr {
    Fr::from_bytes(&x.0).unwrap()
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

    #[test]
    fn bit_trait() {
        assert!(Fr::one().bit(0));
        assert!(!Fr::one().bit(1));
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
        assert!(contains(&[true, true], Fr::from(0b11)));
        assert!(contains(&[], Fr::from(0b11)));

        assert!(contains(&[false, false, false], Fr::zero()));

        assert!(contains(&[false, false, true], Fr::one()));
        assert!(!contains(&[false, false, false], Fr::one()));
    }
}
