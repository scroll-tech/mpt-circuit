//! represent the data for a single operation on the MPT
//!

use super::{eth, serde, HashType};
use halo2_proofs::arithmetic::FieldExt;
use num_bigint::BigUint;
use std::convert::TryFrom;

/// Represent a sequence of hashes in a path inside MPT, it can be full
/// (with leaf) or truncated and being padded to an "empty" leaf node,
/// according to the hash_type. It would be used for the layout of MPT
/// circuit
#[derive(Clone, Debug, Default)]
pub struct MPTPath<Fp> {
    /// hash types from beginning of a path, start with HashType::Start
    pub hash_types: Vec<HashType>,
    /// hashes from beginning of path, from the root of MPT to leaf node
    pub hashes: Vec<Fp>,
    /// the cached traces for calculated all hashes required in verifing a MPT path,
    /// include the leaf hashing      
    pub hash_traces: Vec<(Fp, Fp, Fp)>,
    /// the key for this path
    pub key: Fp,
}

impl<Fp: FieldExt> MPTPath<Fp> {
    /// the root of MPT
    pub fn root(&self) -> Fp {
        self.hashes[0]
    }

    /// the leaf value, for truncated path, give None
    pub fn leaf(&self) -> Option<Fp> {
        let last = *self.hashes.last().unwrap();
        if last == Fp::zero() {
            None
        } else {
            Some(last)
        }
    }

    /// extend a common path (contain only midle and leaf/empty) to under extended status
    pub fn extend(self, l: usize) -> Self {
        if l == 0 {
            return self;
        }

        assert!(!self.hash_types.is_empty(), "can not extend empty path");

        let ins_pos = self.hash_types.len() - 1;
        let mut hash_types = self.hash_types;
        drop(hash_types.splice(ins_pos..ins_pos, vec![HashType::LeafExtFinal]));

        Self {
            hash_types,
            ..self
        }
    }

    /// construct from known data matrix (for example, from geth), the input hash_types
    /// is purposed to has no HashType::Start and all length of the slice arguments
    /// are the same
    pub fn construct(
        hash_types: &[HashType],
        path: &[Fp],
        siblings: &[Fp],
        hashes: &[Fp],
        key: Fp,
        leaf: Fp, //notice 0 value would be considered as empty
    ) -> Self {
        //we have at least one row
        assert!(!path.is_empty(), "data should not empty");
        assert_eq!(path.len(), siblings.len());
        assert_eq!(path.len(), hashes.len());
        assert_eq!(path.len(), hash_types.len());

        let mut hash_types = Vec::from(hash_types);
        hash_types.insert(0, HashType::Start);
        let mut hashes = Vec::from(hashes);

        let mut hash_traces = vec![(key, leaf, *hashes.last().unwrap())];
        let mut last_hash = hashes[0];
        for (index, hash) in hashes.iter().skip(1).enumerate() {
            hash_traces.push(if path[index] == Fp::one() {
                (siblings[index], *hash, last_hash)
            } else {
                (*hash, siblings[index], last_hash)
            });
            last_hash = *hash
        }
        hashes.push(leaf);

        Self {
            key,
            hashes,
            hash_types,
            hash_traces,
        }
    }

    /// create a common path data layout (only contains middle and leaf type)
    /// with the help of siblings and path bits (false indicate zero)
    /// to calculate path ad-hoc by hasher function
    pub fn create(
        path: &[bool],
        siblings: &[Fp],
        key: Fp,
        leaf: Fp,
        mut hasher: impl FnMut(&Fp, &Fp) -> Fp,
    ) -> Self {
        assert_eq!(path.len(), siblings.len());
        let leaf_hash = hasher(&key, &leaf);
        let mut hashes = vec![leaf, leaf_hash];
        let mut hash_types = vec![HashType::Leaf];
        let mut hash_traces = vec![(key, leaf, leaf_hash)];

        for (sibling, bit) in siblings.iter().rev().zip(path.iter().rev()) {
            let (l, r) = if *bit {
                (sibling, hashes.last().unwrap())
            } else {
                (hashes.last().unwrap(), sibling)
            };

            let h = hasher(l, r);
            hash_traces.push((*l, *r, h));
            hashes.push(h);
            hash_types.push(HashType::Middle);
        }

        hashes.reverse();
        hash_types.push(HashType::Start);
        hash_types.reverse();

        Self {
            key,
            hashes,
            hash_types,
            hash_traces,
        }
    }
}

/// Represent for a single operation
#[derive(Clone, Debug, Default)]
pub struct SingleOp<Fp> {
    /// the key of operation
    pub key: Fp,
    /// the path of operation, from top to the leaf's resident
    pub path: Vec<Fp>,
    /// the siblings, with one zero padding in the end
    pub siblings: Vec<Fp>,
    /// the MPT path data before operation
    pub old: MPTPath<Fp>,
    /// the MPT path data after operation
    pub new: MPTPath<Fp>,
}

impl<Fp: FieldExt> SingleOp<Fp> {
    /// indicate rows would take in circuit layout
    pub fn use_rows(&self) -> usize {
        self.siblings.len() + 1
    }

    /// the root of MPT before operation
    pub fn start_root(&self) -> Fp {
        self.old.root()
    }

    /// the root of MPT after operation
    pub fn new_root(&self) -> Fp {
        self.new.root()
    }

    /// data represent an update operation (only contains middle and leaf type)
    /// with the help of siblings and calculating path ad-hoc by hasher function
    pub fn create_update_op(
        layers: usize,
        siblings: &[Fp],
        key: Fp,
        leafs: (Fp, Fp),
        hasher: impl FnMut(&Fp, &Fp) -> Fp + Clone,
    ) -> Self {
        let mut siblings = Vec::from(siblings);

        //decompose path
        let (path, key_res): (Vec<bool>, Fp) = {
            assert!(layers < 128, "not able to decompose more than 128 layers");
            let test = key.get_lower_128();
            (
                (0..layers)
                    .map(|i| (test & (1u128 << i as u128)) != 0u128)
                    .collect(),
                (key - Fp::from_u128(test & ((1u128 << layers) - 1)))
                    * Fp::from_u128(1u128 << layers).invert().unwrap(),
            )
        };
        let (old_leaf, new_leaf) = leafs;

        let old = MPTPath::<Fp>::create(&path, &siblings, key, old_leaf, hasher.clone());
        let new = MPTPath::<Fp>::create(&path, &siblings, key, new_leaf, hasher);
        let mut path: Vec<Fp> = path
            .into_iter()
            .map(|b| if b { Fp::one() } else { Fp::zero() })
            .collect();
        siblings.push(Fp::zero());
        path.push(key_res);

        Self {
            key,
            old,
            new,
            siblings,
            path,
        }
    }

    /// create an fully random update operation with leafs customable
    pub fn create_rand_op(
        layers: usize,
        leafs: Option<(Fp, Fp)>,
        hasher: impl FnMut(&Fp, &Fp) -> Fp + Clone,
    ) -> Self {
        let siblings: Vec<Fp> = (0..layers).map(|_| Fp::rand()).collect();
        let key = Fp::rand();
        let leafs = leafs.unwrap_or_else(|| (Fp::rand(), Fp::rand()));
        Self::create_update_op(layers, &siblings, key, leafs, hasher)
    }

    /// create another updating op base on a previous action
    pub fn update_next(self, new_leaf: Fp, hasher: impl FnMut(&Fp, &Fp) -> Fp + Clone) -> Self {
        let layer_sz = self.siblings.len() - 1;
        let path_bool: Vec<bool> = self
            .path
            .iter()
            .take(layer_sz)
            .map(|v| *v != Fp::zero())
            .collect();
        let new = MPTPath::<Fp>::create(
            &path_bool,
            &self.siblings[..layer_sz],
            self.key,
            new_leaf,
            hasher,
        );
        Self {
            key: self.key,
            old: self.new,
            new,
            siblings: self.siblings,
            path: self.path,
        }
    }
}

// Turn a row array into single op, brutely fail with any reason like
// a unfinished op
impl<'d, Fp: FieldExt> From<&'d [serde::Row]> for SingleOp<Fp> {
    fn from(rows: &[serde::Row]) -> Self {
        let old_leaf = Fp::read(&mut rows.last().unwrap().old_value.start_read()).unwrap();
        let new_leaf = Fp::read(&mut rows.last().unwrap().new_value.start_read()).unwrap();
        let key = Fp::read(&mut rows[0].key.start_read()).unwrap();

        let mut old_hash_type = Vec::new();
        let mut new_hash_type = Vec::new();
        let mut old_hash = Vec::new();
        let mut new_hash = Vec::new();
        let mut path = Vec::new();
        let mut siblings = Vec::new();

        rows.iter().for_each(|row| {
            old_hash.push(Fp::read(&mut row.old_hash.start_read()).unwrap());
            new_hash.push(Fp::read(&mut row.new_hash.start_read()).unwrap());
            siblings.push(Fp::read(&mut row.sib.start_read()).unwrap());
            let mut to_hash_int = row.path.to_bytes_le();
            to_hash_int.resize(32, 0u8);
            path.push(Fp::read(&mut to_hash_int.as_slice()).unwrap());

            new_hash_type.push(row.new_hash_type);
            old_hash_type.push(row.old_hash_type);
        });

        let old =
            MPTPath::<Fp>::construct(&old_hash_type, &path, &siblings, &old_hash, key, old_leaf);
        let new =
            MPTPath::<Fp>::construct(&new_hash_type, &path, &siblings, &new_hash, key, new_leaf);

        Self {
            key,
            path,
            siblings,
            old,
            new,
        }
    }
}

/// Represent for a eth account
#[derive(Clone, Debug, Default)]
pub struct Account<Fp> {
    /// the balance of account, because it is the total amount of ethereum so field should be large enough
    pub balance: Fp,
    /// the nonce of an account
    pub nonce: Fp,
    /// the 256-bit codehash require 2 field (first / last 128bit) to contain
    pub codehash: (Fp, Fp),
    /// the root of state trie
    pub state_root: Fp,
    /// the cached traces for calculated all hashes required in obtain the account hash
    /// the last one calculate the final hash
    pub hash_traces: Vec<(Fp, Fp, Fp)>,
}

impl<Fp: FieldExt> Account<Fp> {
    /// calculating all traces ad-hoc with hasher function
    pub fn trace(mut self, mut hasher: impl FnMut(&Fp, &Fp) -> Fp) -> Self {
        let h1 = hasher(&self.codehash.0, &self.codehash.1);
        let h3 = hasher(&self.nonce, &self.balance);
        let h2 = hasher(&h1, &self.state_root);
        let h_final = hasher(&h3, &h2);

        self.hash_traces = vec![
            (self.codehash.0, self.codehash.1, h1),
            (h1, self.state_root, h2),
            (self.nonce, self.balance, h3),
            (h3, h2, h_final),
        ];

        self
    }

    /// complete the account by calculating all traces ad-hoc with hasher function
    pub fn complete(self, hasher: impl FnMut(&Fp, &Fp) -> Fp) -> Self {
        if self.hash_traces.is_empty() {
            self.trace(hasher)
        } else {
            self
        }
    }

    /// the hash of account, which act as leaf value in account trie
    pub fn account_hash(&self) -> Fp {
        assert_eq!(self.hash_traces.len(), 4);
        self.hash_traces[3].2
    }
}

/// Represent an operation in eth MPT, which update 2 layer of tries (state and account)
#[derive(Clone, Debug, Default)]
pub struct AccountOp<Fp> {
    /// the operation on the account trie (first layer)
    pub acc_trie: SingleOp<Fp>,
    /// the operation on the state trie (second layer)
    pub state_trie: Option<SingleOp<Fp>>,
    /// the state before updating in account
    pub account_before: Option<Account<Fp>>,
    /// the state after updating in account
    pub account_after: Account<Fp>,
}

impl<Fp: FieldExt> AccountOp<Fp> {
    /// indicate rows would take in the account trie part
    pub fn use_rows_trie_account(&self) -> usize {
        self.acc_trie.use_rows()
    }

    /// indicate rows would take in the state trie part
    pub fn use_rows_trie_state(&self) -> usize {
        if let Some(op) = &self.state_trie {
            op.use_rows()
        } else {
            0
        }
    }

    /// indicate rows would take in account part
    pub fn use_rows_account(&self) -> usize {
        if self.state_trie.is_some() {
            eth::CIRCUIT_ROW - 1
        } else {
            eth::CIRCUIT_ROW
        }
    }

    /// the root of account trie, which is global state
    pub fn account_root(&self) -> Fp {
        self.acc_trie.new_root()
    }

    /// the root of account trie before operation
    pub fn account_root_before(&self) -> Fp {
        self.acc_trie.start_root()
    }
}

/// include error raised in deserialize or data verification
#[derive(Debug)]
pub enum TraceError {
    /// error in deserialize
    DeErr(std::io::Error),
    /// error for malform data
    DataErr(String),
}

// parse Trace data into MPTPath and additional data (siblings and path)
struct SMTPathParse<Fp> (MPTPath<Fp>, Vec<Fp>, Vec<Fp>);

impl<'d, Fp: FieldExt> TryFrom<&'d serde::SMTPath> for SMTPathParse<Fp> {

    type Error = TraceError;
    fn try_from(path_trace: &'d serde::SMTPath) -> Result<Self, Self::Error> {

        let mut hashes : Vec<Fp> = vec![Fp::read(&mut path_trace.root.start_read()).map_err(|e| TraceError::DeErr(e))?];
        let mut siblings : Vec<Fp> = Vec::new();

        for n in &path_trace.path {
            let h = Fp::read(&mut n.value.start_read()).map_err(|e| TraceError::DeErr(e))?;
            hashes.push(h);
            let s = Fp::read(&mut n.sibling.start_read()).map_err(|e| TraceError::DeErr(e))?;
            siblings.push(s);
        }

        let mut hash_types : Vec<HashType> = vec![HashType::Start];
        let mut path : Vec<Fp> = Vec::new();
        
        for i in 0..siblings.len() {
            path.push(if (BigUint::from(1u64) << i ) & &path_trace.path_part != BigUint::from(0u64) { Fp::one()} else {Fp::zero()});
            hash_types.push(HashType::Middle);
        }

        let mut key = Fp::zero();
        let mut leaf = Fp::zero();
        // notice when there is no leaf node, providing 0 key_rst
        if let Some(leaf_node) = &path_trace.leaf {
            key = Fp::read(&mut leaf_node.sibling.start_read()).map_err(|e| TraceError::DeErr(e))?;
            leaf = Fp::read(&mut leaf_node.value.start_read()).map_err(|e| TraceError::DeErr(e))?;

            let mut key_i = BigUint::from_bytes_le(leaf_node.sibling.start_read());
            key_i >>= siblings.len();

            path.push(Fp::read(&mut key_i.to_bytes_be().as_slice()).map_err(|e| TraceError::DeErr(e))?);
            hash_types.push(HashType::Leaf);
        } else {
            path.push(Fp::zero());
            hash_types.push(HashType::Empty);
        }

        // notice we need to append one more element for siblings
        siblings.push(Fp::zero());

        Ok(SMTPathParse(
            MPTPath::construct(&hash_types, &path, &siblings, &hashes, key, leaf),
            siblings,
            path,
        ))
    }
}

impl<'d, Fp: FieldExt> TryFrom<(&'d serde::SMTPath, &'d serde::SMTPath, serde::Hash)> for SingleOp<Fp> {

    type Error = TraceError;
    fn try_from(traces: (&'d serde::SMTPath, &'d serde::SMTPath, serde::Hash)) -> Result<Self, Self::Error> {
        let (before, after, ref_key) = traces;

        let before_parsed : SMTPathParse<Fp> = before.try_into()?;
        let after_parsed : SMTPathParse<Fp> = after.try_into()?;
        let old = before_parsed.0;
        let sl_old = before_parsed.1;
        let sl_new = after_parsed.1;

        if sl_old.len() < sl_new.len() {

        } else if sl_old.len() < sl_new.len() {

        }

        Ok(Self::default())
    }
}

impl<'d, Fp: FieldExt> TryFrom<&'d serde::SMTTrace> for Account<Fp> {

    type Error = TraceError;
    fn try_from(trace: &'d serde::SMTTrace) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}
