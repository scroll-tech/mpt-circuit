//! represent the data for a single operation on the MPT
//!

use super::{eth, serde, HashType};
use crate::hash::Hashable;
use ff::PrimeField;
use halo2_proofs::arithmetic::FieldExt;
use num_bigint::BigUint;
use std::cmp::Ordering;
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

impl<Fp: PrimeField> MPTPath<Fp> {
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

    /// the depth of path, for non-empty path it should larger than 1 (with Start)
    pub fn depth(&self) -> usize {
        self.hashes.len() - 1
    }

    /// extend a common path (contain only midle and leaf/empty) to under extended status
    pub fn extend(self, l: usize) -> Self {
        if l == 0 {
            return self;
        }

        assert!(self.hash_types.len() > 1, "can not extend empty path");
        let ins_pos = self.hash_types.len() - 1;
        // can only extend a path with leaf
        assert_eq!(self.hash_types[ins_pos], HashType::Leaf);

        let mut hash_types = self.hash_types;
        let mut addi_types = vec![HashType::LeafExt; l - 1];
        addi_types.push(HashType::LeafExtFinal);

        hash_types[ins_pos] = HashType::Empty;
        drop(hash_types.splice(ins_pos..ins_pos, addi_types));

        let mut hashes = self.hashes;
        let mut addi_hashes = vec![hashes[ins_pos - 1]; l - 1]; //pick the hash of leaf
        addi_hashes.push(Fp::zero());

        // drop the old value at last row
        hashes[ins_pos] = Fp::zero();
        drop(hashes.splice(ins_pos..ins_pos, addi_hashes));

        Self {
            hash_types,
            hashes,
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

impl<Fp: PrimeField> SingleOp<Fp> {
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
            assert!(
                (layers as u32) * 8 < Fp::NUM_BITS,
                "not able to decompose more than bits"
            );
            let mut ret = Vec::new();
            let mut tested_key = key;
            let invert_2 = Fp::one().double().invert().unwrap();
            for _ in 0..layers {
                if tested_key.is_odd().unwrap_u8() == 1 {
                    tested_key = tested_key * invert_2 - invert_2;
                    ret.push(true);
                } else {
                    tested_key *= invert_2;
                    ret.push(false);
                }
            }
            (ret, tested_key)
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

impl<Fp: FieldExt> SingleOp<Fp> {
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
}

fn bytes_to_fp<Fp: FieldExt>(mut bt: Vec<u8>) -> std::io::Result<Fp> {
    let expected_size = Fp::NUM_BITS as usize / 8 + if Fp::NUM_BITS % 8 == 0 { 0 } else { 1 };
    bt.resize(expected_size, 0u8);
    Fp::read(&mut bt.as_slice())
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
            path.push(bytes_to_fp(row.path.to_bytes_le()).unwrap());

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

impl<Fp: PrimeField> Account<Fp> {
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

    /// insert 4 empty hash_trace to build a "empty" account data
    pub fn dummy(self) -> Self {
        if self.hash_traces.is_empty() {
            Self {
                hash_traces: vec![(Fp::zero(), Fp::zero(), Fp::zero()); 4],
                ..self
            }
        } else {
            self
        }
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

impl<Fp: PrimeField> AccountOp<Fp> {
    /// indicate rows would take for whole operation
    pub fn use_rows(&self) -> usize {
        self.use_rows_account() + self.use_rows_trie_state() + self.use_rows_trie_account()
    }

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
struct SMTPathParse<Fp>(MPTPath<Fp>, Vec<Fp>, Vec<Fp>);

impl<'d, Fp: FieldExt> TryFrom<&'d serde::SMTPath> for SMTPathParse<Fp> {
    type Error = TraceError;
    fn try_from(path_trace: &'d serde::SMTPath) -> Result<Self, Self::Error> {
        let mut hashes: Vec<Fp> =
            vec![Fp::read(&mut path_trace.root.start_read()).map_err(TraceError::DeErr)?];
        let mut siblings: Vec<Fp> = Vec::new();

        for n in &path_trace.path {
            let h = Fp::read(&mut n.value.start_read()).map_err(TraceError::DeErr)?;
            hashes.push(h);
            let s = Fp::read(&mut n.sibling.start_read()).map_err(TraceError::DeErr)?;
            siblings.push(s);
        }

        let mut hash_types: Vec<HashType> = Vec::new();
        let mut path: Vec<Fp> = Vec::new();

        for i in 0..siblings.len() {
            path.push(
                if (BigUint::from(1u64) << i) & &path_trace.path_part != BigUint::from(0u64) {
                    Fp::one()
                } else {
                    Fp::zero()
                },
            );
            hash_types.push(HashType::Middle);
        }

        let mut key = Fp::zero();
        let mut leaf = Fp::zero();
        // notice when there is no leaf node, providing 0 key_rst
        if let Some(leaf_node) = &path_trace.leaf {
            key = Fp::read(&mut leaf_node.sibling.start_read()).map_err(TraceError::DeErr)?;
            leaf = Fp::read(&mut leaf_node.value.start_read()).map_err(TraceError::DeErr)?;

            let mut key_i = BigUint::from_bytes_le(leaf_node.sibling.start_read());
            key_i >>= siblings.len();

            path.push(bytes_to_fp(key_i.to_bytes_le()).map_err(TraceError::DeErr)?);
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

impl<'d, Fp: FieldExt> TryFrom<(&'d serde::SMTPath, &'d serde::SMTPath, serde::Hash)>
    for SingleOp<Fp>
{
    type Error = TraceError;
    fn try_from(
        traces: (&'d serde::SMTPath, &'d serde::SMTPath, serde::Hash),
    ) -> Result<Self, Self::Error> {
        let (before, after, ref_key) = traces;

        let key = Fp::read(&mut ref_key.start_read()).map_err(TraceError::DeErr)?;
        let before_parsed: SMTPathParse<Fp> = before.try_into()?;
        let after_parsed: SMTPathParse<Fp> = after.try_into()?;
        let mut old = before_parsed.0;
        let mut new = after_parsed.0;

        // sanity check
        if old.key != key && new.key != key {
            return Err(TraceError::DataErr(
                "one of key for paths must match reference".to_string(),
            ));
        }

        for (a, b) in (&after_parsed.1[0..after_parsed.1.len() - 1])
            .iter()
            .zip(&before_parsed.1[0..before_parsed.1.len() - 1])
        {
            if a != b {
                println!("compare {:?} {:?}", a, b);
                return Err(TraceError::DataErr("unmatch siblings".to_string()));
            }
        }

        // update for inserting op
        match old.depth().cmp(&new.depth()) {
            Ordering::Less => {
                assert_eq!(new.key, key);
                let ext_dist = new.depth() - old.depth();
                old = old.extend(ext_dist);
            }
            Ordering::Greater => {
                assert_eq!(old.key, key);
                let ext_dist = old.depth() - new.depth();
                new = new.extend(ext_dist);
            }
            Ordering::Equal => {}
        }

        let siblings = if new.key == key {
            after_parsed.1
        } else {
            before_parsed.1
        };
        let path = if new.key == key {
            after_parsed.2
        } else {
            before_parsed.2
        };

        Ok(Self {
            key,
            path,
            siblings,
            old,
            new,
        })
    }
}

impl<'d, Fp: FieldExt + Hashable> TryFrom<(&'d serde::AccountData, Fp)> for Account<Fp> {
    type Error = TraceError;
    fn try_from(acc_trace: (&'d serde::AccountData, Fp)) -> Result<Self, Self::Error> {
        let (acc, state_root) = acc_trace;
        let nonce = Fp::from(acc.nonce);
        let balance = bytes_to_fp(acc.balance.to_bytes_le()).map_err(TraceError::DeErr)?;
        let buf = acc.code_hash.to_bytes_le();
        let codehash = if buf.len() < 16 {
            (bytes_to_fp(buf).map_err(TraceError::DeErr)?, Fp::zero())
        } else {
            (
                bytes_to_fp(Vec::from(&buf[16..])).map_err(TraceError::DeErr)?,
                bytes_to_fp(Vec::from(&buf[0..16])).map_err(TraceError::DeErr)?,
            )
        };

        let acc = Self {
            nonce,
            balance,
            codehash,
            state_root,
            ..Default::default()
        };
        Ok(acc.complete(|a, b| <Fp as Hashable>::hash([*a, *b])))
    }
}

impl<'d, Fp: FieldExt + Hashable> TryFrom<&'d serde::SMTTrace> for AccountOp<Fp> {
    type Error = TraceError;
    fn try_from(trace: &'d serde::SMTTrace) -> Result<Self, Self::Error> {
        let acc_trie: SingleOp<Fp> = (
            &trace.account_path[0],
            &trace.account_path[1],
            trace.account_key,
        )
            .try_into()?;

        let state_trie: Option<SingleOp<Fp>> =
            if trace.state_path[0].is_some() && trace.state_path[1].is_some() {
                Some(
                    (
                        trace.state_path[0].as_ref().unwrap(),
                        trace.state_path[1].as_ref().unwrap(),
                        trace.state_key.unwrap(),
                    )
                        .try_into()?,
                )
            } else {
                None
            };

        let comm_state_root = match trace.common_state_root {
            Some(h) => Fp::read(&mut h.start_read()).map_err(TraceError::DeErr)?,
            None => Fp::zero(),
        };

        // TODO: currently we just check if it is creation (no checking for deletion)
        let account_before = if let Some(leaf) = acc_trie.old.leaf() {
            let old_state_root = state_trie
                .as_ref()
                .map(|s| s.start_root())
                .unwrap_or(comm_state_root);
            let account: Account<Fp> = (&trace.account_update[0], old_state_root).try_into()?;
            // sanity check
            assert_eq!(account.account_hash(), leaf);

            Some(account)
        } else {
            None
        };

        let account_after = if let Some(leaf) = acc_trie.new.leaf() {
            let new_state_root = state_trie
                .as_ref()
                .map(|s| s.new_root())
                .unwrap_or(comm_state_root);
            let account: Account<Fp> = (&trace.account_update[1], new_state_root).try_into()?;

            // sanity check
            assert_eq!(account.account_hash(), leaf);
            account
        } else {
            Default::default()
        };

        Ok(Self {
            acc_trie,
            state_trie,
            account_before,
            account_after,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::Fp;
    use halo2_proofs::arithmetic::BaseExt;

    fn decompose<Fp: PrimeField>(inp: Fp, l: usize) -> (Vec<bool>, Fp) {
        let mut ret = Vec::new();
        let mut tested_key = inp;
        let invert_2 = Fp::one().double().invert().unwrap();
        for _ in 0..l {
            if tested_key.is_odd().unwrap_u8() == 1 {
                tested_key = tested_key * invert_2 - invert_2;
                ret.push(true);
            } else {
                tested_key = tested_key * invert_2;
                ret.push(false);
            }
        }
        (ret, tested_key)
    }

    fn recover<Fp: PrimeField>(path: &[bool], res: Fp) -> Fp {
        let mut mask = Fp::one();
        let mut ret = Fp::zero();

        for b in path {
            ret += if *b { mask } else { Fp::zero() };
            mask = mask.double();
        }

        ret + res * mask
    }

    #[test]
    fn path_decomposing() {
        let test1 = Fp::from(75u64);
        let ret1 = decompose(test1, 4);
        assert_eq!(ret1.0, vec![true, true, false, true]);
        assert_eq!(ret1.1, Fp::from(4u64));

        let test2 = Fp::from(16203805u64);
        let ret2 = decompose(test2, 22);
        assert_eq!(recover(&ret2.0, ret2.1), test2);

        for _ in 0..1000 {
            let test = Fp::rand();
            let ret = decompose(test, 22);
            assert_eq!(recover(&ret.0, ret.1), test);
        }
    }

    #[test]
    fn trace_debug_convert() {
        let example = r#"{"index":821,"address":"0x2c73620b223808297ea734d946813f0dd78eb8f7","accountKey":"0x5db403a9dfdfee7fe4a9f6b3bcbd45891acb7d3edca055a30cd98b83fae82509","accountPath":[{"pathPart":"0x1d","root":"0x1a1d32110e36228a8a45cd9f5382f7ae640f6e84d4a04162aeb253732b27280e","path":[{"value":"0x9922448603bb54be4bac94c7330ee722b4e6a28a8be08554a02ed3907b8e7525","sibling":"0x45b594553ac09839214b35507298b747c9e6158573b563a04051ab230e7c8121"},{"value":"0x1d10fc609615971b8f87dcb88e3c0f8361e15c106c0138dfab3af01cfbcc071f","sibling":"0xd8aefbec72b08a3936f8905a3abd895260b2b72fa6d7ca095e1a6eec44ddce00"},{"value":"0x031538758fa1c6a954bb132229a5a282480c84a546ec6c945a90845b8e3dd114","sibling":"0x6d0452d6001e828f0eaad16dcb602548e5741c3ee7e9ea3bda8c3139d00c3b2a"},{"value":"0x93239124402ac4222aa46d6afa6339beba05e6605eb28258f0fbdd736f8fda25","sibling":"0x375c8cf2a07615ea1ab35f8505f76ad1d051994309d5ae23444415dd40abc12d"},{"value":"0x9ce74e858ab0f8e60729cba71bc5347cd37b03d06bccef33ed86d1540a148402","sibling":"0xf0d5c2ea88fd2d87160f828f49907f88cfc68fa4b769a4db3b33456fc2e14f06"}],"leaf":{"value":"0x33c5435c783d711eca3cb21179f8afaf6dd0be8ca0f066d0daace28b17fc281d","sibling":"0x5db403a9dfdfee7fe4a9f6b3bcbd45891acb7d3edca055a30cd98b83fae82509"}},{"pathPart":"0x1d","root":"0x89b59ccc274a164314f1788e1dd3ccb71a311bf9d6f07c406a5790149fc7e614","path":[{"value":"0xd6f0e7d20322d1b242d8887ca18a037fd398c137abbd7eb6aba7d34aff0e151d","sibling":"0x45b594553ac09839214b35507298b747c9e6158573b563a04051ab230e7c8121"},{"value":"0x883a521ba3cb69e04ffc06bad8f10c3a8de9f98577f4d845e9d8777d78f63211","sibling":"0xd8aefbec72b08a3936f8905a3abd895260b2b72fa6d7ca095e1a6eec44ddce00"},{"value":"0xf4e075792965e2571e2ef37a93f1b49d387daa44397a298d6577dd2042f6da0f","sibling":"0x6d0452d6001e828f0eaad16dcb602548e5741c3ee7e9ea3bda8c3139d00c3b2a"},{"value":"0x924f04db123d8232fbb3f5a81c8b61ec447208f6104d162ed76ff09ff5e5da0e","sibling":"0x375c8cf2a07615ea1ab35f8505f76ad1d051994309d5ae23444415dd40abc12d"},{"value":"0x8122cb0be20577b92c8edb44c4377b194eacf2b3f8fa604a6ba167d893845704","sibling":"0xf0d5c2ea88fd2d87160f828f49907f88cfc68fa4b769a4db3b33456fc2e14f06"}],"leaf":{"value":"0xb81e5fff74150a68aae995839ee32592d4d31b826e3ed4841f6a902554287e22","sibling":"0x5db403a9dfdfee7fe4a9f6b3bcbd45891acb7d3edca055a30cd98b83fae82509"}}],"accountUpdate":[{"nonce":1,"balance":"0x","codeHash":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"nonce":1,"balance":"0x","codeHash":"0x0000000000000000000000000000000000000000000000000000000000000000"}],"stateKey":"0x6448b64684ee39a823d5fe5fd52431dc81e4817bf2c3ea3cab9e239efbf59820","statePath":[{"pathPart":"0x","root":"0x0000000000000000000000000000000000000000000000000000000000000000"},{"pathPart":"0x","root":"0xa5e63364b882331be55d929fdfe2e208124fba7e02154ae8bb2f71e7be4eb220","leaf":{"value":"0x81aceea7f0bb4e6e1b9857e6aebe9403903fe71dc9c0e6105e5a30ab7be60a0e","sibling":"0x6448b64684ee39a823d5fe5fd52431dc81e4817bf2c3ea3cab9e239efbf59820"}}],"stateUpdate":[{"key":"0x","value":"0x"},{"key":"0x0000000000000000000000000000000000000000000000000000000000000000","value":"0x48656c6c6f2c204861726468617421000000000000000000000000000000001e"}]}"#;
        let trace: serde::SMTTrace = serde_json::from_str(example).unwrap();

        println!("{:?}", trace.state_path[0]);
        let parse: SMTPathParse<Fp> = trace.state_path[0].as_ref().unwrap().try_into().unwrap();
        println!("{:?}", parse.0);

        println!("{:?}", trace.state_path[1]);
        let parse: SMTPathParse<Fp> = trace.state_path[1].as_ref().unwrap().try_into().unwrap();
        println!("{:?}", parse.0);

        let state_op_test: SingleOp<Fp> = (
            trace.state_path[0].as_ref().unwrap(),
            trace.state_path[1].as_ref().unwrap(),
            trace.state_key.unwrap(),
        )
            .try_into()
            .unwrap();
        println!("{:?}", state_op_test);

        println!("{:?}", trace.account_path[0]);
        let parse: SMTPathParse<Fp> = (&trace.account_path[0]).try_into().unwrap();
        println!("{:?}", parse.0);

        println!("{:?}", trace.account_path[1]);
        let parse: SMTPathParse<Fp> = (&trace.account_path[1]).try_into().unwrap();
        println!("{:?}", parse.0);

        let account_op_test: SingleOp<Fp> = (
            &trace.account_path[0],
            &trace.account_path[1],
            trace.account_key,
        )
            .try_into()
            .unwrap();
        println!("{:?}", account_op_test);

        let account_data_test: Account<Fp> = (&trace.account_update[0], state_op_test.start_root())
            .try_into()
            .unwrap();
        println!("{:?}", account_data_test);
        assert_eq!(
            account_data_test.account_hash(),
            account_op_test.old.leaf().unwrap()
        );

        let account_data_test: Account<Fp> = (&trace.account_update[1], state_op_test.new_root())
            .try_into()
            .unwrap();
        println!("{:?}", account_data_test);
        assert_eq!(
            account_data_test.account_hash(),
            account_op_test.new.leaf().unwrap()
        );

        let final_data: AccountOp<Fp> = (&trace).try_into().unwrap();
        println!("{:?}", final_data);
    }

    #[test]
    fn trace_convert_insert_op() {
        let example = r#"{"index":-1,"address":"0x2c73620b223808297ea734d946813f0dd78eb8f7","accountKey":"0x5db403a9dfdfee7fe4a9f6b3bcbd45891acb7d3edca055a30cd98b83fae82509","accountPath":[{"pathPart":"0x0d","root":"0x5ace42a4c492223e519d0eee46d51e307452276d6ed74e073a4916c915b07223","path":[{"value":"0xb4f8bce5f7e6f384fbdf7561458705c55b25163e9aea66c862f5b8c40e13811d","sibling":"0x45b594553ac09839214b35507298b747c9e6158573b563a04051ab230e7c8121"},{"value":"0x9919c4e1c7e5ea02b0184826806ec8bce9cc1b18fe5cef6d7104cf25af3dc32b","sibling":"0xd8aefbec72b08a3936f8905a3abd895260b2b72fa6d7ca095e1a6eec44ddce00"},{"value":"0x1d0a0219f830de5f86aa6b29208f2a931cabb852f903a1ce118ebb9754b2a11e","sibling":"0x6d0452d6001e828f0eaad16dcb602548e5741c3ee7e9ea3bda8c3139d00c3b2a"},{"value":"0xf0d5c2ea88fd2d87160f828f49907f88cfc68fa4b769a4db3b33456fc2e14f06","sibling":"0x375c8cf2a07615ea1ab35f8505f76ad1d051994309d5ae23444415dd40abc12d"}],"leaf":{"value":"0xb69f961f2e0671b782549639e3acc44157f1da9adbb815d5f0a77e7113012e28","sibling":"0x6d3e389f7dd8c147fe168ec3dfa575f588d5caee7bd4da9fd99c7ecf9cc5df00"}},{"pathPart":"0x1d","root":"0x1a1d32110e36228a8a45cd9f5382f7ae640f6e84d4a04162aeb253732b27280e","path":[{"value":"0x9922448603bb54be4bac94c7330ee722b4e6a28a8be08554a02ed3907b8e7525","sibling":"0x45b594553ac09839214b35507298b747c9e6158573b563a04051ab230e7c8121"},{"value":"0x1d10fc609615971b8f87dcb88e3c0f8361e15c106c0138dfab3af01cfbcc071f","sibling":"0xd8aefbec72b08a3936f8905a3abd895260b2b72fa6d7ca095e1a6eec44ddce00"},{"value":"0x031538758fa1c6a954bb132229a5a282480c84a546ec6c945a90845b8e3dd114","sibling":"0x6d0452d6001e828f0eaad16dcb602548e5741c3ee7e9ea3bda8c3139d00c3b2a"},{"value":"0x93239124402ac4222aa46d6afa6339beba05e6605eb28258f0fbdd736f8fda25","sibling":"0x375c8cf2a07615ea1ab35f8505f76ad1d051994309d5ae23444415dd40abc12d"},{"value":"0x9ce74e858ab0f8e60729cba71bc5347cd37b03d06bccef33ed86d1540a148402","sibling":"0xf0d5c2ea88fd2d87160f828f49907f88cfc68fa4b769a4db3b33456fc2e14f06"}],"leaf":{"value":"0x33c5435c783d711eca3cb21179f8afaf6dd0be8ca0f066d0daace28b17fc281d","sibling":"0x5db403a9dfdfee7fe4a9f6b3bcbd45891acb7d3edca055a30cd98b83fae82509"}}],"accountUpdate":[{"nonce":0,"balance":"0x"},{"nonce":1,"balance":"0x","codeHash":"0x0000000000000000000000000000000000000000000000000000000000000000"}],"commonStateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","statePath":[null,null],"stateUpdate":[null,null]}"#;
        let trace: serde::SMTTrace = serde_json::from_str(example).unwrap();

        let data: AccountOp<Fp> = (&trace).try_into().unwrap();
        println!("{:?}", data);
    }

    // verify the calculation of account data's root
    #[test]
    fn trace_account_data() {
        let data: Account<Fp> = Account {
            balance: Fp::from(0u64),
            nonce: Fp::from(1u64),
            codehash: (Fp::zero(), Fp::zero()),
            //0x20b24ebee7712fbbe84a15027eba4f1208e2e2df9f925de51b3382b86433e6a5
            state_root: Fp::from_str_vartime(
                "14789053415173694845992038966920525110567435779704439275440571405364058384037",
            )
            .unwrap(),
            ..Default::default()
        };

        let data = data.complete(|a, b| <Fp as Hashable>::hash([*a, *b]));

        //0x227e285425906a1f84d43e6e821bd3d49225e39e8395e9aa680a1574ff5f1eb8
        assert_eq!(
            data.account_hash(),
            Fp::from_str_vartime(
                "15601537920438488782505741155807773419253320959345191889201535312143566446264"
            )
            .unwrap()
        );

        let code_hash_int = BigUint::parse_bytes(
            b"e653e6971d6128bd15b83aa8ebeefca96378c1e36ba7bedafc17f76f1e10f632",
            16,
        )
        .unwrap();

        let data: Account<Fp> = Account {
            balance: Fp::from(0u64),
            nonce: Fp::from(1u64),
            //0xe653e6971d6128bd15b83aa8ebeefca96378c1e36ba7bedafc17f76f1e10f632
            codehash: (
                bytes_to_fp(Vec::from(&code_hash_int.to_bytes_le()[16..])).unwrap(),
                bytes_to_fp(Vec::from(&code_hash_int.to_bytes_le()[0..16])).unwrap(),
            ),

            //0x0fb46c93fe32157d73bdaf9359e4ac1fa7514f7043014df64213c18bbd80c2e0
            state_root: Fp::from_str_vartime(
                "7103474578896643880912595670996880817578037370381571930047680755406072759008",
            )
            .unwrap(),
            ..Default::default()
        };

        let data = data.complete(|a, b| <Fp as Hashable>::hash([*a, *b]));
        println!("{:?}", data);

        //0x282e0113717ea7f0d515b8db9adaf15741c4ace339965482b771062e1f969fb6
        assert_eq!(
            data.account_hash(),
            Fp::from_str_vartime(
                "18173796334248186903004954824637212553607820157797929507368343926106786013110"
            )
            .unwrap()
        );
    }
}
