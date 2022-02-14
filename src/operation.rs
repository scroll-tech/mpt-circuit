//! represent the data for a single operation on the MPT
//! 

use super::{HashType, serde};
use halo2::arithmetic::FieldExt;

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
}

impl<Fp: FieldExt> MPTPath<Fp> {

    /// the root of MPT
    pub fn root(&self) -> Fp {
        self.hashes[0]
    }

    /// the leaf value, for truncated path, give None
    pub fn leaf(&self) -> Option<Fp> {
        let last = *self.hashes.last().unwrap();
        if last == Fp::zero() {None} else {Some(last)}
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
}


// Turn a row array into single op, brutely fail with any reason like
// a unfinished op
impl<'d, Fp: FieldExt> From<&'d [serde::Row]> for SingleOp<Fp> {
    fn from(rows: &[serde::Row]) -> Self {

        let old_leaf = Fp::from_bytes(rows.last().unwrap().old_value.as_ref()).unwrap();
        let new_leaf = Fp::from_bytes(rows.last().unwrap().new_value.as_ref()).unwrap();
        let key = Fp::from_bytes(rows[0].key.as_ref()).unwrap();

        let mut old_hash_type = Vec::new();
        let mut new_hash_type = Vec::new();
        let mut old_hash = Vec::new();
        let mut new_hash = Vec::new();
        let mut path = Vec::new();
        let mut siblings = Vec::new();

        rows.iter().for_each(|row| {
            old_hash.push(Fp::from_bytes(row.old_hash.as_ref()).unwrap());
            new_hash.push(Fp::from_bytes(row.new_hash.as_ref()).unwrap());
            siblings.push(Fp::from_bytes(row.sib.as_ref()).unwrap());
            let mut to_hash_int = row.path.to_bytes_le();
            to_hash_int.resize(32, 0u8);
            path.push(Fp::from_bytes(&to_hash_int.try_into().unwrap()).unwrap());

            new_hash_type.push(row.new_hash_type);
            old_hash_type.push(row.old_hash_type);
        });

        let old = MPTPath::<Fp>::construct(&old_hash_type, &path, &siblings, &old_hash, key, old_leaf);
        let new = MPTPath::<Fp>::construct(&new_hash_type, &path, &siblings, &new_hash, key, new_leaf);

        Self {
            key,
            path,
            siblings,
            old,
            new,
        }
    }
}