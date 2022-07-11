//! deserialize data for operations
//!
use super::HashType;
use num_bigint::BigUint;
use serde::{
    de::{Deserializer, Error},
    Deserialize,
};
use std::fmt::{Debug, Display, Formatter};

impl<'de> Deserialize<'de> for HashType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match <&'de str>::deserialize(deserializer)? {
            "empty" => Ok(HashType::Empty),
            "middle" => Ok(HashType::Middle),
            "leafExt" => Ok(HashType::LeafExt),
            "leafExtFinal" => Ok(HashType::LeafExtFinal),
            "leaf" => Ok(HashType::Leaf),
            s => Err(D::Error::unknown_variant(
                s,
                &["empty", "middle", "leafExt", "leafExtFinal", "leaf"],
            )),
        }
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let de_str = <&'de str>::deserialize(deserializer)?;

        de_str.try_into().map_err(D::Error::custom)
    }
}

fn de_uint_bin<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let de_str = <&'de str>::deserialize(deserializer)?;
    BigUint::parse_bytes(de_str.as_bytes(), 2).ok_or_else(|| D::Error::custom(RowDeError::BigInt))
}

fn de_uint_hex<'de, D>(deserializer: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    let de_str = <&'de str>::deserialize(deserializer)?;
    // handling "0x" prefix and a special case that only "0x" occur (i.e.: 0)
    let ret = if de_str.starts_with("0x") {
        if de_str.len() == 2 {
            return Ok(BigUint::default());
        }
        BigUint::parse_bytes(de_str.get(2..).unwrap().as_bytes(), 16)
    } else {
        BigUint::parse_bytes(de_str.as_bytes(), 16)
    };

    ret.ok_or_else(|| D::Error::custom(RowDeError::BigInt))
}

#[derive(Debug, thiserror::Error)]
/// Row type deserialization errors.
pub enum RowDeError {
    #[error(transparent)]
    /// hex decode error
    Hex(#[from] hex::FromHexError),
    #[error("cannot parse bigInt repr")]
    /// bigInt decode error
    BigInt,
}

#[derive(Debug, Deserialize)]
/// Row type
pub struct Row {
    /// maker
    pub is_first: bool,
    /// siblings
    pub sib: Hash,
    /// (aux col, should not used)
    pub depth: usize,
    /// path: bit for mid and int for leaf
    #[serde(deserialize_with = "de_uint_bin")]
    pub path: BigUint,
    /// (aux col, should not used)
    #[serde(deserialize_with = "de_uint_bin")]
    pub path_acc: BigUint,
    /// hash type (before op)
    pub old_hash_type: HashType,
    /// hashs in path (before op)
    pub old_hash: Hash,
    /// values in path (before op)
    pub old_value: Hash,
    /// hash type (after op)
    pub new_hash_type: HashType,
    /// hashs in path (after op)
    pub new_hash: Hash,
    /// values in path (after op)
    pub new_value: Hash,
    /// the key of leaf
    pub key: Hash,
    /// (aux col, should not used)
    pub new_root: Hash,
}

impl Row {
    /// parse rows from JSON array with mutiple records
    pub fn from_lines(lines: &str) -> Result<Vec<Row>, serde_json::Error> {
        lines.trim().split('\n').map(serde_json::from_str).collect()
    }

    /// fold flattern rows into ops array, each ops include serveral rows
    /// and start with an row whose is_first is true
    pub fn fold_flattern_rows(rows: Vec<Row>) -> Vec<Vec<Row>> {
        let mut out = Vec::new();
        let mut current = Vec::new();

        for row in rows {
            if row.is_first && !current.is_empty() {
                out.push(current);
                current = Vec::new();
            }
            current.push(row);
        }

        if !current.is_empty() {
            out.push(current);
        }

        out
    }
}

#[derive(Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
/// Hash expressed by 256bit integer for a Fp repr
pub struct Hash([u8; 32]);

impl Hash {
    /// get hex representation of hash
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// pick the inner content for read
    pub fn start_read(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Debug for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:032}", self.hex())
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:032}", self.hex())
    }
}

impl AsRef<[u8; 32]> for Hash {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsMut<[u8; 32]> for Hash {
    fn as_mut(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

impl TryFrom<&str> for Hash {
    type Error = hex::FromHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut hash = Self::default();
        // handling "0x" prefix
        if value.starts_with("0x") {
            hex::decode_to_slice(value.get(2..).unwrap(), &mut hash.0)?;
        } else {
            hex::decode_to_slice(value, &mut hash.0)?;
        }

        Ok(hash)
    }
}

/// struct in SMTTrace
#[derive(Debug, Deserialize)]
pub struct SMTNode {
    /// value
    pub value: Hash,
    /// sibling
    pub sibling: Hash,
}

/// struct in SMTTrace
#[derive(Debug, Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct SMTPath {
    /// root
    pub root: Hash,
    /// leaf
    pub leaf: Option<SMTNode>,
    /// path
    #[serde(default)]
    pub path: Vec<SMTNode>,
    /// partitial key which is used for path
    #[serde(deserialize_with = "de_uint_hex")]
    pub path_part: BigUint,
}

/// struct in SMTTrace
#[derive(Debug, Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct AccountData {
    /// nonce
    pub nonce: u64,
    /// balance
    #[serde(deserialize_with = "de_uint_hex")]
    pub balance: BigUint,
    /// codeHash
    #[serde(default, deserialize_with = "de_uint_hex")]
    pub code_hash: BigUint,
}

/// represent an updating on SMT, can convert into AccountOp
#[derive(Debug, Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct SMTTrace {
    /// key of account (hash of address)
    pub account_key: Hash,
    /// SMTPath for account
    pub account_path: [SMTPath; 2],
    /// update on accountData
    pub account_update: [Option<AccountData>; 2],
    /// SMTPath for storage,
    pub state_path: [Option<SMTPath>; 2],
    /// common State Root, if no change on storage part
    pub common_state_root: Option<Hash>,
    /// key of address (hash of storage address)
    pub state_key: Option<Hash>,
}
