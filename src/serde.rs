//! deserialize data for operations
//!
use super::HashType;
use num_bigint::BigUint;
use serde::{
    de::{Deserializer, Error},
    ser::Serializer,
    Deserialize, Serialize,
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

impl<const LEN: usize> Serialize for HexBytes<LEN> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ret = format!("0x{:0>1$}", self.hex(), LEN * 2);
        serializer.serialize_str(&ret)
    }
}

impl<'de, const LEN: usize> Deserialize<'de> for HexBytes<LEN> {
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

fn se_uint_hex<S>(bi: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ret = format!("0x{}", bi.to_str_radix(16));
    serializer.serialize_str(&ret)
}

fn se_uint_hex_fixed32<S>(bi: &BigUint, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ret = format!("0x{:0>64}", bi.to_str_radix(16));
    serializer.serialize_str(&ret)
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

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
/// HexBytes struct encoding to "0x...."
pub struct HexBytes<const LEN: usize>(pub [u8; LEN]);

impl<const LEN: usize> HexBytes<LEN> {
    /// get hex representation
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// pick the inner content for read
    pub fn start_read(&self) -> &[u8] {
        &self.0[..]
    }

    /// cast bytes to another length, truncate or append 0 on the target
    pub fn cast<const LNEW: usize>(&self) -> [u8; LNEW] {
        let mut out = [0; LNEW];
        self.0
            .iter()
            .zip(out.as_mut_slice())
            .for_each(|(i, o): (&u8, &mut u8)| *o = *i);
        out
    }
}

impl<const LEN: usize> Default for HexBytes<LEN> {
    fn default() -> Self {
        Self([0; LEN])
    }
}

impl<const LEN: usize> Debug for HexBytes<LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:0>1$}", self.hex(), LEN * 2)
    }
}

impl<const LEN: usize> Display for HexBytes<LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:0>1$}", self.hex(), LEN * 2)
    }
}

impl<const LEN: usize> AsRef<[u8; LEN]> for HexBytes<LEN> {
    fn as_ref(&self) -> &[u8; LEN] {
        &self.0
    }
}

impl<const LEN: usize> AsMut<[u8; LEN]> for HexBytes<LEN> {
    fn as_mut(&mut self) -> &mut [u8; LEN] {
        &mut self.0
    }
}

impl<const LEN: usize> TryFrom<&str> for HexBytes<LEN> {
    type Error = hex::FromHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut bytes = Self::default();
        // handling "0x" prefix
        if value.starts_with("0x") {
            hex::decode_to_slice(value.get(2..).unwrap(), &mut bytes.0)?;
        } else {
            hex::decode_to_slice(value, &mut bytes.0)?;
        }

        Ok(bytes)
    }
}

/// Hash expressed by 256bit integer for a Fp repr
pub type Hash = HexBytes<32>;

/// Address expressed by 20bytes eth address
pub type Address = HexBytes<20>;

/// struct in SMTTrace
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SMTNode {
    /// value
    pub value: Hash,
    /// sibling
    pub sibling: Hash,
}

/// struct in SMTTrace
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "camelCase"))]
pub struct SMTPath {
    /// root
    pub root: Hash,
    /// leaf
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf: Option<SMTNode>,
    /// path
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<SMTNode>,
    /// partitial key which is used for path
    #[serde(deserialize_with = "de_uint_hex", serialize_with = "se_uint_hex")]
    pub path_part: BigUint,
}

/// struct in SMTTrace
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "camelCase"))]
pub struct AccountData {
    /// nonce
    pub nonce: u64,
    /// balance
    #[serde(deserialize_with = "de_uint_hex", serialize_with = "se_uint_hex")]
    pub balance: BigUint,
    /// codeHash
    #[serde(
        default,
        deserialize_with = "de_uint_hex",
        serialize_with = "se_uint_hex_fixed32"
    )]
    pub code_hash: BigUint,
}

/// struct in SMTTrace
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StateData {
    /// the key of storage
    pub key: HexBytes<32>,
    /// the value of storage
    pub value: HexBytes<32>,
}

/// represent an updating on SMT, can convert into AccountOp
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all(deserialize = "camelCase", serialize = "camelCase"))]
pub struct SMTTrace {
    /// Address for the trace
    pub address: Address,
    /// key of account (hash of address)
    pub account_key: Hash,
    /// SMTPath for account
    pub account_path: [SMTPath; 2],
    /// update on accountData
    pub account_update: [Option<AccountData>; 2],
    /// SMTPath for storage,
    pub state_path: [Option<SMTPath>; 2],
    /// common State Root, if no change on storage part
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_state_root: Option<Hash>,
    /// key of address (hash of storage address)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_key: Option<Hash>,
    /// update on storage
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_update: Option<[Option<StateData>; 2]>,
}
