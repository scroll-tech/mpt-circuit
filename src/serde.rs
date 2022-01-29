//! deserialize data for operations
//! 
use num_bigint::BigUint;
use serde::{Deserialize, de::{Error, Deserializer}};
use std::fmt::{Debug, Display, Formatter};
use super::HashType;

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
            s => Err(D::Error::unknown_variant(s, &["empty","middle","leafExt","leafExtFinal","leaf"]))
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
where D: Deserializer<'de>
{
    let de_str = <&'de str>::deserialize(deserializer)?;
    BigUint::parse_bytes(de_str.as_bytes(), 2).ok_or(D::Error::custom(RowDeError::BigInt))
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
            if row.is_first {
                if !current.is_empty() {
                    out.push(current);
                    current = Vec::new();
                }
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
        hex::decode_to_slice(value, &mut hash.0)?;
        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_FILE: &'static str = include_str!("../rows.jsonl");

    #[test]
    fn row_de() {
        Row::from_lines(TEST_FILE).unwrap();
    }

    #[test]
    fn row_parse() {
        let rows = Row::from_lines(TEST_FILE).unwrap();
        for row in rows.iter() {
            println!("{:?}", row);
        }
    }

    #[test]
    fn row_parse_to_op() {
        let ops = Row::fold_flattern_rows(Row::from_lines(TEST_FILE).unwrap());
        for op in ops {
            for row in op {
                println!("{:?}", row);
            }
            println!("----");
        }
    }    
}
