use num_bigint::BigUint;
use serde::Deserialize;
use std::fmt::{Debug, Display, Formatter};

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

#[derive(Debug)]
pub struct Row {
    pub is_first: bool,
    pub sib: Hash,
    pub depth: usize,
    pub path: BigUint,
    pub path_acc: BigUint,
    pub old_hash_type: HashType,
    pub old_hash: Hash,
    pub old_value: Hash,
    pub new_hash_type: HashType,
    pub new_hash: Hash,
    pub new_value: Hash,
    pub key: Hash,
    pub new_root: Hash,
}

#[derive(Debug, Deserialize)]
struct RowDe {
    is_first: bool,
    sib: String,
    depth: usize,
    path: String,
    path_acc: String,
    old_hash_type: HashType,
    old_hash: String,
    old_value: String,
    new_hash_type: HashType,
    new_hash: String,
    new_value: String,
    key: String,
    new_root: String,
}

impl RowDe {
    pub fn from_lines(lines: &str) -> Result<Vec<RowDe>, serde_json::Error> {
        lines.trim().split('\n').map(serde_json::from_str).collect()
    }
}

impl TryFrom<&RowDe> for Row {
    type Error = RowDeError;

    fn try_from(r: &RowDe) -> Result<Self, Self::Error> {
        Ok(Self {
            is_first: r.is_first,
            sib: Hash::try_from(r.sib.as_str())?,
            depth: r.depth,
            path: BigUint::parse_bytes(r.path.as_bytes(), 2).ok_or(RowDeError::BigInt)?,
            path_acc: BigUint::parse_bytes(r.path_acc.as_bytes(), 2).ok_or(RowDeError::BigInt)?,
            old_hash_type: r.old_hash_type,
            old_hash: Hash::try_from(r.old_hash.as_str())?,
            old_value: Hash::try_from(r.old_value.as_str())?,
            new_hash_type: r.new_hash_type,
            new_hash: Hash::try_from(r.new_hash.as_str())?,
            new_value: Hash::try_from(r.new_value.as_str())?,
            key: Hash::try_from(r.key.as_str())?,
            new_root: Hash::try_from(r.new_root.as_str())?,
        })
    }
}

#[derive(Default, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
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
    fn test_de() {
        RowDe::from_lines(TEST_FILE).unwrap();
    }

    #[test]
    fn test_parse() {
        let rows: Result<Vec<Row>, RowDeError> = RowDe::from_lines(TEST_FILE)
            .unwrap()
            .iter()
            .map(Row::try_from)
            .collect();
        let rows = rows.unwrap();
        for row in rows.iter() {
            println!("{:?}", row);
        }
    }
}

/// Indicate the type of a row
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HashType {
    /// Empty node
    Empty = 1,
    /// middle node
    Middle,
    /// leaf node which is extended to middle in insert
    LeafExt,
    /// leaf node which is extended to middle in insert, which is the last node in new path
    LeafExtFinal,
    /// leaf node
    Leaf,
}
