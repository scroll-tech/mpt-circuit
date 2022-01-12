//! mpt demo

#![allow(dead_code)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

/// Indicate the type of a row
#[derive(Clone, Copy, Debug)]
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

pub mod operations;
pub mod mpt;