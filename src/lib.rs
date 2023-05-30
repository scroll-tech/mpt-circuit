//! mpt demo circuits
//

#![allow(dead_code)]
#![allow(unused_macros)]
#![allow(clippy::too_many_arguments)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub use crate::serde::{Hash, Row, RowDeError};

mod constraint_builder;
// mod eth;
mod gadgets;
// mod layers;
// mod mpt;
mod mpt_table;
mod types;
mod util;

// pub mod operation;
pub mod serde;

pub use hash_circuit::{hash, poseidon};
use hash::Hashable;

pub use mpt_table::MPTProofType;

/// Indicate the operation type of a row in MPT circuit
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashType {
    /// Marking the start of node
    Start = 0,
    /// Empty node
    Empty,
    /// middle node
    Middle,
    /// leaf node which is extended to middle in insert
    LeafExt,
    /// leaf node which is extended to middle in insert, which is the last node in new path
    LeafExtFinal,
    /// leaf node
    Leaf,
}
