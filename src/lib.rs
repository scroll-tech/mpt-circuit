#![allow(clippy::too_many_arguments)]
#![deny(unsafe_code, unused_imports)]

#[cfg(any(test, feature = "bench"))]
mod circuit;
pub mod constraint_builder;
pub mod gadgets;
mod mpt_table;
#[cfg(test)]
mod tests;
pub mod types;
mod util;

pub mod mpt;
pub mod serde;

pub use gadgets::mpt_update::hash_traces;
pub use mpt::MptCircuitConfig;
pub use mpt_table::MPTProofType;

#[cfg(feature = "bench")]
pub use circuit::TestCircuit;
