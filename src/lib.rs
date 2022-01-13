//! mpt demo

#![allow(dead_code)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub use crate::serde::{Hash, Row, RowDeError};
use ::serde::Deserialize;

pub mod mpt;
pub mod operations;
mod serde;
#[cfg(test)]
mod test_utils;
