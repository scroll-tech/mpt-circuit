use crate::types::{Claim, ClaimKind};
use strum_macros::EnumIter;

/// The defination is greped from state-circuit
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, Hash)]
pub enum MPTProofType {
    /// non exist proof for account
    AccountDoesNotExist = 0, // we want this to be zero so the default assigment of 0 everywhere is valid.
    /// nonce
    NonceChanged,
    /// balance
    BalanceChanged,
    /// keccak codehash updated
    CodeHashExists,
    /// poseidon codehash updated
    PoseidonCodeHashExists,
    /// code size updated
    CodeSizeExists,
    /// account destructed
    AccountDestructed,
    /// storage
    StorageChanged,
    /// non exist proof for storage
    StorageDoesNotExist,
}

impl From<Claim> for MPTProofType {
    fn from(claim: Claim) -> Self {
        match claim.kind {
            ClaimKind::Nonce { .. } => MPTProofType::NonceChanged,
            ClaimKind::Balance { .. } => MPTProofType::BalanceChanged,
            ClaimKind::PoseidonCodeHash { .. } => MPTProofType::PoseidonCodeHashExists,
            ClaimKind::CodeHash { .. } => MPTProofType::CodeHashExists,
            ClaimKind::CodeSize { .. } => MPTProofType::CodeSizeExists,
            ClaimKind::Storage { .. } => MPTProofType::StorageChanged,
            ClaimKind::IsEmpty(None) => MPTProofType::AccountDoesNotExist,
            ClaimKind::IsEmpty(Some(_)) => MPTProofType::StorageDoesNotExist,
        }
    }
}
