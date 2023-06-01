use crate::types::{Claim, ClaimKind};
use strum_macros::EnumIter;

/// The defination is greped from state-circuit
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, Hash)]
pub enum MPTProofType {
    /// poseidon codehash updated
    PoseidonCodeHashExists,
    /// nonce
    NonceChanged,
    /// balance
    BalanceChanged,
    /// keccak codehash updated
    CodeHashExists,
    /// code size updated
    CodeSizeExists,
    /// account is empty
    AccountDoesNotExist,
    /// storage
    StorageChanged,
    /// non exist proof for storage
    StorageDoesNotExist,
    /// account destructed
    AccountDestructed,
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
