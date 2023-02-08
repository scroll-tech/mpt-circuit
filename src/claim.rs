#[derive(Clone, Copy, Debug)]
pub(crate) struct Claim {
    old_root: Fr,
    new_root: Fr,
    address: Address,
    kind: ClaimKind,
    old_value: U256,
    new_value: U256,
}

#[derive(Clone, Copy, Debug)]
enum ClaimKind {
    Nonce
    CodeHash,
    Balance,
    Storage(U256),
    IsEmpty,
}
