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

//

struct Claim {
    new: (Root, value)
    old: (root, value)

    address,
    kind:
}


each level of the


Claim {
    new: (digest, value)
    old: (digest, value)

    address:
    kind:
    depth:
}


claim -> claim if depth -> depth - 1,



updatetable {
    old:
    balance,
    nonce,
    code_hash,
    code_size,
    poseidon_code_hash,
    storage_root,

    new: {
        field,
        value,
    }
}

