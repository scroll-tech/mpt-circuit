use super::{
    byte_representation::{BytesLookup, RlcLookup},
    key_bit::KeyBitLookup,
    poseidon::PoseidonLookup,
    is_zero_gadget::IsZeroGadget,
};
use crate::constraint_builder::{
    AdviceColumn, BinaryColumn, ConstraintBuilder, Query, SelectorColumn,
};
use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};

pub trait MptUpdateLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 4];
    // old_root,
    // new_root,
    // old_value,
    // new_value,
    // proof_type,
    // address,
    // storage_key
}

struct MptUpdateConfig {
    selector: SelectorColumn,

    // used for lookups
    old_root: AdviceColumn,
    new_root: AdviceColumn,

    old_value: [AdviceColumn; 2],
    new_value: [AdviceColumn; 2],
    proof_type: [BinaryColumn; 5],

    address: [AdviceColumn; 2],
    storage_key: [AdviceColumn; 2],

    // not used for lookups
    // exactly one of these is 1.
    is_common_path: BinaryColumn,
    old_hash_is_unchanged: BinaryColumn,
    new_hash_is_unchanged: BinaryColumn,

    // exactly one of these is 1.
    is_account_path: BinaryColumn,
    is_account_leaf: BinaryColumn,
    is_storage_path: BinaryColumn,

    depth: AdviceColumn,
    depth_is_zero: IsZeroGadget,
    direction: AdviceColumn, // this actually must be binary because of a KeyBitLookup
    key: AdviceColumn,

    sibling: AdviceColumn,
}

impl MptUpdateConfig {
    fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
        poseidon: &impl PoseidonLookup,
        key_bit: &impl KeyBitLookup,
        rlc: &impl RlcLookup,
        bytes: &impl BytesLookup,
    ) -> Self {
        let ([selector], [], []) = cb.build_columns(cs);

        let [old_hash, new_hash] = cb.advice_columns(cs);

        let old_value = cb.advice_columns(cs);
        let new_value = cb.advice_columns(cs);
        let proof_type = cb.binary_columns(cs);
        let address = cb.advice_columns(cs);
        let storage_key = cb.advice_columns(cs);

        let [is_common_path, old_hash_is_unchanged, new_hash_is_unchanged] = cb.binary_columns(cs);
        let [is_account_path, is_account_leaf, is_storage_path] = cb.binary_columns(cs);

        let [depth, direction, key, sibling] = cb.advice_columns(cs);

        [is_common_path, old_hash_is_unchanged, new_hash_is_unchanged].map(|column| {
            cb.add_constraint(
                "column is binary",
                selector.current(),
                Query::from(column.current()) * (Query::one() - column.current()),
            );
        });
        cb.add_constraint(
            "exactly one of is_common_path, old_hash_is_unchanged, and new_hash_is_unchanged is 1",
            selector.current(),
            Query::from(is_common_path.current())
                + old_hash_is_unchanged.current()
                + new_hash_is_unchanged.current(),
        );

        cb.add_constraint(
            "exactly one of is_account_path, is_account_leaf, and is_storage_path is 1",
            selector.current(),
            Query::from(is_account_path.current())
                + is_account_leaf.current()
                + is_storage_path.current(),
        );

        cb.add_constraint(
            "depth is 0 or depth increased by 1",
            selector.current(),
            depth.current() * (depth.current() - depth.previous() - 1),
        );
        cb.add_lookup(
            "direction is correct for key and depth",
            [key.current(), depth.current(), direction.current()],
            key_bit.lookup(),
        );
        let old_left =
            direction.current() * old_hash.previous() + !direction.current() * sibling.previous();
        let old_right =
            direction.current() * sibling.previous() + !direction.current() * old_hash.previous();
        cb.add_lookup(
            "poseidon hash correct for old path",
            [old_left, old_right, old_hash.current()],
            poseidon.lookup(),
        );
        cb.add_lookup("poseidon hash correct for new path", [], poseidon.lookup());

        Self {
            selector,
            old_hash,
            new_hash,
            old_value,
            new_value,
            proof_type,
            address,
            storage_key,
            is_common_path,
            old_hash_is_unchanged,
            new_hash_is_unchanged,
            is_account_path,
            is_account_leaf,
            is_storage_path,
            depth,
            direction,
            key,
            sibling,
        }
    }
}
