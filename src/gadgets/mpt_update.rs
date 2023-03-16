use super::{key_bit::KeyBitLookup, poseidon::PoseidonLookup};
use crate::constraint_builder::{
    AdviceColumn, BinaryColumn, ConstraintBuilder, SelectorColumn, Query,
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
    old_hash: AdviceColumn,
    new_hash: AdviceColumn,

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
    direction: AdviceColumn, // this actually must be binary because of a lookup
    key: AdviceColumn,

    sibling: AdviceColumn,
}

impl MptUpdateConfig {
    fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
        poseidon: &impl PoseidonLookup,
        key_bit: &impl KeyBitLookup,
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
