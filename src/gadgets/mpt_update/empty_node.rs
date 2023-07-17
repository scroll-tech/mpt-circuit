use crate::{
    constraint_builder::{AdviceColumn, ConstraintBuilder, Query, SecondPhaseAdviceColumn},
    gadgets::{is_zero::IsZeroGadget, poseidon::PoseidonLookup},
};
use halo2_proofs::{arithmetic::FieldExt, circuit::Region, halo2curves::bn256::Fr};

pub fn configure<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    value: SecondPhaseAdviceColumn,
    key: AdviceColumn,
    other_key: AdviceColumn,
    key_equals_other_key: IsZeroGadget,
    hash: AdviceColumn,
    hash_is_zero: IsZeroGadget,
    other_key_hash: AdviceColumn,
    other_leaf_data_hash: AdviceColumn,
    poseidon: &impl PoseidonLookup,
) {
    cb.assert_zero("value is 0 for empty node", value.current());
    cb.assert_equal(
        "key_minus_other_key = key - other key",
        key_equals_other_key.value.current(),
        key.current() - other_key.current(),
    );
    cb.assert_equal(
        "hash_is_zero input == hash",
        hash_is_zero.value.current(),
        hash.current(),
    );

    let is_type_1 = !key_equals_other_key.current();
    let is_type_2 = hash_is_zero.current();
    cb.assert_equal(
        "Empty account is either type 1 xor type 2",
        Query::one(),
        Query::from(is_type_1.clone()) + Query::from(is_type_2),
    );

    cb.condition(is_type_1, |cb| {
        cb.poseidon_lookup(
            "other_key_hash == h(1, other_key)",
            [Query::one(), other_key.current(), other_key_hash.current()],
            poseidon,
        );
        cb.poseidon_lookup(
            "hash == h(key_hash, other_leaf_data_hash)",
            [
                other_key_hash.current(),
                other_leaf_data_hash.current(),
                hash.current(),
            ],
            poseidon,
        );
    });
}

pub fn assign(
    region: &mut Region<'_, Fr>,
    offset: usize,
    (key_equals_other_key, key_minus_other_key): (IsZeroGadget, Fr),
    (final_hash_is_zero, final_hash): (IsZeroGadget, Fr),
    (other_key_hash_row, other_key_hash): (AdviceColumn, Fr),
    (other_leaf_data_hash_row, other_leaf_data_hash): (AdviceColumn, Fr),
) {
    key_equals_other_key.assign(region, offset, key_minus_other_key);
    final_hash_is_zero.assign(region, offset, final_hash);
    other_key_hash_row.assign(region, offset, other_key_hash);
    other_leaf_data_hash_row.assign(region, offset, other_leaf_data_hash);
}
