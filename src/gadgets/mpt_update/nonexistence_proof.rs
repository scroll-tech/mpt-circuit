use crate::{
    constraint_builder::{AdviceColumn, ConstraintBuilder, Query, SecondPhaseAdviceColumn},
    gadgets::{is_zero::IsZeroGadget, poseidon::PoseidonLookup},
    types::HashDomain,
};
use halo2_proofs::arithmetic::FieldExt;

pub fn configure<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    value: SecondPhaseAdviceColumn,
    key: AdviceColumn,
    other_key: AdviceColumn,
    key_equals_other_key: IsZeroGadget,
    hash: AdviceColumn,
    hash_is_zero: IsZeroGadget,
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
            "hash == h(other_key, other_leaf_data_hash)",
            [
                other_key.current(),
                other_leaf_data_hash.current(),
                HashDomain::NodeTypeEmpty.into(),
                hash.current(),
            ],
            poseidon,
        );
    });
}
