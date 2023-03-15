use crate::constraint_builder::{
    AdviceColumn, ConstraintBuilder, FixedColumn, Query, SelectorColumn,
};
use crate::gadgets::{
    account_update::AccountUpdateLookup, is_zero::IsZeroGadget, key_bit::KeyBitLookup,
    poseidon::PoseidonLookup,
};
use ethers_core::types::U256;
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::Region,
    halo2curves::bn256::Fr,
    plonk::ConstraintSystem,
};
use itertools::Itertools;
use num_traits::Zero;

pub trait MptUpdateLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 4];
}

struct MptUpdateConfig {
    selector: FixedColumn,

    is_common_path: AdviceColumn,
    old_hash_is_unchanged: AdviceColumn,
    new_hash_is_unchanged: AdviceColumn,

    account_key: AdviceColumn,
    depth: AdviceColumn,
    direction: AdviceColumn,

    old_hash: AdviceColumn,
    new_hash: AdviceColumn,
    sibling: AdviceColumn,
}

impl MptUpdateConfig {
    fn configure(
        cs: &mut ConstraintSystem<Fr>,
        cb: &mut ConstraintBuilder<Fr>,
        poseidon: &impl PoseidonLookup,
        key_bit: &impl KeyBitLookup,
        account_update: &impl AccountUpdateLookup,
    ) -> Self {
        let (
            [selector],
            [],
            [is_common_path, old_hash_is_unchanged, new_hash_is_unchanged, account_key, old_hash, new_hash, sibling],
        ) = cb.build_columns(cs);

        [is_common_path, old_hash_is_unchanged, new_hash_is_unchanged].map(|column| {
            cb.add_constraint(
                "column is binary",
                selector.current(),
                column.current() * (Query::one() - column.current()),
            );
        });
        cb.add_constraint(
            "exactly one of is_common_path, old_hash_is_unchanged, and new_hash_is_unchanged is 1",
            selector.current(),
            is_common_path.current()
                + old_hash_is_unchanged.current()
                + new_hash_is_unchanged.current(),
        );

        // cb.add_constraint(
        // 	""
        // 	selector.current() * is_common_path.current()
        // 	)

        // cb.add_constraint(
        //     "if common_path, ")

        Self {
            selector,
            is_common_path,
            old_hash_is_unchanged,
            new_hash_is_unchanged,
            account_key,
            old_hash,
            new_hash,
            sibling,
        }
    }
}

impl MptUpdateLookup for MptUpdateConfig {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 4] {
        [
            self.old_hash.current(),
            self.new_hash.current(),
            self.depth.current(),
            self.account_key.current(),
        ]
    }
}
