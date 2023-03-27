use super::{
    byte_representation::{BytesLookup, RlcLookup},
    is_zero::IsZeroGadget,
    key_bit::KeyBitLookup,
    poseidon::PoseidonLookup,
};
use crate::constraint_builder::{
    AdviceColumn, BinaryColumn, ConstraintBuilder, Query, SelectorColumn,
};
use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};

pub trait MptUpdateLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 7];
    // old_root, F
    // new_root, F
    // old_value, rlc
    // new_value, rlc
    // proof_type, 0--10
    // address, Address // get this from inputs to key hash
    // storage_key, rlc // get this from inputs to key hash, along with
}

struct MptUpdateConfig {
    selector: SelectorColumn,

    old_root: AdviceColumn, // can only change when depth = 0 and is_account_path is true
    new_root: AdviceColumn, // can only change when depth = 0 and is_account_path is true

    old_hash: AdviceColumn, // when depth = 0, old_hash = old_root
    new_hash: AdviceColumn, // when depth = 0, new_hash = new_root

    proof_type: [BinaryColumn; 5],

    address_hash: AdviceColumn, // poseideon hash of two halves of address
    storage_key_hash: AdviceColumn, // poseidon hash of two halves of storage key

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
        let ([selector], [], [old_root, new_root, old_hash, new_hash]) = cb.build_columns(cs);

        let proof_type = cb.binary_columns(cs);
        let [address_hash, storage_key_hash] = cb.advice_columns(cs);

        let [is_common_path, old_hash_is_unchanged, new_hash_is_unchanged] = cb.binary_columns(cs);
        let [is_account_path, is_account_leaf, is_storage_path] = cb.binary_columns(cs);

        let [depth, direction, sibling] = cb.advice_columns(cs);
        let depth_is_zero = IsZeroGadget::configure(cs, cb, selector.current(), depth);

        // constrain that exactly one of proof type is 1.

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

        // should be if path segment changes, then depth is 0. if not, it increases by 1.
        cb.add_constraint(
            "depth is 0 or depth increased by 1",
            selector.current(),
            depth.current() * (depth.current() - depth.previous() - 1),
        );
        let key = address_hash.current() * is_account_path.current()
            + storage_key_hash.current() * is_storage_path.current(); // + is_account_leaf...
        cb.add_lookup(
            "direction is correct for key and depth",
            [key, depth.current(), direction.current()],
            key_bit.lookup(),
        );
        let old_left = direction.current() * old_hash.previous()
            + (Query::one() - direction.current()) * sibling.previous();
        let old_right = direction.current() * sibling.previous()
            + (Query::one() - direction.current()) * old_hash.previous();
        cb.add_lookup(
            "poseidon hash correct for old path",
            [old_left, old_right, old_hash.current()],
            poseidon.lookup(),
        );
        // cb.add_lookup("poseidon hash correct for new path", [], poseidon.lookup());

        Self {
            selector,
            old_root,
            depth_is_zero,
            new_root,
            old_hash,
            new_hash,
            proof_type,
            address_hash,
            storage_key_hash,
            is_common_path,
            old_hash_is_unchanged,
            new_hash_is_unchanged,
            is_account_path,
            is_account_leaf,
            is_storage_path,
            depth,
            direction,
            sibling,
        }
    }
}
