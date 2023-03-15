use crate::constraint_builder::{AdviceColumn, BinaryColumn, FixedColumn, Query};

use halo2_proofs::arithmetic::FieldExt;

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
    selector: FixedColumn,

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
    key: AdviceColumn,

    sibling: AdviceColumn,
}

// impl MptUpdateConfig {
//     fn configure(
//         cs: &mut ConstraintSystem<Fr>,
//         cb: &mut ConstraintBuilder<Fr>,
//         poseidon: &impl PoseidonLookup,
//         key_bit: &impl KeyBitLookup,
//     ) -> Self {
//         let (
//             [selector],
//             [],
//             [is_common_path, old_hash_is_unchanged, new_hash_is_unchanged, account_key, old_hash, new_hash, sibling, depth, direction],
//         ) = cb.build_columns(cs);

//         [is_common_path, old_hash_is_unchanged, new_hash_is_unchanged].map(|column| {
//             cb.add_constraint(
//                 "column is binary",
//                 selector.current(),
//                 column.current() * (Query::one() - column.current()),
//             );
//         });
//         cb.add_constraint(
//             "exactly one of is_common_path, old_hash_is_unchanged, and new_hash_is_unchanged is 1",
//             selector.current(),
//             is_common_path.current()
//                 + old_hash_is_unchanged.current()
//                 + new_hash_is_unchanged.current(),
//         );

//         // cb.add_constraint(
//         // 	""
//         // 	selector.current() * is_common_path.current()
//         // 	)

//         // cb.add_constraint(
//         //     "if common_path, ")

//         Self {
//             selector,
//             is_common_path,
//             old_hash_is_unchanged,
//             new_hash_is_unchanged,
//             depth,
//             direction,
//             account_key,
//             old_hash,
//             new_hash,
//             sibling,
//         }
//     }
// }

// impl MptUpdateLookup for MptUpdateConfig {
//     fn lookup<F: FieldExt>(&self) -> [Query<F>; 4] {
//         [
//             self.old_hash.current(),
//             self.new_hash.current(),
//             self.depth.current(),
//             self.account_key.current(),
//         ]
//     }
// }
