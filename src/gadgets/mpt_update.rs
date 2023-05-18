mod path;
mod segment;
pub use path::PathType;
use segment::SegmentType;

use super::{
    byte_representation::{BytesLookup, RlcLookup},
    is_equal::IsEqualGadget,
    is_zero::IsZeroGadget,
    key_bit::KeyBitLookup,
    one_hot::OneHot,
    poseidon::PoseidonLookup,
    RANDOMNESS,
};
use crate::{
    constraint_builder::{AdviceColumn, ConstraintBuilder, Query},
    types::{
        account_key, hash,
        storage::{StorageEntry, StorageProof},
        trie::TrieRows,
        ClaimKind, Proof,
    },
    util::{rlc, storage_key_hash, u256_hi_lo, u256_to_big_endian}, // rlc is clobbered by rlc in configure....
    MPTProofType,
};
use ethers_core::{
    k256::elliptic_curve::PrimeField,
    types::{Address, U256},
};
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::Region,
    halo2curves::bn256::Fr,
    plonk::ConstraintSystem,
};
use itertools::izip;
use lazy_static::lazy_static;
use strum::IntoEnumIterator;

// TODO: we also need to check that the account hasn
// is hash(0, 0)
// Speaking strictly, this is not needed, since non-empty accounts cannot become empty.
// We DO need something similar for the storage trie though.
lazy_static! {
    static ref ZERO_ACCOUNT_HASH: Fr = Fr::zero();
}

pub trait MptUpdateLookup<F: FieldExt> {
    fn lookup(&self) -> [Query<F>; 7];
}

// if there's a leaf witness
//  - on the old side, you end at Common (should this be extension then? it shou), AccountLeaf0.
//      - the general rule for Extension should be that the sibling hashes need not be the same?
//  - on the new side, there are 1 or more ExtensionNew, AccountTrie's followed by Extension, AccountLeaf0
// this will be combined like so:
// (Common, AccountTrie)
// ...
// (Common, AccountTrie)
// (Extension, AccountTrie)
// ...
// (Extension, AccountTrie)
// (Extension, AccountLeaf0) // this may be a bit tricky? because on the new side you need to show the key hash is correct for the target address
//                           // you also need to show on the old side that the key hash does not match the target address.
// (Extension, AccountLeaf1)
// ...
// if there's an emptynode witness:
//  - on the old side, it is just (0, sibling).
//  - on the new side, you need to replace 0 with the hash of the new account.
//  - this means you go from Common, AccountTrie -> Extension, AccountLeaf0

#[derive(Clone)]
struct MptUpdateConfig<F: FieldExt> {
    // Lookup columns
    old_hash: AdviceColumn,
    new_hash: AdviceColumn,
    old_value: AdviceColumn, // nonce and codesize are not rlc'ed the others are.
    new_value: AdviceColumn, //
    proof_type: OneHot<MPTProofType>,
    address: AdviceColumn,
    storage_key_rlc: AdviceColumn,

    segment_type: OneHot<SegmentType>,
    path_type: OneHot<PathType>,
    depth: AdviceColumn,

    key: AdviceColumn,

    // These three columns are used to verify a type 1 non-existence proof.
    other_key: AdviceColumn,
    other_key_hash: AdviceColumn,
    other_leaf_data_hash: AdviceColumn,

    // These two are used to verify a type 2 non-existence proof.
    old_hash_is_zero: IsZeroGadget,
    new_hash_is_zero: IsZeroGadget,

    // // These two are needed to prove that a zero account is not in from the MPT.
    // old_hash_is_zero_account_hash: IsEqualGadget<F>,
    // new_hash_is_zero_account_hash: IsEqualGadget<F>,
    key_equals_other_key: IsEqualGadget<F>,
    direction: AdviceColumn, // this actually must be binary because of a KeyBitLookup

    sibling: AdviceColumn,

    // use this for upper/lower half lookups.
    upper_128_bits: AdviceColumn, // most significant 128 bits of address or storage key

                                  // not_equal_witness, // inverse used to prove to expressions are not equal.

                                  // TODO
                                  // nonfirst_rows: SelectorColumn, // Enabled on all rows except the last one.
}

impl<F: FieldExt> MptUpdateLookup<F> for MptUpdateConfig<F> {
    fn lookup(&self) -> [Query<F>; 7] {
        let is_start = || self.segment_type.current_matches(&[SegmentType::Start]);
        let old_root = self.old_hash.current() * is_start();
        let new_root = self.new_hash.current() * is_start();
        let proof_type = self.proof_type.current();
        let old_value = self.old_value.current() * is_start();
        let new_value = self.new_value.current() * is_start();
        let address = self.address.current() * is_start();
        let storage_key_rlc = self.storage_key_rlc.current() * is_start();

        [
            proof_type,
            old_root,
            new_root,
            old_value,
            new_value,
            address,
            storage_key_rlc,
        ]
    }
}

impl<F: FieldExt> MptUpdateConfig<F> {
    fn configure(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
        poseidon: &impl PoseidonLookup,
        key_bit: &impl KeyBitLookup,
        rlc: &impl RlcLookup,
        bytes: &impl BytesLookup,
    ) -> Self {
        let ([], [], [old_hash, new_hash]) = cb.build_columns(cs);

        let proof_type = OneHot::configure(cs, cb);
        let [address, storage_key_rlc] = cb.advice_columns(cs);
        let [old_value, new_value] = cb.advice_columns(cs);
        let [depth, key, direction, sibling, upper_128_bits] = cb.advice_columns(cs);

        let [other_key, other_key_hash, other_leaf_data_hash, other_leaf_hash] =
            cb.advice_columns(cs);

        let segment_type = OneHot::configure(cs, cb);
        let path_type = OneHot::configure(cs, cb);

        let is_trie =
            segment_type.current_matches(&[SegmentType::AccountTrie, SegmentType::StorageTrie]);

        cb.condition(is_trie.clone(), |cb| {
            cb.add_lookup(
                "direction is correct for key and depth",
                [key.current(), depth.current() - 1, direction.current()],
                key_bit.lookup(),
            );
            cb.assert_equal(
                "depth increases by 1 in trie segments",
                depth.current(),
                depth.previous() + 1,
            );

            cb.condition(path_type.current_matches(&[PathType::Common]), |cb| {
                cb.add_lookup(
                    "direction is correct for other_key and depth",
                    [
                        other_key.current(),
                        depth.current() - 1,
                        direction.current(),
                    ],
                    key_bit.lookup(),
                );
            });
        });
        cb.condition(!is_trie, |cb| {
            cb.assert_zero("key is 0 in non-trie segments", key.current());
            cb.assert_zero("depth is 0 in non-trie segments", depth.current());
        });

        // TODO: enable this where needed!!
        // cb.add_lookup(
        //     "upper_128_bits is 16 bytes",
        //     [upper_128_bits.current(), Query::from(15)],
        //     bytes.lookup(),
        // );

        let old_hash_is_zero = IsZeroGadget::configure(cs, cb, old_hash);
        let new_hash_is_zero = IsZeroGadget::configure(cs, cb, new_hash);

        // let old_hash_is_zero_account_hash =
        //     IsEqualGadget::configure(cs, cb, old_hash.current(), Query::zero()); // problem is here because you need to construct a query over Fr.
        // let new_hash_is_zero_account_hash =
        //     IsEqualGadget::configure(cs, cb, new_hash.current(), Query::zero());

        let key_equals_other_key =
            IsEqualGadget::configure(cs, cb, key.current(), other_key.current());

        let config = Self {
            key,
            old_hash,
            new_hash,
            proof_type,
            old_value,
            new_value,
            address,
            storage_key_rlc,
            segment_type,
            path_type,
            other_key,
            other_leaf_data_hash,
            other_key_hash,
            depth,
            direction,
            sibling,
            upper_128_bits,
            key_equals_other_key,
            old_hash_is_zero,
            new_hash_is_zero,
            // old_hash_is_zero_account_hash,
            // new_hash_is_zero_account_hash,
        };

        // Transitions for state machines:
        // TODO: rethink this justification later.... maybe we can just do the forward transitions?
        // We constrain backwards transitions (instead of the forward ones) because the
        // backwards transitions can be enabled on every row except the first (instead
        // of every row except the last). This makes the setting the selectors more
        // consistent between the tests, where the number of active rows is small,
        // and in production, where the number is much larger.
        // for (sink, sources) in segment::backward_transitions().iter() {
        //     cb.condition(config.segment_type.current_matches(&[*sink]), |cb| {
        //         cb.assert(
        //             "backward transition for segment",
        //             config.segment_type.previous_matches(&sources),
        //         );
        //     });
        // }
        // for (sink, sources) in path::backward_transitions().iter() {
        //     cb.condition(config.path_type.current_matches(&[*sink]), |cb| {
        //         cb.assert(
        //             "backward transition for path",
        //             config.path_type.previous_matches(&sources),
        //         );
        //     });
        // }
        // Depth increases by one iff segment type is unchanged, else it is 0?

        for variant in PathType::iter() {
            let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
                PathType::Start => {} // TODO
                PathType::Common => configure_common_path(cb, &config, poseidon),
                PathType::ExtensionOld => configure_extension_old(cb, &config, poseidon),
                PathType::ExtensionNew => configure_extension_new(cb, &config, poseidon),
            };
            cb.condition(
                config.path_type.current_matches(&[variant]),
                conditional_constraints,
            );
        }

        for variant in MPTProofType::iter() {
            let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
                MPTProofType::NonceChanged => configure_nonce(cb, &config, bytes, poseidon),
                MPTProofType::BalanceChanged => configure_balance(cb, &config, poseidon, rlc),
                MPTProofType::CodeSizeExists => configure_code_size(cb, &config, bytes, poseidon),
                MPTProofType::PoseidonCodeHashExists => {
                    configure_poseidon_code_hash(cb, &config, poseidon)
                }
                MPTProofType::CodeHashExists => {
                    configure_keccak_code_hash(cb, &config, poseidon, bytes, rlc)
                }
                MPTProofType::StorageChanged => {
                    configure_storage(cb, &config, poseidon, bytes, rlc)
                }
                _ => cb.assert_unreachable("unimplemented!"),
            };
            cb.condition(
                config.proof_type.current_matches(&[variant]),
                conditional_constraints,
            );
        }

        config
    }

    fn assign(&self, region: &mut Region<'_, Fr>, proofs: &[Proof]) {
        let randomness = Fr::from(RANDOMNESS);

        let mut offset = 0;
        for proof in proofs {
            let proof_type = MPTProofType::from(proof.claim);
            let address = address_to_fr(proof.claim.address);
            let storage_key = rlc(&u256_to_big_endian(&proof.claim.storage_key()), randomness);
            let old_value = proof.claim.old_value_assignment(randomness);
            let new_value = proof.claim.new_value_assignment(randomness);

            for i in 0..proof.n_rows() {
                self.proof_type.assign(region, offset + i, proof_type);
                self.address.assign(region, offset + i, address);
                self.storage_key_rlc.assign(region, offset + i, storage_key);
                self.old_value.assign(region, offset + i, old_value);
                self.new_value.assign(region, offset + i, new_value);
            }

            let key = account_key(proof.claim.address);
            let (other_key, other_key_hash, other_leaf_data_hash) =
                // checking if type 1 or type 2
                if proof.old.key != key {
                    assert!(proof.new.key == key || proof.new.key == proof.old.key);
                    (proof.old.key, proof.old.key_hash, proof.old.leaf_data_hash.unwrap())
                } else if proof.new.key != key {
                    assert!(proof.old.key == key);
                    (proof.new.key, proof.new.key_hash, proof.new.leaf_data_hash.unwrap())
                } else {
                    // neither is a type 1 path
                    // handle type 0 and type 2 paths here:
                    (proof.old.key, proof.old.key_hash, proof.new.leaf_data_hash.unwrap_or_default())
                };

            let mut path_type = PathType::Start; // should get rid of this variant and just start from Common.

            // Assign start row
            self.segment_type.assign(region, offset, SegmentType::Start);
            self.path_type.assign(region, offset, path_type);
            self.old_hash.assign(region, offset, proof.claim.old_root);
            self.old_hash_is_zero
                .assign(region, offset, proof.claim.old_root);
            // self.old_hash_is_zero_account_hash.assign(
            //     region,
            //     offset,
            //     proof.claim.old_root,
            //     *ZERO_ACCOUNT_HASH,
            // );
            self.new_hash.assign(region, offset, proof.claim.new_root);
            self.new_hash_is_zero
                .assign(region, offset, proof.claim.new_root);
            // self.new_hash_is_zero_account_hash.assign(
            //     region,
            //     offset,
            //     proof.claim.new_root,
            //     *ZERO_ACCOUNT_HASH,
            // );
            self.key_equals_other_key
                .assign(region, offset, Fr::zero(), Fr::zero());

            offset += 1;

            let mut previous_old_hash = proof.claim.old_root;
            let mut previous_new_hash = proof.claim.new_root;
            for (
                depth,
                (direction, old_hash, new_hash, sibling, is_padding_open, is_padding_close),
            ) in proof.address_hash_traces.iter().rev().enumerate()
            {
                self.depth
                    .assign(region, offset, u64::try_from(depth + 1).unwrap());
                self.segment_type
                    .assign(region, offset, SegmentType::AccountTrie);
                path_type = match (*is_padding_open, *is_padding_close) {
                    (false, false) => PathType::Common,
                    (false, true) => {
                        assert_eq!(*new_hash, previous_new_hash);
                        PathType::ExtensionOld
                    }
                    (true, false) => {
                        assert_eq!(*old_hash, previous_old_hash);
                        PathType::ExtensionNew
                    }
                    (true, true) => unreachable!(),
                };
                self.path_type.assign(region, offset, path_type);

                self.sibling.assign(region, offset, *sibling);
                self.old_hash.assign(region, offset, *old_hash);
                self.old_hash_is_zero.assign(region, offset, *old_hash);
                // self.old_hash_is_zero_account_hash.assign(
                //     region,
                //     offset,
                //     *old_hash,
                //     *ZERO_ACCOUNT_HASH,
                // );
                self.new_hash.assign(region, offset, *new_hash);
                self.new_hash_is_zero.assign(region, offset, *new_hash);
                // self.new_hash_is_zero_account_hash.assign(
                //     region,
                //     offset,
                //     *new_hash,
                //     *ZERO_ACCOUNT_HASH,
                // );
                self.direction.assign(region, offset, *direction);

                let key = account_key(proof.claim.address);
                self.key.assign(region, offset, key);
                self.other_key.assign(region, offset, other_key);
                self.key_equals_other_key
                    .assign(region, offset, key, other_key);

                match path_type {
                    PathType::Start => {}
                    PathType::Common => {
                        if *direction {
                            assert_eq!(hash(*sibling, *old_hash), previous_old_hash);
                            assert_eq!(hash(*sibling, *new_hash), previous_new_hash);
                        } else {
                            assert_eq!(hash(*old_hash, *sibling), previous_old_hash);
                            assert_eq!(hash(*new_hash, *sibling), previous_new_hash);
                        }
                        previous_old_hash = *old_hash;
                        previous_new_hash = *new_hash;
                    }
                    PathType::ExtensionOld => {
                        assert_eq!(*new_hash, previous_new_hash);
                        if *direction {
                            assert_eq!(hash(*sibling, *old_hash), previous_old_hash);
                        } else {
                            assert_eq!(hash(*old_hash, *sibling), previous_old_hash);
                        }
                        previous_old_hash = *old_hash;
                    }
                    PathType::ExtensionNew => {
                        assert_eq!(*old_hash, previous_old_hash);
                        if *direction {
                            assert_eq!(hash(*sibling, *new_hash), previous_new_hash);
                        } else {
                            assert_eq!(hash(*new_hash, *sibling), previous_new_hash);
                        }
                        previous_new_hash = *new_hash;
                    }
                }
                offset += 1;
            }

            let segment_types = vec![
                SegmentType::AccountLeaf0,
                SegmentType::AccountLeaf1,
                SegmentType::AccountLeaf2,
                SegmentType::AccountLeaf3,
                SegmentType::AccountLeaf4,
            ];
            // Need to figure out the path type for the account leaf rows
            // this is either a leaf hash or 0 (hash of empty node).
            let (final_old_hash, final_new_hash) = match proof.address_hash_traces.first() {
                None => continue, // entire mpt is empty, so no leaf rows to assign.
                Some((_, final_old_hash, final_new_hash, _, _, _)) => {
                    (final_old_hash, final_new_hash)
                }
            };
            path_type = match path_type {
                PathType::Common => {
                    // need to check for type 2 non-existence proof
                    match (
                        final_old_hash.is_zero_vartime(),
                        final_new_hash.is_zero_vartime(),
                    ) {
                        (true, true) => {
                            continue;
                        } // type 2 account non-existence proof. we don't need to assign any leaf rows.
                        (true, false) => PathType::ExtensionNew,
                        (false, true) => PathType::ExtensionOld,
                        (false, false) => PathType::Common,
                    }
                }
                _ => path_type,
            };

            // TODO: this doesn't handle the case where both old and new accounts are empty.
            let directions = match proof_type {
                MPTProofType::NonceChanged | MPTProofType::CodeSizeExists => {
                    vec![true, false, false, false]
                }
                MPTProofType::BalanceChanged => vec![true, false, false, true],
                MPTProofType::PoseidonCodeHashExists => vec![true, true],
                MPTProofType::CodeHashExists => vec![true, false, true, true],
                MPTProofType::StorageChanged => vec![true, false, true, false],
                _ => unimplemented!(),
            };
            let next_offset = offset + directions.len();

            let old_hashes = proof
                .old_account_leaf_hashes()
                .unwrap_or_else(|| vec![*final_old_hash; 4]);
            let new_hashes = proof
                .new_account_leaf_hashes()
                .unwrap_or_else(|| vec![*final_new_hash; 4]);
            let siblings = proof.account_leaf_siblings();

            for (i, (segment_type, sibling, old_hash, new_hash, direction)) in
                izip!(segment_types, siblings, old_hashes, new_hashes, directions).enumerate()
            {
                self.segment_type.assign(region, offset + i, segment_type);
                self.path_type.assign(region, offset + i, path_type);
                self.sibling.assign(region, offset + i, sibling);
                self.old_hash.assign(region, offset + i, old_hash);
                self.old_hash_is_zero.assign(region, offset + i, old_hash);
                // self.old_hash_is_zero_account_hash.assign(
                //     region,
                //     offset + i,
                //     old_hash,
                //     *ZERO_ACCOUNT_HASH,
                // );

                self.new_hash.assign(region, offset + i, new_hash);
                self.new_hash_is_zero.assign(region, offset + i, new_hash);
                // self.new_hash_is_zero_account_hash.assign(
                //     region,
                //     offset + i,
                //     new_hash,
                //     *ZERO_ACCOUNT_HASH,
                // );

                self.direction.assign(region, offset + i, direction);
                // TODO: would it be possible to assign key here to make the keybit lookup unconditional?

                match segment_type {
                    SegmentType::AccountLeaf0 => {
                        self.other_key.assign(region, offset, other_key);
                        self.other_key_hash.assign(region, offset, other_key_hash);
                        self.other_leaf_data_hash
                            .assign(region, offset, other_leaf_data_hash);
                        self.key_equals_other_key
                            .assign(region, offset + i, Fr::zero(), other_key);
                    }
                    _ => {
                        self.key_equals_other_key.assign(
                            region,
                            offset + i,
                            Fr::zero(),
                            Fr::zero(),
                        );
                    }
                };
            }
            self.upper_128_bits.assign(
                region,
                offset,
                Fr::from_u128(address_high(proof.claim.address)),
            );
            match proof.claim.kind {
                ClaimKind::CodeHash { old, new } => {
                    let assign = |region: &mut Region<'_, Fr>,
                                  value,
                                  u128_column: AdviceColumn,
                                  rlc_column: AdviceColumn| {
                        let (high, low) = u256_hi_lo(&value);
                        u128_column.assign(region, offset + 2, Fr::from_u128(high));
                        u128_column.assign(region, offset + 3, Fr::from_u128(low));
                        let rlc_high = rlc(&high.to_be_bytes(), randomness);
                        let rlc_low = rlc(&low.to_be_bytes(), randomness);
                        rlc_column.assign(region, offset + 2, rlc_high);
                        rlc_column.assign(region, offset + 3, rlc_low);
                    };
                    if let Some(value) = old {
                        assign(region, value, self.other_key_hash, self.other_key);
                        let (high, low) = u256_hi_lo(&value);
                        self.key_equals_other_key.assign(
                            region,
                            offset + 2,
                            Fr::zero(),
                            rlc(&high.to_be_bytes(), randomness),
                        );
                        self.key_equals_other_key.assign(
                            region,
                            offset + 3,
                            Fr::zero(),
                            rlc(&low.to_be_bytes(), randomness),
                        );
                    }
                    if let Some(value) = new {
                        assign(
                            region,
                            value,
                            self.upper_128_bits,
                            self.other_leaf_data_hash,
                        );
                    }
                }
                _ => (),
            }

            self.assign_storage(region, next_offset, &proof.storage);
        }
    }

    fn assign_trie_rows(
        &self,
        region: &mut Region<'_, Fr>,
        starting_offset: usize,
        rows: &TrieRows,
    ) -> usize {
        for (i, row) in rows.0.iter().enumerate() {
            let offset = starting_offset + i;
            self.depth
                .assign(region, offset, u64::try_from(i + 1).unwrap());
            self.path_type.assign(region, offset, row.path_type);

            for (value, column) in [
                (row.sibling, self.sibling),
                (row.old, self.old_hash),
                (row.new, self.new_hash),
                (row.direction.into(), self.direction),
            ] {
                column.assign(region, offset, value);
            }

            for (value, gadget) in [
                (row.old, self.old_hash_is_zero),
                (row.new, self.new_hash_is_zero),
            ] {
                gadget.assign(region, offset, value);
            }
        }
        rows.len()
    }

    fn assign_storage(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        storage: &StorageProof,
    ) -> usize {
        match storage {
            StorageProof::Root(_) => 0,
            StorageProof::Update {
                path,
                trie_rows,
                old_entry,
                new_entry,
            } => {
                let n_trie_rows = self.assign_trie_rows(region, offset, trie_rows);
                for i in 0..n_trie_rows {
                    self.segment_type
                        .assign(region, offset + i, SegmentType::StorageTrie);
                    self.key.assign(region, offset + i, *path);
                    self.other_key.assign(region, offset + i, *path);
                    self.key_equals_other_key
                        .assign(region, offset + i, *path, *path);
                }
                let n_leaf_rows = self.assign_storage_leaf_row(
                    region,
                    offset + n_trie_rows,
                    old_entry,
                    new_entry,
                );
                n_trie_rows + n_leaf_rows
            }
        }
    }

    fn assign_storage_leaf_row(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        old: &StorageEntry,
        new: &StorageEntry,
    ) -> usize {
        self.segment_type
            .assign(region, offset, SegmentType::StorageLeaf0);
        self.direction.assign(region, offset, true);
        self.sibling.assign(region, offset, old.path_hash());

        let old_hash = old.value_hash();
        let new_hash = new.value_hash();
        self.old_hash.assign(region, offset, old_hash);
        self.new_hash.assign(region, offset, new_hash);
        self.old_hash_is_zero.assign(region, offset, old_hash);
        self.new_hash_is_zero.assign(region, offset, new_hash);

        let assign_word = |region: &mut Region<'_, Fr>, word: U256, column: &AdviceColumn| {
            let (high, low) = u256_hi_lo(&word);
            let rlc_high = rlc(&high.to_be_bytes(), Fr::from(RANDOMNESS));
            let rlc_low = rlc(&low.to_be_bytes(), Fr::from(RANDOMNESS));
            column.assign(region, offset, Fr::from_u128(high));
            column.assign(region, offset - 1, Fr::from_u128(low));
            column.assign(region, offset - 2, rlc_high);
            column.assign(region, offset - 3, rlc_low);
        };

        assign_word(region, old.key, &self.upper_128_bits);
        self.upper_128_bits.assign(region, offset - 4, old.path());
        assign_word(region, old.value, &self.other_key_hash);
        assign_word(region, new.value, &self.other_leaf_data_hash);

        1
    }
}

fn old_left<F: FieldExt>(config: &MptUpdateConfig<F>) -> Query<F> {
    config.direction.current() * config.sibling.current()
        + (Query::one() - config.direction.current()) * config.old_hash.current()
}

fn old_right<F: FieldExt>(config: &MptUpdateConfig<F>) -> Query<F> {
    config.direction.current() * config.old_hash.current()
        + (Query::one() - config.direction.current()) * config.sibling.current()
}

fn new_left<F: FieldExt>(config: &MptUpdateConfig<F>) -> Query<F> {
    config.direction.current() * config.sibling.current()
        + (Query::one() - config.direction.current()) * config.new_hash.current()
}

fn new_right<F: FieldExt>(config: &MptUpdateConfig<F>) -> Query<F> {
    config.direction.current() * config.new_hash.current()
        + (Query::one() - config.direction.current()) * config.sibling.current()
}

fn address_to_fr(a: Address) -> Fr {
    let mut bytes = [0u8; 32];
    bytes[32 - 20..].copy_from_slice(a.as_bytes());
    bytes.reverse();
    Fr::from_repr(bytes).unwrap()
}

fn configure_common_path<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig<F>,
    poseidon: &impl PoseidonLookup,
) {
    cb.add_lookup(
        "poseidon hash correct for old common path",
        [
            old_left(config),
            old_right(config),
            config.old_hash.previous(),
        ],
        poseidon.lookup(),
    );
    cb.add_lookup(
        "poseidon hash correct for new common path",
        [
            new_left(config),
            new_right(config),
            config.new_hash.previous(),
        ],
        poseidon.lookup(),
    );

    // These apply for AccountTrie rows....
    // If this is the final row of this update, then the proof type must be
    // cb.condition(config.path_type.next_matches(PathType::Start), |cb| {
    //     cb.assert("type 2 non-existence proof if no account leaf rows", config.proof.current_matches(MPTProofType::AccountDoesNotExist));
    //     cb.assert_zero(
    //         "old value is 0 for type 2 non-existence proof",
    //         config.old_value.current(),
    //     );
    //     cb.assert_zero(
    //         "new value is 0 for type 2 non-existence proof",
    //         config.new_value.current(),
    //     );
    // });
    cb.condition(
        config
            .path_type
            .next_matches(&[PathType::ExtensionNew])
            .and(
                config
                    .segment_type
                    .next_matches(&[SegmentType::AccountLeaf0]),
            ),
        |cb| {
            cb.assert_zero(
                "old hash is zero for type 2 empty account",
                config.old_hash.current(),
            )
        },
    );
    cb.condition(
        config
            .path_type
            .next_matches(&[PathType::ExtensionOld])
            .and(
                config
                    .segment_type
                    .next_matches(&[SegmentType::AccountLeaf0]),
            ),
        |cb| {
            cb.assert_zero(
                "new hash is zero for type 2 empty account",
                config.new_hash.current(),
            )
        },
    );
}

fn configure_extension_old<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig<F>,
    poseidon: &impl PoseidonLookup,
) {
    // TODO: add these once you create the test json.
    // cb.add_lookup(
    //     "poseidon hash correct for old path",
    //     [
    //         old_left(config),
    //         old_right(config),
    //         config.old_hash.current(),
    //     ],
    //     poseidon.lookup(),
    // );
    // need to check that
    let is_final_trie_segment = config
        .segment_type
        .current_matches(&[SegmentType::AccountTrie, SegmentType::StorageTrie])
        .and(
            !config
                .segment_type
                .next_matches(&[SegmentType::AccountTrie, SegmentType::StorageTrie]),
        );
    cb.condition(!is_final_trie_segment.clone(), |cb| {
        cb.assert_zero(
            "sibling is zero for non-final old extension path segments",
            config.sibling.current(),
        );
    });
    cb.condition(is_final_trie_segment, |cb| {
        // TODO: assert that the leaf that was being used as the non-empty witness is put here....
    });
    cb.assert_equal(
        "new_hash unchanged for path_type=Old",
        config.new_hash.current(),
        config.new_hash.previous(),
    );
}

fn configure_extension_new<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig<F>,
    poseidon: &impl PoseidonLookup,
) {
    cb.assert_zero(
        "old value is 0 if old account is empty",
        config.old_value.current(),
    );

    let is_trie_segment = config
        .segment_type
        .current_matches(&[SegmentType::AccountTrie, SegmentType::StorageTrie]);
    cb.condition(is_trie_segment, |cb| {
        let is_final_trie_segment = !config
            .segment_type
            .next_matches(&[SegmentType::AccountTrie, SegmentType::StorageTrie]);
        cb.condition(!is_final_trie_segment.clone(), |cb| {
            cb.assert_zero(
                "sibling is zero for non-final new extension path segments",
                config.sibling.current(),
            )
        });
        cb.condition(is_final_trie_segment, |cb| {
            cb.assert_equal(
                "sibling is old leaf hash for final new extension path segments",
                config.sibling.current(),
                config.old_hash.current(),
            )
        });
    });

    cb.assert_equal(
        "old_hash unchanged for path_type=New",
        config.old_hash.current(),
        config.old_hash.previous(),
    );
    cb.add_lookup(
        "poseidon hash correct for new path",
        [
            new_left(config),
            new_right(config),
            config.new_hash.previous(),
        ],
        poseidon.lookup(),
    );
    cb.condition(
        config
            .segment_type
            .current_matches(&[SegmentType::AccountLeaf0]),
        |cb| {
            cb.add_lookup(
                "other_key_hash = h(1, other_key)",
                [
                    Query::one(),
                    config.other_key.current(),
                    config.other_key_hash.current(),
                ],
                poseidon.lookup(),
            );

            cb.condition(!config.old_hash_is_zero.current(), |cb| {
                cb.add_lookup(
                    "previous old_hash = h(data_hash, key_hash)",
                    [
                        config.other_key_hash.current(),
                        config.other_leaf_data_hash.current(),
                        config.old_hash.previous(),
                    ],
                    poseidon.lookup(),
                );
            });
            // A type 1 account is an empty account in an MPT where another leaf occupies the node where it would be.
            let old_account_is_type_1 = !config.key_equals_other_key.clone().current();
            cb.condition(!config.key_equals_other_key.clone().current(), |cb| {
                // cb.assert_unreachable("asdfasdfasfd");
                cb.assert_zero(
                    "if old account is type 1, then old value is 0",
                    config.old_value.current(),
                );
            })
        },
    );
    // Need to check that other key !=  key for type 1 and other_key = key for type 2
}

fn configure_nonce<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig<F>,
    bytes: &impl BytesLookup,
    poseidon: &impl PoseidonLookup,
) {
    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::Start | SegmentType::AccountTrie => {}
            SegmentType::AccountLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());

                // this should hold for all MPTProofType's
                let address_low: Query<F> = (config.address.current()
                    - config.upper_128_bits.current() * (1 << 32))
                    * (1 << 32)
                    * (1 << 32)
                    * (1 << 32);
                cb.add_lookup(
                    "key = h(address_high, address_low)",
                    [
                        config.upper_128_bits.current(),
                        address_low,
                        config.key.previous(),
                    ],
                    poseidon.lookup(),
                );
                cb.add_lookup(
                    "sibling = h(1, key)",
                    [
                        Query::one(),
                        // this could be Start, which could have key = 0. Do we need to special case that?
                        // We could also just assign a non-zero key here....
                        config.key.previous(),
                        config.sibling.current(),
                    ],
                    poseidon.lookup(),
                );
            }
            SegmentType::AccountLeaf1 => {
                cb.assert_zero("direction is 0", config.direction.current());
            }
            SegmentType::AccountLeaf2 => {
                cb.assert_zero("direction is 0", config.direction.current());
            }
            SegmentType::AccountLeaf3 => {
                cb.assert_zero("direction is 0", config.direction.current());

                let old_code_size = (config.old_hash.current() - config.old_value.current())
                    * Query::Constant(F::from(1 << 32).square().invert().unwrap()); // should this be 64?
                let new_code_size = (config.new_hash.current() - config.new_value.current())
                    * Query::Constant(F::from(1 << 32).square().invert().unwrap());
                cb.condition(
                    config.path_type.current_matches(&[PathType::Common]),
                    |cb| {
                        cb.add_lookup(
                            "old nonce is 8 bytes",
                            [config.old_value.current(), Query::from(7)],
                            bytes.lookup(),
                        );
                        cb.add_lookup(
                            "new nonce is 8 bytes",
                            [config.old_value.current(), Query::from(7)],
                            bytes.lookup(),
                        );
                        cb.assert_equal(
                            "old_code_size = new_code_size for nonce update",
                            old_code_size.clone(),
                            new_code_size.clone(),
                        );
                        cb.add_lookup(
                            "existing code size is 8 bytes",
                            [old_code_size.clone(), Query::from(7)],
                            bytes.lookup(),
                        );
                    },
                );
                cb.condition(
                    config.path_type.current_matches(&[PathType::ExtensionNew]),
                    |cb| {
                        cb.add_lookup(
                            "new nonce is 8 bytes",
                            [config.old_value.current(), Query::from(7)],
                            bytes.lookup(),
                        );
                        cb.assert_zero(
                            "code size is 0 for ExtensionNew nonce update",
                            new_code_size,
                        );
                    },
                );
                cb.condition(
                    config.path_type.current_matches(&[PathType::ExtensionOld]),
                    |cb| {
                        cb.add_lookup(
                            "old nonce is 8 bytes",
                            [config.old_value.current(), Query::from(7)],
                            bytes.lookup(),
                        );
                        cb.assert_zero(
                            "code size is 0 for ExtensionOld nonce update",
                            old_code_size,
                        );
                    },
                );
            }
            SegmentType::AccountLeaf4
            | SegmentType::StorageTrie
            | SegmentType::StorageLeaf0
            | SegmentType::StorageLeaf1 => {
                cb.assert_unreachable("unreachable segment type for nonce update")
            }
        };
        cb.condition(
            config.segment_type.current_matches(&[variant]),
            conditional_constraints,
        );
    }
}

fn configure_code_size<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig<F>,
    bytes: &impl BytesLookup,
    poseidon: &impl PoseidonLookup,
) {
    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::Start | SegmentType::AccountTrie => {}
            SegmentType::AccountLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());

                // this should hold for all MPTProofType's
                let address_low: Query<F> = (config.address.current()
                    - config.upper_128_bits.current() * (1 << 32))
                    * (1 << 32)
                    * (1 << 32)
                    * (1 << 32);
                cb.add_lookup(
                    "key = h(address_high, address_low)",
                    [
                        config.upper_128_bits.current(),
                        address_low,
                        config.key.previous(),
                    ],
                    poseidon.lookup(),
                );
                cb.add_lookup(
                    "sibling = h(1, key)",
                    [
                        Query::one(),
                        // this could be Start, which could have key = 0. Do we need to special case that?
                        // We could also just assign a non-zero key here....
                        config.key.previous(),
                        config.sibling.current(),
                    ],
                    poseidon.lookup(),
                );
            }
            SegmentType::AccountLeaf1 => {
                cb.assert_zero("direction is 0", config.direction.current());
            }
            SegmentType::AccountLeaf2 => {
                cb.assert_zero("direction is 0", config.direction.current());
            }
            SegmentType::AccountLeaf3 => {
                cb.assert_zero("direction is 0", config.direction.current());

                let old_nonce = config.old_hash.current()
                    - config.old_value.current() * Query::Constant(F::from(1 << 32).square());
                let new_nonce = config.new_hash.current()
                    - config.new_value.current() * Query::Constant(F::from(1 << 32).square());
                cb.condition(
                    config.path_type.current_matches(&[PathType::Common]),
                    |cb| {
                        cb.add_lookup(
                            "old code size is 8 bytes",
                            [config.old_value.current(), Query::from(7)],
                            bytes.lookup(),
                        );
                        cb.add_lookup(
                            "new code size is 8 bytes",
                            [config.new_value.current(), Query::from(7)],
                            bytes.lookup(),
                        );
                        cb.assert_equal(
                            "old nonce = new nonce for code size update",
                            old_nonce.clone(),
                            new_nonce.clone(),
                        );
                        cb.add_lookup(
                            "nonce is 8 bytes",
                            [old_nonce.clone(), Query::from(7)],
                            bytes.lookup(),
                        );
                    },
                );
                cb.condition(
                    config.path_type.current_matches(&[PathType::ExtensionNew]),
                    |cb| {
                        cb.add_lookup(
                            "new nonce is 8 bytes",
                            [config.old_value.current(), Query::from(7)],
                            bytes.lookup(),
                        );
                        cb.assert_zero(
                            "new nonce is 0 for ExtensionNew code size update",
                            new_nonce,
                        );
                    },
                );
                cb.condition(
                    config.path_type.current_matches(&[PathType::ExtensionOld]),
                    |cb| {
                        cb.add_lookup(
                            "old code size is 8 bytes",
                            [config.old_value.current(), Query::from(7)],
                            bytes.lookup(),
                        );
                        cb.assert_zero(
                            "old nonce is 0 for ExtensionOld code size update",
                            old_nonce,
                        );
                    },
                );
            }
            SegmentType::AccountLeaf4
            | SegmentType::StorageTrie
            | SegmentType::StorageLeaf0
            | SegmentType::StorageLeaf1 => {
                cb.assert_unreachable("unreachable segment type for nonce update")
            }
        };
        cb.condition(
            config.segment_type.current_matches(&[variant]),
            conditional_constraints,
        );
    }
}

fn configure_balance<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig<F>,
    poseidon: &impl PoseidonLookup,
    rlc: &impl RlcLookup,
) {
    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::Start | SegmentType::AccountTrie => {}
            SegmentType::AccountLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());

                // this should hold for all MPTProofType's
                let address_low: Query<F> = (config.address.current()
                    - config.upper_128_bits.current() * (1 << 32))
                    * (1 << 32)
                    * (1 << 32)
                    * (1 << 32);
                cb.add_lookup(
                    "key = h(address_high, address_low)",
                    [
                        config.upper_128_bits.current(),
                        address_low,
                        config.key.previous(),
                    ],
                    poseidon.lookup(),
                );
                cb.add_lookup(
                    "sibling = h(1, key)",
                    [
                        Query::one(),
                        // this could be Start, which could have key = 0. Do we need to special case that?
                        // We could also just assign a non-zero key here....
                        config.key.previous(),
                        config.sibling.current(),
                    ],
                    poseidon.lookup(),
                );
            }
            SegmentType::AccountLeaf1 => {
                cb.assert_zero("direction is 0", config.direction.current());
            }
            SegmentType::AccountLeaf2 => {
                cb.assert_zero("direction is 0", config.direction.current());
            }
            SegmentType::AccountLeaf3 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());

                // TODO: canonical representation lookups?
                cb.condition(
                    config
                        .path_type
                        .current_matches(&[PathType::Common, PathType::ExtensionOld]),
                    |cb| {
                        cb.add_lookup(
                            "old value is rlc(old_hash)",
                            [config.old_hash.current(), config.old_value.current()],
                            rlc.lookup(),
                        );
                    },
                );
                cb.condition(
                    config
                        .path_type
                        .current_matches(&[PathType::Common, PathType::ExtensionNew]),
                    |cb| {
                        cb.add_lookup(
                            "new value is rlc(new_hash)",
                            [config.new_hash.current(), config.new_value.current()],
                            rlc.lookup(),
                        );
                    },
                );
            }
            SegmentType::AccountLeaf4
            | SegmentType::StorageTrie
            | SegmentType::StorageLeaf0
            | SegmentType::StorageLeaf1 => {
                cb.assert_unreachable("unreachable segment type for nonce update")
            }
        };
        cb.condition(
            config.segment_type.current_matches(&[variant]),
            conditional_constraints,
        );
    }
}

fn configure_poseidon_code_hash<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig<F>,
    poseidon: &impl PoseidonLookup,
) {
    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::Start | SegmentType::AccountTrie => {}
            SegmentType::AccountLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());

                // this should hold for all MPTProofType's
                let address_low: Query<F> = (config.address.current()
                    - config.upper_128_bits.current() * (1 << 32))
                    * (1 << 32)
                    * (1 << 32)
                    * (1 << 32);
                cb.add_lookup(
                    "key = h(address_high, address_low)",
                    [
                        config.upper_128_bits.current(),
                        address_low,
                        config.key.previous(),
                    ],
                    poseidon.lookup(),
                );
                cb.add_lookup(
                    "sibling = h(1, key)",
                    [
                        Query::one(),
                        // this could be Start, which could have key = 0. Do we need to special case that?
                        // We could also just assign a non-zero key here....
                        config.key.previous(),
                        config.sibling.current(),
                    ],
                    poseidon.lookup(),
                );
            }
            SegmentType::AccountLeaf1 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
                cb.condition(
                    config
                        .path_type
                        .current_matches(&[PathType::Common, PathType::ExtensionOld]),
                    |cb| {
                        cb.assert_equal(
                            "old_hash is old poseidon code hash",
                            config.old_value.current(),
                            config.old_hash.current(),
                        );
                    },
                );
                cb.condition(
                    config
                        .path_type
                        .current_matches(&[PathType::Common, PathType::ExtensionNew]),
                    |cb| {
                        cb.assert_equal(
                            "new_hash is new poseidon code hash",
                            config.new_value.current(),
                            config.new_hash.current(),
                        );
                    },
                );
            }
            SegmentType::AccountLeaf2
            | SegmentType::AccountLeaf3
            | SegmentType::AccountLeaf4
            | SegmentType::StorageTrie
            | SegmentType::StorageLeaf0
            | SegmentType::StorageLeaf1 => {
                cb.assert_unreachable("unreachable segment type for poseidon code hash update")
            }
        };
        cb.condition(
            config.segment_type.current_matches(&[variant]),
            conditional_constraints,
        );
    }
}

fn configure_keccak_code_hash<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig<F>,
    poseidon: &impl PoseidonLookup,
    bytes: &impl BytesLookup,
    rlc: &impl RlcLookup,
) {
    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::Start | SegmentType::AccountTrie => {}
            SegmentType::AccountLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());

                // this should hold for all MPTProofType's
                let address_low: Query<F> = (config.address.current()
                    - config.upper_128_bits.current() * (1 << 32))
                    * (1 << 32)
                    * (1 << 32)
                    * (1 << 32);
                cb.add_lookup(
                    "key = h(address_high, address_low)",
                    [
                        config.upper_128_bits.current(),
                        address_low,
                        config.key.previous(),
                    ],
                    poseidon.lookup(),
                );
                cb.add_lookup(
                    "sibling = h(1, key)",
                    [
                        Query::one(),
                        // this could be Start, which could have key = 0. Do we need to special case that?
                        // We could also just assign a non-zero key here....
                        config.key.previous(),
                        config.sibling.current(),
                    ],
                    poseidon.lookup(),
                );
            }
            SegmentType::AccountLeaf1 => {
                cb.assert_zero("direction is 0", config.direction.current());
            }
            SegmentType::AccountLeaf2 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
            }
            SegmentType::AccountLeaf3 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());

                cb.condition(
                    config
                        .path_type
                        .current_matches(&[PathType::Common, PathType::ExtensionNew]),
                    |cb| {
                        // We current and previous values of other_key_hash, other_key,
                        // upper_128_bits and other_leaf_data_hash to store intermediate
                        // values here.
                        let [old_high, old_low] =
                            [-1, 0].map(|i| config.other_key_hash.rotation(i));
                        cb.add_lookup(
                            "old hash = poseidon(high, low)",
                            [old_high.clone(), old_low.clone(), config.old_hash.current()],
                            poseidon.lookup(),
                        );
                        cb.add_lookup(
                            "old_high is 16 bytes",
                            [old_high.clone(), Query::from(15)],
                            bytes.lookup(),
                        );
                        cb.add_lookup(
                            "old_low is 16 bytes",
                            [old_low.clone(), Query::from(15)],
                            bytes.lookup(),
                        );

                        let [rlc_old_high, rlc_old_low] =
                            [-1, 0].map(|i| config.other_key.rotation(i));
                        cb.add_lookup(
                            "rlc_old_high = rlc(old_high)",
                            [old_high, rlc_old_high.clone()],
                            rlc.lookup(),
                        );

                        cb.add_lookup(
                            "rlc_old_low = rlc(old_low)",
                            [old_low, rlc_old_low.clone()],
                            rlc.lookup(),
                        );

                        let randomness_raised_to_16 =
                            Query::from(RANDOMNESS).square().square().square().square();
                        cb.assert_equal(
                            "old value is rlc(old_high) * randomness ^ 16 + rlc(old_low)",
                            config.old_value.current(),
                            rlc_old_high * randomness_raised_to_16.clone() + rlc_old_low,
                        );

                        let [new_high, new_low] =
                            [-1, 0].map(|i| config.upper_128_bits.rotation(i));
                        cb.add_lookup(
                            "new hash = poseidon(high, low)",
                            [new_high.clone(), new_low.clone(), config.new_hash.current()],
                            poseidon.lookup(),
                        );
                        cb.add_lookup(
                            "new_high is 16 bytes",
                            [new_high.clone(), Query::from(15)],
                            bytes.lookup(),
                        );
                        cb.add_lookup(
                            "new_low is 16 bytes",
                            [new_low.clone(), Query::from(15)],
                            bytes.lookup(),
                        );

                        let [rlc_new_high, rlc_new_low] =
                            [-1, 0].map(|i| config.other_leaf_data_hash.rotation(i));
                        cb.add_lookup(
                            "rlc_new_high = rlc(new_high)",
                            [new_high, rlc_new_high.clone()],
                            rlc.lookup(),
                        );
                        cb.add_lookup(
                            "rlc_new_low = rlc(new_low)",
                            [new_low, rlc_new_low.clone()],
                            rlc.lookup(),
                        );
                        cb.assert_equal(
                            "new value is rlc(new_high) * randomness ^ 16 + rlc(new_low)",
                            config.new_value.current(),
                            rlc_new_high * randomness_raised_to_16 + rlc_new_low,
                        );
                    },
                );
            }
            SegmentType::AccountLeaf4
            | SegmentType::StorageTrie
            | SegmentType::StorageLeaf0
            | SegmentType::StorageLeaf1 => {
                cb.assert_unreachable("unreachable segment type for keccak code hash update")
            }
        };
        cb.condition(
            config.segment_type.current_matches(&[variant]),
            conditional_constraints,
        );
    }
}

fn configure_storage<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig<F>,
    poseidon: &impl PoseidonLookup,
    bytes: &impl BytesLookup,
    rlc: &impl RlcLookup,
) {
    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::Start | SegmentType::AccountTrie => {}
            SegmentType::AccountLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());

                // this should hold for all MPTProofType's
                let address_low: Query<F> = (config.address.current()
                    - config.upper_128_bits.current() * (1 << 32))
                    * (1 << 32)
                    * (1 << 32)
                    * (1 << 32);
                cb.add_lookup(
                    "key = h(address_high, address_low)",
                    [
                        config.upper_128_bits.current(),
                        address_low,
                        config.key.previous(),
                    ],
                    poseidon.lookup(),
                );
                cb.add_lookup(
                    "sibling = h(1, key)",
                    [
                        Query::one(),
                        // this could be Start, which could have key = 0. Do we need to special case that?
                        // We could also just assign a non-zero key here....
                        config.key.previous(),
                        config.sibling.current(),
                    ],
                    poseidon.lookup(),
                );
            }
            SegmentType::AccountLeaf1 => {
                cb.assert_zero("direction is 0", config.direction.current());
            }
            SegmentType::AccountLeaf2 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
            }
            SegmentType::AccountLeaf3 => {
                cb.assert_zero("direction is 0", config.direction.current());
            }
            SegmentType::AccountLeaf4 => {
                cb.assert_unreachable("AccountLeaf4 is not used");
            }
            SegmentType::StorageTrie => {}
            SegmentType::StorageLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());

                let randomness_raised_to_16 =
                    Query::from(RANDOMNESS).square().square().square().square();
                let configure_word = |cb: &mut ConstraintBuilder<F>,
                                      high: Query<F>,
                                      low: Query<F>,
                                      rlc_high: Query<F>,
                                      rlc_low: Query<F>,
                                      rlc_word: Query<F>,
                                      hash_word: Query<F>| {
                    cb.add_lookup(
                        "rlc_high = rlc(high)",
                        [high.clone(), rlc_high.clone()],
                        rlc.lookup(),
                    );
                    cb.add_lookup(
                        "rlc_low = rlc(low)",
                        [low.clone(), rlc_low.clone()],
                        rlc.lookup(),
                    );
                    cb.assert_equal(
                        "rlc_word = rlc(high) * randomness ^ 16 + rlc(low)",
                        rlc_word,
                        rlc_high.clone() * randomness_raised_to_16.clone() + rlc_low.clone(),
                    );
                    cb.add_lookup(
                        "hash_word = h(high, low)",
                        [high, low, hash_word],
                        poseidon.lookup(),
                    );
                };

                let storage_key_hash = config.upper_128_bits.rotation(-4);
                configure_word(
                    cb,
                    config.upper_128_bits.rotation(0),
                    config.upper_128_bits.rotation(-1),
                    config.upper_128_bits.rotation(-2),
                    config.upper_128_bits.rotation(-3),
                    config.storage_key_rlc.current(),
                    storage_key_hash.clone(),
                );
                cb.add_lookup(
                    "sibling = h(1, storage_key_hash)",
                    [Query::one(), storage_key_hash, config.sibling.current()],
                    poseidon.lookup(),
                );

                configure_word(
                    cb,
                    config.other_key_hash.rotation(0),
                    config.other_key_hash.rotation(-1),
                    config.other_key_hash.rotation(-2),
                    config.other_key_hash.rotation(-3),
                    config.old_value.current(),
                    config.old_hash.current(),
                );

                configure_word(
                    cb,
                    config.other_leaf_data_hash.rotation(0),
                    config.other_leaf_data_hash.rotation(-1),
                    config.other_leaf_data_hash.rotation(-2),
                    config.other_leaf_data_hash.rotation(-3),
                    config.new_value.current(),
                    config.new_hash.current(),
                );
            }
            SegmentType::StorageLeaf1 => {
                cb.assert_unreachable("StorageLeaf1 is not used");
            }
        };
        cb.condition(
            config.segment_type.current_matches(&[variant]),
            conditional_constraints,
        );
    }
}

fn configure_empty_account<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig<F>,
) {
}

fn configure_self_destruct<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig<F>,
) {
}
fn configure_empty_storage<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig<F>,
) {
}

fn address_high(a: Address) -> u128 {
    let high_bytes: [u8; 16] = a.0[..16].try_into().unwrap();
    u128::from_be_bytes(high_bytes)
}

fn address_low(a: Address) -> u128 {
    let low_bytes: [u8; 4] = a.0[16..].try_into().unwrap();
    u128::from(u32::from_be_bytes(low_bytes)) << 96
}

fn hash_address(a: Address) -> Fr {
    hash(
        Fr::from_u128(address_high(a)),
        Fr::from_u128(address_low(a)),
    )
}

#[cfg(test)]
mod test {
    use super::super::{
        byte_bit::ByteBitGadget, byte_representation::ByteRepresentationConfig,
        canonical_representation::CanonicalRepresentationConfig, key_bit::KeyBitConfig,
        poseidon::PoseidonConfig,
    };
    use super::*;
    use crate::{constraint_builder::SelectorColumn, serde::SMTTrace};
    use ethers_core::types::U256;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, Error},
    };

    #[derive(Clone, Debug)]
    struct TestCircuit {
        proofs: Vec<Proof>,
    }

    impl TestCircuit {
        fn new(traces: Vec<(MPTProofType, SMTTrace)>) -> Self {
            Self {
                proofs: traces.into_iter().map(Proof::from).collect(),
            }
        }

        fn hash_traces(&self) -> Vec<(Fr, Fr, Fr)> {
            let mut hash_traces = vec![(Fr::zero(), Fr::zero(), Fr::zero())];
            for proof in self.proofs.iter() {
                let address_hash_traces = &proof.address_hash_traces;
                for (direction, old_hash, new_hash, sibling, is_padding_open, is_padding_close) in
                    address_hash_traces.iter().rev()
                {
                    if !*is_padding_open {
                        let (left, right) = if *direction {
                            (sibling, old_hash)
                        } else {
                            (old_hash, sibling)
                        };
                        hash_traces.push((*left, *right, hash(*left, *right)));
                    }
                    if !*is_padding_close {
                        let (left, right) = if *direction {
                            (sibling, new_hash)
                        } else {
                            (new_hash, sibling)
                        };
                        hash_traces.push((*left, *right, hash(*left, *right)));
                    }
                }
                assert_eq!(
                    proof.storage.old_root(),
                    proof.old_account_hash_traces[1][0]
                );
                assert_eq!(
                    proof.storage.new_root(),
                    proof.new_account_hash_traces[1][0]
                );
                hash_traces.extend(proof.storage.poseidon_lookups());

                hash_traces.push((
                    Fr::from_u128(address_high(proof.claim.address)),
                    Fr::from_u128(address_low(proof.claim.address)),
                    account_key(proof.claim.address),
                ));

                hash_traces.push((Fr::one(), proof.old.key, proof.old.key_hash));
                hash_traces.push((Fr::one(), proof.new.key, proof.new.key_hash));

                if let Some(data_hash) = proof.old.leaf_data_hash {
                    hash_traces.push((
                        proof.old.key_hash,
                        data_hash,
                        hash(proof.old.key_hash, data_hash),
                    ));
                }
                if let Some(data_hash) = proof.new.leaf_data_hash {
                    hash_traces.push((
                        proof.new.key_hash,
                        data_hash,
                        hash(proof.new.key_hash, data_hash),
                    ));
                }

                // TODO: some of these hash traces are not used.
                hash_traces.extend(
                    proof
                        .old_account_hash_traces
                        .iter()
                        .map(|x| (x[0], x[1], x[2])),
                );
                hash_traces.extend(
                    proof
                        .new_account_hash_traces
                        .iter()
                        .map(|x| (x[0], x[1], x[2])),
                );
            }
            hash_traces
        }

        fn keys(&self) -> Vec<Fr> {
            let mut keys = vec![Fr::zero(), Fr::one()];
            for proof in self.proofs.iter() {
                keys.push(proof.old.key);
                keys.push(proof.new.key);
                match proof.claim.kind {
                    ClaimKind::Storage { key, .. } => keys.push(storage_key_hash(key)),
                    _ => (),
                };
            }
            keys
        }

        fn key_bit_lookups(&self) -> Vec<(Fr, usize, bool)> {
            let mut lookups = vec![(Fr::zero(), 0, false), (Fr::one(), 0, true)];
            for proof in self.proofs.iter() {
                for (i, (direction, _, _, _, is_padding_open, is_padding_close)) in
                    proof.address_hash_traces.iter().rev().enumerate()
                {
                    // TODO: use PathType here
                    if !is_padding_open {
                        lookups.push((proof.old.key, i, *direction));
                    }
                    if !is_padding_close {
                        lookups.push((proof.new.key, i, *direction));
                    }
                }
                lookups.extend(proof.storage.key_bit_lookups());
            }
            lookups
        }

        fn byte_representations(&self) -> (Vec<u64>, Vec<u128>, Vec<Fr>) {
            let mut u64s = vec![];
            let mut u128s = vec![0];
            let mut frs = vec![];

            for proof in &self.proofs {
                match MPTProofType::from(proof.claim) {
                    MPTProofType::NonceChanged | MPTProofType::CodeSizeExists => {
                        u128s.push(address_high(proof.claim.address));
                        if let Some(account) = proof.old_account {
                            u64s.push(account.nonce);
                            u64s.push(account.code_size);
                        };
                        if let Some(account) = proof.new_account {
                            u64s.push(account.nonce);
                            u64s.push(account.code_size);
                        };
                    }
                    MPTProofType::BalanceChanged => {
                        u128s.push(address_high(proof.claim.address));
                        if let Some(account) = proof.old_account {
                            frs.push(account.balance);
                        };
                        if let Some(account) = proof.new_account {
                            frs.push(account.balance);
                        };
                    }
                    MPTProofType::PoseidonCodeHashExists => {
                        u128s.push(address_high(proof.claim.address));
                    }
                    MPTProofType::CodeHashExists => {
                        u128s.push(address_high(proof.claim.address));
                        if let Some(account) = proof.old_account {
                            let (hi, lo) = u256_hi_lo(&account.keccak_codehash);
                            u128s.push(hi);
                            u128s.push(lo);
                        };
                        if let Some(account) = proof.new_account {
                            let (hi, lo) = u256_hi_lo(&account.keccak_codehash);
                            u128s.push(hi);
                            u128s.push(lo);
                        };
                    }
                    MPTProofType::StorageChanged => {
                        u128s.push(address_high(proof.claim.address));
                        let (storage_key_high, storage_key_low) =
                            u256_hi_lo(&proof.claim.storage_key());
                        u128s.push(storage_key_high);
                        u128s.push(storage_key_low);

                        match &proof.storage {
                            StorageProof::Root(_) => unreachable!(),
                            StorageProof::Update {
                                old_entry,
                                new_entry,
                                ..
                            } => {
                                let (old_value_high, old_value_low) = u256_hi_lo(&old_entry.value);
                                let (new_value_high, new_value_low) = u256_hi_lo(&new_entry.value);
                                u128s.extend(vec![
                                    old_value_high,
                                    old_value_low,
                                    new_value_high,
                                    new_value_low,
                                ]);
                            }
                        }
                    }
                    _ => {}
                }
            }
            (u64s, u128s, frs)
        }

        fn rlc_lookups(&self) -> Vec<U256> {
            let mut words = vec![];
            for proof in &self.proofs {
                match proof.claim.kind {
                    ClaimKind::Nonce { .. }
                    | ClaimKind::CodeSize { .. }
                    | ClaimKind::PoseidonCodeHash { .. } => {}
                    ClaimKind::Balance { old, new } | ClaimKind::CodeHash { old, new } => {
                        words.push(old);
                        words.push(new);
                    }
                    ClaimKind::Storage {
                        key,
                        old_value,
                        new_value,
                    } => {
                        words.push(Some(key));
                        words.push(old_value);
                        words.push(new_value);
                    }
                    ClaimKind::IsEmpty(key) => {
                        words.push(key);
                    }
                }
            }
            words.into_iter().flatten().collect()
        }
    }

    impl Circuit<Fr> for TestCircuit {
        type Config = (
            SelectorColumn,
            MptUpdateConfig<Fr>,
            PoseidonConfig,
            CanonicalRepresentationConfig,
            KeyBitConfig,
            ByteBitGadget,
            ByteRepresentationConfig,
        );
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self { proofs: vec![] }
        }

        fn configure(cs: &mut ConstraintSystem<Fr>) -> Self::Config {
            let selector = SelectorColumn(cs.fixed_column());
            let mut cb = ConstraintBuilder::new(selector);

            let poseidon = PoseidonConfig::configure(cs, &mut cb);
            let byte_bit = ByteBitGadget::configure(cs, &mut cb);
            let byte_representation = ByteRepresentationConfig::configure(cs, &mut cb, &byte_bit);
            let canonical_representation =
                CanonicalRepresentationConfig::configure(cs, &mut cb, &byte_bit);
            let key_bit = KeyBitConfig::configure(
                cs,
                &mut cb,
                &canonical_representation,
                &byte_bit,
                &byte_bit,
                &byte_bit,
            );

            let mpt_update = MptUpdateConfig::configure(
                cs,
                &mut cb,
                &poseidon,
                &key_bit,
                &byte_representation,
                &byte_representation,
            );

            cb.build(cs);
            (
                selector,
                mpt_update,
                poseidon,
                canonical_representation,
                key_bit,
                byte_bit,
                byte_representation,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let (
                selector,
                mpt_update,
                poseidon,
                canonical_representation,
                key_bit,
                byte_bit,
                byte_representation,
            ) = config;

            let (u64s, u128s, frs) = self.byte_representations();

            layouter.assign_region(
                || "",
                |mut region| {
                    for offset in 0..1024 {
                        selector.enable(&mut region, offset);
                    }
                    mpt_update.assign(&mut region, &self.proofs);
                    poseidon.assign(&mut region, &self.hash_traces());
                    canonical_representation.assign(&mut region, &self.keys());
                    key_bit.assign(&mut region, &self.key_bit_lookups());
                    byte_bit.assign(&mut region);
                    byte_representation.assign(&mut region, &u64s, &u128s, &frs);
                    Ok(())
                },
            )
        }
    }

    fn mock_prove(proof_type: MPTProofType, trace: &str) {
        let circuit = TestCircuit::new(vec![(proof_type, serde_json::from_str(trace).unwrap())]);
        let prover = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_mpt_updates() {
        let circuit = TestCircuit { proofs: vec![] };
        let prover = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn nonce_write_existing_account() {
        mock_prove(
            MPTProofType::NonceChanged,
            include_str!("../../tests/dual_code_hash/nonce_write_existing_account.json"),
        );
    }

    #[test]
    fn nonce_write_type_1_empty_account() {
        mock_prove(
            MPTProofType::NonceChanged,
            include_str!("../../tests/dual_code_hash/nonce_write_type_1_empty_account.json"),
        );
    }

    #[test]
    fn nonce_write_type_2_empty_account() {
        mock_prove(
            MPTProofType::NonceChanged,
            include_str!("../../tests/dual_code_hash/nonce_write_type_2_empty_account.json"),
        );
    }

    #[test]
    fn nonce_update_existing() {
        mock_prove(
            MPTProofType::NonceChanged,
            include_str!("../../tests/generated/nonce_update_existing.json"),
        );
    }

    #[test]
    fn nonce_update_type_1() {
        mock_prove(
            MPTProofType::NonceChanged,
            include_str!("../../tests/generated/nonce_update_type_1.json"),
        );
    }

    #[test]
    fn nonce_update_type_2() {
        mock_prove(
            MPTProofType::NonceChanged,
            include_str!("../../tests/generated/nonce_update_type_2.json"),
        );
    }

    #[test]
    fn balance_update_existing() {
        mock_prove(
            MPTProofType::BalanceChanged,
            include_str!("../../tests/generated/balance_update_existing.json"),
        );
    }

    #[test]
    fn balance_update_type_1() {
        mock_prove(
            MPTProofType::BalanceChanged,
            include_str!("../../tests/generated/balance_update_type_1.json"),
        );
    }

    #[test]
    fn balance_update_type_2() {
        mock_prove(
            MPTProofType::BalanceChanged,
            include_str!("../../tests/generated/balance_update_type_2.json"),
        );
    }

    #[test]
    fn code_size_update_existing() {
        mock_prove(
            MPTProofType::CodeSizeExists,
            include_str!("../../tests/generated/code_size_update_existing.json"),
        );
    }

    #[test]
    fn code_hash_update_existing() {
        mock_prove(
            MPTProofType::PoseidonCodeHashExists,
            include_str!("../../tests/generated/code_hash_update_existing.json"),
        );
    }

    #[test]
    fn keccak_code_hash_update_existing() {
        mock_prove(
            MPTProofType::CodeHashExists, // yes, the naming is very confusing :/
            include_str!("../../tests/generated/keccak_code_hash_update_existing.json"),
        );
    }

    #[test]
    fn keccak_code_hash_read_existing() {
        mock_prove(
            MPTProofType::CodeHashExists, // yes, the naming is very confusing :/
            include_str!("../../tests/generated/keccak_code_hash_read_existing.json"),
        );
    }

    #[test]
    fn update_storage_existing_to_existing() {
        mock_prove(
            MPTProofType::StorageChanged,
            include_str!("../../tests/generated/storage/update_storage_existing_to_existing.json"),
        );
    }

    #[test]
    fn test_account_key() {
        for address in vec![Address::zero(), Address::repeat_byte(0x56)] {
            assert_eq!(
                hash(
                    Fr::from_u128(address_high(address)),
                    Fr::from_u128(address_low(address)),
                ),
                account_key(address)
            );
        }
    }
}
