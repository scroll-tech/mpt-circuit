mod nonexistence_proof;
mod path;
mod segment;
mod word_rlc;
pub use path::PathType;
use segment::SegmentType;
use word_rlc::{assign as assign_word_rlc, configure as configure_word_rlc};

use super::{
    byte_representation::{BytesLookup, RlcLookup},
    is_zero::IsZeroGadget,
    key_bit::KeyBitLookup,
    one_hot::OneHot,
    poseidon::PoseidonLookup,
    rlc_randomness::RlcRandomness,
};
use crate::{
    constraint_builder::{AdviceColumn, ConstraintBuilder, Query, SecondPhaseAdviceColumn},
    types::{
        storage::{StorageLeaf, StorageProof},
        trie::TrieRows,
        ClaimKind, Proof, HASH_ZERO_ZERO,
    },
    util::{account_key, hash, rlc, u256_hi_lo, u256_to_big_endian},
    MPTProofType,
};
use ethers_core::{k256::elliptic_curve::PrimeField, types::Address};
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::{Region, Value},
    halo2curves::bn256::Fr,
    plonk::ConstraintSystem,
};
use itertools::izip;
use lazy_static::lazy_static;
use strum::IntoEnumIterator;

lazy_static! {
    static ref ZERO_STORAGE_HASH: Fr = hash(Fr::zero(), Fr::zero());
}

pub trait MptUpdateLookup<F: FieldExt> {
    fn lookup(&self) -> [Query<F>; 8];
}

#[derive(Clone)]
pub struct MptUpdateConfig {
    old_hash: AdviceColumn,
    new_hash: AdviceColumn,
    old_value: SecondPhaseAdviceColumn,
    new_value: SecondPhaseAdviceColumn,
    proof_type: OneHot<MPTProofType>,
    storage_key_rlc: SecondPhaseAdviceColumn,

    segment_type: OneHot<SegmentType>,
    path_type: OneHot<PathType>,
    depth: AdviceColumn,

    key: AdviceColumn,
    other_key: AdviceColumn,

    direction: AdviceColumn,
    sibling: AdviceColumn,

    intermediate_values: [AdviceColumn; 10], // can be 4?
    second_phase_intermediate_values: [SecondPhaseAdviceColumn; 10], // 4?
    is_zero_gadgets: [IsZeroGadget; 4],      // can be 3
}

impl<F: FieldExt> MptUpdateLookup<F> for MptUpdateConfig {
    fn lookup(&self) -> [Query<F>; 8] {
        let is_start = || self.segment_type.current_matches(&[SegmentType::Start]);
        let old_root_rlc = self.second_phase_intermediate_values[0].current() * is_start();
        let new_root_rlc = self.second_phase_intermediate_values[1].current() * is_start();
        let proof_type = self.proof_type.current() * is_start();
        let old_value = self.old_value.current() * is_start();
        let new_value = self.new_value.current() * is_start();
        let address = self.intermediate_values[0].current() * is_start();
        let storage_key_rlc = self.storage_key_rlc.current() * is_start();
        [
            is_start().into(),
            address,
            storage_key_rlc,
            proof_type,
            new_root_rlc,
            old_root_rlc,
            new_value,
            old_value,
        ]
    }
}

impl MptUpdateConfig {
    pub fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
        poseidon: &impl PoseidonLookup,
        key_bit: &impl KeyBitLookup,
        rlc: &impl RlcLookup,
        bytes: &impl BytesLookup,
        rlc_randomness: &RlcRandomness,
        fr_rlc: &impl RlcLookup,
    ) -> Self {
        let proof_type: OneHot<MPTProofType> = OneHot::configure(cs, cb);
        let [storage_key_rlc, old_value, new_value] = cb.second_phase_advice_columns(cs);
        let [old_hash, new_hash, depth, key, other_key, direction, sibling] = cb.advice_columns(cs);

        let intermediate_values: [AdviceColumn; 10] = cb.advice_columns(cs);
        let second_phase_intermediate_values: [SecondPhaseAdviceColumn; 10] =
            cb.second_phase_advice_columns(cs);
        let is_zero_gadgets = cb
            .advice_columns(cs)
            .map(|column| IsZeroGadget::configure(cs, cb, column));

        let segment_type = OneHot::configure(cs, cb);
        let path_type = OneHot::configure(cs, cb);

        let is_start = segment_type.current_matches(&[SegmentType::Start]);
        cb.assert_equal(
            "segment is Start iff path is Start",
            is_start.clone().into(),
            path_type.current_matches(&[PathType::Start]).into(),
        );
        cb.condition(is_start.clone().and(cb.every_row_selector()), |cb| {
            let [address, address_high, ..] = intermediate_values;
            let [old_hash_rlc, new_hash_rlc, ..] = second_phase_intermediate_values;
            let address_low: Query<F> = (address.current() - address_high.current() * (1 << 32))
                * (1 << 32)
                * (1 << 32)
                * (1 << 32);
            cb.poseidon_lookup(
                "account mpt key = h(address_high, address_low)",
                [address_high.current(), address_low.clone(), key.current()],
                poseidon,
            );
            cb.add_lookup(
                "address_high is 16 bytes",
                [address_high.current(), Query::from(15)],
                bytes.lookup(),
            );
            cb.add_lookup(
                "rlc_old_root = rlc(old_root)",
                [old_hash.current(), old_hash_rlc.current(), Query::from(31)],
                fr_rlc.lookup(),
            );
            cb.add_lookup(
                "rlc_new_root = rlc(new_root)",
                [new_hash.current(), new_hash_rlc.current(), Query::from(31)],
                fr_rlc.lookup(),
            );
        });
        cb.condition(!is_start, |cb| {
            cb.assert_equal(
                "proof type does not change",
                proof_type.current(),
                proof_type.previous(),
            );
            cb.assert_equal(
                "storage_key_rlc does not change",
                storage_key_rlc.current(),
                storage_key_rlc.previous(),
            );
            cb.assert_equal(
                "old_value does not change",
                old_value.current(),
                old_value.previous(),
            );
            cb.assert_equal(
                "old_value does not change",
                new_value.current(),
                new_value.previous(),
            );
        });

        cb.condition(
            !segment_type.current_matches(&[SegmentType::Start, SegmentType::AccountLeaf3]),
            |cb| {
                cb.assert_equal(
                    "key can only change on Start or AccountLeaf3 rows",
                    key.current(),
                    key.previous(),
                );
                cb.assert_equal(
                    "other_key can only change on Start or AccountLeaf3 rows",
                    other_key.current(),
                    other_key.previous(),
                );
            },
        );

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
            cb.assert_zero("depth is 0 in non-trie segments", depth.current());
        });

        cb.condition(
            segment_type.current_matches(&[SegmentType::AccountLeaf0, SegmentType::StorageLeaf0]),
            |cb| {
                cb.poseidon_lookup(
                    "sibling = h(1, key)",
                    [Query::one(), key.current(), sibling.current()],
                    poseidon,
                );
            },
        );

        let config = Self {
            key,
            old_hash,
            new_hash,
            proof_type,
            old_value,
            new_value,
            storage_key_rlc,
            segment_type,
            path_type,
            other_key,
            depth,
            direction,
            sibling,
            intermediate_values,
            second_phase_intermediate_values,
            is_zero_gadgets,
        };

        let path_transitions = path::forward_transitions();
        for variant in PathType::iter() {
            let conditional_constraints = |cb: &mut ConstraintBuilder<F>| {
                cb.assert(
                    "transition for path_type",
                    config
                        .path_type
                        .next_matches(path_transitions.get(&variant).unwrap()),
                );
                match variant {
                    PathType::Start => {}
                    PathType::Common => configure_common_path(cb, &config, poseidon),
                    PathType::ExtensionOld => configure_extension_old(cb, &config, poseidon),
                    PathType::ExtensionNew => configure_extension_new(cb, &config, poseidon),
                }
            };
            cb.condition(
                config.path_type.current_matches(&[variant]),
                conditional_constraints,
            );
        }

        for proof_type in MPTProofType::iter() {
            let conditional_constraints = |cb: &mut ConstraintBuilder<F>| {
                configure_segment_transitions(cb, &config.segment_type, proof_type);
                match proof_type {
                    MPTProofType::NonceChanged => configure_nonce(cb, &config, bytes, poseidon),
                    MPTProofType::BalanceChanged => configure_balance(cb, &config, poseidon, rlc),
                    MPTProofType::CodeSizeExists => {
                        configure_code_size(cb, &config, bytes, poseidon)
                    }
                    MPTProofType::PoseidonCodeHashExists => {
                        configure_poseidon_code_hash(cb, &config)
                    }
                    MPTProofType::AccountDoesNotExist => {
                        configure_empty_account(cb, &config, poseidon)
                    }
                    MPTProofType::CodeHashExists => configure_keccak_code_hash(
                        cb,
                        &config,
                        poseidon,
                        bytes,
                        rlc,
                        rlc_randomness.query(),
                    ),
                    MPTProofType::StorageChanged => {
                        configure_storage(cb, &config, poseidon, bytes, rlc, rlc_randomness.query())
                    }
                    MPTProofType::StorageDoesNotExist => configure_empty_storage(
                        cb,
                        &config,
                        poseidon,
                        bytes,
                        rlc,
                        rlc_randomness.query(),
                    ),
                    MPTProofType::AccountDestructed => cb.assert_unreachable("unimplemented!"),
                }
            };
            cb.condition(
                config.proof_type.current_matches(&[proof_type]),
                conditional_constraints,
            );
        }

        config
    }

    /// Valid assignment proving that the address 0 doesn't exist in an empty MPT.
    pub fn assign_padding_row(&self, region: &mut Region<'_, Fr>, offset: usize) {
        self.proof_type
            .assign(region, offset, MPTProofType::AccountDoesNotExist);
        self.key.assign(region, offset, *HASH_ZERO_ZERO);
        self.other_key.assign(region, offset, *HASH_ZERO_ZERO);
    }

    /// ..
    pub fn assign(
        &self,
        region: &mut Region<'_, Fr>,
        proofs: &[Proof],
        randomness: Value<Fr>,
    ) -> usize {
        let mut n_rows = 0;
        let mut offset = 1; // selector on first row is disabled.
        for proof in proofs {
            let proof_type = MPTProofType::from(proof.claim);
            let storage_key =
                randomness.map(|r| rlc(&u256_to_big_endian(&proof.claim.storage_key()), r));
            let old_value = randomness.map(|r| proof.claim.old_value_assignment(r));
            let new_value = randomness.map(|r| proof.claim.new_value_assignment(r));

            for i in 0..proof.n_rows() {
                self.proof_type.assign(region, offset + i, proof_type);
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
            // Assign start row
            self.segment_type.assign(region, offset, SegmentType::Start);
            self.path_type.assign(region, offset, PathType::Start);
            self.old_hash.assign(region, offset, proof.claim.old_root);
            self.new_hash.assign(region, offset, proof.claim.new_root);

            self.key.assign(region, offset, key);
            self.other_key.assign(region, offset, other_key);

            self.intermediate_values[0].assign(region, offset, address_to_fr(proof.claim.address));
            self.intermediate_values[1].assign(
                region,
                offset,
                Fr::from_u128(address_high(proof.claim.address)),
            );

            let rlc_fr = |x: Fr| {
                let mut bytes = x.to_bytes();
                bytes.reverse();
                randomness.map(|r| rlc(&bytes, r))
            };

            self.second_phase_intermediate_values[0].assign(
                region,
                offset,
                rlc_fr(proof.claim.old_root),
            );
            self.second_phase_intermediate_values[1].assign(
                region,
                offset,
                rlc_fr(proof.claim.new_root),
            );

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
                let path_type = match (*is_padding_open, *is_padding_close) {
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
                self.new_hash.assign(region, offset, *new_hash);
                self.direction.assign(region, offset, *direction);

                self.key.assign(region, offset, key);
                self.other_key.assign(region, offset, other_key);

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

            let final_path_type = proof
                .address_hash_traces
                .first()
                .map(|(_, _, _, _, is_padding_open, is_padding_close)| {
                    match (*is_padding_open, *is_padding_close) {
                        (false, false) => PathType::Common,
                        (false, true) => PathType::ExtensionOld,
                        (true, false) => PathType::ExtensionNew,
                        (true, true) => unreachable!(),
                    }
                })
                .unwrap_or(PathType::Common);
            let (final_old_hash, final_new_hash) = match proof.address_hash_traces.first() {
                None => (proof.old.hash(), proof.new.hash()),
                Some((_, old_hash, new_hash, _, _, _)) => (*old_hash, *new_hash),
            };

            if proof.old_account.is_none() && proof.new_account.is_none() {
                offset -= 1;
                self.is_zero_gadgets[2].assign_value_and_inverse(region, offset, key - other_key);
                self.is_zero_gadgets[3].assign_value_and_inverse(region, offset, final_old_hash);

                self.intermediate_values[2].assign(region, offset, other_key_hash);
                self.intermediate_values[3].assign(region, offset, other_leaf_data_hash);

                n_rows += proof.n_rows();
                offset = 1 + n_rows;
                continue; // we don't need to assign any leaf rows for empty accounts
            }

            let segment_types = vec![
                SegmentType::AccountLeaf0,
                SegmentType::AccountLeaf1,
                SegmentType::AccountLeaf2,
                SegmentType::AccountLeaf3,
            ];

            let leaf_path_type = match final_path_type {
                PathType::Common => {
                    // need to check if the old or new account is type 2 empty
                    match (
                        final_old_hash.is_zero_vartime(),
                        final_new_hash.is_zero_vartime(),
                    ) {
                        (true, true) => unreachable!("proof type must be AccountDoesNotExist"),
                        (true, false) => PathType::ExtensionNew,
                        (false, true) => PathType::ExtensionOld,
                        (false, false) => PathType::Common,
                    }
                }
                _ => final_path_type,
            };

            let directions = match proof_type {
                MPTProofType::NonceChanged | MPTProofType::CodeSizeExists => {
                    vec![true, false, false, false]
                }
                MPTProofType::BalanceChanged => vec![true, false, false, true],
                MPTProofType::PoseidonCodeHashExists => vec![true, true],
                MPTProofType::CodeHashExists => vec![true, false, true, true],
                MPTProofType::StorageChanged | MPTProofType::StorageDoesNotExist => {
                    vec![true, false, true, false]
                }
                MPTProofType::AccountDoesNotExist => unreachable!(),
                MPTProofType::AccountDestructed => unimplemented!(),
            };
            let next_offset = offset + directions.len();

            let old_hashes = proof
                .old_account_leaf_hashes()
                .unwrap_or_else(|| vec![final_old_hash; 4]);
            let new_hashes = proof
                .new_account_leaf_hashes()
                .unwrap_or_else(|| vec![final_new_hash; 4]);
            let siblings = proof.account_leaf_siblings();

            for (i, (segment_type, sibling, old_hash, new_hash, direction)) in
                izip!(segment_types, siblings, old_hashes, new_hashes, directions).enumerate()
            {
                if i == 0 {
                    self.is_zero_gadgets[3].assign_value_and_inverse(region, offset, old_hash);
                }
                self.segment_type.assign(region, offset + i, segment_type);
                self.path_type.assign(region, offset + i, leaf_path_type);
                self.sibling.assign(region, offset + i, sibling);
                self.old_hash.assign(region, offset + i, old_hash);
                self.new_hash.assign(region, offset + i, new_hash);
                self.direction.assign(region, offset + i, direction);
                self.key.assign(region, offset + i, key);
                self.other_key.assign(region, offset + i, other_key);

                match segment_type {
                    SegmentType::AccountLeaf0 => {
                        let [.., other_key_hash_column, other_leaf_data_hash_column] =
                            self.intermediate_values;
                        other_key_hash_column.assign(region, offset, other_key_hash);
                        other_leaf_data_hash_column.assign(region, offset, other_leaf_data_hash);
                    }
                    SegmentType::AccountLeaf3 => {
                        if let ClaimKind::Storage { key, .. } | ClaimKind::IsEmpty(Some(key)) =
                            proof.claim.kind
                        {
                            self.key.assign(region, offset + 3, proof.storage.key());
                            let [storage_key_high, storage_key_low, ..] = self.intermediate_values;
                            let [rlc_storage_key_high, rlc_storage_key_low, ..] =
                                self.second_phase_intermediate_values;
                            assign_word_rlc(
                                region,
                                offset + 3,
                                key,
                                [storage_key_high, storage_key_low],
                                [rlc_storage_key_high, rlc_storage_key_low],
                                randomness,
                            );
                            self.other_key
                                .assign(region, offset + 3, proof.storage.other_key());
                        }
                    }
                    _ => {}
                };
            }
            self.key.assign(region, offset, key);
            self.other_key.assign(region, offset, other_key);
            self.is_zero_gadgets[2].assign_value_and_inverse(region, offset, key - other_key);
            if let ClaimKind::CodeHash { old, new } = proof.claim.kind {
                let [old_high, old_low, new_high, new_low, ..] = self.intermediate_values;
                let [old_rlc_high, old_rlc_low, new_rlc_high, new_rlc_low, ..] =
                    self.second_phase_intermediate_values;
                if let Some(value) = old {
                    assign_word_rlc(
                        region,
                        offset + 3,
                        value,
                        [old_high, old_low],
                        [old_rlc_high, old_rlc_low],
                        randomness,
                    );
                }
                if let Some(value) = new {
                    assign_word_rlc(
                        region,
                        offset + 3,
                        value,
                        [new_high, new_low],
                        [new_rlc_high, new_rlc_low],
                        randomness,
                    );
                }
            };
            self.assign_storage(region, next_offset, &proof.storage, randomness);
            n_rows += proof.n_rows();
            offset = 1 + n_rows;
        }
        n_rows
    }

    fn assign_storage_trie_rows(
        &self,
        region: &mut Region<'_, Fr>,
        starting_offset: usize,
        rows: &TrieRows,
    ) -> usize {
        let n_rows = self.assign_trie_rows(region, starting_offset, rows);
        for i in 0..n_rows {
            self.segment_type
                .assign(region, starting_offset + i, SegmentType::StorageTrie);
        }
        n_rows
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
        }
        rows.len()
    }

    fn assign_storage(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        storage: &StorageProof,
        randomness: Value<Fr>,
    ) -> usize {
        match storage {
            StorageProof::Root(_) => 0,
            StorageProof::Update {
                key,
                trie_rows,
                old_leaf,
                new_leaf,
            } => {
                let other_key = storage.other_key();
                let n_trie_rows = self.assign_storage_trie_rows(region, offset, trie_rows);
                let n_leaf_rows = self.assign_storage_leaf_row(
                    region,
                    offset + n_trie_rows,
                    *key,
                    other_key,
                    old_leaf,
                    new_leaf,
                    randomness,
                );
                let n_rows = n_trie_rows + n_leaf_rows;

                for i in 0..n_rows {
                    self.key.assign(region, offset + i, *key);
                    self.other_key.assign(region, offset + i, other_key);
                }

                n_rows
            }
        }
    }

    fn assign_empty_storage_proof(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        key: Fr,
        other_key: Fr,
        old: &StorageLeaf,
        new: &StorageLeaf,
    ) -> usize {
        let [_key_high, _key_low, other_key_hash, other_leaf_data_hash, ..] =
            self.intermediate_values;
        let [.., key_equals_other_key, hash_is_zero] = self.is_zero_gadgets;
        match (old, new) {
            (
                StorageLeaf::Leaf {
                    mpt_key: old_key,
                    value_hash: old_value_hash,
                },
                StorageLeaf::Leaf {
                    mpt_key: new_key,
                    value_hash: new_value_hash,
                },
            ) => {
                assert!(key != other_key);

                key_equals_other_key.assign_value_and_inverse(region, offset, key - other_key);

                assert_eq!(new_key, old_key);
                assert_eq!(old_value_hash, new_value_hash);

                hash_is_zero.assign_value_and_inverse(region, offset, old.hash());

                other_key_hash.assign(region, offset, old.key_hash());
                other_leaf_data_hash.assign(region, offset, *old_value_hash);
            }
            (StorageLeaf::Empty { .. }, StorageLeaf::Empty { .. }) => {
                assert!(key == other_key);

                assert_eq!(old.hash(), Fr::zero());
                assert_eq!(new.hash(), Fr::zero());

                key_equals_other_key.assign_value_and_inverse(region, offset, key - other_key);
            }
            (StorageLeaf::Entry { .. }, _) | (_, StorageLeaf::Entry { .. }) => return 0,
            (StorageLeaf::Leaf { .. }, StorageLeaf::Empty { .. })
            | (StorageLeaf::Empty { .. }, StorageLeaf::Leaf { .. }) => unreachable!(),
        }

        0
    }

    fn assign_storage_leaf_row(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        key: Fr,
        other_key: Fr,
        old: &StorageLeaf,
        new: &StorageLeaf,
        randomness: Value<Fr>,
    ) -> usize {
        let path_type = match (old, new) {
            (StorageLeaf::Entry { .. }, StorageLeaf::Entry { .. }) => PathType::Common,
            (StorageLeaf::Entry { .. }, _) => PathType::ExtensionOld,
            (_, StorageLeaf::Entry { .. }) => PathType::ExtensionNew,
            _ => {
                return self.assign_empty_storage_proof(
                    region,
                    offset - 1,
                    key,
                    other_key,
                    old,
                    new,
                )
            }
        };
        self.path_type.assign(region, offset, path_type);
        self.segment_type
            .assign(region, offset, SegmentType::StorageLeaf0);
        self.direction.assign(region, offset, true);

        let sibling = match path_type {
            PathType::Start => unreachable!(),
            PathType::Common | PathType::ExtensionOld => old.key_hash(),
            PathType::ExtensionNew => new.key_hash(),
        };
        self.sibling.assign(region, offset, sibling);

        let (old_hash, new_hash) = match path_type {
            PathType::Start => unreachable!(),
            PathType::Common => (old.value_hash(), new.value_hash()),
            PathType::ExtensionOld => (old.value_hash(), new.hash()),
            PathType::ExtensionNew => (old.hash(), new.value_hash()),
        };
        self.old_hash.assign(region, offset, old_hash);
        self.new_hash.assign(region, offset, new_hash);

        let [old_high, old_low, new_high, new_low, ..] = self.intermediate_values;
        let [old_rlc_high, old_rlc_low, new_rlc_high, new_rlc_low, ..] =
            self.second_phase_intermediate_values;

        if let StorageLeaf::Entry { .. } = old {
            assign_word_rlc(
                region,
                offset,
                old.value(),
                [old_high, old_low],
                [old_rlc_high, old_rlc_low],
                randomness,
            );
        }

        if let StorageLeaf::Entry { .. } = new {
            assign_word_rlc(
                region,
                offset,
                new.value(),
                [new_high, new_low],
                [new_rlc_high, new_rlc_low],
                randomness,
            );
        }

        let [old_hash_is_zero_storage_hash, new_hash_is_zero_storage_hash, ..] =
            self.is_zero_gadgets;
        old_hash_is_zero_storage_hash.assign_value_and_inverse(
            region,
            offset,
            old_hash - *ZERO_STORAGE_HASH,
        );
        new_hash_is_zero_storage_hash.assign_value_and_inverse(
            region,
            offset,
            new_hash - *ZERO_STORAGE_HASH,
        );

        match path_type {
            PathType::Start => unreachable!(),
            PathType::Common => {}
            PathType::ExtensionOld => {
                let new_key = new.key();
                let other_key = if key != new_key { new_key } else { old.key() };

                let [.., key_equals_other_key, new_hash_is_zero] = self.is_zero_gadgets;
                key_equals_other_key.assign_value_and_inverse(region, offset, key - other_key);
                new_hash_is_zero.assign_value_and_inverse(region, offset, new_hash);

                if key != other_key {
                    let [.., other_key_hash, other_leaf_data_hash] = self.intermediate_values;
                    other_key_hash.assign(region, offset, new.key_hash());
                    other_leaf_data_hash.assign(region, offset, new.value_hash());
                }
            }
            PathType::ExtensionNew => {
                let old_key = old.key();
                let other_key = if key != old_key { old_key } else { new.key() };

                let [.., key_equals_other_key, old_hash_is_zero] = self.is_zero_gadgets;
                key_equals_other_key.assign_value_and_inverse(region, offset, key - other_key);
                old_hash_is_zero.assign_value_and_inverse(region, offset, old_hash);

                if key != other_key {
                    let [.., other_key_hash, other_leaf_data_hash] = self.intermediate_values;
                    other_key_hash.assign(region, offset, old.key_hash());
                    other_leaf_data_hash.assign(region, offset, old.value_hash());
                }
            }
        }

        1
    }
}

fn old_left<F: FieldExt>(config: &MptUpdateConfig) -> Query<F> {
    config.direction.current() * config.sibling.current()
        + (Query::one() - config.direction.current()) * config.old_hash.current()
}

fn old_right<F: FieldExt>(config: &MptUpdateConfig) -> Query<F> {
    config.direction.current() * config.old_hash.current()
        + (Query::one() - config.direction.current()) * config.sibling.current()
}

fn new_left<F: FieldExt>(config: &MptUpdateConfig) -> Query<F> {
    config.direction.current() * config.sibling.current()
        + (Query::one() - config.direction.current()) * config.new_hash.current()
}

fn new_right<F: FieldExt>(config: &MptUpdateConfig) -> Query<F> {
    config.direction.current() * config.new_hash.current()
        + (Query::one() - config.direction.current()) * config.sibling.current()
}

fn address_to_fr(a: Address) -> Fr {
    let mut bytes = [0u8; 32];
    bytes[32 - 20..].copy_from_slice(a.as_bytes());
    bytes.reverse();
    Fr::from_repr(bytes).unwrap()
}

fn configure_segment_transitions<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    segment: &OneHot<SegmentType>,
    proof: MPTProofType,
) {
    let transitions = segment::transitions(proof);
    for variant in SegmentType::iter() {
        cb.condition(segment.current_matches(&[variant]), |cb| {
            if let Some(next_segments) = transitions.get(&variant) {
                cb.assert(
                    "transition for current segment -> next segment",
                    segment.next_matches(next_segments),
                );
            } else {
                cb.assert_unreachable("unreachable segment for proof");
            }
        });
    }
}

fn configure_common_path<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig,
    poseidon: &impl PoseidonLookup,
) {
    cb.poseidon_lookup(
        "poseidon hash correct for old common path",
        [
            old_left(config),
            old_right(config),
            config.old_hash.previous(),
        ],
        poseidon,
    );
    cb.poseidon_lookup(
        "poseidon hash correct for new common path",
        [
            new_left(config),
            new_right(config),
            config.new_hash.previous(),
        ],
        poseidon,
    );

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
    config: &MptUpdateConfig,
    poseidon: &impl PoseidonLookup,
) {
    cb.assert(
        "can only delete existing nodes for storage proofs",
        config
            .proof_type
            .current_matches(&[MPTProofType::StorageChanged]),
    );
    cb.assert_zero(
        "new value is 0 when deleting node",
        config.new_value.current(),
    );
    cb.assert_equal(
        "new_hash unchanged for path_type=ExtensionOld",
        config.new_hash.current(),
        config.new_hash.previous(),
    );
    cb.poseidon_lookup(
        "poseidon hash correct for old path",
        [
            old_left(config),
            old_right(config),
            config.old_hash.previous(),
        ],
        poseidon,
    );
    cb.assert(
        "common -> extension old switch only allowed in storage trie segments",
        config
            .path_type
            .previous_matches(&[PathType::ExtensionOld])
            .or(config
                .segment_type
                .current_matches(&[SegmentType::StorageTrie, SegmentType::StorageLeaf0])),
    );
    let is_storage_trie_segment = config
        .segment_type
        .current_matches(&[SegmentType::StorageTrie]);
    cb.condition(is_storage_trie_segment, |cb| {
        let is_final_storage_trie_segment = config
            .segment_type
            .next_matches(&[SegmentType::StorageLeaf0]);
        cb.condition(!is_final_storage_trie_segment.clone(), |cb| {
            cb.assert_zero(
                "sibling is zero for non-final old extension path segments",
                config.sibling.current(),
            );
        });
        cb.condition(is_final_storage_trie_segment, |cb| {
            cb.assert_equal(
                "sibling is new leaf hash for final new extension path segments",
                config.sibling.current(),
                config.new_hash.previous(),
            );
        });
    });
    cb.condition(
        config
            .segment_type
            .current_matches(&[SegmentType::StorageLeaf0]),
        |cb| {
            let [.., key_equals_other_key, new_hash_is_zero] = config.is_zero_gadgets;
            let [.., other_key_hash, other_leaf_data_hash] = config.intermediate_values;
            nonexistence_proof::configure(
                cb,
                config.new_value,
                config.key,
                config.other_key,
                key_equals_other_key,
                config.new_hash,
                new_hash_is_zero,
                other_key_hash,
                other_leaf_data_hash,
                poseidon,
            );
        },
    );
}

fn configure_extension_new<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig,
    poseidon: &impl PoseidonLookup,
) {
    cb.assert(
        "can only add new nodes for nonce, balance and storage proofs",
        config.proof_type.current_matches(&[
            MPTProofType::NonceChanged,
            MPTProofType::BalanceChanged,
            MPTProofType::StorageChanged,
        ]),
    );
    cb.assert_zero(
        "old value is 0 if old account is empty",
        config.old_value.current(),
    );
    cb.assert_equal(
        "old_hash unchanged for path_type=New",
        config.old_hash.current(),
        config.old_hash.previous(),
    );
    cb.poseidon_lookup(
        "poseidon hash correct for new extension path",
        [
            new_left(config),
            new_right(config),
            config.new_hash.previous(),
        ],
        poseidon,
    );
    cb.assert(
        "common -> extension new switch only allowed in trie segments",
        config
            .path_type
            .previous_matches(&[PathType::ExtensionNew])
            .or(config.segment_type.current_matches(&[
                SegmentType::AccountTrie,
                SegmentType::AccountLeaf0,
                SegmentType::StorageTrie,
                SegmentType::StorageLeaf0,
            ])),
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
    cb.condition(
        config
            .segment_type
            .current_matches(&[SegmentType::AccountLeaf0, SegmentType::StorageLeaf0]),
        |cb| {
            let [.., key_equals_other_key, old_hash_is_zero] = config.is_zero_gadgets;
            let [.., other_key_hash, other_leaf_data_hash] = config.intermediate_values;
            nonexistence_proof::configure(
                cb,
                config.old_value,
                config.key,
                config.other_key,
                key_equals_other_key,
                config.old_hash,
                old_hash_is_zero,
                other_key_hash,
                other_leaf_data_hash,
                poseidon,
            );
        },
    );
}

fn configure_nonce<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig,
    bytes: &impl BytesLookup,
    poseidon: &impl PoseidonLookup,
) {
    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::AccountTrie => {
                cb.condition(
                    config.segment_type.next_matches(&[SegmentType::Start]),
                    |cb| {
                        let [.., key_equals_other_key, hash_is_zero] = config.is_zero_gadgets;
                        let [_, _, other_key_hash, other_leaf_data_hash, ..] =
                            config.intermediate_values;
                        cb.assert_equal(
                            "old hash = new hash for empty account proof",
                            config.old_hash.current(),
                            config.new_hash.current(),
                        );
                        cb.assert_equal(
                            "old value = new value for empty account proof",
                            config.old_value.current(),
                            config.new_value.current(),
                        );
                        nonexistence_proof::configure(
                            cb,
                            config.old_value,
                            config.key,
                            config.other_key,
                            key_equals_other_key,
                            config.old_hash,
                            hash_is_zero,
                            other_key_hash,
                            other_leaf_data_hash,
                            poseidon,
                        );
                    },
                );
            }
            SegmentType::AccountLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
            }
            SegmentType::AccountLeaf1 => {
                cb.assert_zero("direction is 0", config.direction.current());
                cb.condition(
                    config.path_type.current_matches(&[PathType::ExtensionNew]),
                    |cb| {
                        cb.assert_zero(
                            "poseidon code hash is 0 for nonce extension new at AccountLeaf1",
                            config.sibling.current(),
                        )
                    },
                );
            }
            SegmentType::AccountLeaf2 => {
                cb.assert_zero("direction is 0", config.direction.current());
                cb.condition(
                    config.path_type.current_matches(&[PathType::ExtensionNew]),
                    |cb| {
                        cb.assert_equal(
                        "sibling is hash(0, hash(0, 0)) for nonce extension new at AccountLeaf2",
                        config.sibling.current(),
                        hash(Fr::zero(), hash(Fr::zero(), Fr::zero())).into(),
                    );
                    },
                );
            }
            SegmentType::AccountLeaf3 => {
                cb.assert_zero("direction is 0", config.direction.current());

                let old_code_size = (config.old_hash.current() - config.old_value.current())
                    * Query::Constant(F::from(1 << 32).square().invert().unwrap());
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
                        cb.assert_zero(
                            "balance is 0 for ExtensionNew nonce update",
                            config.sibling.current(),
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
            _ => {}
        };
        cb.condition(
            config.segment_type.current_matches(&[variant]),
            conditional_constraints,
        );
    }
}

fn configure_code_size<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig,
    bytes: &impl BytesLookup,
    poseidon: &impl PoseidonLookup,
) {
    cb.assert(
        "new accounts have balance or nonce set first",
        config
            .path_type
            .current_matches(&[PathType::Start, PathType::Common]),
    );
    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::AccountTrie => {
                cb.condition(
                    config.segment_type.next_matches(&[SegmentType::Start]),
                    |cb| {
                        let [.., key_equals_other_key, hash_is_zero] = config.is_zero_gadgets;
                        let [_, _, other_key_hash, other_leaf_data_hash, ..] =
                            config.intermediate_values;
                        cb.assert_equal(
                            "old hash = new hash for empty account proof",
                            config.old_hash.current(),
                            config.new_hash.current(),
                        );
                        cb.assert_equal(
                            "old value = new value for empty account proof",
                            config.old_value.current(),
                            config.new_value.current(),
                        );
                        nonexistence_proof::configure(
                            cb,
                            config.old_value,
                            config.key,
                            config.other_key,
                            key_equals_other_key,
                            config.old_hash,
                            hash_is_zero,
                            other_key_hash,
                            other_leaf_data_hash,
                            poseidon,
                        );
                    },
                );
            }
            SegmentType::AccountLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
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
                        cb.assert_zero(
                            "nonce and code size are 0 for ExtensionNew balance update",
                            config.sibling.current(),
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
            _ => {}
        };
        cb.condition(
            config.segment_type.current_matches(&[variant]),
            conditional_constraints,
        );
    }
}

fn configure_balance<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig,
    poseidon: &impl PoseidonLookup,
    rlc: &impl RlcLookup,
) {
    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::AccountTrie => {
                cb.condition(
                    config.segment_type.next_matches(&[SegmentType::Start]),
                    |cb| {
                        let [.., key_equals_other_key, hash_is_zero] = config.is_zero_gadgets;
                        let [_, _, other_key_hash, other_leaf_data_hash, ..] =
                            config.intermediate_values;
                        cb.assert_equal(
                            "old hash = new hash for empty account proof",
                            config.old_hash.current(),
                            config.new_hash.current(),
                        );
                        cb.assert_equal(
                            "old value = new value for empty account proof",
                            config.old_value.current(),
                            config.new_value.current(),
                        );
                        nonexistence_proof::configure(
                            cb,
                            config.old_value,
                            config.key,
                            config.other_key,
                            key_equals_other_key,
                            config.old_hash,
                            hash_is_zero,
                            other_key_hash,
                            other_leaf_data_hash,
                            poseidon,
                        );
                    },
                );
            }
            SegmentType::AccountLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
            }
            SegmentType::AccountLeaf1 => {
                cb.assert_zero("direction is 0", config.direction.current());
                cb.condition(
                    config.path_type.current_matches(&[PathType::ExtensionNew]),
                    |cb| {
                        cb.assert_zero(
                            "poseidon code hash is 0 for balance extension new at AccountLeaf1",
                            config.sibling.current(),
                        );
                    },
                );
            }
            SegmentType::AccountLeaf2 => {
                cb.assert_zero("direction is 0", config.direction.current());
                cb.condition(
                    config.path_type.current_matches(&[PathType::ExtensionNew]),
                    |cb| {
                        cb.assert_equal(
                        "sibling is hash(0, hash(0, 0)) for balance extension new at AccountLeaf2",
                        config.sibling.current(),
                        hash(Fr::zero(), hash(Fr::zero(), Fr::zero())).into(),
                    );
                    },
                );
            }
            SegmentType::AccountLeaf3 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
                cb.condition(
                    config
                        .path_type
                        .current_matches(&[PathType::Common, PathType::ExtensionOld]),
                    |cb| {
                        cb.add_lookup(
                            "old balance is rlc(old_hash) and fits into 31 bytes",
                            [
                                config.old_hash.current(),
                                Query::from(30),
                                config.old_value.current(),
                            ],
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
                            "new balance is rlc(new_hash) and fits into 31 bytes",
                            [
                                config.new_hash.current(),
                                Query::from(30),
                                config.new_value.current(),
                            ],
                            rlc.lookup(),
                        );
                    },
                );
            }
            _ => {}
        };
        cb.condition(
            config.segment_type.current_matches(&[variant]),
            conditional_constraints,
        );
    }
}

fn configure_poseidon_code_hash<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig,
) {
    cb.assert(
        "new accounts have balance or nonce set first",
        config
            .path_type
            .current_matches(&[PathType::Start, PathType::Common]),
    );
    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::AccountLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
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
            _ => {}
        };
        cb.condition(
            config.segment_type.current_matches(&[variant]),
            conditional_constraints,
        );
    }
}

fn configure_keccak_code_hash<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig,
    poseidon: &impl PoseidonLookup,
    bytes: &impl BytesLookup,
    rlc: &impl RlcLookup,
    randomness: Query<F>,
) {
    cb.assert(
        "new accounts have balance or nonce set first",
        config
            .path_type
            .current_matches(&[PathType::Start, PathType::Common]),
    );
    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::AccountTrie => {
                cb.condition(
                    config.segment_type.next_matches(&[SegmentType::Start]),
                    |cb| {
                        let [.., key_equals_other_key, hash_is_zero] = config.is_zero_gadgets;
                        let [_, _, other_key_hash, other_leaf_data_hash, ..] =
                            config.intermediate_values;
                        cb.assert_equal(
                            "old hash = new hash for empty account proof",
                            config.old_hash.current(),
                            config.new_hash.current(),
                        );
                        cb.assert_equal(
                            "old value = new value for empty account proof",
                            config.old_value.current(),
                            config.new_value.current(),
                        );
                        nonexistence_proof::configure(
                            cb,
                            config.old_value,
                            config.key,
                            config.other_key,
                            key_equals_other_key,
                            config.old_hash,
                            hash_is_zero,
                            other_key_hash,
                            other_leaf_data_hash,
                            poseidon,
                        );
                    },
                );
            }
            SegmentType::AccountLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
            }
            SegmentType::AccountLeaf1 => {
                cb.assert_zero("direction is 0", config.direction.current());
            }
            SegmentType::AccountLeaf2 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
            }
            SegmentType::AccountLeaf3 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());

                let [old_high, old_low, new_high, new_low, ..] = config.intermediate_values;
                let [rlc_old_high, rlc_old_low, rlc_new_high, rlc_new_low, ..] =
                    config.second_phase_intermediate_values;
                configure_word_rlc(
                    cb,
                    [config.old_hash, old_high, old_low],
                    [config.old_value, rlc_old_high, rlc_old_low],
                    poseidon,
                    bytes,
                    rlc,
                    randomness.clone(),
                );
                configure_word_rlc(
                    cb,
                    [config.new_hash, new_high, new_low],
                    [config.new_value, rlc_new_high, rlc_new_low],
                    poseidon,
                    bytes,
                    rlc,
                    randomness.clone(),
                );
            }
            _ => {}
        };
        cb.condition(
            config.segment_type.current_matches(&[variant]),
            conditional_constraints,
        );
    }
}

fn configure_storage<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig,
    poseidon: &impl PoseidonLookup,
    bytes: &impl BytesLookup,
    rlc: &impl RlcLookup,
    randomness: Query<F>,
) {
    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::AccountLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
            }
            SegmentType::AccountLeaf1 => {
                cb.assert_zero("direction is 0", config.direction.current());
            }
            SegmentType::AccountLeaf2 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
            }
            SegmentType::AccountLeaf3 => {
                cb.assert(
                    "storage modifications must be on an existing account",
                    config.path_type.current_matches(&[PathType::Common]),
                );
                cb.assert_zero("direction is 0", config.direction.current());
                let [key_high, key_low, ..] = config.intermediate_values;
                let [rlc_key_high, rlc_key_low, ..] = config.second_phase_intermediate_values;
                configure_word_rlc(
                    cb,
                    [config.key, key_high, key_low],
                    [config.storage_key_rlc, rlc_key_high, rlc_key_low],
                    poseidon,
                    bytes,
                    rlc,
                    randomness.clone(),
                );
            }
            SegmentType::StorageLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());

                let [old_high, old_low, new_high, new_low, ..] = config.intermediate_values;
                let [rlc_old_high, rlc_old_low, rlc_new_high, rlc_new_low, ..] =
                    config.second_phase_intermediate_values;

                cb.condition(
                    config
                        .path_type
                        .current_matches(&[PathType::Common, PathType::ExtensionOld]),
                    |cb| {
                        configure_word_rlc(
                            cb,
                            [config.old_hash, old_high, old_low],
                            [config.old_value, rlc_old_high, rlc_old_low],
                            poseidon,
                            bytes,
                            rlc,
                            randomness.clone(),
                        );
                    },
                );
                cb.condition(
                    config
                        .path_type
                        .current_matches(&[PathType::Common, PathType::ExtensionNew]),
                    |cb| {
                        configure_word_rlc(
                            cb,
                            [config.new_hash, new_high, new_low],
                            [config.new_value, rlc_new_high, rlc_new_low],
                            poseidon,
                            bytes,
                            rlc,
                            randomness.clone(),
                        );
                    },
                );

                let [old_hash_is_zero_storage_hash, new_hash_is_zero_storage_hash, ..] =
                    config.is_zero_gadgets;
                cb.assert_equal(
                    "old_hash_minus_zero_storage_hash = old_hash - hash(0, 0)",
                    old_hash_is_zero_storage_hash.value.current(),
                    config.old_hash.current() - *ZERO_STORAGE_HASH,
                );
                cb.assert_equal(
                    "new_hash_minus_zero_storage_hash = new_hash - hash(0, 0)",
                    new_hash_is_zero_storage_hash.value.current(),
                    config.new_hash.current() - *ZERO_STORAGE_HASH,
                );
                cb.assert(
                    "old hash != hash(0, 0)",
                    !old_hash_is_zero_storage_hash.current(),
                );
                cb.assert(
                    "new hash != hash(0, 0)",
                    !new_hash_is_zero_storage_hash.current(),
                );
            }
            _ => {}
        };
        cb.condition(
            config.segment_type.current_matches(&[variant]),
            conditional_constraints,
        );
    }
}

fn configure_empty_storage<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig,
    poseidon: &impl PoseidonLookup,
    bytes: &impl BytesLookup,
    rlc: &impl RlcLookup,
    randomness: Query<F>,
) {
    let [key_high, key_low, other_key_hash, other_leaf_data_hash, ..] = config.intermediate_values;
    let [rlc_key_high, rlc_key_low, ..] = config.second_phase_intermediate_values;
    let [.., key_equals_other_key, hash_is_zero] = config.is_zero_gadgets;

    cb.assert_zero(
        "old value is 0 for empty storage",
        config.old_value.current(),
    );
    cb.assert_zero(
        "new value is 0 for empty storage",
        config.new_value.current(),
    );
    cb.assert(
        "empty storage proof does not extend trie",
        config
            .path_type
            .current_matches(&[PathType::Start, PathType::Common]),
    );

    let is_final_segment = config.segment_type.next_matches(&[SegmentType::Start]);
    cb.condition(is_final_segment, |cb| {
        cb.assert_equal(
            "old_hash = new_hash",
            config.old_hash.current(),
            config.new_hash.current(),
        );
        cb.assert_equal(
            "old value = new value for empty account proof",
            config.old_value.current(),
            config.new_value.current(),
        );
        nonexistence_proof::configure(
            cb,
            config.old_value,
            config.key,
            config.other_key,
            key_equals_other_key,
            config.old_hash,
            hash_is_zero,
            other_key_hash,
            other_leaf_data_hash,
            poseidon,
        );
    });

    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::AccountLeaf0 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
            }
            SegmentType::AccountLeaf1 => {
                cb.assert_zero("direction is 0", config.direction.current());
            }
            SegmentType::AccountLeaf2 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
            }
            SegmentType::AccountLeaf3 => {
                cb.assert_zero("direction is 0", config.direction.current());
                configure_word_rlc(
                    cb,
                    [config.key, key_high, key_low],
                    [config.storage_key_rlc, rlc_key_high, rlc_key_low],
                    poseidon,
                    bytes,
                    rlc,
                    randomness.clone(),
                );
            }
            _ => (),
        };
        cb.condition(
            config.segment_type.current_matches(&[variant]),
            conditional_constraints,
        );
    }
}

fn configure_empty_account<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    config: &MptUpdateConfig,
    poseidon: &impl PoseidonLookup,
) {
    cb.assert(
        "path type is start or common for empty account proof",
        config
            .path_type
            .current_matches(&[PathType::Start, PathType::Common]),
    );
    cb.assert_zero("old value is 0", config.old_value.current());
    cb.assert_zero("new value is 0", config.new_value.current());
    cb.assert_equal(
        "hash doesn't change for empty account",
        config.old_hash.current(),
        config.new_hash.current(),
    );
    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::Start | SegmentType::AccountTrie => {
                let is_final_segment = config.segment_type.next_matches(&[SegmentType::Start]);
                cb.condition(is_final_segment, |cb| {
                    let [.., key_equals_other_key, hash_is_zero] = config.is_zero_gadgets;
                    let [_, _, other_key_hash, other_leaf_data_hash, ..] =
                        config.intermediate_values;
                    cb.assert_equal(
                        "new_hash = old_hash",
                        config.old_hash.current(),
                        config.new_hash.current(),
                    );
                    cb.assert_equal(
                        "old value = new value for empty account proof",
                        config.old_value.current(),
                        config.new_value.current(),
                    );
                    nonexistence_proof::configure(
                        cb,
                        config.old_value,
                        config.key,
                        config.other_key,
                        key_equals_other_key,
                        config.new_hash,
                        hash_is_zero,
                        other_key_hash,
                        other_leaf_data_hash,
                        poseidon,
                    );
                });
            }
            _ => {}
        };
        cb.condition(
            config.segment_type.current_matches(&[variant]),
            conditional_constraints,
        );
    }
}

fn address_high(a: Address) -> u128 {
    let high_bytes: [u8; 16] = a.0[..16].try_into().unwrap();
    u128::from_be_bytes(high_bytes)
}

fn address_low(a: Address) -> u128 {
    let low_bytes: [u8; 4] = a.0[16..].try_into().unwrap();
    u128::from(u32::from_be_bytes(low_bytes)) << 96
}

// ...
pub fn hash_traces(proofs: &[Proof]) -> Vec<(Fr, Fr, Fr)> {
    let mut hash_traces = vec![(Fr::zero(), Fr::zero(), *HASH_ZERO_ZERO)];
    for proof in proofs.iter() {
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
        let (storage_key_high, storage_key_low) = u256_hi_lo(&proof.claim.storage_key());
        hash_traces.push((
            Fr::from_u128(storage_key_high),
            Fr::from_u128(storage_key_low),
            hash(
                Fr::from_u128(storage_key_high),
                Fr::from_u128(storage_key_low),
            ),
        ));
        hash_traces.extend(proof.storage.poseidon_lookups());

        let key = account_key(proof.claim.address);
        hash_traces.push((
            Fr::from_u128(address_high(proof.claim.address)),
            Fr::from_u128(address_low(proof.claim.address)),
            key,
        ));

        let other_key = if key != proof.old.key {
            proof.old.key
        } else {
            proof.new.key
        };
        if key != other_key {
            hash_traces.push((Fr::one(), other_key, hash(Fr::one(), other_key)));
        }

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

        for account_leaf_hash_traces in
            [proof.old_account_hash_traces, proof.new_account_hash_traces]
        {
            for [left, right, digest] in account_leaf_hash_traces {
                if hash(left, right) == digest {
                    hash_traces.push((left, right, digest))
                }
            }
        }
    }
    hash_traces
}

/// ...
pub fn key_bit_lookups(proofs: &[Proof]) -> Vec<(Fr, usize, bool)> {
    let mut lookups = vec![(Fr::zero(), 0, false), (Fr::one(), 0, true)];
    for proof in proofs.iter() {
        for (i, (direction, _, _, _, is_padding_open, is_padding_close)) in
            proof.address_hash_traces.iter().rev().enumerate()
        {
            match (is_padding_open, is_padding_close) {
                (false, false) => {
                    let mut lookup_keys = vec![proof.old.key, proof.new.key];
                    let key = account_key(proof.claim.address);
                    if !lookup_keys.contains(&key) {
                        lookup_keys.push(key);
                    }
                    lookup_keys
                        .into_iter()
                        .for_each(|k| lookups.push((k, i, *direction)));
                }
                (false, true) => {
                    lookups.push((proof.old.key, i, *direction));
                }
                (true, false) => {
                    lookups.push((proof.new.key, i, *direction));
                }
                (true, true) => unreachable!(),
            };
        }
        lookups.extend(proof.storage.key_bit_lookups());
    }
    lookups
}

/// ...
pub fn byte_representations(proofs: &[Proof]) -> (Vec<u64>, Vec<u128>, Vec<Fr>) {
    let mut u64s = vec![];
    let mut u128s = vec![0];
    let mut frs = vec![];

    for proof in proofs {
        u128s.push(address_high(proof.claim.address));
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
                let (storage_key_high, storage_key_low) = u256_hi_lo(&proof.claim.storage_key());
                u128s.push(storage_key_high);
                u128s.push(storage_key_low);

                match &proof.storage {
                    StorageProof::Root(_) => unreachable!(),
                    StorageProof::Update {
                        old_leaf, new_leaf, ..
                    } => {
                        let (old_value_high, old_value_low) = u256_hi_lo(&old_leaf.value());
                        let (new_value_high, new_value_low) = u256_hi_lo(&new_leaf.value());
                        u128s.extend(vec![
                            old_value_high,
                            old_value_low,
                            new_value_high,
                            new_value_low,
                        ]);
                    }
                }
            }
            MPTProofType::StorageDoesNotExist => {
                u128s.push(address_high(proof.claim.address));
                let (storage_key_high, storage_key_low) = u256_hi_lo(&proof.claim.storage_key());
                u128s.push(storage_key_high);
                u128s.push(storage_key_low);
            }
            _ => {}
        }
    }
    (u64s, u128s, frs)
}

/// ..
pub fn mpt_update_keys(proofs: &[Proof]) -> Vec<Fr> {
    let mut keys = vec![Fr::zero(), Fr::one()];
    for proof in proofs.iter() {
        keys.push(proof.old.key);
        keys.push(proof.new.key);
        keys.push(account_key(proof.claim.address));
        keys.extend(proof.storage.key_lookups());
        keys.push(proof.claim.old_root);
        keys.push(proof.claim.new_root);
    }
    keys
}
