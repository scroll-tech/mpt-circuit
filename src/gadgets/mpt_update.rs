mod assign;
mod nonexistence_proof;
mod path;
mod segment;
mod word_rlc;
pub use path::PathType;
use segment::SegmentType;
use word_rlc::{assign as assign_word_rlc, configure as configure_word_rlc};

use super::{
    byte_representation::{BytesLookup, RlcLookup},
    canonical_representation::FrRlcLookup,
    is_zero::IsZeroGadget,
    key_bit::KeyBitLookup,
    one_hot::OneHot,
    poseidon::PoseidonLookup,
    rlc_randomness::RlcRandomness,
};
use crate::{
    constraint_builder::{
        AdviceColumn, BinaryQuery, ConstraintBuilder, Query, SecondPhaseAdviceColumn,
    },
    types::{storage::StorageProof, HashDomain, Proof},
    util::{account_key, domain_hash, lagrange_polynomial, u256_hi_lo},
    MPTProofType,
};
use ethers_core::types::Address;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    halo2curves::{bn256::Fr, group::ff::PrimeField},
    plonk::{ConstraintSystem, Error},
};
use lazy_static::lazy_static;
use std::iter::{once, repeat};
use strum::IntoEnumIterator;

lazy_static! {
    static ref ZERO_PAIR_HASH: Fr = domain_hash(Fr::zero(), Fr::zero(), HashDomain::Pair);
    static ref ZERO_STORAGE_ROOT_KECCAK_CODEHASH_HASH: Fr =
        domain_hash(Fr::zero(), *ZERO_PAIR_HASH, HashDomain::AccountFields);
}

pub trait MptUpdateLookup<F: FieldExt> {
    fn lookup(&self) -> [Query<F>; 8];
}

#[derive(Clone)]
pub struct MptUpdateConfig {
    domain: AdviceColumn,

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

    // TODO: make this a BinaryColumn for readability, even though this actually must already
    // binary because of the key bit lookup.
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
        let [address_high, address_low, ..] = self.intermediate_values;
        let address = (address_high.current() * Query::Constant(F::from_u128(1 << 32))
            + address_low.current())
            * is_start();
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
        fr_rlc: &impl FrRlcLookup,
    ) -> Self {
        let proof_type: OneHot<MPTProofType> = OneHot::configure(cs, cb);
        let [storage_key_rlc, old_value, new_value] = cb.second_phase_advice_columns(cs);
        let [domain, old_hash, new_hash, depth, key, other_key, direction, sibling] =
            cb.advice_columns(cs);

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
            let [address_high, address_low, ..] = intermediate_values;
            let [old_hash_rlc, new_hash_rlc, ..] = second_phase_intermediate_values;
            cb.poseidon_lookup(
                "account mpt key = h(address_high, address_low << 96)",
                [
                    address_high.current(),
                    address_low.current() * Query::Constant(F::from_u128(1 << 96)),
                    Query::from(u64::from(HashDomain::Pair)),
                    key.current(),
                ],
                poseidon,
            );
            cb.add_lookup(
                "address_high is 16 bytes",
                [address_high.current(), Query::from(15)],
                bytes.lookup(),
            );
            cb.add_lookup(
                "address_low is 4 bytes",
                [address_low.current(), Query::from(3)],
                bytes.lookup(),
            );
            cb.add_lookup(
                "rlc_old_root = rlc(old_root)",
                [old_hash.current(), old_hash_rlc.current()],
                fr_rlc.lookup(),
            );
            cb.add_lookup(
                "rlc_new_root = rlc(new_root)",
                [new_hash.current(), new_hash_rlc.current()],
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
                "new_value does not change",
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

        let config = Self {
            key,
            domain,
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

        for variant in SegmentType::iter() {
            let conditional_constraints = |cb: &mut ConstraintBuilder<F>| {
                cb.assert_zero(
                    "domain in allowed set for segment type",
                    segment::domains(variant)
                        .iter()
                        .fold(Query::one(), |product, domain| {
                            product * (config.domain.current() - u64::from(*domain))
                        }),
                );
            };
            cb.condition(
                config.segment_type.current_matches(&[variant]),
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

    pub fn assign(
        &self,
        region: &mut Region<'_, Fr>,
        proofs: &[Proof],
        n_rows: usize,
        randomness: Value<Fr>,
    ) {
        let mut n_rows_used = 1; // selector on first row is disabled.
        for proof in proofs {
            n_rows_used += self.assign_proof(region, n_rows_used, proof, randomness);
        }

        let expected_offset = Self::n_rows_required(proofs);
        debug_assert!(
            n_rows_used == expected_offset,
            "assign used {n_rows_used} rows but {expected_offset} rows expected from `n_rows_required`",
        );

        for offset in n_rows_used..n_rows {
            self.assign_padding_row(region, offset);
        }
    }

    pub fn assignments(
        &self,
        proofs: Vec<Proof>,
        n_rows: usize,
        randomness: Value<Fr>,
    ) -> Vec<impl FnMut(Region<'_, Fr>) -> Result<(), Error> + '_> {
        let n_padding_rows = n_rows - Self::n_rows_required(&proofs);
        let n_closures = 1 + proofs.len() + n_padding_rows;
        dbg!(n_closures);
        once(None)
            .chain(proofs.into_iter().map(Some).chain(repeat(None)))
            .take(n_closures)
            .enumerate()
            .map(move |(i, maybe_proof)| {
                move |mut region: Region<'_, Fr>| {
                    if let Some(proof) = maybe_proof.clone() {
                        self.assign_proof(&mut region, 0, &proof, randomness);
                    } else if i == 0 {
                        // Need make one assignment so region size is calculated correctly.
                        self.key.assign(&mut region, 0, 0);
                    } else {
                        self.assign_padding_row(&mut region, 0);
                    }
                    Ok(())
                }
            })
            .collect()
    }

    pub fn n_rows_required(proofs: &[Proof]) -> usize {
        // +1 because assigment starts on offset = 1 instead of offset = 0.
        proofs.iter().map(Proof::n_rows).sum::<usize>() + 1
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
    cb.condition(
        config
            .path_type
            .next_matches(&[PathType::Common, PathType::Start]),
        |cb| {
            cb.poseidon_lookup(
                "poseidon hash correct for old common path",
                [
                    old_left(config),
                    old_right(config),
                    config.domain.current(),
                    config.old_hash.previous(),
                ],
                poseidon,
            );
            cb.poseidon_lookup(
                "poseidon hash correct for new common path",
                [
                    new_left(config),
                    new_right(config),
                    config.domain.current(),
                    config.new_hash.previous(),
                ],
                poseidon,
            );
        },
    );
    cb.condition(
        config.path_type.next_matches(&[PathType::ExtensionNew]),
        |cb| {
            cb.assert_zero(
                "old domain is not HashDomain::Branch3",
                (config.domain.current() - u64::from(HashDomain::Branch0))
                    * (config.domain.current() - u64::from(HashDomain::Branch1))
                    * (config.domain.current() - u64::from(HashDomain::Branch2))
                    * (config.domain.current() - u64::from(HashDomain::AccountFields)),
            );
            cb.poseidon_lookup(
                "poseidon hash correct for old common path",
                [
                    old_left(config),
                    old_right(config),
                    config.domain.current(),
                    config.old_hash.previous(),
                ],
                poseidon,
            );

            let is_type_2 = config
                .segment_type
                .next_matches(&[SegmentType::AccountLeaf0, SegmentType::StorageLeaf0]);
            cb.condition(!is_type_2.clone(), |cb| {
                let new_domain = config.intermediate_values[2];
                cb.assert_equal(
                    "new domain matches direction and domain after insertion",
                    new_domain.current(),
                    lagrange_polynomial(
                        config.domain.current(),
                        &[
                            (
                                HashDomain::Branch0.into(),
                                BinaryQuery(config.direction.current()).select(
                                    Query::from(HashDomain::Branch1.into_u64()),
                                    Query::from(HashDomain::Branch2.into_u64()),
                                ),
                            ),
                            (
                                HashDomain::Branch1.into(),
                                Query::from(HashDomain::Branch3.into_u64()),
                            ),
                            (
                                HashDomain::Branch2.into(),
                                Query::from(HashDomain::Branch3.into_u64()),
                            ),
                            (
                                HashDomain::AccountFields.into(),
                                Query::from(HashDomain::AccountFields.into_u64()),
                            ),
                        ],
                    ),
                );
                cb.poseidon_lookup(
                    "poseidon hash correct for new common path",
                    [
                        new_left(config),
                        new_right(config),
                        new_domain.current(),
                        config.new_hash.previous(),
                    ],
                    poseidon,
                );
            });
            cb.condition(is_type_2, |cb| {
                cb.assert_zero(
                    "old hash is zero for type 2 empty account",
                    config.old_hash.current(),
                );
                cb.poseidon_lookup(
                    "poseidon hash correct for new common path",
                    [
                        new_left(config),
                        new_right(config),
                        config.domain.current(),
                        config.new_hash.previous(),
                    ],
                    poseidon,
                );
            });
        },
    );
    cb.condition(
        config.path_type.next_matches(&[PathType::ExtensionOld]),
        |cb| {
            cb.assert_zero(
                "new domain is not HashDomain::Branch3",
                (config.domain.current() - u64::from(HashDomain::Branch0))
                    * (config.domain.current() - u64::from(HashDomain::Branch1))
                    * (config.domain.current() - u64::from(HashDomain::Branch2))
                    * (config.domain.current() - u64::from(HashDomain::AccountFields)),
            );
            cb.poseidon_lookup(
                "poseidon hash correct for new common path",
                [
                    new_left(config),
                    new_right(config),
                    config.domain.current(),
                    config.new_hash.previous(),
                ],
                poseidon,
            );
            let is_type_2 = config
                .segment_type
                .next_matches(&[SegmentType::AccountLeaf0, SegmentType::StorageLeaf0]);
            cb.condition(!is_type_2.clone(), |cb| {
                let new_domain = config.intermediate_values[2];
                cb.assert_equal(
                    "new domain matches direction and domain before deletion",
                    new_domain.current(),
                    lagrange_polynomial(
                        config.domain.current(),
                        &[
                            (
                                HashDomain::Branch0.into(),
                                BinaryQuery(config.direction.current()).select(
                                    Query::from(Fr::from(HashDomain::Branch1)),
                                    Query::from(Fr::from(HashDomain::Branch2)),
                                ),
                            ),
                            (
                                HashDomain::Branch1.into(),
                                Query::from(Fr::from(HashDomain::Branch3)),
                            ),
                            (
                                HashDomain::Branch2.into(),
                                Query::from(Fr::from(HashDomain::Branch3)),
                            ),
                            (
                                HashDomain::AccountFields.into(),
                                Query::from(Fr::from(HashDomain::AccountFields)),
                            ),
                        ],
                    ),
                );
                cb.poseidon_lookup(
                    "poseidon hash correct for old common path",
                    [
                        old_left(config),
                        old_right(config),
                        new_domain.current(),
                        config.old_hash.previous(),
                    ],
                    poseidon,
                );
            });
            cb.condition(is_type_2, |cb| {
                cb.assert_zero(
                    "new hash is zero for type 2 empty account",
                    config.new_hash.current(),
                );
                cb.poseidon_lookup(
                    "poseidon hash correct for old common path",
                    [
                        old_left(config),
                        old_right(config),
                        config.domain.current(),
                        config.old_hash.previous(),
                    ],
                    poseidon,
                );
            });
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
            config.domain.current(),
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
            let [.., other_leaf_data_hash] = config.intermediate_values;
            nonexistence_proof::configure(
                cb,
                config.new_value,
                config.key,
                config.other_key,
                key_equals_other_key,
                config.new_hash,
                new_hash_is_zero,
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
            config.domain.current(),
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
            let [.., other_leaf_data_hash] = config.intermediate_values;
            nonexistence_proof::configure(
                cb,
                config.old_value,
                config.key,
                config.other_key,
                key_equals_other_key,
                config.old_hash,
                old_hash_is_zero,
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
    cb.assert(
        "account leafs cannot be deleted",
        !config.path_type.current_matches(&[PathType::ExtensionOld]),
    );
    for variant in SegmentType::iter() {
        let conditional_constraints = |cb: &mut ConstraintBuilder<F>| match variant {
            SegmentType::Start | SegmentType::AccountTrie => {
                cb.condition(
                    config.segment_type.next_matches(&[SegmentType::Start]),
                    |cb| {
                        let [.., key_equals_other_key, hash_is_zero] = config.is_zero_gadgets;
                        let [_, _, _, other_leaf_data_hash, ..] = config.intermediate_values;
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
                        Query::from(*ZERO_STORAGE_ROOT_KECCAK_CODEHASH_HASH),
                    );
                    },
                );
            }
            SegmentType::AccountLeaf3 => {
                cb.assert_zero("direction is 0", config.direction.current());

                let new_code_size = (config.new_hash.current() - config.new_value.current())
                    * Query::Constant(F::from(1 << 32).square().invert().unwrap());
                cb.add_lookup(
                    "new nonce is 8 bytes",
                    [config.new_value.current(), Query::from(7)],
                    bytes.lookup(),
                );
                cb.condition(
                    config.path_type.current_matches(&[PathType::Common]),
                    |cb| {
                        cb.add_lookup(
                            "old nonce is 8 bytes",
                            [config.old_value.current(), Query::from(7)],
                            bytes.lookup(),
                        );
                        let old_code_size = (config.old_hash.current()
                            - config.old_value.current())
                            * Query::Constant(F::from(1 << 32).square().invert().unwrap());
                        cb.assert_equal(
                            "old_code_size = new_code_size for nonce update",
                            old_code_size.clone(),
                            new_code_size.clone(),
                        );
                        cb.add_lookup(
                            "existing code size is 8 bytes",
                            [old_code_size, Query::from(7)],
                            bytes.lookup(),
                        );
                    },
                );
                cb.condition(
                    config.path_type.current_matches(&[PathType::ExtensionNew]),
                    |cb| {
                        cb.assert_zero(
                            "old nonce is 0 for ExtensionNew nonce update",
                            config.old_value.current(),
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
            SegmentType::Start | SegmentType::AccountTrie => {
                cb.condition(
                    config.segment_type.next_matches(&[SegmentType::Start]),
                    |cb| {
                        let [.., key_equals_other_key, hash_is_zero] = config.is_zero_gadgets;
                        let [_, _, _, other_leaf_data_hash, ..] = config.intermediate_values;
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
                    new_nonce,
                );
                cb.add_lookup(
                    "nonce is 8 bytes",
                    [old_nonce, Query::from(7)],
                    bytes.lookup(),
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
            SegmentType::Start | SegmentType::AccountTrie => {
                cb.condition(
                    config.segment_type.next_matches(&[SegmentType::Start]),
                    |cb| {
                        let [.., key_equals_other_key, hash_is_zero] = config.is_zero_gadgets;
                        let [_, _, _, other_leaf_data_hash, ..] = config.intermediate_values;
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
                            other_leaf_data_hash,
                            poseidon,
                        );
                    },
                );
            }
            SegmentType::AccountLeaf0 => {
                cb.assert_equal(
                    "balance AccountLeaf0 domain is Leaf",
                    config.domain.current(),
                    Query::from(u64::from(HashDomain::Leaf)),
                );
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
            }
            SegmentType::AccountLeaf1 => {
                cb.assert_equal(
                    "balance AccountLeaf1 domain is AccountFields",
                    config.domain.current(),
                    Query::from(u64::from(HashDomain::AccountFields)),
                );
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
                            Query::from(*ZERO_STORAGE_ROOT_KECCAK_CODEHASH_HASH),
                        );
                    },
                );
            }
            SegmentType::AccountLeaf3 => {
                cb.assert_equal("direction is 1", config.direction.current(), Query::one());
                cb.condition(
                    config.path_type.current_matches(&[PathType::Common]),
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
                cb.condition(
                    config.path_type.current_matches(&[PathType::ExtensionNew]),
                    |cb| {
                        cb.assert_zero(
                            "nonce and code size are 0 for new account",
                            config.sibling.current(),
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
            SegmentType::Start | SegmentType::AccountTrie => {
                cb.condition(
                    config.segment_type.next_matches(&[SegmentType::Start]),
                    |cb| {
                        let [.., key_equals_other_key, hash_is_zero] = config.is_zero_gadgets;
                        let [_, _, _, other_leaf_data_hash, ..] = config.intermediate_values;
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
                    config.old_hash.current() - *ZERO_PAIR_HASH,
                );
                cb.assert_equal(
                    "new_hash_minus_zero_storage_hash = new_hash - hash(0, 0)",
                    new_hash_is_zero_storage_hash.value.current(),
                    config.new_hash.current() - *ZERO_PAIR_HASH,
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
    let [key_high, key_low, _, other_leaf_data_hash, ..] = config.intermediate_values;
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
    cb.assert_equal(
        "hash doesn't change for empty account",
        config.old_hash.current(),
        config.new_hash.current(),
    );

    let is_final_segment = config.segment_type.next_matches(&[SegmentType::Start]);
    cb.condition(is_final_segment, |cb| {
        nonexistence_proof::configure(
            cb,
            config.old_value,
            config.key,
            config.other_key,
            key_equals_other_key,
            config.old_hash,
            hash_is_zero,
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
                // Note that this constraint doesn't apply if the account doesn't exist. This
                // is ok, because every storage key for an empty account is empty.
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
                    let [_, _, _, other_leaf_data_hash, ..] = config.intermediate_values;
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

fn address_low(a: Address) -> u32 {
    let low_bytes: [u8; 4] = a.0[16..].try_into().unwrap();
    u32::from_be_bytes(low_bytes)
}

// ... the return traces: ([inp;2], domain, hash)
pub fn hash_traces(proofs: &[Proof]) -> Vec<([Fr; 2], Fr, Fr)> {
    let mut hash_traces = vec![(
        [Fr::zero(), Fr::zero()],
        HashDomain::Pair.into(),
        *ZERO_PAIR_HASH,
    )];
    for proof in proofs.iter() {
        for (left, right, domain, hash) in proof.account_trie_rows.poseidon_lookups() {
            hash_traces.push(([left, right], Fr::from(domain), hash));
        }

        hash_traces.extend(
            proof
                .storage
                .poseidon_lookups()
                .into_iter()
                .map(|(left, right, domain, h)| ([left, right], Fr::from(domain), h)),
        );

        let key = account_key(proof.claim.address);
        hash_traces.push((
            [
                Fr::from_u128(address_high(proof.claim.address)),
                Fr::from_u128(u128::from(address_low(proof.claim.address)) << 96),
            ],
            HashDomain::Pair.into(),
            key,
        ));

        if let Some(data_hash) = proof.old.leaf_data_hash {
            hash_traces.push((
                [proof.old.key, data_hash],
                HashDomain::Leaf.into(),
                domain_hash(proof.old.key, data_hash, HashDomain::Leaf),
            ));
        }
        if let Some(data_hash) = proof.new.leaf_data_hash {
            hash_traces.push((
                [proof.new.key, data_hash],
                HashDomain::Leaf.into(),
                domain_hash(proof.new.key, data_hash, HashDomain::Leaf),
            ));
        }

        for account_leaf_hash_traces in
            [proof.old_account_hash_traces, proof.new_account_hash_traces]
        {
            for [left, right, digest] in account_leaf_hash_traces {
                if domain_hash(left, right, HashDomain::AccountFields) == digest {
                    hash_traces.push(([left, right], HashDomain::AccountFields.into(), digest))
                } else if domain_hash(left, right, HashDomain::Leaf) == digest {
                    hash_traces.push(([left, right], HashDomain::Leaf.into(), digest))
                } else if domain_hash(left, right, HashDomain::Pair) == digest {
                    hash_traces.push(([left, right], HashDomain::Pair.into(), digest))
                }
            }
        }
    }
    hash_traces.sort();
    hash_traces.dedup();
    hash_traces
}

/// ...
pub fn key_bit_lookups(proofs: &[Proof]) -> Vec<(Fr, usize, bool)> {
    let mut lookups = vec![(Fr::zero(), 0, false), (Fr::one(), 0, true)];
    for proof in proofs.iter() {
        for (i, (direction, _, _, _, _, is_padding_open, is_padding_close)) in
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

    lookups.sort();
    lookups.dedup();
    lookups
}

/// ...
pub fn byte_representations(proofs: &[Proof]) -> (Vec<u32>, Vec<u64>, Vec<u128>, Vec<Fr>) {
    let mut u32s = vec![];
    let mut u64s = vec![];
    let mut u128s = vec![0];
    let mut frs = vec![];

    for proof in proofs {
        u128s.push(address_high(proof.claim.address));
        u32s.push(address_low(proof.claim.address));
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

    u32s.sort();
    u32s.dedup();

    u64s.sort();
    u64s.dedup();

    u128s.sort();
    u128s.dedup();

    frs.sort();
    frs.dedup();

    (u32s, u64s, u128s, frs)
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
    keys.sort();
    keys.dedup();
    keys
}
