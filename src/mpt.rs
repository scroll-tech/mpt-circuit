use crate::{
    constraint_builder::{ConstraintBuilder, Query, SelectorColumn},
    gadgets::{
        byte_bit::ByteBitGadget,
        byte_representation::ByteRepresentationConfig,
        canonical_representation::CanonicalRepresentationConfig,
        key_bit::KeyBitConfig,
        mpt_update::{
            byte_representations, key_bit_lookups, mpt_update_keys, MptUpdateConfig,
            MptUpdateLookup,
        },
        poseidon::PoseidonLookup,
        rlc_randomness::RlcRandomness,
    },
    mpt_table::MPTProofType,
    types::Proof,
};
use halo2_proofs::{
    circuit::Layouter,
    halo2curves::{bn256::Fr, ff::FromUniformBytes},
    plonk::{Challenge, ConstraintSystem, Error, Expression, VirtualCells},
};
use itertools::Itertools;
use std::time::Instant;

/// Config for MptCircuit
#[derive(Clone)]
pub struct MptCircuitConfig {
    selector: SelectorColumn,
    is_final_row: SelectorColumn,
    rlc_randomness: RlcRandomness,
    mpt_update: MptUpdateConfig,
    canonical_representation: CanonicalRepresentationConfig,
    key_bit: KeyBitConfig,
    byte_bit: ByteBitGadget,
    byte_representation: ByteRepresentationConfig,
}

impl MptCircuitConfig {
    pub fn configure(
        cs: &mut ConstraintSystem<Fr>,
        evm_word_challenge: Challenge,
        poseidon: &impl PoseidonLookup,
    ) -> Self {
        let selector = SelectorColumn(cs.fixed_column());
        let rlc_randomness = RlcRandomness(evm_word_challenge);
        let mut cb = ConstraintBuilder::new(selector);

        let byte_bit = ByteBitGadget::configure(cs, &mut cb);
        let byte_representation =
            ByteRepresentationConfig::configure(cs, &mut cb, &byte_bit, &rlc_randomness);
        let canonical_representation =
            CanonicalRepresentationConfig::configure(cs, &mut cb, &byte_bit, &rlc_randomness);
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
            poseidon,
            &key_bit,
            &byte_representation,
            &byte_representation,
            &rlc_randomness,
            &canonical_representation,
        );

        // This ensures that the final mpt update in the circuit is complete, since the padding
        // for the mpt update is a valid proof that shows the account with address 0 does not
        // exist in an mpt with root = 0 (i.e. the mpt is empty).
        let is_final_row = SelectorColumn(cs.fixed_column());
        let padding_row_expressions = [
            0.into(),
            0.into(),
            (MPTProofType::AccountDoesNotExist as u64).into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ];
        cb.condition(is_final_row.current(), |cb| {
            for (padding_row_expression, lookup_expression) in padding_row_expressions
                .into_iter()
                .zip_eq(mpt_update.lookup())
            {
                cb.assert_equal(
                    "final mpt update is padding",
                    padding_row_expression,
                    lookup_expression,
                )
            }
        });

        cb.build(cs);

        Self {
            selector,
            is_final_row,
            rlc_randomness,
            mpt_update,
            key_bit,
            byte_bit,
            canonical_representation,
            byte_representation,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Fr>,
        proofs: &[Proof],
        n_rows: usize,
    ) -> Result<(), Error> {
        let randomness = self.rlc_randomness.value(layouter);
        let (u32s, u64s, u128s, frs) = byte_representations(proofs);

        let mpt_updates_assign_dur = Instant::now();
        let use_par = std::env::var("PARALLEL_SYN").map_or(false, |s| s == *"true");
        if use_par {
            let n_assigned_rows = self.mpt_update.assign_par(layouter, proofs, randomness);

            layouter.assign_region(
                || "mpt update padding rows",
                |mut region| {
                    if n_assigned_rows == 0 {
                        // first row is all-zeroes row
                        for offset in 1..n_rows {
                            self.mpt_update.assign_padding_row(&mut region, offset);
                        }
                    } else {
                        for offset in 0..(n_rows - (1 + n_assigned_rows)) {
                            self.mpt_update.assign_padding_row(&mut region, offset);
                        }
                    }
                    Ok(())
                },
            )?;
        } else {
            layouter.assign_region(
                || "mpt update",
                |mut region| {
                    let n_assigned_rows = self.mpt_update.assign(&mut region, proofs, randomness);

                    assert!(
                        2 + n_assigned_rows <= n_rows,
                        "mpt circuit requires {n_assigned_rows} rows for mpt updates + 1 initial \
                    all-zero row + at least 1 final padding row. Only {n_rows} rows available."
                    );

                    for offset in (1 + n_assigned_rows)..n_rows {
                        self.mpt_update.assign_padding_row(&mut region, offset);
                    }

                    Ok(())
                },
            )?;
        }
        log::debug!(
            "mpt updates assignment(use_par = {}) took {:?}",
            use_par,
            mpt_updates_assign_dur.elapsed()
        );

        if use_par {
            let key_bit_time = {
                let dur = Instant::now();
                self.key_bit.assign_par(layouter, &key_bit_lookups(proofs));
                dur.elapsed()
            };
            log::debug!("mpt key_bit assignment took {:?}", key_bit_time);
        }

        // pad canonical_representation to fixed count
        // notice each input cost 32 rows in canonical_representation, and inside
        // assign one extra input is added
        let (keys, get_keys_time) = {
            let dur = Instant::now();
            let mut keys = mpt_update_keys(proofs);
            keys.sort();
            keys.dedup();
            (keys, dur.elapsed())
        };
        let total_rep_size = n_rows / 32 - 1;
        assert!(
            total_rep_size >= keys.len(),
            "no enough space for canonical representation of all keys (need {})",
            keys.len()
        );
        log::debug!("get keys took {:?}", get_keys_time);

        if use_par {
            let canon_repr_time = {
                let dur = Instant::now();
                self.canonical_representation
                    .assign_par(layouter, randomness, &keys, n_rows);
                dur.elapsed()
            };
            log::debug!("canonical_repr assignment took {:?}", canon_repr_time);
        }

        layouter.assign_region(
            || "mpt keys",
            |mut region| {
                for offset in 1..n_rows {
                    self.selector.enable(&mut region, offset);
                }

                let keys_assign_dur = Instant::now();
                if !use_par {
                    self.canonical_representation
                        .assign(&mut region, randomness, &keys, n_rows);
                    self.key_bit.assign(&mut region, &key_bit_lookups(proofs));
                }

                let byte_bit_time = {
                    let dur = Instant::now();
                    self.byte_bit.assign(&mut region);
                    dur.elapsed()
                };
                let byte_repr_time = {
                    let dur = Instant::now();
                    self.byte_representation.assign(
                        &mut region,
                        &u32s,
                        &u64s,
                        &u128s,
                        &frs,
                        randomness,
                    );
                    dur.elapsed()
                };
                let keys_assign_time = keys_assign_dur.elapsed();
                log::debug!("keys assignment took {:?}", keys_assign_time);
                log::debug!(
                    "byte_bit: {}",
                    byte_bit_time.as_micros() as f64 / keys_assign_time.as_micros() as f64
                );
                log::debug!(
                    "byte_repr: {}",
                    byte_repr_time.as_micros() as f64 / keys_assign_time.as_micros() as f64
                );

                self.is_final_row.enable(&mut region, n_rows - 1);

                Ok(())
            },
        )
    }

    pub fn lookup_exprs<F: FromUniformBytes<64> + Ord>(
        &self,
        meta: &mut VirtualCells<'_, F>,
    ) -> [Expression<F>; 8] {
        std::iter::once(Query::from(self.selector.current()))
            .chain(self.mpt_update.lookup().into_iter())
            .map(|q| q.run(meta))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// The number of minimum number of rows required for the mpt circuit.
    pub fn n_rows_required(proofs: &[Proof]) -> usize {
        let (u32s, u64s, u128s, frs) = byte_representations(proofs);

        // +1 for the final padding row to satisfy the "final mpt update is padding" constraint.
        1 + *[
            MptUpdateConfig::n_rows_required(proofs),
            CanonicalRepresentationConfig::n_rows_required(&mpt_update_keys(proofs)),
            KeyBitConfig::n_rows_required(&key_bit_lookups(proofs)),
            // TODO: move rlc lookup for frs into CanonicalRepresentationConfig.
            ByteRepresentationConfig::n_rows_required(&u32s, &u64s, &u128s, &frs),
            ByteBitGadget::n_rows_required(),
        ]
        .iter()
        .max()
        .unwrap()
    }
}
