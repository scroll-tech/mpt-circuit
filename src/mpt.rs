use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Challenge, Circuit, Column, ConstraintSystem, Error, FirstPhase, Fixed},
};

use crate::{
    constraint_builder::{AdviceColumn, ConstraintBuilder, FixedColumn, SelectorColumn},
    gadgets::{
        byte_bit::ByteBitGadget,
        byte_representation::ByteRepresentationConfig,
        canonical_representation::CanonicalRepresentationConfig,
        key_bit::KeyBitConfig,
        mpt_update::{byte_representations, key_bit_lookups, mpt_update_keys, MptUpdateConfig},
        poseidon::PoseidonTable,
        rlc_randomness::RlcRandomness,
    },
    serde::SMTTrace,
    types::Proof,
    MPTProofType,
};

/// the integration of full mpt circuit
#[derive(Clone)]
pub struct MptCircuitConfig {
    mpt_update: MptUpdateConfig,
    canonical_representation: CanonicalRepresentationConfig,
    key_bit: KeyBitConfig,
    byte_bit: ByteBitGadget,
    byte_representation: ByteRepresentationConfig,
    /// export PoseidonTable for external assign
    pub poseidon_table: PoseidonTable,
    q_rows: SelectorColumn,
}

impl MptCircuitConfig {
    pub fn create(
        cs: &mut ConstraintSystem<Fr>,
        _mpt_tbl: [Column<Advice>; 7],
        hash_tbl: (Column<Fixed>, [Column<Advice>; 5]),
        randomness: Challenge,
    ) -> Self {
        // TODO: connect mpt_table
        Self::create_core(cs, hash_tbl, randomness)
    }

    pub fn create_core(
        cs: &mut ConstraintSystem<Fr>,
        hash_tbl: (Column<Fixed>, [Column<Advice>; 5]),
        randomness: Challenge,
    ) -> Self {
        let q_rows = SelectorColumn(cs.fixed_column());
        let rlc_randomness = RlcRandomness(randomness);
        let mut cb = ConstraintBuilder::new(q_rows);

        let byte_bit = ByteBitGadget::configure(cs, &mut cb);
        let byte_representation =
            ByteRepresentationConfig::configure(cs, &mut cb, &byte_bit, &rlc_randomness);
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
        let poseidon_table: PoseidonTable =
            (FixedColumn(hash_tbl.0), hash_tbl.1.map(AdviceColumn)).into();

        let mpt_update = MptUpdateConfig::configure(
            cs,
            &mut cb,
            &poseidon_table,
            &key_bit,
            &byte_representation,
            &byte_representation,
            &rlc_randomness,
        );

        cb.build(cs);

        Self {
            mpt_update,
            key_bit,
            byte_bit,
            canonical_representation,
            byte_representation,
            poseidon_table,
            q_rows,
        }
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Fr>,
        randomness: Value<Fr>,
        proofs: &[Proof],
        row_limit: usize,
    ) -> Result<(), Error> {
        let (u64s, u128s, frs) = byte_representations(&proofs);

        layouter.assign_region(
            || "",
            |mut region| {
                self.canonical_representation
                    .assign(&mut region, &mpt_update_keys(&proofs));
                self.key_bit.assign(&mut region, &key_bit_lookups(&proofs));
                self.byte_bit.assign(&mut region);
                self.byte_representation
                    .assign(&mut region, &u64s, &u128s, &frs, randomness);

                // TODO: selector?
                let rows = self.mpt_update.assign(&mut region, &proofs, randomness);

                assert!(
                    rows < row_limit,
                    "the assigned rows for mpt update has {rows} rows and exceed limit {row_limit}"
                );

                for offset in rows..row_limit {
                    self.mpt_update.assign_padding_row(&mut region, offset);
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

// export hash_traces for poseidon table
pub use crate::gadgets::mpt_update::hash_traces;

// the circuit object
#[derive(Debug, Clone, Default)]
pub struct MptCircuit {
    pub row_limit: usize,
    /// the proofs required
    pub proofs: Vec<Proof>,
}

impl MptCircuit {
    pub fn from_traces(
        traces: impl IntoIterator<Item = (MPTProofType, SMTTrace)>,
        row_limit: usize,
    ) -> Self {
        let proofs = traces.into_iter().map(Proof::from).collect();
        Self { row_limit, proofs }
    }

    pub fn hash_traces(&self) -> Vec<(Fr, Fr, Fr)> {
        hash_traces(&self.proofs)
    }
}

// an example for implement of circuit
impl Circuit<Fr> for MptCircuit {
    type Config = (MptCircuitConfig, Challenge);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            row_limit: self.row_limit,
            ..Default::default()
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let hash_tbl = (meta.fixed_column(), [0; 5].map(|_| meta.advice_column()));
        let challenge = meta.challenge_usable_after(FirstPhase);

        (
            MptCircuitConfig::create_core(meta, hash_tbl, challenge),
            challenge,
        )
    }

    fn synthesize(
        &self,
        (config, challenge): Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let chg = layouter.get_challenge(challenge);

        layouter.assign_region(
            || "poseidon table for dev",
            |mut region| {
                config
                    .poseidon_table
                    .dev_load(&mut region, &self.hash_traces(), self.row_limit);
                Ok(())
            },
        )?;

        config.assign(&mut layouter, chg, &self.proofs, self.row_limit)?;

        Ok(())
    }
}
