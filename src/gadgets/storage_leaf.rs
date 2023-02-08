use super::poseidon::Config as PoseidonConfig;
use ethers_core::types::U256;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{Chip, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

#[derive(Clone, Copy, Debug)]
struct Config {
    selector: Selector,

    key_high: Column<Advice>,
    key_low: Column<Advice>,

    value_high: Column<Advice>,
    value_low: Column<Advice>,

    key_hash: Column<Advice>,   // poseidon(code_hash_high, code_hash_low)
    value_hash: Column<Advice>, // poseidon(value_high, value_low)

    leaf_hash: Column<Advice>, // poseidon(poseidon(1, key_hash), value_hash)
}

impl Config {
    fn configure<F: Field>(meta: &mut ConstraintSystem<F>, poseidon_table: PoseidonConfig) -> Self {
        let [key_high, key_low, key_hash] = [(); 3].map(|()| meta.advice_column());
        poseidon_table.lookup_columns(meta, key_high, key_low, key_hash);

        let [value_high, value_low, value_hash] = [(); 3].map(|()| meta.advice_column());
        poseidon_table.lookup_columns(meta, value_high, value_low, value_hash);

        let leaf_hash = meta.advice_column();
        // poseidon_table.lookup_leaf(meta, key_hash, leaf_hash);

        // Need constraint that value is not 0.

        Self {
            selector: meta.selector(),
            key_high,
            key_low,
            value_high,
            value_low,
            key_hash,
            value_hash,
            leaf_hash,
        }
    }

    fn assign<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        storage_entry: &[(U256, U256)],
    ) -> Result<(), Error> {
        Ok(())
    }
}
