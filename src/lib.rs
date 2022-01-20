//! mpt demo circuits
//

#![allow(dead_code)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub use crate::serde::{Hash, HashType, Row, RowDeError};

pub mod mpt;
pub mod operations;
mod serde;

#[cfg(test)]
mod test_utils;

use ff::PrimeField;
use halo2::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Expression, Selector, Column, ConstraintSystem, Error},
    poly::Rotation,
};

#[derive(Clone, Debug)]
struct MPTConfig {
    s_row: Selector,
    sibling: Column<Advice>,
    path: Column<Advice>,
    old_hash_type: Column<Advice>,
    new_hash_type: Column<Advice>,
    old_hash: Column<Advice>,
    new_hash: Column<Advice>,
    old_val: Column<Advice>,
    new_val: Column<Advice>,    
    op_chip: operations::MPTOpChipConfig,
    old_state_chip: mpt::MPTChipConfig,
    new_state_chip: mpt::MPTChipConfig,
}

#[derive(Clone, Default)]
struct SingleOp<Fp: PrimeField> {
    pub old_hash_type: Vec<HashType>,
    pub new_hash_type: Vec<HashType>,
    pub path: Vec<Fp>,
    pub old_hash: Vec<Fp>,
    pub new_hash: Vec<Fp>,
    pub siblings: Vec<Fp>, //siblings from top to bottom
}

impl<Fp: PrimeField> SingleOp<Fp> {

}

#[derive(Clone, Default)]
struct MPTDemoCircuit<Fp: PrimeField> {
    pub ops: Vec<SingleOp<Fp>>,
    pub max_rows: usize,
}

impl<Fp: FieldExt> Circuit<Fp> for MPTDemoCircuit<Fp> {
    type Config = MPTConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {

        let s_row = meta.selector();
        let sibling = meta.advice_column();
        let path = meta.advice_column();
        let old_hash_type = meta.advice_column();
        let new_hash_type = meta.advice_column();
        let old_hash = meta.advice_column();
        let new_hash = meta.advice_column();
        let old_val = meta.advice_column();
        let new_val = meta.advice_column();

        let op_chip = operations::MPTOpChip::<Fp>::configure(meta, s_row, sibling, path, old_hash_type, new_hash_type, old_hash, new_hash);
        let new_state_chip = mpt::MPTChip::<Fp>::configure(meta, old_hash_type, old_hash, op_chip.key, sibling, path);
        let old_state_chip = mpt::MPTChip::<Fp>::configure(meta, new_hash_type, new_hash, op_chip.key, sibling, path);

        MPTConfig {
            s_row,
            sibling,
            path,
            old_hash_type,
            new_hash_type,
            old_hash,
            new_hash,
            old_val,
            new_val,
            op_chip,
            old_state_chip,
            new_state_chip,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {

        Ok(())
    }

}