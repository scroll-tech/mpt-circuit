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

    open: Column<Advice>,
    close: Column<Advice>,
    sibling: Column<Advice>,

    is_first: Column<Advice>,
    direction: Column<Advice>,
    is_padding_open: Column<Advice>,
    is_padding_close: Column<Advice>,
}

impl Config {
    fn configure<F: Field>(meta: &mut ConstraintSystem<F>, poseidon_table: PoseidonConfig) -> Self {
        let selector = meta.selector();
        let [open, close, sibling] = [(); 3].map(|()| meta.advice_column());

        let [is_first, direction, is_padding_open, is_padding_close] = [(); 4].map(|()| {
            let column = meta.advice_column();
            meta.create_gate("is binary", |meta| {
                let selector = meta.query_selector(selector);
                let e = meta.query_advice(column, Rotation::cur());
                vec![selector * e.clone() * (Expression::Constant(F::one()) - e)]
            });
            column
        });

        Self {
            selector,
            open,
            close,
            sibling,
            is_first,
            direction,
            is_padding_open,
            is_padding_close,
        }
    }
}
