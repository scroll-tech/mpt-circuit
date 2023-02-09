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
    is_last: Column<Advice>,
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

        [(open, is_padding_open), (close, is_padding_close)].map(|(value, is_padding)| {
            meta.lookup_any("open hash", |meta| {
                let direction = meta.query_advice(direction, Rotation::cur());
                let hash = meta.query_advice(value, Rotation::next());
                let value = meta.query_advice(value, Rotation::cur());
                let sibling = meta.query_advice(sibling, Rotation::cur());

                let left = value.clone() * direction.clone()
                    + sibling.clone() * (Expression::Constant(F::one()) - direction.clone());
                let right = sibling.clone() * direction.clone()
                    + value.clone() * (Expression::Constant(F::one()) - direction.clone());

                let is_padding = meta.query_advice(is_padding, Rotation::cur());
                poseidon_table.lookup_expressions(
                    meta,
                    left * is_padding.clone(),
                    right * is_padding.clone(),
                    hash * is_padding,
                )
            })
        });

        Self {
            selector,
            open,
            close,
            sibling,
            is_first,
            is_last: meta.advice_column(),
            direction,
            is_padding_open,
            is_padding_close,
        }
    }
}
