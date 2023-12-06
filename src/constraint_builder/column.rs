use super::{BinaryQuery, Query};
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, Fixed},
};
use std::fmt::Debug;

#[derive(Clone, Copy)]
pub struct SelectorColumn(pub Column<Fixed>);

impl SelectorColumn {
    pub fn current<F: PrimeField>(self) -> BinaryQuery<F> {
        self.rotation(0)
    }

    pub fn rotation<F: PrimeField>(self, i: i32) -> BinaryQuery<F> {
        BinaryQuery(Query::Fixed(self.0, i))
    }

    pub fn enable<F: PrimeField>(&self, region: &mut Region<'_, F>, offset: usize) {
        region
            .assign_fixed(|| "selector", self.0, offset, || Value::known(F::ONE))
            .expect("failed enable selector");
    }
}

#[derive(Clone, Copy)]
pub struct FixedColumn(pub Column<Fixed>);

impl FixedColumn {
    pub fn rotation<F: PrimeField>(self, i: i32) -> Query<F> {
        Query::Fixed(self.0, i)
    }

    pub fn current<F: PrimeField>(self) -> Query<F> {
        self.rotation(0)
    }

    pub fn previous<F: PrimeField>(self) -> Query<F> {
        self.rotation(-1)
    }

    pub fn assign<F: PrimeField, T: Copy + TryInto<F>>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: T,
    ) where
        <T as TryInto<F>>::Error: Debug,
    {
        region
            .assign_fixed(
                || "fixed",
                self.0,
                offset,
                || Value::known(value.try_into().unwrap()),
            )
            .expect("failed assign_fixed");
    }
}

#[derive(Clone, Copy)]
pub struct AdviceColumn(pub Column<Advice>);

impl AdviceColumn {
    pub fn rotation<F: PrimeField>(self, i: i32) -> Query<F> {
        Query::Advice(self.0, i)
    }

    pub fn current<F: PrimeField>(self) -> Query<F> {
        self.rotation(0)
    }

    pub fn previous<F: PrimeField>(self) -> Query<F> {
        self.rotation(-1)
    }

    pub fn next<F: PrimeField>(self) -> Query<F> {
        self.rotation(1)
    }

    pub fn delta<F: PrimeField>(self) -> Query<F> {
        self.current() - self.previous()
    }

    pub fn assign<F: PrimeField, T: Copy + TryInto<F>>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: T,
    ) where
        <T as TryInto<F>>::Error: Debug,
    {
        region
            .assign_advice(
                || "advice",
                self.0,
                offset,
                || Value::known(value.try_into().unwrap()),
            )
            .expect("failed assign_advice");
    }
}
