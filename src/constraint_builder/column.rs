use super::{BinaryQuery, Query};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::{Advice, Column, Fixed, Selector},
    poly::Rotation,
};
use std::fmt::Debug;

#[derive(Clone, Copy)]
pub struct SelectorColumn(pub Column<Fixed>);

impl SelectorColumn {
    pub fn current<F: FieldExt>(self) -> BinaryQuery<F> {
        BinaryQuery(Query(Box::new(move |meta| {
            meta.query_fixed(self.0, Rotation::cur())
        })))
    }

    pub fn enable<F: FieldExt>(&self, region: &mut Region<'_, F>, offset: usize) {
        region
            .assign_fixed(|| "", self.0, offset, || Value::known(F::one()))
            .expect("failed enable selector");
    }
}

#[derive(Clone, Copy)]
pub struct FixedColumn(pub Column<Fixed>);

impl FixedColumn {
    pub fn rotation<F: FieldExt>(self, i: i32) -> Query<F> {
        Query(Box::new(move |meta| meta.query_fixed(self.0, Rotation(i))))
    }

    pub fn current<F: FieldExt>(self) -> Query<F> {
        self.rotation(0)
    }

    pub fn previous<F: FieldExt>(self) -> Query<F> {
        self.rotation(-1)
    }

    pub fn assign<F: FieldExt, T: Copy + TryInto<F>>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: T,
    ) where
        <T as TryInto<F>>::Error: Debug,
    {
        region
            .assign_fixed(
                || "",
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
    pub fn rotation<F: FieldExt>(self, i: i32) -> Query<F> {
        Query(Box::new(move |meta| meta.query_advice(self.0, Rotation(i))))
    }

    pub fn current<F: FieldExt>(self) -> Query<F> {
        self.rotation(0)
    }

    pub fn previous<F: FieldExt>(self) -> Query<F> {
        self.rotation(-1)
    }

    pub fn assign<F: FieldExt, T: Copy + TryInto<F>>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: T,
    ) where
        <T as TryInto<F>>::Error: Debug,
    {
        region
            .assign_advice(
                || "",
                self.0,
                offset,
                || Value::known(value.try_into().unwrap()),
            )
            .expect("failed assign_advice");
    }
}

#[derive(Clone, Copy)]
pub struct IsZeroColumn {
    pub value: AdviceColumn,
    pub inverse_or_zero: AdviceColumn,
}

// probably a better name for this is IsZeroConfig
impl IsZeroColumn {
    pub fn current<F: FieldExt>(self) -> BinaryQuery<F> {
        BinaryQuery(Query::one() - self.value.current() - self.inverse_or_zero.current())
    }

    pub fn assign<F: FieldExt, T: Copy + TryInto<F>>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: T,
    ) where
        <T as TryInto<F>>::Error: Debug,
    {
        self.inverse_or_zero.assign(
            region,
            offset,
            value.try_into().unwrap().invert().unwrap_or(F::zero()),
        );
    }
}
