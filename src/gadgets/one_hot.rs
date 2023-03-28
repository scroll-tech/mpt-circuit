use crate::constraint_builder::BinaryQuery;
use crate::constraint_builder::{AdviceColumn, BinaryColumn, ConstraintBuilder, Query};
use halo2_proofs::{arithmetic::FieldExt, circuit::Region, plonk::ConstraintSystem};
use itertools::Itertools;
use std::fmt::Debug;
use std::marker::PhantomData;
use strum::IntoEnumIterator;

#[derive(Clone)]
pub struct OneHot<T> {
    // TODO: use [BinaryColumn; T::COUNT] once generic_const_exprs is enabled.
    columns: Vec<BinaryColumn>,
    phantom_data: PhantomData<T>,
}

impl<T: IntoEnumIterator + Eq> OneHot<T> {
    pub fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
    ) -> Self {
        let ([selector], [], []) = cb.build_columns(cs);
        let columns: Vec<_> = T::iter().map(|_| cb.binary_columns::<1>(cs)[0]).collect();
        cb.add_constraint(
            "exactly one binary column is set in one hot encoding",
            selector.current(),
            columns
                .iter()
                .fold(Query::zero(), |a, b| a.clone() + b.current())
                - 1,
        );
        Self {
            columns,
            phantom_data: PhantomData,
        }
    }

    pub fn assign<F: FieldExt>(&self, region: &mut Region<'_, F>, offset: usize, value: T) {
        for (variant, column) in T::iter().zip_eq(&self.columns) {
            column.assign(region, offset, variant == value);
        }
    }

    pub fn matches<F: FieldExt>(&self, value: T) -> BinaryQuery<F> {
        T::iter()
            .zip_eq(&self.columns)
            .find_map(|(variant, column)| {
                if variant == value {
                    Some(column.current())
                } else {
                    None
                }
            })
            .unwrap()
    }
}
