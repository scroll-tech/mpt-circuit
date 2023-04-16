use crate::constraint_builder::BinaryQuery;
use crate::constraint_builder::{AdviceColumn, BinaryColumn, ConstraintBuilder, Query};
use halo2_proofs::{arithmetic::FieldExt, circuit::Region, plonk::ConstraintSystem};
use itertools::Itertools;
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
        let columns: Vec<_> = T::iter().map(|_| cb.binary_columns::<1>(cs)[0]).collect();
        cb.assert_equal(
            "exactly one binary column is set in one hot encoding",
            columns
                .iter()
                .fold(Query::zero(), |a, b| a.clone() + b.current()),
            Query::one(),
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

    pub fn previous_matches<F: FieldExt>(&self, value: T) -> BinaryQuery<F> {
        T::iter()
            .zip_eq(&self.columns)
            .find_map(|(variant, column)| {
                if variant == value {
                    Some(column.previous())
                } else {
                    None
                }
            })
            .unwrap()
    }

    pub fn previous_in<F: FieldExt>(&self, values: &[T]) -> BinaryQuery<F> {
        BinaryQuery::one()
    }

    pub fn next_matches<F: FieldExt>(&self, value: T) -> BinaryQuery<F> {
        T::iter()
            .zip_eq(&self.columns)
            .find_map(|(variant, column)| {
                if variant == value {
                    Some(column.next())
                } else {
                    None
                }
            })
            .unwrap()
    }

    pub fn current<F: FieldExt>(&self) -> Query<F> {
        T::iter()
            .enumerate()
            .zip(&self.columns)
            .fold(Query::zero(), |acc, ((i, _), column)| {
                acc.clone() + Query::from(u64::try_from(i).unwrap()) * column.current()
            })
    }

    pub fn previous<F: FieldExt>(&self) -> Query<F> {
        T::iter()
            .enumerate()
            .zip(&self.columns)
            .fold(Query::zero(), |acc, ((i, _), column)| {
                acc.clone() + Query::from(u64::try_from(i).unwrap()) * column.previous()
            })
    }
}
