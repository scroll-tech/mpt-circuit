use crate::constraint_builder::{AdviceColumn, BinaryQuery, ConstraintBuilder, Query};
use halo2_proofs::{arithmetic::FieldExt, circuit::Region, plonk::ConstraintSystem};
use std::fmt::Debug;
use strum::EnumCount;

#[derive(Clone, Copy)]
pub struct OneHot<const N: usize>([BinaryColumn; N]);

impl<const N: usize> OneHot<N> {
    pub fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
    ) -> Self {
        let binary_columns = [0; N].map(BinaryColumn(cs.advice_column()));
        cb.add_constraint(
            "exactly one binary column is 1 in one hot encoding",
            binary_columns.iter().map(|b| b.current()).sum() - 1,
        );
        Self(binary_columns)
    }

    pub fn assign<T: EnumCount + IntoIterator>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: T,
    ) where
        T::COUNT = N,
    {
        self.0.assign(
            region,
            offset,
            value.try_into().unwrap().invert().unwrap_or(F::zero()),
        );
    }

    pub fn condition<F: FieldExt, T: EnumCount + IntoIterator>(
        &self,
        cb: &mut ConstraintBuilder<F>,
        add_constraints: &dyn FnMut(&mut ConstraintBuilder<F>) -> (),
    ) where
        T::COUNT = N,
    {
        for variant in T::into_iter() {
            add_constraints(cb);
        }
    }
}
