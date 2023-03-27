use crate::constraint_builder::{AdviceColumn, BinaryColumn, ConstraintBuilder, Query};
use halo2_proofs::{arithmetic::FieldExt, circuit::Region, plonk::ConstraintSystem};
use itertools::Itertools;
use std::fmt::Debug;
use strum::IntoEnumIterator;

// TODO: use EnumCount once generic_const_exprs is enabled.

#[derive(Clone)]
pub struct OneHot(Vec<BinaryColumn>);

impl OneHot {
    pub fn configure<F: FieldExt, T: IntoEnumIterator + Eq>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
    ) -> Self {
        let ([selector], [], []) = cb.build_columns(cs);

        let columns: Vec<_> = T::iter().map(|_| cb.binary_columns::<1>(cs)[0]).collect();
        cb.add_constraint(
            "exactly one binary column is 1 in one hot encoding",
            selector.current(),
            columns
                .iter()
                .map(|b| Query::from(b.current()))
                .sum::<Query<F>>()
                - 1,
        );
        Self(columns)
    }

    pub fn assign<F: FieldExt, T: IntoEnumIterator + Eq>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: T,
    ) {
        for (variant, column) in T::iter().zip_eq(&self.0) {
            column.assign(region, offset, variant == value);
        }
    }

    pub fn condition<F: FieldExt, T: IntoEnumIterator + Eq>(
        &self,
        cb: &mut ConstraintBuilder<F>,
        add_constraints: &mut dyn FnMut(&mut ConstraintBuilder<F>, T) -> (),
    ) {
        for variant in T::iter() {
            add_constraints(cb, variant);
        }
    }
}
