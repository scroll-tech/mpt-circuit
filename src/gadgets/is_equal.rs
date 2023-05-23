use crate::constraint_builder::{AdviceColumn, BinaryQuery, ConstraintBuilder, Query};
use halo2_proofs::{arithmetic::FieldExt, circuit::Region, plonk::ConstraintSystem};
use std::fmt::Debug;

#[derive(Clone)]
pub struct IsEqualGadget<F: FieldExt> {
    left: Query<F>,
    right: Query<F>,
    inverse_or_zero: AdviceColumn,
}

impl<F: FieldExt> IsEqualGadget<F> {
    pub fn current(&self) -> BinaryQuery<F> {
        BinaryQuery(
            Query::one()
                - self.inverse_or_zero.current() * (self.left.clone() - self.right.clone()),
        )
    }

    pub fn assign<G: FieldExt, T: Copy + TryInto<G>>(
        &self,
        region: &mut Region<'_, G>,
        offset: usize,
        left: T,
        right: T,
    ) where
        <T as TryInto<G>>::Error: Debug,
    {
        self.inverse_or_zero.assign(
            region,
            offset,
            (TryInto::<G>::try_into(left).unwrap() - TryInto::<G>::try_into(right).unwrap())
                .invert()
                .unwrap_or(G::zero()),
        );
    }

    pub fn configure(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
        left: Query<F>,
        right: Query<F>,
    ) -> Self {
        let difference = left.clone() - right.clone();
        let inverse_or_zero = AdviceColumn(cs.advice_column());
        cb.assert_zero(
            "difference is 0 or inverse_or_zero is inverse of difference",
            difference.clone() * (Query::one() - difference * inverse_or_zero.current()),
        );
        Self {
            left,
            right,
            inverse_or_zero,
        }
    }
}
