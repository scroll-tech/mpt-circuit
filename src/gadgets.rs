// use halo2_proofs::{
//     arithmetic::Field,
//     circuit::{Layouter, SimpleFloorPlanner},
//     plonk::{Circuit, ConstraintSystem, Error},
// };
// use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::{Layouter, Value},
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

mod byte_bit;
mod canonical_representation;
mod is_zero;
mod key_bit;
mod poseidon;
mod storage_leaf;
mod storage_parents;

#[derive(Clone, Copy, Debug)]
struct ByteRangeCheckConfig(Column<Fixed>);

impl ByteRangeCheckConfig {
    fn configure<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let column = meta.fixed_column();
        Self(column)
    }

    fn assign<F: FieldExt>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "byte range check fixed column",
            |mut region| {
                for i in 0..256 {
                    region.assign_fixed(
                        || "",
                        self.0,
                        i,
                        || {
                            let value: F = u64::try_from(i).unwrap().into();
                            Value::known(value)
                        },
                    )?;
                }
                Ok(())
            },
        )
    }

    pub(crate) fn lookup_expressions<F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>,
    ) -> Vec<Expression<F>> {
        vec![meta.query_fixed(self.0, Rotation::cur())]
    }
}
