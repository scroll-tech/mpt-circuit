// use halo2_proofs::{
//     arithmetic::Field,
//     circuit::{Layouter, SimpleFloorPlanner},
//     plonk::{Circuit, ConstraintSystem, Error},
// };
// use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::{Chip, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector, TableColumn,
        VirtualCells,
    },
    poly::Rotation,
};

mod canonical_representation;
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

struct ConstraintBuilder<F: Field> {
    constraints: Vec<(
        &'static str,
        Box<dyn FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>>,
    )>,
}

impl<F: Field> ConstraintBuilder<F> {
    fn add_constraint<T: IntoQuery<F>>(&mut self, name: &'static str, t: T) {
        self.constraints.push((name, Box::new(t.into_query())))
    }

    fn build(self, cs: &mut ConstraintSystem<F>) {
        for (name, query) in self.constraints {
            cs.create_gate(&name, |meta| vec![query(meta)])
        }
    }
}

trait IntoQuery<F: Field>: Clone {
    fn into_query(&self) -> Box<dyn FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>>;
}

// enum Cell {
//     One,
//     Byte(u8),
//     Add(Box<Cell>, Box<Cell>),
//     Neg(Box<Cell>),
//     Mul(Box<Cell>, Box<Cell>),
//     Inv(Box<Cell>),
//     Advice,
//     Fixed,
// }
