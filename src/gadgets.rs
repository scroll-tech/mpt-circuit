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
    constraints: Vec<(&'static str, Query<F>)>,
}

impl<F: Field> ConstraintBuilder<F> {
    fn add_constraint<T: Into<Query<F>>>(&mut self, name: &'static str, t: T) {
        self.constraints.push((name, t.into()))
    }

    fn build(self, cs: &mut ConstraintSystem<F>) {
        for (name, query) in self.constraints {
            cs.create_gate(&name, |meta| vec![query.0(meta)])
        }
    }
}

struct Query<F: Field>(Box<dyn FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>>);

impl<F: FieldExt> From<u64> for Query<F> {
    fn from(x: u64) -> Self {
        let f: F = x.into();
        Self(Box::new(move |meta| Expression::Constant(f)))
    }
}

impl<F: Field, T: Into<Query<F>>> std::ops::Add<T> for Query<F> {
    type Output = Self;
    fn add(self, other: T) -> Self::Output {
        let left = self.0;
        let right = other.into().0;
        Self(Box::new(move |meta| left(meta) + right(meta)))
    }
}

impl<F: Field, T: Into<Query<F>>> std::ops::Sub<T> for Query<F> {
    type Output = Self;
    fn sub(self, other: T) -> Self::Output {
        let left = self.0;
        let right = other.into().0;
        Self(Box::new(move |meta| left(meta) - right(meta)))
    }
}

impl<F: Field, T: Into<Query<F>>> std::ops::Mul<T> for Query<F> {
    type Output = Self;
    fn mul(self, other: T) -> Self::Output {
        let left = self.0;
        let right = other.into().0;
        Self(Box::new(move |meta| left(meta) * right(meta)))
    }
}

// trait IntoQuery<F: Field> {
//     fn into_query(self) -> Box<dyn FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>>;
// }

// impl<F: Field, T: Into<F>> IntoQuery<F> for T {
//     fn into_query(self) -> Box<dyn FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>> {
//         let f: F = self.into();
//         Box::new(move |meta| Expression::Constant(f))
//     }
// }

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
