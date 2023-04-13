use super::BinaryQuery;
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    plonk::{Advice, Column, Expression, Fixed, Instance, VirtualCells},
    poly::Rotation,
};

#[derive(Clone, Copy)]
pub enum ColumnType {
    Advice,
    Fixed,
    Instance,
}

#[derive(Clone)]
pub enum Query<F: Clone> {
    Constant(F),
    Advice(Column<Advice>, i32),
    Fixed(Column<Fixed>, i32),
    Instance(Column<Instance>, i32),
    Neg(Box<Self>),
    Add(Box<Self>, Box<Self>),
    Mul(Box<Self>, Box<Self>),
}

impl<F: FieldExt> Query<F> {
    pub fn zero() -> Self {
        Self::from(0)
    }

    pub fn one() -> Self {
        Self::from(1)
    }

    pub fn run(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        match self {
            Query::Constant(f) => Expression::Constant(*f),
            Query::Advice(c, r) => meta.query_advice(*c, Rotation(*r)),
            Query::Fixed(c, r) => meta.query_fixed(*c, Rotation(*r)),
            Query::Instance(c, r) => meta.query_instance(*c, Rotation(*r)),
            Query::Neg(q) => Expression::Constant(F::zero()) - q.run(meta),
            Query::Add(q, u) => q.run(meta) + u.run(meta),
            Query::Mul(q, u) => q.run(meta) * u.run(meta),
        }
    }
}

impl<F: FieldExt> From<u64> for Query<F> {
    fn from(x: u64) -> Self {
        Self::Constant(F::from(x))
    }
}

impl<F: FieldExt> From<BinaryQuery<F>> for Query<F> {
    fn from(b: BinaryQuery<F>) -> Self {
        b.0
    }
}

impl<F: Field, T: Into<Query<F>>> std::ops::Add<T> for Query<F> {
    type Output = Self;
    fn add(self, other: T) -> Self::Output {
        Self::Add(Box::new(self), Box::new(other.into()))
    }
}

impl<F: Field, T: Into<Query<F>>> std::ops::Sub<T> for Query<F> {
    type Output = Self;
    fn sub(self, other: T) -> Self::Output {
        Self::Add(Box::new(self), Box::new(Self::Neg(Box::new(other.into()))))
    }
}

impl<F: Field, T: Into<Query<F>>> std::ops::Mul<T> for Query<F> {
    type Output = Self;
    fn mul(self, other: T) -> Self::Output {
        Self::Mul(Box::new(self), Box::new(other.into()))
    }
}
