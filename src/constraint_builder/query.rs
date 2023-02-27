use super::BinaryQuery;
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    plonk::{Expression, VirtualCells},
};

pub struct Query<F: Field>(pub Box<dyn FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>>);

impl<F: FieldExt> Query<F> {
    pub fn zero() -> Self {
        Self::from(0u64)
    }

    pub fn one() -> Self {
        Self::from(1u64)
    }
}

impl<F: Field> Query<F> {
    pub fn run(self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        self.0(meta)
    }
}

impl<F: FieldExt> From<u64> for Query<F> {
    fn from(x: u64) -> Self {
        let f: F = x.into();
        Self(Box::new(move |_meta| Expression::Constant(f)))
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

impl<F: Field> From<BinaryQuery<F>> for Query<F> {
    fn from(b: BinaryQuery<F>) -> Self {
        b.0
    }
}
