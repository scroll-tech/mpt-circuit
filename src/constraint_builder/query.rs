use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    plonk::{Advice, Column, Expression, Fixed, Selector, VirtualCells},
};

pub struct Query<F: Field>(
    pub  Box<
        dyn FnOnce(
            &mut VirtualCells<'_, F>,
            &[Selector],
            &[Column<Fixed>],
            &[Column<Advice>],
        ) -> Expression<F>,
    >,
);

impl<F: Field> Query<F> {
    pub fn run(
        self,
        meta: &mut VirtualCells<'_, F>,
        s: &[Selector],
        f: &[Column<Fixed>],
        a: &[Column<Advice>],
    ) -> Expression<F> {
        self.0(meta, s, f, a)
    }
}

impl<F: FieldExt> From<u64> for Query<F> {
    fn from(x: u64) -> Self {
        let f: F = x.into();
        Self(Box::new(move |_meta, _, _, _| Expression::Constant(f)))
    }
}

impl<F: Field, T: Into<Query<F>>> std::ops::Add<T> for Query<F> {
    type Output = Self;
    fn add(self, other: T) -> Self::Output {
        let left = self.0;
        let right = other.into().0;
        Self(Box::new(move |meta, s, f, a| {
            left(meta, s, f, a) + right(meta, s, f, a)
        }))
    }
}

impl<F: Field, T: Into<Query<F>>> std::ops::Sub<T> for Query<F> {
    type Output = Self;
    fn sub(self, other: T) -> Self::Output {
        let left = self.0;
        let right = other.into().0;
        Self(Box::new(move |meta, s, f, a| {
            left(meta, s, f, a) - right(meta, s, f, a)
        }))
    }
}

impl<F: Field, T: Into<Query<F>>> std::ops::Mul<T> for Query<F> {
    type Output = Self;
    fn mul(self, other: T) -> Self::Output {
        let left = self.0;
        let right = other.into().0;
        Self(Box::new(move |meta, s, f, a| {
            left(meta, s, f, a) * right(meta, s, f, a)
        }))
    }
}
