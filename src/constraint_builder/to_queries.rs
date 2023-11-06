use super::Query;
use halo2_proofs::arithmetic::FieldExt;

pub trait ToQueries<F: FieldExt, const N: usize> {
    fn to_queries(&self) -> [Query<F>; N];
}

impl<F: FieldExt> ToQueries<F, 1> for Query<F> {
    fn to_queries(&self) -> [Query<F>; 1] {
        [self.clone()]
    }
}

impl<F: FieldExt, const N: usize> ToQueries<F, N> for [Query<F>; N] {
    fn to_queries(&self) -> [Query<F>; N] {
        self.clone()
    }
}
