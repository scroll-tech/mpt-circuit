use super::Query;
use halo2_proofs::halo2curves::ff::FromUniformBytes;

pub trait ToQueries<F: FromUniformBytes<64>, const N: usize> {
    fn to_queries(&self) -> [Query<F>; N];
}

impl<F: FromUniformBytes<64>> ToQueries<F, 1> for Query<F> {
    fn to_queries(&self) -> [Query<F>; 1] {
        [self.clone()]
    }
}

impl<F: FromUniformBytes<64>, const N: usize> ToQueries<F, N> for [Query<F>; N] {
    fn to_queries(&self) -> [Query<F>; N] {
        self.clone()
    }
}
