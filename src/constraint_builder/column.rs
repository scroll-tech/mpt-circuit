use super::Query;
use halo2_proofs::{
    arithmetic::Field,
    plonk::{Expression, Fixed, Selector, TableColumn, VirtualCells},
    poly::Rotation,
};

#[derive(Clone, Copy)]
pub struct Advice(pub usize);

impl Advice {
    fn rotation<F: Field>(self, i: i32) -> Query<F> {
        Query(Box::new(move |meta, _, _, a| {
            let index = self.0;
            meta.query_advice(
                *a.get(index)
                    .expect(&format!("index = {index} n_advice_columns = {}", a.len())),
                Rotation(i),
            )
        }))
    }

    fn current<F: Field>(self) -> Query<F> {
        self.rotation(0)
    }

    fn previous<F: Field>(self) -> Query<F> {
        self.rotation(-1)
    }
}
