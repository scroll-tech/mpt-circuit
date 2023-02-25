use super::Query;
use halo2_proofs::{arithmetic::Field, poly::Rotation};

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

#[derive(Clone, Copy)]
pub struct Fixed(pub usize);

impl Fixed {
    fn rotation<F: Field>(self, i: i32) -> Query<F> {
        Query(Box::new(move |meta, _, f, _| {
            let index = self.0;
            meta.query_fixed(
                *f.get(index)
                    .expect(&format!("index = {index} n_fixed_columns = {}", f.len())),
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

#[derive(Clone, Copy)]
pub struct Selector(pub usize);

impl Selector {
    fn current<F: Field>(self) -> Query<F> {
        Query(Box::new(move |meta, s, _, _| {
            let index = self.0;
            meta.query_selector(
                *s.get(index)
                    .expect(&format!("index = {index} n_selectors = {}", s.len())),
            )
        }))
    }
}
