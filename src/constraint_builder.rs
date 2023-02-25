use halo2_proofs::{arithmetic::Field, plonk::ConstraintSystem};

mod column;
mod query;

use column::{Advice, Fixed, Selector};
use query::Query;

struct ConstraintBuilder<F: Field> {
    constraints: Vec<(&'static str, Query<F>)>,
    n_selectors: usize,
    n_fixed_columns: usize,
    n_advice_columns: usize,
}

impl<F: Field> ConstraintBuilder<F> {
    fn advice_column(&mut self) -> Advice {
        let column = Advice(self.n_advice_columns);
        self.n_advice_columns += 1;
        column
    }

    fn fixed_column(&mut self) -> Fixed {
        let column = Fixed(self.n_fixed_columns);
        self.n_fixed_columns += 1;
        column
    }

    fn selector(&mut self) -> Selector {
        let column = Selector(self.n_selectors);
        self.n_selectors += 1;
        column
    }

    fn add_constraint<T: Into<Query<F>>>(&mut self, name: &'static str, t: T) {
        self.constraints.push((name, t.into()))
    }

    fn build(self, cs: &mut ConstraintSystem<F>) {
        let selectors: Vec<_> = (0..self.n_advice_columns).map(|_| cs.selector()).collect();
        let fixed_columns: Vec<_> = (0..self.n_advice_columns)
            .map(|_| cs.fixed_column())
            .collect();
        let advice_columns: Vec<_> = (0..self.n_advice_columns)
            .map(|_| cs.advice_column())
            .collect();
        for (name, query) in self.constraints {
            cs.create_gate(&name, |meta| {
                vec![query.run(meta, &selectors, &fixed_columns, &advice_columns)]
            })
        }
    }
}
