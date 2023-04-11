use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};

mod binary_column;
mod binary_query;
mod column;
mod query;

pub use binary_column::BinaryColumn;
pub use binary_query::BinaryQuery;
pub use column::{AdviceColumn, FixedColumn, SelectorColumn};
pub use query::Query;

pub struct ConstraintBuilder<F: FieldExt> {
    // TODO: cs: &mut ConstraintSystem<F>...
    constraints: Vec<(&'static str, Query<F>)>,
    lookups: Vec<(&'static str, Vec<(Query<F>, Query<F>)>)>,

    conditions: Vec<BinaryQuery<F>>,
}

impl<F: FieldExt> ConstraintBuilder<F> {
    pub fn new() -> Self {
        Self {
            constraints: vec![],
            lookups: vec![],

            conditions: vec![],
        }
    }

    pub fn add_constraint(
        &mut self,
        name: &'static str,
        selector: BinaryQuery<F>,
        constraint: Query<F>,
    ) {
        let condition = self
            .conditions
            .iter()
            .fold(BinaryQuery::one(), |a, b| a.clone().and(b.clone()));
        self.constraints
            .push((name, condition.and(selector).condition(constraint)))
    }

    pub fn assert(
        &mut self,
        name: &'static str,
        selector: BinaryQuery<F>,
        condition: BinaryQuery<F>,
    ) {
        self.add_constraint(name, selector, Query::one() - condition);
    }

    pub fn assert_unreachable(&mut self, name: &'static str, selector: BinaryQuery<F>) {
        self.assert(name, selector, BinaryQuery::zero());
    }

    pub fn condition(&mut self, condition: BinaryQuery<F>, configure: impl FnOnce(&mut Self)) {
        self.conditions.push(condition);
        configure(self);
        self.conditions.pop().unwrap();
    }

    pub fn add_lookup<const N: usize>(
        &mut self,
        name: &'static str,
        left: [Query<F>; N],
        right: [Query<F>; N],
    ) {
        let lookup = left.into_iter().zip(right.into_iter()).collect();
        self.lookups.push((name, lookup))
    }

    pub fn build_columns<const A: usize, const B: usize, const C: usize>(
        &self,
        cs: &mut ConstraintSystem<F>,
    ) -> ([SelectorColumn; A], [FixedColumn; B], [AdviceColumn; C]) {
        let selectors = [0; A].map(|_| SelectorColumn(cs.fixed_column()));
        let fixed_columns = [0; B].map(|_| FixedColumn(cs.fixed_column()));
        let advice_columns = [0; C].map(|_| AdviceColumn(cs.advice_column()));
        (selectors, fixed_columns, advice_columns)
    }

    pub fn advice_columns<const N: usize>(
        &self,
        cs: &mut ConstraintSystem<F>,
    ) -> [AdviceColumn; N] {
        [0; N].map(|_| AdviceColumn(cs.advice_column()))
    }

    pub fn binary_columns<const N: usize>(
        &mut self,
        cs: &mut ConstraintSystem<F>,
    ) -> [BinaryColumn; N] {
        [0; N].map(|_| BinaryColumn::configure::<F>(cs, self))
    }

    pub fn build(self, cs: &mut ConstraintSystem<F>) {
        for (name, query) in self.constraints {
            cs.create_gate(&name, |meta| vec![query.run(meta)])
        }
        for (name, lookup) in self.lookups {
            cs.lookup_any(&name, |meta| {
                lookup
                    .into_iter()
                    .map(|(left, right)| (left.run(meta), right.run(meta)))
                    .collect()
            });
        }
    }
}
