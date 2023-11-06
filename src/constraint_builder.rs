use crate::gadgets::poseidon::PoseidonLookup;
use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};
use itertools::Itertools;

mod binary_column;
mod binary_query;
mod column;
mod query;
mod to_queries;
mod word_columns;

pub use binary_column::BinaryColumn;
pub use binary_query::BinaryQuery;
pub use column::{AdviceColumn, FixedColumn, SelectorColumn};
pub use query::Query;
use to_queries::ToQueries;
pub use word_columns::WordColumns;

pub struct ConstraintBuilder<F: FieldExt> {
    constraints: Vec<(&'static str, Query<F>)>,
    #[allow(clippy::type_complexity)]
    lookups: Vec<(&'static str, Vec<(Query<F>, Query<F>)>)>,

    conditions: Vec<BinaryQuery<F>>,
}

impl<F: FieldExt> ConstraintBuilder<F> {
    pub fn new(every_row: SelectorColumn) -> Self {
        Self {
            constraints: vec![],
            lookups: vec![],

            conditions: vec![every_row.current()],
        }
    }

    pub fn every_row_selector(&self) -> BinaryQuery<F> {
        self.conditions
            .first()
            .expect("every_row selector should always be first condition")
            .clone()
    }

    pub fn assert_zero<const N: usize, T: ToQueries<F, N>>(
        &mut self,
        name: &'static str,
        queries: T,
    ) {
        let condition = self
            .conditions
            .iter()
            .fold(BinaryQuery::one(), |a, b| a.and(b.clone()));
        for query in queries.to_queries() {
            self.constraints
                .push((name, condition.clone().condition(query)));
        }
    }

    pub fn assert_equal<const N: usize, T: ToQueries<F, N>>(
        &mut self,
        name: &'static str,
        left: T,
        right: T,
    ) {
        let a = left.to_queries();
        let b = right.to_queries();
        assert_eq!(a.len(), b.len());
        let differences: [Query<F>; N] = left
            .to_queries()
            .into_iter()
            .zip_eq(right.to_queries())
            .map(|(left, right)| left - right)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        self.assert_zero(name, differences)
    }

    pub fn assert(&mut self, name: &'static str, condition: BinaryQuery<F>) {
        self.assert_zero(name, Query::one() - condition);
    }

    pub fn assert_unreachable(&mut self, name: &'static str) {
        self.assert(name, BinaryQuery::zero());
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
        let condition = self
            .conditions
            .iter()
            .fold(BinaryQuery::one(), |a, b| a.and(b.clone()));
        let mut lookup: Vec<_> = left
            .into_iter()
            .map(|q| q * condition.clone())
            .zip(right.into_iter())
            .collect();
        // If condition is true, every_row_selector must be enabled.
        lookup.push((condition.into(), self.every_row_selector().into()));
        self.lookups.push((name, lookup))
    }

    pub fn poseidon_lookup(
        &mut self,
        name: &'static str,
        [left, right, domain, hash]: [Query<F>; 4],
        poseidon: &impl PoseidonLookup,
    ) {
        let condition = self
            .conditions
            .iter()
            .skip(1) // Save a degree by skipping every row selector
            .fold(BinaryQuery::one(), |a, b| a.and(b.clone()));
        let extended_queries = [
            Query::one(),
            hash,
            left,
            right,
            Query::zero(),
            domain,
            Query::one(),
        ]
        .map(|q| q * condition.clone());

        let (q_enable, [hash, left, right, control, domain_spec, head_mark]) =
            poseidon.lookup_columns();
        let poseidon_lookup_queries = [
            q_enable.current(),
            hash.current(),
            left.current(),
            right.current(),
            control.current(),
            domain_spec.current(),
            head_mark.current(),
        ];

        self.lookups.push((
            name,
            extended_queries
                .into_iter()
                .zip_eq(poseidon_lookup_queries)
                .collect(),
        ))
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
        assert_eq!(
            self.conditions.len(),
            1,
            "Cannot call build while in a condition"
        );

        for (name, query) in self.constraints {
            cs.create_gate(name, |meta| vec![query.run(meta)])
        }
        for (name, lookup) in self.lookups {
            cs.lookup_any(name, |meta| {
                lookup
                    .into_iter()
                    .map(|(left, right)| (left.run(meta), right.run(meta)))
                    .collect()
            });
        }
    }
}
