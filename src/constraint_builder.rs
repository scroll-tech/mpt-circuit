use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};

mod binary_query;
mod column;
mod query;

pub use binary_query::BinaryQuery;
pub use column::{AdviceColumn, FixedColumn, IsZeroColumn, SelectorColumn};
pub use query::Query;

pub struct ConstraintBuilder<F: FieldExt> {
    constraints: Vec<(&'static str, Query<F>)>,
    lookups: Vec<(&'static str, Vec<(Query<F>, Query<F>)>)>,
}

impl<F: FieldExt> ConstraintBuilder<F> {
    pub fn new() -> Self {
        Self {
            constraints: vec![],
            lookups: vec![],
        }
    }

    pub fn add_constraint(
        &mut self,
        name: &'static str,
        selector: BinaryQuery<F>,
        constraint: Query<F>,
    ) {
        self.constraints
            .push((name, selector.condition(constraint)))
    }

    pub fn add_lookup(&mut self, name: &'static str, lookup: Vec<(Query<F>, Query<F>)>) {
        self.lookups.push((name, lookup))
    }

    pub fn is_zero_gadget(
        &mut self,
        cs: &mut ConstraintSystem<F>,
        selector: BinaryQuery<F>,
        value: AdviceColumn, // TODO: make this a query once Query is clonable/copyable.....
    ) -> IsZeroColumn {
        let inverse_or_zero = AdviceColumn(cs.advice_column());
        self.add_constraint(
            "is_zero_gadget",
            selector,
            value.current() * (Query::from(1) - value.current() * inverse_or_zero.current()),
        );
        IsZeroColumn {
            value,
            inverse_or_zero,
        }
    }

    pub fn build_columns<const A: usize, const B: usize, const C: usize>(
        &self,
        cs: &mut ConstraintSystem<F>,
    ) -> ([SelectorColumn; A], [FixedColumn; B], [AdviceColumn; C]) {
        let selectors = [0; A].map(|_| SelectorColumn(cs.fixed_column())); // halo2 doesn't allow subtraction for simple selectors
        let fixed_columns = [0; B].map(|_| FixedColumn(cs.fixed_column()));
        let advice_columns = [0; C].map(|_| AdviceColumn(cs.advice_column()));
        (selectors, fixed_columns, advice_columns)
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

// #[cfg(test)]
// mod test {
//     use super::*;

//     use super::super::proof::HashTrace;
//     use halo2_proofs::{
//         circuit::{Layouter, SimpleFloorPlanner},
//         dev::MockProver,
//         halo2curves::bn256::Fr,
//         plonk::Circuit,
//         plonk::{ConstraintSystem, Error, Expression, VirtualCells},
//     };

//     #[derive(Clone, Default, Debug)]
//     struct TestCircuit {
//         traces: Vec<u8>,
//     }

//     #[derive(Clone)]
//     struct TestConfig {
//         x: AdviceColumn,
//         y: FixedColumn,
//     }

//     impl Circuit<Fr> for TestCircuit {
//         type Config = TestConfig;
//         type FloorPlanner = SimpleFloorPlanner;

//         fn without_witnesses(&self) -> Self {
//             Self::default()
//         }

//         fn configure(cs: &mut ConstraintSystem<Fr>) -> Self::Config {
//             let mut cb = ConstraintBuilder::new();

//             let ([], [y], [x]) = cb.build_columns(cs);

//             cb.add_constraint("testtttt", x.current() + y.previous());
//             cb.add_constraint("testtttt", x.current() - y.previous());
//             cb.add_constraint("testtttt", y.current() * y.previous());
//             cb.add_constraint("testtttt", x.previous() + 1);
//             cb.add_constraint("testtttt", y.current() - 0);

//             cb.build(cs);

//             TestConfig { x, y }
//         }

//         fn synthesize(
//             &self,
//             config: Self::Config,
//             mut layouter: impl Layouter<Fr>,
//         ) -> Result<(), Error> {
//             Ok(())
//         }
//     }

//     #[test]
//     fn masonnnnnnn() {
//         let circuit = TestCircuit { traces: vec![] };
//         let prover = MockProver::<Fr>::run(4, &circuit, vec![]).unwrap();
//         assert_eq!(prover.verify(), Ok(()));
//     }
// }
