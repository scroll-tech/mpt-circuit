use halo2_proofs::{arithmetic::Field, plonk, plonk::ConstraintSystem};

mod column;
mod query;

use column::{AdviceColumn, FixedColumn, SelectorColumn};
use query::Query;

struct ConstraintBuilder<F: Field> {
    constraints: Vec<(&'static str, Query<F>)>,
}

impl<F: Field> ConstraintBuilder<F> {
    fn new() -> Self {
        Self {
            constraints: vec![],
        }
    }

    fn add_constraint<T: Into<Query<F>>>(&mut self, name: &'static str, t: T) {
        self.constraints.push((name, t.into()))
    }

    fn build_columns<const A: usize, const B: usize, const C: usize>(
        &self,
        cs: &mut ConstraintSystem<F>,
    ) -> ([SelectorColumn; A], [FixedColumn; B], [AdviceColumn; C]) {
        let selectors = [0; A].map(|_| SelectorColumn(cs.selector()));
        let fixed_columns = [0; B].map(|_| FixedColumn(cs.fixed_column()));
        let advice_columns = [0; C].map(|_| AdviceColumn(cs.advice_column()));
        (selectors, fixed_columns, advice_columns)
    }

    fn build(self, cs: &mut ConstraintSystem<F>) {
        for (name, query) in self.constraints {
            cs.create_gate(&name, |meta| vec![query.run(meta)])
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use super::super::proof::HashTrace;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::Circuit,
        plonk::{ConstraintSystem, Error, Expression, VirtualCells},
    };

    #[derive(Clone, Default, Debug)]
    struct TestCircuit {
        traces: Vec<u8>,
    }

    #[derive(Clone)]
    struct TestConfig {
        x: AdviceColumn,
        y: FixedColumn,
    }

    impl Circuit<Fr> for TestCircuit {
        type Config = TestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(cs: &mut ConstraintSystem<Fr>) -> Self::Config {
            let mut cb = ConstraintBuilder::new();

            let ([], [y], [x]) = cb.build_columns(cs);

            cb.add_constraint("testtttt", x.current() + y.previous());
            cb.add_constraint("testtttt", x.current() - y.previous());
            cb.add_constraint("testtttt", y.current() * y.previous());
            cb.add_constraint("testtttt", x.previous() + 1);
            cb.add_constraint("testtttt", y.current() - 0);

            cb.build(cs);

            TestConfig { x, y }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            Ok(())
        }
    }

    #[test]
    fn masonnnnnnn() {
        let circuit = TestCircuit { traces: vec![] };
        let prover = MockProver::<Fr>::run(4, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
