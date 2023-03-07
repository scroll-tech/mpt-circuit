use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

pub trait PoseidonLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3];
}

// use halo2curves::bn256::Fr

#[derive(Clone, Copy, Debug)]
pub(crate) struct Config {
    left: Column<Advice>,
    right: Column<Advice>,
    hash: Column<Advice>,
}

impl Config {
    pub(crate) fn configure<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let [left, right, hash] = [(); 3].map(|()| meta.advice_column());
        Self { left, right, hash }
    }

    fn assign<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        hash_traces: &[(F, F, F)],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assign poseidon columns",
            |mut region| {
                for (i, hash_trace) in hash_traces.iter().enumerate() {
                    for (column, value) in [
                        (self.left, hash_trace.0),
                        (self.right, hash_trace.1),
                        (self.hash, hash_trace.2),
                    ] {
                        region.assign_advice(|| "", column, i, || Value::known(value))?;
                    }
                }
                Ok(())
            },
        )
    }

    pub(crate) fn add_lookup<F: Field>(
        &self,
        meta: &mut ConstraintSystem<F>,
        left: Column<Advice>,
        right: Column<Advice>,
        hash: Column<Advice>,
    ) {
        meta.lookup_any("", |meta| {
            let mut q = |a| meta.query_advice(a, Rotation::cur());
            vec![
                (q(left), q(self.left)),
                (q(right), q(self.right)),
                (q(hash), q(self.hash)),
            ]
        });
    }

    pub(crate) fn lookup_expressions<F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>,
        left: Expression<F>,
        right: Expression<F>,
        hash: Expression<F>,
    ) -> Vec<(Expression<F>, Expression<F>)> {
        let mut q = |a| meta.query_advice(a, Rotation::cur());
        vec![
            (left, q(self.left)),
            (right, q(self.right)),
            (hash, q(self.hash)),
        ]
    }
}

#[cfg(test)]
mod test {
    use super::super::super::proof::HashTrace;
    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };

    #[derive(Clone, Default, Debug)]
    struct PoseidonCircuit {
        traces: Vec<HashTrace>,
    }

    impl Circuit<Fr> for PoseidonCircuit {
        type Config = Config;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            Self::Config::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let witness: Vec<_> = self
                .traces
                .iter()
                .map(|t| (t.left, t.right, t.out))
                .collect();
            config.assign(&mut layouter, witness.as_slice())
        }
    }

    #[test]
    fn circuit() {
        let circuit = PoseidonCircuit { traces: vec![] };
        let prover = MockProver::<Fr>::run(4, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
