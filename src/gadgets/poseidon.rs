use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::{Chip, Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Selector, TableColumn, VirtualCells,
    },
    poly::Rotation,
};

// use halo2curves::bn256::Fr

use crate::proof::HashTrace;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Config {
    left: Column<Advice>,
    right: Column<Advice>,
    hash: Column<Advice>,
}

impl Config {
    fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        let [left, right, hash] = [(); 3].map(|()| meta.advice_column());
        Self { left, right, hash }
    }

    fn assign<F: FieldExt>(
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
