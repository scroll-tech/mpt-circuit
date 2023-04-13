use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, TableColumn, VirtualCells},
    poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub(crate) struct Config<const N: usize>(TableColumn);

impl<const N: usize> Config<N> {
    pub fn range_check<F: Field>(
        &self,
        meta: &mut ConstraintSystem<F>,
        msg: &'static str,
        exp_fn: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup(msg, |meta| vec![(exp_fn(meta), self.0)]);
    }

    pub fn range_check_col<F: Field>(
        &self,
        meta: &mut ConstraintSystem<F>,
        msg: &'static str,
        col: Column<Advice>,
    ) {
        self.range_check(meta, msg, |meta| meta.query_advice(col, Rotation::cur()))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Chip<F: Field, const N: usize> {
    config: Config<N>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const N: usize> Chip<F, N> {
    const RANGE: usize = 1 << N;

    pub fn construct(config: Config<N>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Config<N> {
        Config(meta.lookup_table_column())
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || format!("range check {N}"),
            |mut table| {
                for i in 0..Self::RANGE {
                    table.assign_cell(
                        || format!("assign {i} in rng_check{N} fixed column"),
                        self.config.0,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}
