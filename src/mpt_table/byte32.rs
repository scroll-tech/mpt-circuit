use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub rep_hi: Column<Advice>,
    pub rep_lo: Column<Advice>,
}

impl Config {
    pub fn configure<F: FieldExt, const N: usize>(
        meta: &mut ConstraintSystem<F>,
        sel: Selector,
        rep: &[Column<Advice>; N],
    ) -> Self {
        let half = N / 2;
        assert_eq!(half * 2, N);
        let rep_hi = meta.advice_column();
        let rep_lo = meta.advice_column();

        let nib_bytes = 256 / N;
        assert_eq!(nib_bytes * N, 256);

        meta.create_gate("split represents into two 128bit rep", |meta| {
            let sel = meta.query_selector(sel);
            let rep_hi = meta.query_advice(rep_hi, Rotation::cur());
            let rep_lo = meta.query_advice(rep_lo, Rotation::cur());
            let factor = Expression::Constant(F::from((1 << nib_bytes) as u64));

            let acc_hi = rep[0..half]
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::cur()))
                .reduce(|exp, col_exp| exp * factor.clone() + col_exp)
                .expect("should have enough fields");

            let acc_lo = rep[half..]
                .iter()
                .map(|col| meta.query_advice(*col, Rotation::cur()))
                .reduce(|exp, col_exp| exp * factor.clone() + col_exp)
                .expect("should have enough fields");

            vec![sel.clone() * (rep_hi - acc_hi), sel * (rep_lo - acc_lo)]
        });

        Self { rep_hi, rep_lo }
    }

    pub fn assign<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        v_pair: &(F, F),
    ) -> Result<bool, Error> {
        for (col, v, tip) in [(self.rep_hi, v_pair.0, "hi"), (self.rep_lo, v_pair.1, "lo")] {
            region.assign_advice(
                || format!("assign for byte32 pair {tip} base"),
                col,
                offset,
                || Value::known(v),
            )?;
        }

        Ok(true)
    }

    pub fn flush<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
    ) -> Result<bool, Error> {
        self.assign(region, offset, &(F::zero(), F::zero()))
    }
}
