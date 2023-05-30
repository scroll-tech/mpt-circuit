use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

use super::range_check::Config as RangeCheckConfig;
use halo2_proofs::halo2curves::group::ff::{Field, PrimeField};

#[derive(Clone, Debug)]
pub(crate) struct Config<const N: usize, const EXP: usize> {
    pub limbs: [Column<Advice>; N],
}

impl<const N: usize, const EXP: usize> Config<N, EXP> {
    pub fn configure<F: Field>(
        meta: &mut ConstraintSystem<F>,
        rg_check: &RangeCheckConfig<EXP>,
    ) -> Self {
        let limbs = [0; N].map(|_| meta.advice_column());

        for col in limbs {
            rg_check.range_check_col(meta, "limb range check", col);
        }

        Self { limbs }
    }

    pub fn bind_mpi_value<F: PrimeField>(
        &self,
        meta: &mut VirtualCells<'_, F>,
        val: Expression<F>,
        effect_limbs: Option<usize>,
    ) -> Expression<F> {
        // mpi consider value as the be represent of limbs
        // and can be considered as a special rlc use LIMB_RANGE as randomness
        self.bind_rlc_value(
            meta,
            val,
            Expression::Constant(F::from((1 << EXP) as u64)),
            effect_limbs,
        )
    }

    pub fn bind_rlc_value<F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>,
        val: Expression<F>,
        randomness: Expression<F>,
        effect_limbs: Option<usize>,
    ) -> Expression<F> {
        let limbs = &self.limbs;
        let half = N / 2;
        assert_eq!(half * 2, N);

        let nib_bytes = 256 / N;
        assert_eq!(nib_bytes * N, 256);

        let val_rep = limbs[0..effect_limbs.unwrap_or(N)]
            .iter()
            .map(|col| meta.query_advice(*col, Rotation::cur()))
            .reduce(|exp, col_exp| randomness.clone() * exp + col_exp)
            .expect("should have fields");

        val_rep - val
    }

    pub fn le_value_to_limbs<F: PrimeField>(val: F) -> [F; N] {
        assert_eq!(EXP % 8, 0);

        let le_bytes = val.to_repr();
        let limb_bytes = EXP / 8;

        let mut out = [F::zero(); N];

        for i in 0..N {
            out[N - i - 1] = F::from(
                le_bytes.as_ref()[i * limb_bytes..(i + 1) * limb_bytes]
                    .iter()
                    .rev()
                    .copied()
                    .fold(0u64, |acc, v| acc * 256 + v as u64),
            );
        }

        out
    }

    pub fn assign<'d, F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        limbs: impl IntoIterator<Item = &'d F>,
    ) -> Result<bool, Error> {
        for (limb, col) in limbs.into_iter().zip(self.limbs.as_slice().iter()) {
            region.assign_advice(
                || format!("assign for limbs on rep {N}"),
                *col,
                offset,
                || Value::known(*limb),
            )?;
        }

        Ok(true)
    }

    pub fn flush<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
    ) -> Result<bool, Error> {
        self.assign(region, offset, [F::zero(); N].as_slice())
    }
}
