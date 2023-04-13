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

#[cfg(test)]
mod test {
    #![allow(unused_imports)]

    use super::super::range_check::Chip as RangeCheckChip;
    use super::*;
    use crate::test_utils::*;
    use halo2_proofs::{
        circuit::{Layouter, Region, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        plonk::{Circuit, Selector},
    };

    #[derive(Clone, Debug)]
    struct TestConfig {
        rep: Config<16, 16>,
        sel: Selector,
        val: Column<Advice>,
        rg_chk: RangeCheckConfig<16>,
    }

    #[derive(Clone, Default)]
    struct TestCircuit {
        data: Vec<Fp>,
    }

    impl Circuit<Fp> for TestCircuit {
        type Config = TestConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let sel = meta.selector();
            let val = meta.advice_column();
            let rg_chk = RangeCheckChip::<Fp, 16>::configure(meta);
            let rep = Config::<16, 16>::configure(meta, &rg_chk);

            meta.create_gate("bind rep", |meta| {
                let val = meta.query_advice(val, Rotation::cur());
                vec![meta.query_selector(sel) * rep.bind_mpi_value(meta, val, None)]
            });

            TestConfig {
                sel,
                val,
                rg_chk,
                rep,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let rg_chip = RangeCheckChip::<Fp, 16>::construct(config.rg_chk);
            rg_chip.load(&mut layouter)?;

            layouter.assign_region(
                || "main",
                |mut region| {
                    for (offset, v) in self.data.iter().enumerate() {
                        region.assign_advice(|| "val", config.val, offset, || Value::known(*v))?;

                        config.rep.assign(
                            &mut region,
                            offset,
                            &Config::<16, 16>::le_value_to_limbs(*v),
                        )?;

                        config.sel.enable(&mut region, offset)?;
                    }
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn value_rep_test() {
        let circuit = TestCircuit {
            data: vec![
                "7103474578896643880912595670996880817578037370381571930047680755406072759008",
            ]
            .into_iter()
            .map(|s| Fp::from_str_vartime(s).unwrap())
            .collect(),
        };

        let k = 17;
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
