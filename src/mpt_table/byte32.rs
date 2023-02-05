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

#[cfg(test)]
mod test {
    #![allow(unused_imports)]

    use super::super::range_check::{Chip as RangeCheckChip, Config as RangeCheckConfig};
    use super::super::value_rep::Config as RepConfig;
    use super::*;
    use crate::test_utils::*;
    use halo2_proofs::{
        circuit::{Layouter, Region, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        plonk::Circuit,
    };

    #[derive(Clone, Debug)]
    struct TestConfig {
        sel: Selector,
        val: Column<Advice>,

        byte32_rep: Config,
        rep: RepConfig<32, 8>,
        rg_chk: RangeCheckConfig<8>,
    }

    #[derive(Clone, Default)]
    struct TestCircuit {
        data: Vec<(u8, u8)>,
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
            let rg_chk = RangeCheckChip::<Fp, 8>::configure(meta);
            let rep = RepConfig::<32, 8>::configure(meta, &rg_chk);
            let byte32_rep = Config::configure(meta, sel, &rep.limbs);

            meta.create_gate("bind rep", |meta| {
                let val = meta.query_advice(val, Rotation::cur());
                vec![
                    meta.query_selector(sel)
                        * rep.bind_rlc_value(meta, val, Expression::Constant(Fp::one()), None),
                ]
            });

            TestConfig {
                sel,
                val,
                byte32_rep,
                rg_chk,
                rep,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            let rg_chip = RangeCheckChip::<Fp, 8>::construct(config.rg_chk);
            rg_chip.load(&mut layouter)?;

            layouter.assign_region(
                || "main",
                |mut region| {
                    for (offset, (base1, base2)) in self.data.iter().enumerate() {
                        region.assign_advice(
                            || "val",
                            config.val,
                            offset,
                            || Value::known(Fp::from((base1 + base2) as u64 * 16)),
                        )?;

                        config.rep.assign(
                            &mut region,
                            offset,
                            vec![Fp::from(*base1 as u64); 16]
                                .iter()
                                .chain(vec![Fp::from(*base2 as u64); 16].iter()),
                        )?;

                        config.byte32_rep.assign(
                            &mut region,
                            offset,
                            &(
                                Fp::from_u128(u128::from_be_bytes([*base1; 16])),
                                Fp::from_u128(u128::from_be_bytes([*base2; 16])),
                            ),
                        )?;

                        config.sel.enable(&mut region, offset)?;
                    }
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn byte32_rep_test() {
        let circuit = TestCircuit { data: vec![(3, 4)] };

        let k = 10;
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
