use super::poseidon::Config as PoseidonConfig;
use ethers_core::types::U256;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::{
    arithmetic::Field,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
};

#[derive(Clone, Copy, Debug)]
struct Config {
    selector: Selector,

    key_high: Column<Advice>,
    key_low: Column<Advice>,

    value_high: Column<Advice>,
    value_low: Column<Advice>,

    key_hash: Column<Advice>,   // poseidon(code_hash_high, code_hash_low)
    value_hash: Column<Advice>, // poseidon(value_high, value_low)

    leaf_hash: Column<Advice>, // poseidon(poseidon(1, key_hash), value_hash)
}

impl Config {
    fn configure<F: Field>(meta: &mut ConstraintSystem<F>, poseidon_table: PoseidonConfig) -> Self {
        let [key_high, key_low, key_hash] = [(); 3].map(|()| meta.advice_column());
        poseidon_table.add_lookup(meta, key_high, key_low, key_hash);

        let [value_high, value_low, value_hash] = [(); 3].map(|()| meta.advice_column());
        poseidon_table.add_lookup(meta, value_high, value_low, value_hash);

        let leaf_hash = meta.advice_column();
        // poseidon_table.lookup_leaf(meta, key_hash, leaf_hash);

        // Need constraint that value is not 0.

        Self {
            selector: meta.selector(),
            key_high,
            key_low,
            value_high,
            value_low,
            key_hash,
            value_hash,
            leaf_hash,
        }
    }

    fn assign<F: Field>(
        &self,
        _layouter: &mut impl Layouter<F>,
        _storage_entry: &[(U256, U256)],
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };

    #[derive(Clone, Default, Debug)]
    struct TestCircuit {
        traces: Vec<(U256, U256)>,
    }

    impl Circuit<Fr> for TestCircuit {
        type Config = Config;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let poseidon = PoseidonConfig::configure(meta);

            // panic!();
            Self::Config::configure(meta, poseidon)
        }

        fn synthesize(
            &self,
            _config: Self::Config,
            _layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            // config.assign(&mut layouter, &self.traces);

            panic!();
        }
    }

    #[test]
    fn circuit() {
        let circuit = TestCircuit { traces: vec![] };
        let prover = MockProver::<Fr>::run(4, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
