use crate::{
    gadgets::poseidon::PoseidonTable, hash_traces, serde::SMTTrace, types::Proof, MPTProofType,
    MptCircuitConfig,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error, FirstPhase},
};

#[derive(Clone, Debug, Default)]
pub struct TestCircuit {
    n_rows: usize,
    proofs: Vec<Proof>,
}

impl TestCircuit {
    pub fn new(n_rows: usize, traces: Vec<(MPTProofType, SMTTrace)>) -> Self {
        Self {
            n_rows,
            proofs: traces.into_iter().map(Proof::from).collect(),
        }
    }
}

impl Circuit<Fr> for TestCircuit {
    type Config = (PoseidonTable, MptCircuitConfig);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self::Config {
        let poseidon = PoseidonTable::configure(cs);
        let challenge = cs.challenge_usable_after(FirstPhase);
        let mpt_circuit_config = MptCircuitConfig::configure(cs, challenge, &poseidon);
        (poseidon, mpt_circuit_config)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let (poseidon, mpt_circuit_config) = config;
        mpt_circuit_config.assign(&mut layouter, &self.proofs, self.n_rows)?;
        layouter.assign_region(
            || "load poseidon table",
            |mut region| {
                poseidon.load(&mut region, &hash_traces(&self.proofs));
                Ok(())
            },
        )
    }
}
