use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_mpt_circuits::{
    gadgets::poseidon::PoseidonTable, serde::SMTTrace, tests::TestCircuit, MPTProofType,
    MptCircuitConfig,
};
use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr},
    plonk::ConstraintSystem,
};

fn bench(criterion: &mut Criterion) {
    let json = include_str!("traces.json");
    let witness: Vec<(MPTProofType, SMTTrace)> = serde_json::from_str(&json).unwrap();
    let circuit = TestCircuit::new(10_000, witness);

    criterion.bench_function("assign trace", |bencher| {
        bencher.iter(|| MockProver::<Fr>::run(14, &circuit, vec![]))
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
}

criterion_main!(benches);
