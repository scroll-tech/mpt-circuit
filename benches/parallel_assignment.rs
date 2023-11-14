use criterion::{black_box, criterion_group, criterion_main, Criterion};
use halo2_mpt_circuits::MPTProofType;
use halo2_mpt_circuits::{
    gadgets::poseidon::PoseidonTable, serde::SMTTrace, tests::TestCircuit, MptCircuitConfig,
};
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::plonk::FirstPhase;

fn bench(c: &mut Criterion) {
    let json = include_str!("traces.json");
    let witness: Vec<(MPTProofType, SMTTrace)> = serde_json::from_str(&json).unwrap();
    let circuit = TestCircuit::new(10_000, witness);

    c.bench_function("assign trace", |b| {
        b.iter(|| MockProver::<Fr>::run(14, &circuit, vec![]))
    });
}

// fn criterion_benchmark(c: &mut Criterion) {
//     let json = include_str!("traces.json");
//     let trace: SMTTrace = serde_json::from_str(&json).unwrap();

//     let mut cs = ConstraintSystem::default();
//     let poseidon = PoseidonTable::configure(&mut cs);
//     let challenge = cs.challenge_usable_after(FirstPhase);
//     let mpt = MptCircuitConfig::configure(&mut cs, challenge, &poseidon);

//     c.bench_function("assign trace", |b| b.iter(|| mpt.assign((black_box(20))));
// }

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
}

criterion_main!(benches);
