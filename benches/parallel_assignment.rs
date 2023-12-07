use criterion::{criterion_group, criterion_main, Criterion};
use halo2_mpt_circuits::TestCircuit;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

fn bench(criterion: &mut Criterion) {
    let json = include_str!("traces.json");
    let circuit = TestCircuit::new(10_000, serde_json::from_str(&json).unwrap());

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
