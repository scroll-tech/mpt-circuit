use halo2_mpt_circuits::{operation::AccountOp, serde::SMTTrace, EthTrie};
use halo2_proofs::dev::MockProver;
pub use halo2_proofs::halo2curves::bn256::Fr as Fp;
use std::fs::File;
use std::io::Read;

use serde::Deserialize;

#[derive(Deserialize, Default)]
pub struct BlockResult {
    #[serde(rename = "mptwitness", default)]
    pub mpt_witness: Vec<SMTTrace>,
}

fn main() {
    let mut buffer = Vec::new();
    let mut f = File::open("integration-tests/trace.json").unwrap();
    f.read_to_end(&mut buffer).unwrap();

    let traces: Vec<SMTTrace> = serde_json::from_slice::<BlockResult>(&buffer)
        .unwrap()
        .mpt_witness;
    let ops: Vec<AccountOp<Fp>> = traces.iter().map(|tr| tr.try_into().unwrap()).collect();

    let mut data: EthTrie<Fp> = Default::default();
    data.add_ops(ops);

    let (rows, hash_rows) = data.use_rows();
    let log2_ceil = |n| u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32;
    let k = log2_ceil(rows) + 1;
    let k = k.max(6);

    println!(
        "start proving trace with mpt-circuit, has {rows} rows, {hash_rows} hash_rows and base k is {k}",
    );

    let final_root = data.final_root();

    let (circuit, hash_circuit) = match k {
        6 => data.circuits(40),
        7 => data.circuits(90),
        8 => data.circuits(200),
        9 => data.circuits(450),
        10 => data.circuits(900),
        11 => data.circuits(1950),
        _ => panic!("too large k {k}"),
    };

    let prover_mpt = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
    let prover_hash = MockProver::<Fp>::run(k + 6, &hash_circuit, vec![]).unwrap();

    assert_eq!(prover_mpt.verify(), Ok(()));
    assert_eq!(prover_hash.verify(), Ok(()));

    println!("done, final hash {final_root:?}");
}
