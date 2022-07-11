use halo2_mpt_circuits::{operation::AccountOp, serde::SMTTrace, EthTrie};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pairing::bn256::Fr as Fp;
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

    let rows: usize = ops.iter().fold(0, |acc, op| acc + op.use_rows());
    let log2_ceil = |n| u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32;
    let k = log2_ceil(rows) + 1;
    let k = k.max(6);

    println!(
        "start proving trace with mpt-circuit, has {} rows and k is {}",
        rows, k
    );

    let final_root = ops.last().unwrap().account_root();

    let mut circuit = EthTrie::<Fp>::new(rows + 5);
    circuit.add_ops(ops);

    let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    println!("done, final hash {:?}", final_root);
}
