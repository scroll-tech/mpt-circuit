use halo2_mpt_circuits::{operation::AccountOp, serde::SMTTrace, EthTrie};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pairing::bn256::Fr as Fp;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;

#[derive(Deserialize)]
pub struct BlockResult {
    #[serde(rename = "executionResults", default)]
    pub execution_results: Vec<ExecutionResult>,
}

#[derive(Deserialize)]
pub struct ExecutionResult {
    #[serde(default)]
    pub storage: StorageInfo,
}

#[derive(Deserialize, Default)]
pub struct StorageInfo {
    #[serde(rename = "smtTrace", default)]
    pub smt_trace: Vec<SMTTrace>,
}

fn main() {
    let mut buffer = Vec::new();
    let mut f = File::open("integration-tests/trace.json").unwrap();
    f.read_to_end(&mut buffer).unwrap();

    let blk_result = serde_json::from_slice::<BlockResult>(&buffer).unwrap();
    let mut ops: Vec<AccountOp<Fp>> = Vec::new();

    for tx in blk_result.execution_results {
        for trace in &tx.storage.smt_trace {
            ops.push(trace.try_into().unwrap());
        }
    }

    let rows: usize = ops.iter().fold(0, |acc, op| acc + op.use_rows());
    let log2_ceil = |n| u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32;
    let k = log2_ceil(rows);
    let k = k.max(6);

    println!(
        "start proving trace with mpt-circuit, has {} rows and k is {}",
        rows, k
    );

    let mut circuit = EthTrie::<Fp>::new(rows + 5);
    circuit.add_ops(ops);

    let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    println!("done");
}
