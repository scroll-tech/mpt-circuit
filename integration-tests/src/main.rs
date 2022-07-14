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

macro_rules! mock_prove {
    // `()` indicates that the macro takes no argument.
    ($k: expr, $circuits:expr) => {{
        let (circuit, hash_circuit) = $circuits;
        let prover_mpt = MockProver::<Fp>::run($k, &circuit, vec![]).unwrap();
        let prover_hash = MockProver::<Fp>::run($k + 5, &hash_circuit, vec![]).unwrap();
        (prover_mpt.verify(), prover_hash.verify())
    }};
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
        "start proving trace with mpt-circuit, has {} rows, {} hash_rows and base k is {}",
        rows, hash_rows, k
    );

    let final_root = data.final_root();

    let (prove_mpt_ret, prove_hash_ret) = match k {
        6 => mock_prove!(k, data.circuits::<40>()),
        7 => mock_prove!(k, data.circuits::<90>()),
        8 => mock_prove!(k, data.circuits::<200>()),
        9 => mock_prove!(k, data.circuits::<450>()),
        10 => mock_prove!(k, data.circuits::<900>()),
        _ => panic!("too large k {}", k),
    };

    assert_eq!(prove_mpt_ret, Ok(()));
    assert_eq!(prove_hash_ret, Ok(()));

    println!("done, final hash {:?}", final_root);
}
