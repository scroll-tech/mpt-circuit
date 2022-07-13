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
    ($k: expr, $circuits:expr) => {
        {
            let (circuit, _) = $circuits;
            let prover = MockProver::<Fp>::run($k, &circuit, vec![]).unwrap();
            prover.verify()
        }
    };
}

fn main() {
    let mut buffer = Vec::new();
    let mut f = File::open("integration-tests/trace.json").unwrap();
    f.read_to_end(&mut buffer).unwrap();

    let traces: Vec<SMTTrace> = serde_json::from_slice::<BlockResult>(&buffer)
        .unwrap()
        .mpt_witness;
    let ops: Vec<AccountOp<Fp>> = traces.iter().map(|tr| tr.try_into().unwrap()).collect();

    let mut data : EthTrie<Fp> = Default::default();
    data.add_ops(ops);

    let (rows, _) = data.use_rows();
    let log2_ceil = |n| u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32;
    let k = log2_ceil(rows) + 1;
    let k = k.max(6);

    println!(
        "start proving trace with mpt-circuit, has {} rows and k is {}",
        rows, k
    );

    let final_root = data.final_root();

    let prove_ret = match k {
        6 => mock_prove!(k, data.circuits::<40>()),
        7 => mock_prove!(k, data.circuits::<90>()),
        8 => mock_prove!(k, data.circuits::<200>()),
        9 => mock_prove!(k, data.circuits::<450>()),
        10 => mock_prove!(k, data.circuits::<900>()),
        _ => panic!("too large k {}", k)
    };

    assert_eq!(prove_ret, Ok(()));

    println!("done, final hash {:?}", final_root);
}
