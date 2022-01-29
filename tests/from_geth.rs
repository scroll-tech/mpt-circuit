
#![allow(unused_imports)]

use halo2_mpt_circuits as self_crate;
use self_crate::serde::Row;
use halo2::{dev::{MockProver, VerifyFailure}, pairing::bn256::Fr as Fp};

const TEST_FILE: &'static str = include_str!("../rows.jsonl");

#[test]
fn rows_data() {

    use self_crate::{SingleOp, MPTDemoCircuit};

    let k = 5;
    

    let mut circuit = MPTDemoCircuit::<Fp>::new(20);

    let ops = Row::fold_flattern_rows(Row::from_lines(TEST_FILE).unwrap());

    for op in ops {
        circuit.add_operation(SingleOp::<Fp>::from(op.as_ref())).unwrap();
    }

    let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}