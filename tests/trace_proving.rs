use halo2_mpt_circuits::{operation::AccountOp, serde, EthTrie};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pairing::bn256::Fr as Fp;

const TEST_TRACE: &'static str = include_str!("../traces.jsonl");

#[test]
fn trace_to_eth_trie_each() {
    let lines: Vec<&str> = TEST_TRACE.trim().split('\n').collect();
    for ln in lines.into_iter() {
        let k = 6;
        let trace = serde_json::from_str::<serde::SMTTrace>(ln).unwrap();
        let op: AccountOp<Fp> = (&trace).try_into().unwrap();

        println!("{:?}", op);

        let mut circuit = EthTrie::<Fp>::new(20);
        circuit.add_op(op);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}

#[test]
fn trace_to_eth_trie() {
    let lines: Vec<&str> = TEST_TRACE.trim().split('\n').collect();
    let ops: Vec<AccountOp<Fp>> = lines
        .into_iter()
        .map(|ln| {
            let trace = serde_json::from_str::<serde::SMTTrace>(ln).unwrap();
            (&trace).try_into().unwrap()
        })
        .collect();

    let k = 8;

    let mut circuit = EthTrie::<Fp>::new(200);
    circuit.add_ops(ops);

    let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
