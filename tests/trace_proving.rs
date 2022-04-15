use halo2_mpt_circuits::{operation::AccountOp, serde, EthTrie};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pairing::bn256::{Bn256, Fr as Fp, G1Affine};
use halo2_proofs::plonk::keygen_vk;
use halo2_proofs::poly::commitment::Params;

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

#[test]
fn vk_validity() {
    let params = Params::<G1Affine>::unsafe_setup::<Bn256>(8);
    let lines: Vec<&str> = TEST_TRACE.trim().split('\n').collect();
    let ops: Vec<AccountOp<Fp>> = lines
        .into_iter()
        .map(|ln| {
            let trace = serde_json::from_str::<serde::SMTTrace>(ln).unwrap();
            (&trace).try_into().unwrap()
        })
        .collect();

    let mut circuit = EthTrie::<Fp>::new(200);
    circuit.add_ops(ops.clone());
    let vk1 = keygen_vk(&params, &circuit).unwrap();

    let mut vk1_buf: Vec<u8> = Vec::new();
    vk1.write(&mut vk1_buf).unwrap();

    let circuit = EthTrie::<Fp>::new(200);
    let vk2 = keygen_vk(&params, &circuit).unwrap();

    let mut vk2_buf: Vec<u8> = Vec::new();
    vk2.write(&mut vk2_buf).unwrap();

    assert_eq!(vk1_buf, vk2_buf);
}
