use halo2_mpt_circuits::{operation::AccountOp, serde, EthTrie};
use halo2_proofs::dev::MockProver;
use halo2_proofs::pairing::bn256::{Bn256, Fr as Fp, G1Affine};
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
use halo2_proofs::poly::commitment::{Params, ParamsVerifier};
use halo2_proofs::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

const TEST_TRACE: &'static str = include_str!("./traces.json");
const TEST_TRACE_SMALL: &'static str = include_str!("./deploy_traces.json");

#[test]
fn trace_to_eth_trie_each() {
    let data: Vec<serde::SMTTrace> = serde_json::from_str(TEST_TRACE_SMALL).unwrap();
    let ops: Vec<AccountOp<Fp>> = data
        .into_iter()
        .map(|tr| (&tr).try_into().unwrap())
        .collect();

    for op in ops {
        let k = 6;
        println!("{:?}", op);

        let mut circuit = EthTrie::<Fp>::new(20);
        circuit.add_op(op);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}

#[test]
fn trace_to_eth_trie() {
    let data: Vec<serde::SMTTrace> = serde_json::from_str(TEST_TRACE_SMALL).unwrap();
    let ops: Vec<AccountOp<Fp>> = data
        .into_iter()
        .map(|tr| (&tr).try_into().unwrap())
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
    let data: Vec<serde::SMTTrace> = serde_json::from_str(TEST_TRACE_SMALL).unwrap();
    let ops: Vec<AccountOp<Fp>> = data
        .into_iter()
        .map(|tr| (&tr).try_into().unwrap())
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

#[test]
fn proof_and_verify() {
    let data: Vec<serde::SMTTrace> = serde_json::from_str(TEST_TRACE).unwrap();
    let ops: Vec<AccountOp<Fp>> = data
        .into_iter()
        .map(|tr| (&tr).try_into().unwrap())
        .collect();

    let k = 8;

    let params = Params::<G1Affine>::unsafe_setup::<Bn256>(k);
    let os_rng = ChaCha8Rng::from_seed([101u8; 32]);
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    let mut circuit = EthTrie::<Fp>::new(200);
    circuit.add_ops(ops.clone());

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();

    create_proof(&params, &pk, &[circuit], &[&[]], os_rng, &mut transcript).unwrap();

    let proof_script = transcript.finalize();
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof_script[..]);
    let verifier_params: ParamsVerifier<Bn256> = params.verifier(0).unwrap();
    let strategy = SingleVerifier::new(&verifier_params);
    let circuit = EthTrie::<Fp>::new(200);
    let vk = keygen_vk(&params, &circuit).unwrap();

    verify_proof(&verifier_params, &vk, strategy, &[&[]], &mut transcript).unwrap();
}
