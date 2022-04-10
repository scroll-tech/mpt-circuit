use halo2_mpt_circuits::{operation::*, SimpleTrie};
use halo2_proofs::arithmetic::BaseExt;
use halo2_proofs::dev::MockProver;
use halo2_proofs::pairing::bn256::Fr as Fp;
use lazy_static::lazy_static;

lazy_static! {
    static ref GAMMA: Fp = Fp::rand();
}

pub fn mock_hash(a: &Fp, b: &Fp) -> Fp {
    (a + *GAMMA) * (b + *GAMMA)
}

/*
    This case test a circuit layout which do not include a leaf line, i.e. hash_types is not Empty / Leaf, should fail
*/
#[test]
fn milice_case_truncated_line() {
    let k = 5;
    let mut circuit = SimpleTrie::<Fp>::new(20);

    let layers = 3;
    let siblings: Vec<Fp> = (0..layers).map(|_| Fp::rand()).collect();
    /*
        in common case, 'path bit' gate would detect a non-bit path cell if the hash_types is not empty/leaf,
        but this constraint become vain when the key is small enough that the residents of key is 0 or 1
        And even under such circumstance, the lookup for edge would still detect the issue
    */
    let key = Fp::from(6u64);
    let leafs = (Fp::rand(), Fp::rand());
    let fst = SingleOp::<Fp>::create_update_op(layers, &siblings, key, leafs, mock_hash);
    let sec = fst.clone().update_next(Fp::rand(), mock_hash);
    circuit.add_op(fst.clone());
    circuit.add_op(sec.clone());

    // control sample
    let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let mut fst = fst;
    // we need more calc to keep the kep consistent with path ..
    let key_rest = fst.path.pop().unwrap();
    let key_rest = key_rest * Fp::from(2u64) + fst.path.pop().unwrap();
    fst.path.push(key_rest);
    fst.siblings.pop();

    fst.old.hash_types.pop();
    fst.old.hashes.pop();
    fst.new.hash_types.pop();
    fst.new.hashes.pop();

    let mut circuit = SimpleTrie::<Fp>::new(20);
    circuit.add_op(fst);
    circuit.add_op(sec);

    let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
    // an lookup err is expected
    assert_ne!(prover.verify(), Ok(()));
}
