use halo2::arithmetic::BaseExt;
use halo2::dev::MockProver;
use halo2::pairing::bn256::Fr as Fp;
use halo2_mpt_circuits::{operation::*, SimpleTrie};
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
#[cfg(test)]
#[test]
fn milice_case_truncated_line() {
    let k = 5;
    let mut circuit = SimpleTrie::<Fp>::new(20);

    let fst = SingleOp::<Fp>::create_rand_op(3, None, mock_hash);
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
    assert_ne!(prover.verify(), Ok(()));
}
