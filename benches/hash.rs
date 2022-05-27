#[macro_use]
extern crate bencher;

use bencher::Bencher;
use ff::{Field, PrimeField};
use halo2_proofs::pairing::bn256;
use lazy_static::lazy_static;
use poseidon_rs::{Fr, Poseidon};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

fn same_fr_convert<A: PrimeField, B: PrimeField>(fr: A) -> B {
    let mut ret = B::Repr::default();
    ret.as_mut().copy_from_slice(fr.to_repr().as_ref());

    B::from_repr(ret).unwrap()
}

lazy_static! {
    static ref RNDFRS: [Fr; 16] = {
        let rng = ChaCha8Rng::from_seed([101u8; 32]);
        [(); 16]
            .map(|_| bn256::Fr::random(rng.clone()))
            .map(same_fr_convert)
    };
}

macro_rules! hashes {
    ( $fname:ident, $n:expr ) => {
        fn $fname(bench: &mut Bencher) {
            let hasher = Poseidon::new();
            bench.iter(|| hasher.hash(Vec::from(&RNDFRS.as_slice()[..$n])).unwrap());
        }
    };
}

hashes!(h02, 2);
hashes!(h03, 3);
hashes!(h04, 4);
hashes!(h05, 5);
hashes!(h06, 6);
hashes!(h07, 6);

fn vec_ref(bench: &mut Bencher) {
    bench.iter(|| Vec::from(&RNDFRS.as_slice()[..8]));
}

benchmark_group!(hashes_bench, h02, h03, h04, h05, h06, h07, vec_ref);
benchmark_main!(hashes_bench);
