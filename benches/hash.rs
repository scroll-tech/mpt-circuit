#[macro_use]
extern crate bencher;

use bencher::Bencher;
use ff::Field;
use halo2_proofs::pairing::bn256::Fr;
use lazy_static::lazy_static;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use halo2_mpt_circuits::poseidon::primitives::{ConstantLengthIden3, P128Pow5T3, Hash};

lazy_static! {
    static ref RNDFRS: [Fr; 16] = {
        let rng = ChaCha8Rng::from_seed([101u8; 32]);
        [(); 16]
            .map(|_| Fr::random(rng.clone()))
    };
}

macro_rules! hashes {
    ( $fname:ident, $n:expr ) => {
        fn $fname(bench: &mut Bencher) {

            bench.iter(|| 
                Hash::<Fr, P128Pow5T3<Fr>, ConstantLengthIden3<$n>, 3, 2>::init().hash(Vec::from(&RNDFRS.as_slice()[..$n]).try_into().unwrap())
            );
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
