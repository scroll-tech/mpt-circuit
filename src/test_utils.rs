use rand::{random, SeedableRng};
use lazy_static::lazy_static;
use rand_chacha::ChaCha8Rng;
use ff::Field;
pub use halo2::{arithmetic::FieldExt, pairing::bn256::Fr as Fp}; // why halo2-merkle tree use base field?

lazy_static! {
    static ref GAMMA: Fp = Fp::random(ChaCha8Rng::from_seed([101u8; 32]));
}

pub fn mock_hash(a: &Fp, b: &Fp) -> Fp {
    (a + *GAMMA) * (b + *GAMMA)
}

pub fn rand_bytes(n: usize) -> Vec<u8> {
    vec![random(); n]
}

pub fn rand_bytes_array<const N: usize>() -> [u8; N] {
    [(); N].map(|_| random())
}

pub fn rand_fp() -> Fp {
    let mut arr = rand_bytes_array::<32>();
    //avoiding failure in unwrap
    arr[31] &= 31;
    Fp::from_bytes(&arr).unwrap()
}

