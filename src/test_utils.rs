pub use halo2_proofs::arithmetic::{Field, FieldExt};
pub use halo2_proofs::halo2curves::bn256::Fr as Fp;
use lazy_static::lazy_static;
use rand::{random, SeedableRng};
use rand_chacha::ChaCha8Rng; // why halo2-merkle tree use base field?

lazy_static! {
    static ref GAMMA: Fp = Fp::random(rand_gen([101u8; 32]));
    pub static ref TEST_RANDOMNESS: Fp = Fp::from_u128(0x10000000000000000u128).square();
}

pub fn rand_gen(seed: [u8; 32]) -> ChaCha8Rng {
    ChaCha8Rng::from_seed(seed)
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
    let arr = rand_bytes_array::<32>();
    Fp::random(rand_gen(arr))
}

macro_rules! print_layout {
    ( $pic:expr, $k:expr, $circuit:expr ) => {
        use plotters::prelude::*;
        let root = BitMapBackend::new($pic, (1024, 768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Test Circuit Layout", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            // You can optionally render only a section of the circuit.
            //.view_width(0..2)
            //.view_height(0..16)
            // You can hide labels, which can be useful with smaller areas.
            .show_labels(true)
            .mark_equality_cells(true)
            // Render the circuit onto your area!
            // The first argument is the size parameter for the circuit.
            .render($k, $circuit, &root)
            .unwrap();
    };
}

#[cfg(feature = "print_layout")]
pub(crate) use print_layout;
