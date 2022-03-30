use ff::Field;
pub use halo2_proofs::{arithmetic::BaseExt, pairing::bn256::Fr as Fp};
use lazy_static::lazy_static;
use rand::{random, SeedableRng};
use rand_chacha::ChaCha8Rng; // why halo2-merkle tree use base field?

pub const TEST_FILE: &'static str = include_str!("../rows.jsonl");
pub const TEST_TRACE: &'static str = include_str!("../traces.jsonl");

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
    Fp::read(&mut &arr[..]).unwrap()
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
