#![allow(unused_imports)]

use halo2::{
    dev::{MockProver, VerifyFailure},
    pairing::bn256::Fr as Fp,
};
use halo2_mpt_circuits as self_crate;
use lazy_static::lazy_static;
use self_crate::serde::Row;

const TEST_FILE: &'static str = include_str!("../rows.jsonl");

#[test]
fn demo_from_static() {
    use self_crate::{MPTDemoCircuit, SingleOp};

    let k = 5;

    let mut circuit = MPTDemoCircuit::<Fp>::new(20);

    let ops = Row::fold_flattern_rows(Row::from_lines(TEST_FILE).unwrap());

    for op in ops {
        circuit
            .add_operation(SingleOp::<Fp>::from(op.as_ref()))
            .unwrap();
    }

    #[cfg(feature = "print_layout")]
    {
        use plotters::prelude::*;
        let root = BitMapBackend::new("demo_static.png", (2048, 1536)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Demo Circuit Layout For Static Data", ("sans-serif", 60))
            .unwrap();

        halo2::dev::CircuitLayout::default()
            // You can optionally render only a section of the circuit.
            //.view_width(0..2)
            //.view_height(0..16)
            // You can hide labels, which can be useful with smaller areas.
            .show_labels(true)
            .mark_equality_cells(true)
            // Render the circuit onto your area!
            // The first argument is the size parameter for the circuit.
            .render(k, &circuit, &root)
            .unwrap();
    }

    let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
