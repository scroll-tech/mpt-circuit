//! mpt demo circuits
//

#![allow(dead_code)]
#![allow(unused_macros)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub use crate::serde::{Hash, Row, RowDeError};

mod layers;
mod mpt;
mod eth;
mod operation;
mod serde;

#[cfg(test)]
mod test_utils;

/// Indicate the operation type of a row in MPT circuit
#[derive(Clone, Copy, Debug)]
pub enum HashType {
    /// Marking the start of node
    Start = 0,
    /// Empty node
    Empty,
    /// middle node
    Middle,
    /// leaf node which is extended to middle in insert
    LeafExt,
    /// leaf node which is extended to middle in insert, which is the last node in new path
    LeafExtFinal,
    /// leaf node
    Leaf,
}

// we lookup the transition of ctrl type from the preset table, and different kind of rules
// is specified here
enum CtrlTransitionKind {
    Mpt = 1,        // transition in MPT circuit
    Account,        // transition in account circuit
    Operation = 99, // transition of the old state to new state in MPT circuit
}

use halo2::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Expression, Circuit, ConstraintSystem, Error},
};
use layers::{LayerGadget, PaddingGadget};
use mpt::MPTOpGadget;
use operation::SingleOp;

// building lagrange polynmials L for T so that L(n) = 1 when n = T else 0, n in [0, TO] 
fn lagrange_polynomial<Fp: ff::PrimeField, const T: usize, const TO: usize>(
    ref_n: Expression<Fp>,
) -> Expression<Fp> {
    let mut denominators : Vec<Fp> = (0..(TO+1)).map(|v| Fp::from(T as u64) - Fp::from(v as u64)).collect();
    denominators.swap_remove(T);
    let denominator = denominators.into_iter().fold(Fp::one(), |acc, v| v * acc);
    assert_ne!(denominator, Fp::zero());

    let mut factors : Vec<Expression<Fp>> = (0..(TO+1)).map(|v| ref_n.clone() - Expression::Constant(Fp::from(v as u64))).collect();
    factors.swap_remove(T);
    factors.into_iter().fold(
        Expression::Constant(denominator.invert().unwrap()),
        |acc, f| acc * f,
    )
}

/// The config for circuit
#[derive(Clone, Debug)]
pub struct SimpleTrieConfig {
    layer: LayerGadget,
    padding: PaddingGadget,
    mpt: MPTOpGadget,
}

/// The chip for op on a simple trie
#[derive(Clone, Default)]
pub struct SimpleTrie<F: FieldExt> {
    c_size: usize, //how many rows
    start_root: F,
    final_root: F,
    ops: Vec<SingleOp<F>>,
}

const OP_MPT: u32 = 1;
const OP_PADDING: u32 = 0;

impl<Fp: FieldExt> Circuit<Fp> for SimpleTrie<Fp> {
    type Config = SimpleTrieConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let layer = LayerGadget::configure(meta, 2, MPTOpGadget::min_free_cols());
        let padding =
            PaddingGadget::configure(meta, layer.public_sel(), layer.exported_cols(OP_PADDING));
        let mpt = MPTOpGadget::configure_simple(
            meta,
            layer.public_sel(),
            layer.exported_cols(OP_MPT),
            layer.get_free_cols(),
        );

        let cst = meta.fixed_column();
        meta.enable_constant(cst);

        SimpleTrieConfig {
            layer,
            padding,
            mpt,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "main",
            |mut region| {
                let mut series: usize = 1;
                let mut last_op_code = config.layer.start_op_code();
                let mut start = config
                    .layer
                    .assign(&mut region, self.c_size, self.start_root)?;
                for op in self.ops.iter() {
                    config.layer.pace_op(
                        &mut region,
                        start,
                        series,
                        (last_op_code, OP_MPT),
                        op.new_root(),
                        op.use_rows(),
                    )?;
                    start = config.mpt.assign(&mut region, start, op)?;
                    assert!(
                        start <= self.c_size,
                        "assigned rows exceed limited {}",
                        self.c_size
                    );
                    series += 1;
                    last_op_code = OP_MPT;
                }

                let row_left = self.c_size - start;
                if row_left > 0 {
                    config.layer.pace_op(
                        &mut region,
                        start,
                        series,
                        (last_op_code, OP_PADDING),
                        self.final_root,
                        row_left,
                    )?;
                    config
                        .padding
                        .padding(&mut region, start, row_left, self.final_root)?;
                }

                Ok(())
            },
        )?;

        config.mpt.init(&mut layouter)?;
        config.mpt.init_hash_table(&mut layouter, self.ops.iter())?;

        // only ctrl_type as HashType::leaf / empty can start new block
        let possible_end_block = [
            (OP_MPT, HashType::Empty as u32),
            (OP_MPT, HashType::Leaf as u32),
        ];
        let possible_start_block = [(OP_MPT, HashType::Start as u32), (OP_PADDING, 0)];

        let border_list: Vec<layers::OpBorder> = possible_start_block
            .into_iter()
            .flat_map(|st0| possible_end_block.iter().map(move |st1| (st0, *st1)))
            .collect();
        config.layer.set_op_border(
            &mut layouter,
            &border_list,
            &[],
            (OP_MPT, HashType::Start as u32),
        )
    }
}

#[cfg(test)]
mod test {
    #![allow(unused_imports)]
    use super::*;
    use crate::{serde::Row, test_utils::*};
    use halo2::dev::{MockProver, VerifyFailure};

    #[test]
    fn geth_case_simple_trie() {
        let ops: Vec<SingleOp<Fp>> = Row::fold_flattern_rows(Row::from_lines(TEST_FILE).unwrap())
            .iter()
            .map(|v| SingleOp::<Fp>::from(v.as_slice()))
            .collect();

        let k = 5;
        let circuit = SimpleTrie::<Fp> {
            c_size: 22,
            start_root: ops[0].start_root(),
            final_root: ops.last().unwrap().new_root(),
            ops,
        };

        #[cfg(feature = "print_layout")]
        print_layout!("layouts/simple_trie_layout.png", k, &circuit);

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        //no padding
        let circuit = SimpleTrie::<Fp> {
            c_size: 20,
            start_root: circuit.start_root,
            final_root: circuit.final_root,
            ops: circuit.ops,
        };

        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
