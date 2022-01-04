//! TODO: docs
#![allow(unused_imports)]

use ff::Field;
use halo2::{
    circuit::{Cell, Chip, Layouter},
    dev::{MockProver, VerifyFailure},
    plonk::{
        Advice, Assignment, Circuit, Column, ConstraintSystem, Error, Expression, Instance,
        Selector,
    },
    poly::Rotation,
    arithmetic::FieldExt,
};
use std::marker::PhantomData;

struct MerkleOpChip<F> {
    config: MerkleOpChipConfig,
    _phantom_data: PhantomData<F>,
}

#[derive(Clone, Debug)]
struct MerkleOpChipConfig {

}

impl MerkleOpChipConfig {
    fn new<Fp: FieldExt>(cs: &mut ConstraintSystem<Fp>) -> MerkleOpChipConfig {
        Self {}
    }
}

impl<Fp: FieldExt> Chip<Fp> for MerkleOpChip<Fp> {

    type Config = MerkleOpChipConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<Fp: FieldExt> MerkleOpChip<Fp> {
    fn new(config: MerkleOpChipConfig) -> Self {
        Self { 
            config,
            _phantom_data: PhantomData::default(),
        }
    }
}

// TODO: we can copy merklechip from https://github.com/adria0/halo2-merkle and organize these two 
// for a full working MPT gadget
