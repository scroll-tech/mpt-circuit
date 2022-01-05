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

struct MPTOpChip<F> {
    config: MPTOpChipConfig,
    _marker: PhantomData<F>,
}

#[derive(Clone, Debug)]
struct MPTOpChipConfig {

}

impl<Fp: FieldExt> Chip<Fp> for MPTOpChip<Fp> {

    type Config = MPTOpChipConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<Fp: FieldExt> MPTOpChip<Fp> {
    pub fn construct(config: MPTOpChipConfig) -> Self {
        Self { 
            config,
            _marker: PhantomData,
        }
    }
}


