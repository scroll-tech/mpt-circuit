use crate::constraint_builder::Query;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

pub trait AccountUpdateLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3];
}
