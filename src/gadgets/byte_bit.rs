use super::super::constraint_builder::{ConstraintBuilder, FixedColumn, Query};
use crate::assignment_map::Column;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::{ConstraintSystem, Error},
};
use rayon::prelude::*;

// TODO: fix name to configggggggg
#[derive(Clone)]
pub struct ByteBitGadget {
    byte: FixedColumn,
    index: FixedColumn,
    bit: FixedColumn,
}

pub trait RangeCheck8Lookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 1];
}

pub trait RangeCheck256Lookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 1];
}

pub trait ByteBitLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3];
}

impl ByteBitGadget {
    pub fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
    ) -> Self {
        let ([], [byte, index, bit], []) = cb.build_columns(cs);
        Self { byte, index, bit }
    }

    pub fn assign<F: FieldExt>(&self, region: &mut Region<'_, F>) {
        let assignments: Vec<_> = self.assignments::<F>().collect();
        for ((column, offset), value) in assignments.into_iter() {
            match column {
                Column::Fixed(s) => region.assign_fixed(|| "fixed", s.0, offset, || value),
                _ => unreachable!(),
            };
        }
    }

    pub fn assignments<F: FieldExt>(
        &self,
    ) -> impl ParallelIterator<Item = ((Column, usize), Value<F>)> + '_ {
        (0..256u64).into_par_iter().flat_map(move |byte| {
            let starting_offset = byte * 8;
            (0..8u64).into_par_iter().flat_map_iter(move |index| {
                let offset = usize::try_from(1 + starting_offset + index).unwrap();
                [
                    self.byte.assignment(offset, byte),
                    self.index.assignment(offset, index),
                    self.bit.assignment(offset, byte & (1 << index) != 0),
                ]
                .into_iter()
            })
        })
    }

    pub fn n_rows_required() -> usize {
        // +1 because assigment starts on offset = 1 instead of offset = 0.
        256 * 8 + 1
    }
}

impl RangeCheck8Lookup for ByteBitGadget {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 1] {
        [self.index.current()]
    }
}

impl RangeCheck256Lookup for ByteBitGadget {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 1] {
        [self.byte.current()]
    }
}

impl ByteBitLookup for ByteBitGadget {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3] {
        [
            self.byte.current(),
            self.index.current(),
            self.bit.current(),
        ]
    }
}
