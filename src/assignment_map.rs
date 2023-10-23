use crate::constraint_builder::{
    AdviceColumn, FixedColumn, SecondPhaseAdviceColumn, SelectorColumn,
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    halo2curves::bn256::Fr,
    plonk::{Challenge, ConstraintSystem, Error, Expression, VirtualCells},
};
use rayon::prelude::*;
use std::collections::HashMap;

#[derive(Clone, Default)]
pub struct AssignmentMap<F: FieldExt>(HashMap<(Column, usize), Value<F>>);

impl<F: FieldExt> AssignmentMap<F> {
    pub fn new(assignments: impl ParallelIterator<Item = ((Column, usize), Value<F>)>) -> Self {
        Self(assignments.collect())
    }

    // pub fn enable_selector(&mut self, column: SelectorColumn, offset: usize) {
    //     self.add_assignment(column.into(), offset, Value::known(F::one()));
    // }

    // pub fn assign_fixed(&mut self, column: FixedColumn, offset: usize, assignment: F) {
    //     self.add_assignment(column.into(), offset, Value::known(assignment));
    // }

    // pub fn assign_advice(&mut self, column: AdviceColumn, offset: usize, assignment: F) {
    //     self.add_assignment(column.into(), offset, Value::known(assignment));
    // }

    // pub fn assign_second_phase_advice(
    //     &mut self,
    //     column: SecondPhaseAdviceColumn,
    //     offset: usize,
    //     assignment: Value<F>,
    // ) {
    //     self.add_assignment(column.into(), offset, assignment);
    // }

    // fn add_assignment(&mut self, column: Column, offset: usize, assignment: Value<F>) {
    //     self.0
    //         .entry((column.into(), offset))
    //         .and_modify(|_| panic!("Did you mean to assign twice????"))
    //         .or_insert(assignment);
    // }

    pub fn assignments(self) -> Vec<impl FnMut(Region<'_, F>) -> Result<(), Error>> {
        // self.0
        //     .into_iter()
        //     .map(|((column, offset), value)| {
        //         move |mut region: Region<'_, F>| {
        //             match column {
        //                 Column::Selector(s) => {
        //                     region.assign_fixed(|| "selector", s.0, offset, || value)
        //                 }
        //                 Column::Fixed(s) => region.assign_fixed(|| "fixed", s.0, offset, || value),
        //                 Column::Advice(s) => {
        //                     region.assign_advice(|| "advice", s.0, offset, || value)
        //                 }
        //                 Column::SecondPhaseAdvice(s) => {
        //                     region.assign_advice(|| "second phase advice", s.0, offset, || value)
        //                 }
        //             };
        //             Ok(())
        //         }
        //     })
        //     .collect()
        vec![move |mut region: Region<'_, F>| {
            let x = self.0.clone();
            for ((column, offset), value) in x.into_iter() {
                match column {
                    Column::Selector(s) => {
                        region.assign_fixed(|| "selector", s.0, offset, || value)
                    }
                    Column::Fixed(s) => region.assign_fixed(|| "fixed", s.0, offset, || value),
                    Column::Advice(s) => region.assign_advice(|| "advice", s.0, offset, || value),
                    Column::SecondPhaseAdvice(s) => {
                        region.assign_advice(|| "second phase advice", s.0, offset, || value)
                    }
                };
            }
            Ok(())
        }]
    }
}

#[derive(Clone, Copy, Hash, Eq, PartialEq)]
pub enum Column {
    Selector(SelectorColumn),
    Fixed(FixedColumn),
    Advice(AdviceColumn),
    SecondPhaseAdvice(SecondPhaseAdviceColumn),
}

impl From<SelectorColumn> for Column {
    fn from(c: SelectorColumn) -> Self {
        Self::Selector(c)
    }
}

impl From<FixedColumn> for Column {
    fn from(c: FixedColumn) -> Self {
        Self::Fixed(c)
    }
}

impl From<AdviceColumn> for Column {
    fn from(c: AdviceColumn) -> Self {
        Self::Advice(c)
    }
}

impl From<SecondPhaseAdviceColumn> for Column {
    fn from(c: SecondPhaseAdviceColumn) -> Self {
        Self::SecondPhaseAdvice(c)
    }
}
