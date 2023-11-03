use crate::constraint_builder::{
    AdviceColumn, FixedColumn, SecondPhaseAdviceColumn, SelectorColumn,
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::Error,
};
use itertools::Itertools;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone, Default)]
pub struct AssignmentMap<F: FieldExt>(BTreeMap<usize, Vec<(Column, Value<F>)>>);

impl<F: FieldExt> AssignmentMap<F> {
    pub fn new(stream: impl ParallelIterator<Item = ((Column, usize), Value<F>)>) -> Self {
        let mut sorted_by_offset: Vec<_> = stream
            .map(|((column, offset), value)| (offset, column, value))
            .collect();
        sorted_by_offset.sort_by(|x, y| x.0.cmp(&y.0));
        let grouped_by_offset = sorted_by_offset.iter().group_by(|(offset, _, _)| offset);
        let y: BTreeMap<_, _> = grouped_by_offset
            .into_iter()
            .map(|(offset, group)| {
                (
                    *offset,
                    group
                        .map(|(_offset, column, value)| (*column, *value))
                        .collect(),
                )
            })
            .collect();
        Self(y)
    }

    pub fn to_vec(self) -> Vec<impl FnMut(Region<'_, F>) -> Result<(), Error>> {
        self.0
            .into_iter()
            .map(|(_offset, column_assignments)| {
                move |mut region: Region<'_, F>| {
                    for (column, value) in column_assignments.iter() {
                        match *column {
                            Column::Selector(s) => {
                                region.assign_fixed(|| "selector", s.0, 0, || *value)
                            }
                            Column::Fixed(s) => region.assign_fixed(|| "fixed", s.0, 0, || *value),
                            Column::Advice(s) => {
                                region.assign_advice(|| "advice", s.0, 0, || *value)
                            }
                            Column::SecondPhaseAdvice(s) => {
                                region.assign_advice(|| "second phase advice", s.0, 0, || *value)
                            }
                        }
                        .unwrap();
                    }
                    Ok(())
                }
            })
            .collect()
    }
}

#[derive(Clone, Copy, Hash, Eq, PartialEq, Ord, PartialOrd)]
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
