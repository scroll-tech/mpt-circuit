use crate::{
    constraint_builder::{
        AdviceColumn, ConstraintBuilder, FixedColumn, Query, SecondPhaseAdviceColumn,
    },
    types::HASH_ZERO_ZERO,
    util::hash as poseidon_hash,
};
use halo2_proofs::plonk::{Advice, Column, Fixed};
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::{Region, Value},
    halo2curves::bn256::Fr,
    plonk::ConstraintSystem,
};

/// PoseidonTable represent the poseidon table in zkevm circuit
pub trait PoseidonLookup {
    fn lookup(&self) -> (FixedColumn, [AdviceColumn; 4], SecondPhaseAdviceColumn);
}

impl<F: FieldExt> ConstraintBuilder<F> {
    pub fn poseidon_lookup(
        &mut self,
        name: &'static str,
        queries: [Query<F>; 3],
        poseidon: &impl PoseidonLookup,
    ) {
        let extended_queries = [
            Query::one(),
            queries[2].clone(),
            queries[0].clone(),
            queries[1].clone(),
            Query::zero(),
            Query::one(),
        ];

        let (q_enable, [left, right, control, head_mark], hash) = poseidon.lookup();

        self.add_lookup_with_default(
            name,
            extended_queries,
            [
                q_enable.current(),
                hash.current(),
                left.current(),
                right.current(),
                control.current(),
                head_mark.current(),
            ],
            [
                Query::one(),
                Query::from(*HASH_ZERO_ZERO),
                Query::zero(),
                Query::zero(),
                Query::zero(),
                Query::one(),
            ],
        )
    }
}

#[derive(Clone, Copy)]
pub struct PoseidonTable {
    q_enable: FixedColumn,
    left: AdviceColumn,
    right: AdviceColumn,
    hash: SecondPhaseAdviceColumn,
    control: AdviceColumn,
    head_mark: AdviceColumn,
}

impl PoseidonTable {
    pub fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
    ) -> Self {
        let [left, right, control, head_mark] = cb.advice_columns(cs);
        let [hash] = cb.second_phase_advice_columns(cs);
        Self {
            left,
            right,
            hash,
            control,
            head_mark,
            q_enable: FixedColumn(cs.fixed_column()),
        }
    }

    pub fn columns(&self) -> (Column<Fixed>, [Column<Advice>; 5]) {
        (
            self.q_enable.0,
            [
                self.hash.0,
                self.left.0,
                self.right.0,
                self.control.0,
                self.head_mark.0,
            ],
        )
    }
}

impl PoseidonLookup for PoseidonTable {
    fn lookup(&self) -> (FixedColumn, [AdviceColumn; 4], SecondPhaseAdviceColumn) {
        (
            self.q_enable,
            [self.left, self.right, self.control, self.head_mark],
            self.hash,
        )
    }
}
