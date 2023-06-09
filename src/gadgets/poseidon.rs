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

impl From<(Column<Fixed>, [Column<Advice>; 5])> for PoseidonTable {
    fn from(src: (Column<Fixed>, [Column<Advice>; 5])) -> Self {
        Self {
            left: AdviceColumn(src.1[0]),
            right: AdviceColumn(src.1[1]),
            hash: SecondPhaseAdviceColumn(src.1[2]),
            control: AdviceColumn(src.1[3]),
            head_mark: AdviceColumn(src.1[4]),
            q_enable: FixedColumn(src.0),
        }
    }
}

impl PoseidonTable {
    pub fn dev_configure<F: FieldExt>(
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

    pub fn dev_load(&self, region: &mut Region<'_, Fr>, hash_traces: &[(Fr, Fr, Fr)], size: usize) {
        assert!(
            size >= hash_traces.len(),
            "too many traces ({}), limit is {}",
            hash_traces.len(),
            size,
        );

        for (offset, hash_trace) in hash_traces.iter().enumerate() {
            assert!(
                poseidon_hash(hash_trace.0, hash_trace.1) == hash_trace.2,
                "{:?}",
                (hash_trace.0, hash_trace.1, hash_trace.2)
            );
            for (column, value) in [
                (self.left, hash_trace.0),
                (self.right, hash_trace.1),
                (self.control, Fr::zero()),
                (self.head_mark, Fr::one()),
            ] {
                column.assign(region, offset, value);
            }
            self.hash.assign(region, offset, Value::known(hash_trace.2));
            self.q_enable.assign(region, offset, Fr::one());
        }

        for offset in hash_traces.len()..size {
            self.q_enable.assign(region, offset, Fr::one());
        }

        // add an total zero row for disabled lookup
        for col in [self.left, self.right, self.control, self.head_mark] {
            col.assign(region, size, Fr::zero());
        }
        self.hash.assign(region, size, Value::known(Fr::zero()));
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
