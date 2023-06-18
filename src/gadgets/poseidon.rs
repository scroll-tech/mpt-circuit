#[cfg(test)]
use crate::util::hash as poseidon_hash;
use crate::{
    constraint_builder::{
        AdviceColumn, ConstraintBuilder, FixedColumn, Query, SecondPhaseAdviceColumn,
    },
    types::HASH_ZERO_ZERO,
};
use halo2_proofs::arithmetic::FieldExt;
#[cfg(test)]
use halo2_proofs::{
    circuit::{Region, Value},
    halo2curves::bn256::Fr,
    plonk::ConstraintSystem,
    plonk::SecondPhase,
};

/// Lookup  represent the poseidon table in zkevm circuit
pub trait PoseidonLookup {
    fn lookup_columns(&self) -> (FixedColumn, [AdviceColumn; 4], SecondPhaseAdviceColumn);
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

        let (q_enable, [left, right, control, head_mark], hash) = poseidon.lookup_columns();

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

#[cfg(test)]
#[derive(Clone, Copy)]
pub struct PoseidonTable {
    q_enable: FixedColumn,
    left: AdviceColumn,
    right: AdviceColumn,
    hash: SecondPhaseAdviceColumn,
    control: AdviceColumn,
    head_mark: AdviceColumn,
}

#[cfg(test)]
impl PoseidonTable {
    pub fn configure<F: FieldExt>(cs: &mut ConstraintSystem<F>) -> Self {
        let [left, right, control, head_mark] = [0; 4].map(|_| AdviceColumn(cs.advice_column()));
        let hash = SecondPhaseAdviceColumn(cs.advice_column_in(SecondPhase));
        Self {
            left,
            right,
            hash,
            control,
            head_mark,
            q_enable: FixedColumn(cs.fixed_column()),
        }
    }

    pub fn load(&self, region: &mut Region<'_, Fr>, hash_traces: &[(Fr, Fr, Fr)], size: usize) {
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

        // TODO: fix
        // add an total zero row for disabled lookup
        for col in [self.left, self.right, self.control, self.head_mark] {
            col.assign(region, size, Fr::zero());
        }
        self.hash.assign(region, size, Value::known(Fr::zero()));
    }
}

#[cfg(test)]
impl PoseidonLookup for PoseidonTable {
    fn lookup_columns(&self) -> (FixedColumn, [AdviceColumn; 4], SecondPhaseAdviceColumn) {
        (
            self.q_enable,
            [self.left, self.right, self.control, self.head_mark],
            self.hash,
        )
    }
}
