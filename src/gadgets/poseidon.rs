use crate::constraint_builder::{AdviceColumn, ConstraintBuilder, FixedColumn, Query};
use crate::util::hash as poseidon_hash;
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::Region,
    halo2curves::bn256::Fr,
    plonk::ConstraintSystem,
};
use std::iter::once;

#[derive(Clone, Copy)]
pub struct PoseidonTable {
    q_enable: FixedColumn,
    left: AdviceColumn,
    right: AdviceColumn,
    hash: AdviceColumn,
    control: AdviceColumn,
    head_mark: AdviceColumn,
    size: usize,
}

impl PoseidonTable {
    pub fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
        size: usize,
    ) -> Self {
        let [left, right, hash, control, head_mark] = cb.advice_columns(cs);
        Self {
            left,
            right,
            hash,
            control,
            head_mark,
            q_enable: FixedColumn(cs.fixed_column()),
            size,
        }
    }

    pub fn dev_load(&self, region: &mut Region<'_, Fr>, hash_traces: &[(Fr, Fr, Fr)]) {
        assert!(
            self.size >= hash_traces.len(),
            "too many traces ({}), limit is {}",
            hash_traces.len(),
            self.size
        );

        for (offset, hash_trace) in hash_traces
            .iter()
            .chain(&[(
                Fr::one(),
                Fr::one(),
                poseidon_hash(1.into(), 1.into()),
            )])
            .enumerate()
        {
            assert!(
                hash_trace.0.is_zero_vartime()
                    && hash_trace.1.is_zero_vartime()
                    && hash_trace.2.is_zero_vartime()
                    || poseidon_hash(hash_trace.0, hash_trace.1) == hash_trace.2,
                "{:?}",
                (hash_trace.0, hash_trace.1, hash_trace.2)
            );
            for (column, value) in [
                (self.left, hash_trace.0),
                (self.right, hash_trace.1),
                (self.hash, hash_trace.2),
                (self.control, Fr::zero()),
                (self.head_mark, Fr::one()),
            ] {
                column.assign(region, offset, value);
            }
            self.q_enable.assign(region, offset, Fr::one());
        }

        for offset in hash_traces.len()..self.size {
            self.q_enable.assign(region, offset, Fr::one());
        }

        // add an total zero row for disabled lookup
        for col in [
            self.hash,
            self.left,
            self.right,
            self.control,
            self.head_mark,
        ] {
            col.assign(region, self.size, Fr::zero());
        }
    }

    pub fn lookup<F: FieldExt>(
        &self,
        cb: &mut ConstraintBuilder<F>,
        name: &'static str,
        left: Query<F>,
        right: Query<F>,
        hash: Query<F>,
    ) {
        cb.add_lookup_with_default(
            name,
            [Query::one(), hash, left, right, Query::zero(), Query::one()],
            [
                self.q_enable.current(),
                self.hash.current(),
                self.left.current(),
                self.right.current(),
                self.control.current(),
                self.head_mark.current(),
            ],
            Self::default_lookup(),
        )
    }

    fn default_lookup<F: FieldExt>() -> [Query<F>; 6] {
        [
            Query::one(),
            Query::from(poseidon_hash(1.into(), 1.into())),
            Query::one(),
            Query::one(),
            Query::zero(),
            Query::one(),
        ]
    }
}
