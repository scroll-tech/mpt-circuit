use crate::constraint_builder::{FixedColumn, AdviceColumn, ConstraintBuilder, Query};
use crate::util::hash as poseidon_hash;
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::Region,
    halo2curves::bn256::Fr,
    plonk::ConstraintSystem,
};

/// PoseidonTable represent the poseidon table in zkevm circuit
pub trait PoseidonLookup {
    fn lookup(&self) -> (FixedColumn, [AdviceColumn; 5]);
}

impl<F: FieldExt> ConstraintBuilder<F> {
    pub fn poseidon_lookup(&mut self, 
        name: &'static str, 
        queries: [Query<F>; 3], 
        poseidon : &impl PoseidonLookup
    ){
        let extended_queries = [
            Query::one(),
            queries[2].clone(),
            queries[0].clone(),
            queries[1].clone(),
            Query::zero(),
            Query::one(),
        ];

        let (q_enable, table_cols) = poseidon.lookup();

        self.add_lookup(name, 
            extended_queries,
            [
                q_enable.current(),
                table_cols[0].current(),
                table_cols[1].current(),
                table_cols[2].current(),
                table_cols[3].current(),
                table_cols[4].current(),
            ]
        )
    }
}

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
        Self { left, right, hash, control, head_mark,
            q_enable: FixedColumn(cs.fixed_column()),
            size,
        }
    }

    pub fn dev_load(&self, region: &mut Region<'_, Fr>, hash_traces: &[(Fr, Fr, Fr)]) {

        assert!(self.size >= hash_traces.len(), 
            "too many traces ({}), limit is {}", hash_traces.len(), self.size);

        for (offset, hash_trace) in hash_traces.iter().enumerate() {
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

        for offset in hash_traces.len()..self.size{
            self.q_enable.assign(region, offset, Fr::one());
        }

        // add an total zero row for unactived lookup
        let (_, cols) = self.lookup();
        for col in cols {
            col.assign(region, self.size, Fr::zero());
        }

    }
}

impl PoseidonLookup for PoseidonTable {
    fn lookup(&self) -> (FixedColumn, [AdviceColumn; 5]) {
        (
            self.q_enable,
            [
                self.hash,
                self.left,
                self.right,
                self.control,
                self.head_mark,
            ],                
        )
    }
}
