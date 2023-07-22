use crate::constraint_builder::{AdviceColumn, ConstraintBuilder, FixedColumn, Query};
#[cfg(test)]
use crate::util::hash as poseidon_hash;
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, Fixed},
};
#[cfg(test)]
use halo2_proofs::{circuit::Region, halo2curves::bn256::Fr, plonk::ConstraintSystem};

/// Lookup  represent the poseidon table in zkevm circuit
pub trait PoseidonLookup {
    fn lookup_columns(&self) -> (FixedColumn, [AdviceColumn; 6]) {
        let (fixed, adv) = self.lookup_columns_generic();
        (FixedColumn(fixed), adv.map(AdviceColumn))
    }
    fn lookup_columns_generic(&self) -> (Column<Fixed>, [Column<Advice>; 6]) {
        let (fixed, adv) = self.lookup_columns();
        (fixed.0, adv.map(|col| col.0))
    }
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
            Query::zero(),
            Query::one(),
        ];

        let (q_enable, [hash, left, right, control, domain_spec, head_mark]) =
            poseidon.lookup_columns();

        self.add_lookup(
            name,
            extended_queries,
            [
                q_enable.current(),
                hash.current(),
                left.current(),
                right.current(),
                control.current(),
                domain_spec.current(),
                head_mark.current(),
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
    hash: AdviceColumn,
    control: AdviceColumn,
    domain_spec: AdviceColumn,
    head_mark: AdviceColumn,
}

#[cfg(test)]
impl PoseidonTable {
    pub fn configure<F: FieldExt>(cs: &mut ConstraintSystem<F>) -> Self {
        let [hash, left, right, control, domain_spec, head_mark] =
            [0; 6].map(|_| AdviceColumn(cs.advice_column()));
        Self {
            left,
            right,
            hash,
            control,
            head_mark,
            domain_spec,
            q_enable: FixedColumn(cs.fixed_column()),
        }
    }

    pub fn load(&self, region: &mut Region<'_, Fr>, hash_traces: &[([Fr; 2], Fr, Fr)]) {
        for (offset, hash_trace) in hash_traces.iter().enumerate() {
            assert!(
                poseidon_hash(hash_trace.0[0], hash_trace.0[1]) == hash_trace.2,
                "{:?}",
                (hash_trace.0, hash_trace.1, hash_trace.2)
            );
            for (column, value) in [
                (self.left, hash_trace.0[0]),
                (self.right, hash_trace.0[1]),
                (self.hash, hash_trace.2),
                (self.control, Fr::zero()),
                (self.domain_spec, hash_trace.1),
                (self.head_mark, Fr::one()),
            ] {
                column.assign(region, offset, value);
            }
            self.q_enable.assign(region, offset, Fr::one());
        }
    }
}

#[cfg(test)]
impl PoseidonLookup for PoseidonTable {
    fn lookup_columns(&self) -> (FixedColumn, [AdviceColumn; 6]) {
        (
            self.q_enable,
            [
                self.hash,
                self.left,
                self.right,
                self.control,
                self.domain_spec,
                self.head_mark,
            ],
        )
    }
}
