use crate::constraint_builder::{AdviceColumn, FixedColumn};
use halo2_proofs::plonk::{Advice, Column, Fixed};
#[cfg(any(test, feature = "bench"))]
use halo2_proofs::{circuit::Region, halo2curves::bn256::Fr, plonk::ConstraintSystem};
#[cfg(any(test, feature = "bench"))]
use hash_circuit::hash::Hashable;

#[cfg(any(test, feature = "bench"))]
const MAX_POSEIDON_ROWS: usize = 200;

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

#[cfg(any(test, feature = "bench"))]
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

#[cfg(any(test, feature = "bench"))]
impl PoseidonTable {
    pub fn configure<F: halo2_proofs::halo2curves::ff::FromUniformBytes<64> + Ord>(
        cs: &mut ConstraintSystem<F>,
    ) -> Self {
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
        // The test poseidon table starts assigning from the first row, which has a disabled
        // selector, but this is fine because the poseidon_lookup in the ConstraintBuilder
        // doesn't include the mpt circuit's selector column.
        for (offset, hash_trace) in hash_traces.iter().enumerate() {
            assert!(
                Hashable::hash_with_domain([hash_trace.0[0], hash_trace.0[1]], hash_trace.1)
                    == hash_trace.2,
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

        // We need to do this so that the fixed columns in the tests will not depend on the
        // number of poseidon hashes that are looked up.
        for offset in hash_traces.len()..MAX_POSEIDON_ROWS {
            self.q_enable.assign(region, offset, Fr::one());
        }
    }
}

#[cfg(any(test, feature = "bench"))]
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
