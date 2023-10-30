use super::{AdviceColumn, ConstraintBuilder, Query};
use crate::gadgets::byte_representation::BytesLookup;
use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};

pub struct WordColumns {
    hi: AdviceColumn,
    lo: AdviceColumn,
}

impl WordColumns {
    pub fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
        bytes: &impl BytesLookup,
    ) -> Self {
        let [hi, lo] = cb.advice_columns(cs);

        cb.add_lookup(
            "hi is 16 bytes",
            [hi.current(), Query::from(15)],
            bytes.lookup(),
        );
        cb.add_lookup(
            "lo is 16 bytes",
            [lo.current(), Query::from(15)],
            bytes.lookup(),
        );

        Self { hi, lo }
    }

    pub fn hi(&self) -> AdviceColumn {
        self.hi
    }

    pub fn lo(&self) -> AdviceColumn {
        self.lo
    }
}
