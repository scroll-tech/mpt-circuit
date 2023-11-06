use super::{AdviceColumn, ConstraintBuilder, Query};
use crate::{gadgets::byte_representation::BytesLookup, util::u256_hi_lo};
use ethers_core::types::U256;
use halo2_proofs::circuit::Region;
use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};

#[derive(Clone, Copy)]
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

    pub fn current<F: FieldExt>(&self) -> [Query<F>; 2] {
        [self.hi.current(), self.lo.current()]
    }

    pub fn previous<F: FieldExt>(&self) -> [Query<F>; 2] {
        [self.hi.previous(), self.lo.previous()]
    }

    pub fn assign<F: FieldExt>(&self, region: &mut Region<'_, F>, offset: usize, value: U256) {
        let (hi, lo) = u256_hi_lo(&value);
        self.hi.assign(region, offset, F::from_u128(hi));
        self.lo.assign(region, offset, F::from_u128(lo));
    }
}
