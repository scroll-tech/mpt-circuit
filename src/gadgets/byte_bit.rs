use super::super::constraint_builder::{ConstraintBuilder, FixedColumn, Query};
use halo2_proofs::{circuit::Region, halo2curves::ff::FromUniformBytes, plonk::ConstraintSystem};

// TODO: fix name to configggggggg
#[derive(Clone)]
pub struct ByteBitGadget {
    byte: FixedColumn,
    index: FixedColumn,
    bit: FixedColumn,
}

pub trait RangeCheck8Lookup {
    fn lookup<F: FromUniformBytes<64> + Ord>(&self) -> [Query<F>; 1];
}

pub trait RangeCheck256Lookup {
    fn lookup<F: FromUniformBytes<64> + Ord>(&self) -> [Query<F>; 1];
}

pub trait ByteBitLookup {
    fn lookup<F: FromUniformBytes<64> + Ord>(&self) -> [Query<F>; 3];
}

impl ByteBitGadget {
    pub fn configure<F: FromUniformBytes<64> + Ord>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
    ) -> Self {
        let ([], [byte, index, bit], []) = cb.build_columns(cs);
        Self { byte, index, bit }
    }

    pub fn assign<F: FromUniformBytes<64> + Ord>(&self, region: &mut Region<'_, F>) {
        let mut offset = 1;
        for byte in 0..256 {
            for index in 0..8 {
                self.byte.assign(region, offset, byte);
                self.index.assign(region, offset, index);
                self.bit
                    .assign(region, offset, (byte & (1 << index) != 0) as u64);
                offset += 1;
            }
        }

        let expected_offset = Self::n_rows_required();
        debug_assert!(
            offset == expected_offset,
            "assign used {offset} rows but {expected_offset} rows expected from `n_rows_required`",
        );
    }

    pub fn n_rows_required() -> usize {
        // +1 because assigment starts on offset = 1 instead of offset = 0.
        256 * 8 + 1
    }
}

impl RangeCheck8Lookup for ByteBitGadget {
    fn lookup<F: FromUniformBytes<64> + Ord>(&self) -> [Query<F>; 1] {
        [self.index.current()]
    }
}

impl RangeCheck256Lookup for ByteBitGadget {
    fn lookup<F: FromUniformBytes<64> + Ord>(&self) -> [Query<F>; 1] {
        [self.byte.current()]
    }
}

impl ByteBitLookup for ByteBitGadget {
    fn lookup<F: FromUniformBytes<64> + Ord>(&self) -> [Query<F>; 3] {
        [
            self.byte.current(),
            self.index.current(),
            self.bit.current(),
        ]
    }
}
