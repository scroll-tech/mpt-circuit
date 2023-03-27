use super::byte_bit::{ByteBitLookup, RangeCheck256Lookup, RangeCheck8Lookup};
use super::canonical_representation::CanonicalRepresentationLookup;
use crate::constraint_builder::ConstraintBuilder;
use crate::constraint_builder::{AdviceColumn, Query, SelectorColumn};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::ConstraintSystem;

pub trait KeyBitLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3];
}

#[derive(Clone)]
struct KeyBitConfig {
    selector: SelectorColumn, // always enabled selector for constraints we want always enabled.

    // Lookup columns
    value: AdviceColumn, // We're proving value.bit(i) = bit in this gadget
    index: AdviceColumn, // 0 <= index <256
    bit: AdviceColumn,

    // Witness columns
    index_div_8: AdviceColumn, // constrained to be between 0 and 255. (actually will be between 0 and 31)
    index_mod_8: AdviceColumn, // between 0 and 7
    byte: AdviceColumn,        // value.to_be_bytes[index_div_8]
}

impl KeyBitConfig {
    fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
        representation: impl CanonicalRepresentationLookup,
        range_check_8: impl RangeCheck8Lookup,
        range_check_256: impl RangeCheck256Lookup,
        byte_bit: impl ByteBitLookup,
    ) -> Self {
        let ([selector], [], [value, index, bit, index_div_8, index_mod_8, byte]) =
            cb.build_columns(cs);

        cb.add_lookup(
            "0 <= index < 256",
            [index.current()],
            range_check_256.lookup(),
        );
        cb.add_lookup(
            "0 <= index_div_8 < 256",
            // Note that if index_div_8 < 256, then it must actually be less than 32 because of the other range checks.
            [index_div_8.current()],
            range_check_256.lookup(),
        );
        cb.add_lookup(
            "0 <= index_mod_8 < 8",
            [index_mod_8.current()],
            range_check_8.lookup(),
        );
        cb.add_lookup(
            "byte is correct",
            [value.current(), index_div_8.current(), byte.current()],
            representation.lookup(),
        );
        cb.add_lookup(
            "bit is correct",
            [byte.current(), index_mod_8.current(), bit.current()],
            byte_bit.lookup(),
        );
        cb.add_constraint(
            "index = index_div_8 * 8 + index_mod_8",
            selector.current(),
            index.current() - index_div_8.current() * 8 + index_mod_8.current(),
        );

        Self {
            selector,
            value,
            index,
            bit,
            index_div_8,
            index_mod_8,
            byte,
        }
    }

    // fn synthesize(
    //     &self,
    //     config: Self::Config,
    //     mut layouter: impl Layouter<Fr>,
    // ) -> Result<(), Error> {
    //     layouter.assign_region(
    //         || "",
    //         // |mut region| {
    //         //     for offset in 0..256 {
    //         //         config
    //         //             .byte_lookup
    //         //             .assign(&mut region, offset, u64::try_from(offset).unwrap());
    //         //     }
    //         //     let mut offset = 0;
    //         //     for value in &self.values {
    //         //         let mut bytes = value.to_bytes();
    //         //         bytes.reverse();
    //         //         let mut differences_are_zero_so_far = true;
    //         //         for (index, (byte, modulus_byte)) in
    //         //             bytes.iter().zip_eq(&modulus_bytes).enumerate()
    //         //         {
    //         //             config.selector.enable(&mut region, offset);
    //         //             config.byte.assign(&mut region, offset, u64::from(*byte));
    //         //             config
    //         //                 .modulus_byte
    //         //                 .assign(&mut region, offset, u64::from(*modulus_byte));

    //         //             config
    //         //                 .index
    //         //                 .assign(&mut region, offset, u64::try_from(index).unwrap());
    //         //             if index.is_zero() {
    //         //                 config.index_is_zero.enable(&mut region, offset);
    //         //             }

    //         //             let difference =
    //         //                 Fr::from(u64::from(*modulus_byte)) - Fr::from(u64::from(*byte));
    //         //             config.difference.assign(&mut region, offset, difference);
    //         //             config
    //         //                 .difference_is_zero
    //         //                 .assign(&mut region, offset, difference);

    //         //             config.differences_are_zero_so_far.assign(
    //         //                 &mut region,
    //         //                 offset,
    //         //                 differences_are_zero_so_far,
    //         //             );
    //         //             differences_are_zero_so_far &= difference.is_zero_vartime();

    //         //             config.value.assign(&mut region, offset, *value);

    //         //             offset += 1
    //         //         }
    //         //     }
    //         //     Ok(())
    //         // },
    //     )
    // }
}

impl KeyBitLookup for KeyBitConfig {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3] {
        [
            self.value.current(),
            self.index.current(),
            self.bit.current(),
        ]
    }
}
