use super::super::constraint_builder::{
    AdviceColumn, ConstraintBuilder, FixedColumn, Query, SelectorColumn,
};
use super::{byte_bit::RangeCheck256Lookup, is_zero::IsZeroGadget};
use ethers_core::types::U256;
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::Region,
    halo2curves::bn256::Fr,
    plonk::ConstraintSystem,
};
use itertools::Itertools;
use num_traits::Zero;

pub trait RlcLookup {

}

pub trait BytesLookup {

}

#[derive(Clone)]
struct ByteRepresentationConfig {
    selector: SelectorColumn, // always enabled selector for constraints we want always enabled.

    randomness: FixedColumn, // TODO: this should be an instance column.

    // lookup columns
    value: AdviceColumn,
    rlc: AdviceColumn,
    index: AdviceColumn,

    // internal columns
    byte: AdviceColumn,
    index_is_zero: IsZeroGadget,
}

impl ByteRepresentationConfig {
    fn configure(
        cs: &mut ConstraintSystem<Fr>,
        cb: &mut ConstraintBuilder<Fr>,
        range_check: &impl RangeCheck256Lookup,
    ) -> Self {
        let ([selector], [randomness], [value, rlc, index, byte]) = cb.build_columns(cs);
        let index_is_zero = IsZeroGadget::configure(cs, cb, selector.current(), index);

        cb.add_constraint(
            "index increases by 1 or resets to 0",
            selector.current(),
            value.current() * (value.current() - value.previous() - 1),
        );
        cb.add_constraint(
            "current value = previous value * 8 * (index == 0) + byte",
            selector.current(),
            value.current() - (value.previous() * 8 * !index_is_zero.current() + byte.current()),
        );
        cb.add_constraint(
            "current rlc = previous rlc * randomness * (index == 0) + byte",
            selector.current(),
            rlc.current()
                - (rlc.previous() * randomness.current() * !index_is_zero.current()
                    + byte.current()),
        );
        cb.add_lookup("0 <= byte < 256", [byte.current()], range_check.lookup());

        Self {
            selector,
            randomness,
            value,
            rlc,
            index,
            index_is_zero,
            byte,
        }
    }

    fn assign(&self, region: &mut Region<'_, Fr>, values: &[Fr]) {
        // let modulus = U256::from_str_radix(Fr::MODULUS, 16).unwrap();
        // let mut modulus_bytes = [0u8; 32];
        // modulus.to_big_endian(&mut modulus_bytes);

        // let mut offset = 0;
        // for value in values {
        //     let mut bytes = value.to_bytes();
        //     bytes.reverse();
        //     let mut differences_are_zero_so_far = true;
        //     for (index, (byte, modulus_byte)) in bytes.iter().zip_eq(&modulus_bytes).enumerate() {
        //         self.selector.enable(region, offset);
        //         self.byte.assign(region, offset, u64::from(*byte));
        //         self.modulus_byte
        //             .assign(region, offset, u64::from(*modulus_byte));

        //         self.index
        //             .assign(region, offset, u64::try_from(index).unwrap());
        //         if index.is_zero() {
        //             self.index_is_zero.enable(region, offset);
        //         }

        //         let difference = Fr::from(u64::from(*modulus_byte)) - Fr::from(u64::from(*byte));
        //         self.difference.assign(region, offset, difference);
        //         self.difference_is_zero.assign(region, offset, difference);

        //         self.differences_are_zero_so_far.assign(
        //             region,
        //             offset,
        //             differences_are_zero_so_far,
        //         );
        //         differences_are_zero_so_far &= difference.is_zero_vartime();

        //         self.value.assign(region, offset, *value);

        //         offset += 1
        //     }
        // }
    }
}

#[cfg(test)]
mod test {
    use super::{super::byte_bit::ByteBitGadget, *};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Circuit, Error},
    };

    #[derive(Clone, Default, Debug)]
    struct TestCircuit {
        values: Vec<Fr>,
    }

    impl Circuit<Fr> for TestCircuit {
        type Config = (ByteBitGadget, CanonicalRepresentationConfig);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(cs: &mut ConstraintSystem<Fr>) -> Self::Config {
            let mut cb = ConstraintBuilder::new();
            let byte_bit = ByteBitGadget::configure(cs, &mut cb);
            let canonical_representation =
                CanonicalRepresentationConfig::configure(cs, &mut cb, &byte_bit);
            cb.build(cs);
            (byte_bit, canonical_representation)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "",
                |mut region| {
                    config.0.assign(&mut region);
                    config.1.assign(&mut region, &self.values);
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn test_canonical_representation() {
        let circuit = TestCircuit {
            values: vec![Fr::zero(), Fr::one(), Fr::from(256), Fr::zero() - Fr::one()],
        };
        let prover = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
