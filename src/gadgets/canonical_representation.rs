use super::super::constraint_builder::{
    AdviceColumn, BinaryColumn, ConstraintBuilder, FixedColumn, Query, SelectorColumn,
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

pub trait CanonicalRepresentationLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3];
}

#[derive(Clone)]
pub struct CanonicalRepresentationConfig {
    // Lookup columns
    value: AdviceColumn, // We're proving value.to_le_bytes()[i] = byte in this gadget
    index: FixedColumn,  // (0..32).repeat()
    byte: AdviceColumn,  // we need to prove that bytes form the canonical representation of value.

    // Witness columns
    index_is_zero: SelectorColumn, // (0..32).repeat().map(|i| i == 0)
    modulus_byte: FixedColumn,     // (0..32).repeat().map(|i| Fr::MODULUS.to_le_bytes()[i])
    difference: AdviceColumn,      // modulus_byte - byte
    difference_is_zero: IsZeroGadget,
    differences_are_zero_so_far: BinaryColumn, // difference[0] ... difference[index - 1] are all 0.
}

impl CanonicalRepresentationConfig {
    pub fn configure(
        cs: &mut ConstraintSystem<Fr>,
        cb: &mut ConstraintBuilder<Fr>,
        range_check: &impl RangeCheck256Lookup,
    ) -> Self {
        let ([index_is_zero], [index, modulus_byte], [value, byte, difference]) =
            cb.build_columns(cs);

        let [differences_are_zero_so_far] = cb.binary_columns(cs);
        let difference_is_zero = IsZeroGadget::configure(cs, cb, difference);

        cb.assert_equal(
            "difference = modulus_byte - byte",
            difference.current(),
            modulus_byte.current() - byte.current(),
        );
        // TODO: just add an accumlator column?
        cb.condition(index_is_zero.current(), |cb| {
            cb.assert_equal(
                "every group of 32 bytes represent value",
                value.current(),
                (0..32)
                    .map(|i| byte.rotation(i))
                    .fold(Query::zero(), |acc, x| acc * 256 + x),
            );
            cb.assert(
                "differences_are_zero_so_far = 1 when index = 0",
                differences_are_zero_so_far.current(),
            );
        });
        cb.condition(!index_is_zero.current(), |cb| {
            cb.assert_equal(
                "value only changes when index = 0",
                value.current(),
                value.previous(),
            );
            cb.assert_equal(
            "differences_are_zero_so_far = difference == 0 && differences_are_zero_so_far.previous() when index != 0",
            differences_are_zero_so_far.current().into(),
            differences_are_zero_so_far.previous().and( difference_is_zero.previous()).into()
        );
        });

        cb.add_lookup("0 <= byte < 256", [byte.current()], range_check.lookup());

        cb.condition(differences_are_zero_so_far.current()
                .and( !difference_is_zero.current()), |cb| {cb.add_lookup(
            "if differences are 0 so far, either current difference is 0, or it is the first and 1 <= difference < 257",
            // We already know that difference < 256 because difference = modulus_byte - byte which are both 8 bit.
            // There do not exist two 8 bit numbers whose difference is 256 in Fr.
            [difference.current() - 1], // TODO: can remove -1 here because difference is non-zero anyways?
            range_check.lookup(),
        );});
        // TODO: need a constraut that !difference_is_zero.current() for when index = 31?

        Self {
            value,
            index,
            byte,
            index_is_zero,
            modulus_byte,
            difference,
            difference_is_zero,
            differences_are_zero_so_far,
        }
    }

    pub fn assign(&self, region: &mut Region<'_, Fr>, values: &[Fr]) {
        let modulus = U256::from_str_radix(Fr::MODULUS, 16).unwrap();
        let mut modulus_bytes = [0u8; 32];
        modulus.to_big_endian(&mut modulus_bytes);

        let mut offset = 0;
        for value in values {
            let mut bytes = value.to_bytes();
            bytes.reverse();
            let mut differences_are_zero_so_far = true;
            for (index, (byte, modulus_byte)) in bytes.iter().zip_eq(&modulus_bytes).enumerate() {
                self.byte.assign(region, offset, u64::from(*byte));
                self.modulus_byte
                    .assign(region, offset, u64::from(*modulus_byte));

                self.index
                    .assign(region, offset, u64::try_from(index).unwrap());
                if index.is_zero() {
                    self.index_is_zero.enable(region, offset);
                }

                let difference = Fr::from(u64::from(*modulus_byte)) - Fr::from(u64::from(*byte));
                self.difference.assign(region, offset, difference);
                self.difference_is_zero.assign(region, offset, difference);

                self.differences_are_zero_so_far.assign(
                    region,
                    offset,
                    differences_are_zero_so_far,
                );
                differences_are_zero_so_far &= difference.is_zero_vartime();

                self.value.assign(region, offset, *value);

                offset += 1
            }
        }
    }
}

impl CanonicalRepresentationLookup for CanonicalRepresentationConfig {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3] {
        [
            self.value.current(),
            self.index.current(),
            self.byte.current(),
        ]
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
                || "asfwf121asfasd",
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
