use super::super::constraint_builder::{
    AdviceColumn, ConstraintBuilder, FixedColumn, IsZeroColumn, Query, SelectorColumn,
};
use ethers_core::types::U256;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use itertools::Itertools;
use num_traits::Zero;

#[derive(Clone, Default, Debug)]
struct CanonicalRepresentationCircuit {
    values: Vec<Fr>,
}

#[derive(Clone)]
struct CanonicalRepresentationConfig {
    selector: SelectorColumn, // always enabled selector for constraints we want always enabled.

    // Lookup columns
    value: AdviceColumn, // We're proving value.to_le_bytes()[i] = byte in this gadget
    index: FixedColumn,  // (0..32).repeat()
    byte: AdviceColumn,  // we need to prove that bytes form the canonical representation of value.

    // Witness columns
    index_is_zero: SelectorColumn, // (0..32).repeat().map(|i| i == 0)
    modulus_byte: FixedColumn,     // (0..32).repeat().map(|i| Fr::MODULUS.to_le_bytes()[i])
    difference: AdviceColumn,      // modulus_byte - byte
    difference_is_zero: IsZeroColumn,
    differences_are_zero_so_far: AdviceColumn, // difference[0] ... difference[index] are all 0.
}

impl Circuit<Fr> for CanonicalRepresentationCircuit {
    type Config = CanonicalRepresentationConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(cs: &mut ConstraintSystem<Fr>) -> Self::Config {
        let mut cb = ConstraintBuilder::new();

        let (
            [selector, index_is_zero],
            [index, modulus_byte],
            [value, byte, difference, differences_are_zero_so_far],
        ) = cb.build_columns(cs);

        cb.add_constraint(
            "differences_are_zero_so_far is binary",
            selector.current(),
            differences_are_zero_so_far.current()
                * (Query::one() - differences_are_zero_so_far.current()),
        );
        cb.add_constraint(
            "difference = modulus_byte - byte",
            selector.current(),
            difference.current() - (modulus_byte.current() - byte.current()),
        );
        cb.add_constraint(
            "bytes represent value",
            index_is_zero.current(),
            value.current()
                - (0..32)
                    .map(|i| byte.rotation(i))
                    .fold(Query::zero(), |acc, x| acc * 256 + x),
        );
        let difference_is_zero = cb.is_zero_gadget(cs, selector.current(), difference);
        // cb.add_constraint(
        //     "differences_are_zero_so_far = difference is 0 when index = 0",
        //     index_is_zero.current(),
        //     differences_are_zero_so_far.current() - difference_is_zero.current(), // x = 0 or x = 1
        // );
        // cb.add_constraint(
        //     "differences_are_zero_so_far = difference is 0 * differences_are_zero_so_far.previous() when index != 0",
        //     !index_is_zero.current(),
        //     differences_are_zero_so_far.current()
        //         - differences_are_zero_so_far.previous() * difference_is_zero.current()
        // );

        cb.build(cs);

        Self::Config {
            selector,
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

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let modulus = U256::from_str_radix(Fr::MODULUS, 16).unwrap();
        let mut modulus_bytes = [0u8; 32];
        modulus.to_big_endian(&mut modulus_bytes);

        layouter.assign_region(
            || "",
            |mut region| {
                let mut offset = 0;
                for value in &self.values {
                    let mut bytes = value.to_bytes();
                    bytes.reverse();
                    for (index, (byte, modulus_byte)) in
                        bytes.iter().zip_eq(&modulus_bytes).enumerate()
                    {
                        config.selector.enable(&mut region, offset);
                        config.byte.assign(&mut region, offset, u64::from(*byte));
                        config
                            .modulus_byte
                            .assign(&mut region, offset, u64::from(*modulus_byte));

                        config
                            .index
                            .assign(&mut region, offset, u64::try_from(index).unwrap());

                        let difference =
                            Fr::from(u64::from(*modulus_byte)) - Fr::from(u64::from(*byte));
                        dbg!(difference);
                        config.difference.assign(&mut region, offset, difference);
                        config
                            .difference_is_zero
                            .assign(&mut region, offset, difference);

                        if index.is_zero() {
                            config.index_is_zero.enable(&mut region, offset);
                            config.differences_are_zero_so_far.assign(
                                &mut region,
                                offset,
                                Fr::zero(),
                            );
                        } else {
                            config.differences_are_zero_so_far.assign(
                                &mut region,
                                offset,
                                difference == Fr::zero(),
                            );
                        }
                        config.value.assign(&mut region, offset, *value);

                        offset += 1
                    }
                }
                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use halo2_proofs::dev::MockProver;

    #[test]
    fn masonnnnnnn() {
        let circuit = CanonicalRepresentationCircuit {
            values: vec![
                Fr::one(),
                // Fr::from(2342),
                // Fr::zero() - Fr::one()
            ],
        };
        let prover = MockProver::<Fr>::run(8, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
