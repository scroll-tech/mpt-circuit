use super::{
    byte_bit::{ByteBitLookup, RangeCheck256Lookup, RangeCheck8Lookup},
    canonical_representation::CanonicalRepresentationLookup,
};
use crate::{
    assignment_map::Column,
    constraint_builder::{AdviceColumn, ConstraintBuilder, Query, SelectorColumn},
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    halo2curves::bn256::Fr,
    plonk::ConstraintSystem,
};
use rayon::prelude::*;

pub trait KeyBitLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3];
}

#[derive(Clone)]
pub struct KeyBitConfig {
    selector: SelectorColumn, // always enabled selector for constraints we want always enabled.

    // Lookup columns
    value: AdviceColumn, // We're proving value.bit(i) = bit in this gadget
    index: AdviceColumn, // 0 <= index < 256
    bit: AdviceColumn,

    // Witness columns
    index_div_8: AdviceColumn, // constrained to be between 0 and 255. (actually will be between 0 and 31)
    index_mod_8: AdviceColumn, // between 0 and 7
    byte: AdviceColumn,        // value.to_be_bytes[index_div_8]
}

impl KeyBitConfig {
    pub fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
        representation: &impl CanonicalRepresentationLookup,
        range_check_8: &impl RangeCheck8Lookup,
        range_check_256: &impl RangeCheck256Lookup,
        byte_bit: &impl ByteBitLookup,
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
        // TODO: standardize endianess to remove this 31 here?
        cb.add_lookup(
            "byte in canonical representation",
            [
                value.current(),
                Query::from(31) - index_div_8.current(),
                byte.current(),
            ],
            representation.lookup(),
        );
        cb.add_lookup(
            "bit is correct",
            [byte.current(), index_mod_8.current(), bit.current()],
            byte_bit.lookup(),
        );
        cb.assert_equal(
            "index = index_div_8 * 8 + index_mod_8",
            index.current(),
            index_div_8.current() * 8 + index_mod_8.current(),
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

    pub fn assign(&self, region: &mut Region<'_, Fr>, lookups: Vec<(Fr, usize, bool)>) {
        let assignments: Vec<_> = self.assignments(lookups).collect();
        for ((column, offset), value) in assignments.into_iter() {
            match column {
                Column::Advice(s) => region
                    .assign_advice(|| "advice", s.0, offset, || value)
                    .unwrap(),
                _ => unreachable!(),
            };
        }
    }

    pub fn assignments(
        &self,
        lookups: Vec<(Fr, usize, bool)>,
    ) -> impl ParallelIterator<Item = ((Column, usize), Value<Fr>)> + '_ {
        lookups
            .into_par_iter()
            .enumerate()
            .flat_map_iter(|(i, (value, index, bit))| {
                let offset = i + 1;
                let index_div_8 = index / 8;
                let index_mod_8 = index % 8;
                let byte = value.to_bytes()[index_div_8];
                [
                    self.value.assignment::<Fr, _>(offset, value),
                    self.index.assignment(offset, u64::try_from(index).unwrap()),
                    self.bit.assignment(offset, bit),
                    self.index_div_8
                        .assignment(offset, u64::try_from(index_div_8).unwrap()),
                    self.index_mod_8
                        .assignment(offset, u64::try_from(index_mod_8).unwrap()),
                    self.byte.assignment(offset, u64::from(byte)),
                ]
                .into_iter()
            })
    }

    pub fn n_rows_required(lookups: &[(Fr, usize, bool)]) -> usize {
        // +1 because assigment starts on offset = 1 instead of offset = 0.
        1 + lookups.len()
    }
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

#[cfg(test)]
mod test {
    use super::super::{
        byte_bit::ByteBitGadget, canonical_representation::CanonicalRepresentationConfig,
        rlc_randomness::RlcRandomness,
    };
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Circuit, Error},
    };

    #[derive(Clone, Default, Debug)]
    struct TestCircuit {
        lookups: Vec<(Fr, usize, bool)>,
    }

    impl Circuit<Fr> for TestCircuit {
        type Config = (
            SelectorColumn,
            KeyBitConfig,
            ByteBitGadget,
            CanonicalRepresentationConfig,
            RlcRandomness,
        );
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(cs: &mut ConstraintSystem<Fr>) -> Self::Config {
            let selector = SelectorColumn(cs.fixed_column());
            let mut cb = ConstraintBuilder::new(selector);

            let byte_bit = ByteBitGadget::configure(cs, &mut cb);
            let randomness = RlcRandomness::configure(cs);
            let canonical_representation =
                CanonicalRepresentationConfig::configure(cs, &mut cb, &byte_bit, &randomness);
            let key_bit = KeyBitConfig::configure(
                cs,
                &mut cb,
                &canonical_representation,
                &byte_bit,
                &byte_bit,
                &byte_bit,
            );
            cb.build(cs);
            (
                selector,
                key_bit,
                byte_bit,
                canonical_representation,
                randomness,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let keys: Vec<_> = self.lookups.iter().map(|lookup| lookup.0).collect();

            let (selector, key_bit, byte_bit, canonical_representation, rlc_randomness) = config;
            let randomness = rlc_randomness.value(&layouter);

            layouter.assign_region(
                || "",
                |mut region| {
                    for offset in 1..(1 + 8 * 256) {
                        selector.enable(&mut region, offset);
                    }

                    key_bit.assign(&mut region, self.lookups.clone());
                    byte_bit.assign(&mut region);
                    canonical_representation.assign(&mut region, randomness, keys.clone(), 256);
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn test_key_bit() {
        let circuit = TestCircuit {
            lookups: vec![
                (Fr::one(), 0, true),
                (Fr::one(), 1, false),
                (Fr::from(2342341), 10, true),
                (Fr::from(2342341), 255, false),
            ],
        };
        let prover = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
