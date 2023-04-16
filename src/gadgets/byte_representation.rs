use super::{byte_bit::RangeCheck256Lookup, is_zero::IsZeroGadget};
use crate::constraint_builder::{
    AdviceColumn, ConstraintBuilder, FixedColumn, Query, SelectorColumn,
};
use ethers_core::types::{Address, H256, U256};
use halo2_proofs::{arithmetic::FieldExt, circuit::Region, plonk::ConstraintSystem};

pub trait RlcLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 2];
}

pub trait BytesLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 2];
}

#[derive(Clone)]
pub struct ByteRepresentationConfig {
    randomness: FixedColumn, // TODO: this should be an instance column.

    // lookup columns
    value: AdviceColumn,
    rlc: AdviceColumn,
    index: AdviceColumn,

    // internal columns
    byte: AdviceColumn,
    index_is_zero: IsZeroGadget,
}

impl RlcLookup for ByteRepresentationConfig {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 2] {
        [self.value.current(), self.rlc.current()]
    }
}

impl BytesLookup for ByteRepresentationConfig {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 2] {
        [self.value.current(), self.index.current()]
    }
}

impl ByteRepresentationConfig {
    pub fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
        range_check: &impl RangeCheck256Lookup,
    ) -> Self {
        let ([], [randomness], [value, rlc, index, byte]) = cb.build_columns(cs);
        let index_is_zero = IsZeroGadget::configure(cs, cb, index);

        cb.assert_zero(
            "index increases by 1 or resets to 0",
            index.current() * (index.current() - index.previous() - 1),
        );
        cb.assert_equal(
            "current value = previous value * 8 * (index == 0) + byte",
            value.current(),
            value.previous() * 8 * !index_is_zero.current() + byte.current(),
        );
        cb.assert_equal(
            "current rlc = previous rlc * randomness * (index == 0) + byte",
            rlc.current(),
            rlc.previous() * randomness.current() * !index_is_zero.current() + byte.current(),
        );
        cb.add_lookup("0 <= byte < 256", [byte.current()], range_check.lookup());

        Self {
            randomness,
            value,
            rlc,
            index,
            index_is_zero,
            byte,
        }
    }

    pub fn assign<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        addresses: &[Address],
        hashes: &[H256],
        words: &[U256],
    ) {
        let randomness = F::from(123123u64); // TODOOOOOOO

        let byte_representations = addresses
            .iter()
            .map(address_to_big_endian)
            .chain(hashes.iter().map(h256_to_big_endian))
            .chain(words.iter().map(u256_to_big_endian));

        let mut offset = 0;
        for byte_representation in byte_representations {
            let mut value = F::zero();
            let mut rlc = F::zero();
            for (index, byte) in byte_representation.iter().enumerate() {
                let byte = F::from(u64::from(*byte));
                value = value * F::from(8) + byte;
                rlc = rlc * randomness + byte;

                self.randomness.assign(region, offset, randomness);
                self.value.assign(region, offset, value);
                self.rlc.assign(region, offset, rlc);
                self.byte.assign(region, offset, byte);

                let index = u64::try_from(index).unwrap();
                self.index.assign(region, offset, index);
                self.index_is_zero.assign(region, offset, index);

                offset += 1;
            }
        }
    }
}

fn address_to_big_endian(x: &Address) -> Vec<u8> {
    x.0.to_vec()
}

fn u256_to_big_endian(x: &U256) -> Vec<u8> {
    let mut bytes = [0; 32];
    x.to_big_endian(&mut bytes);
    bytes.to_vec()
}

fn h256_to_big_endian(x: &H256) -> Vec<u8> {
    x.0.to_vec()
}

#[cfg(test)]
mod test {
    use super::{super::byte_bit::ByteBitGadget, *};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, Error},
    };

    #[derive(Clone, Default, Debug)]
    struct TestCircuit {
        addresses: Vec<Address>,
        hashes: Vec<H256>,
        words: Vec<U256>,
    }

    impl Circuit<Fr> for TestCircuit {
        type Config = (ByteBitGadget, ByteRepresentationConfig);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(cs: &mut ConstraintSystem<Fr>) -> Self::Config {
            let selector = SelectorColumn(cs.fixed_column());
            let mut cb = ConstraintBuilder::new(selector);

            let byte_bit = ByteBitGadget::configure(cs, &mut cb);
            let byte_representation = ByteRepresentationConfig::configure(cs, &mut cb, &byte_bit);
            cb.build(cs);
            (byte_bit, byte_representation)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "asdfawefasdf",
                |mut region| {
                    config.0.assign(&mut region);
                    config
                        .1
                        .assign(&mut region, &self.addresses, &self.hashes, &self.words);
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn test_byte_representation() {
        let circuit = TestCircuit {
            addresses: vec![Address::repeat_byte(34)],
            hashes: vec![H256::repeat_byte(48)],
            words: vec![U256::zero(), U256::from(123412123)],
        };
        let prover = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // TODO test that intermediate values are in here....
    }
}
