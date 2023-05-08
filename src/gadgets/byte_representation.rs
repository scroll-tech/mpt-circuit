use super::{byte_bit::RangeCheck256Lookup, is_zero::IsZeroGadget};
use crate::constraint_builder::{
    AdviceColumn, ConstraintBuilder, FixedColumn, Query, SelectorColumn,
};
use crate::util::u256_to_big_endian;
use ethers_core::types::{Address, H256, U256};
use halo2_proofs::{
    arithmetic::FieldExt, circuit::Region, halo2curves::bn256::Fr, plonk::ConstraintSystem,
};

pub trait RlcLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 2];
}

pub trait BytesLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 2];
}

// Right the byte order is big endian, which means that e.g. proving that 0x01 fits into 3
// bytes doesn't prove that it fits into 2 or 1 bytes. If we switch to little endian, we
// could get the intermediate values for free.
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
            "current value = previous value * 256 * (index == 0) + byte",
            value.current(),
            value.previous() * 256 * !index_is_zero.current() + byte.current(),
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

    // can this we done with an Iterator<Item: impl ToBigEndianBytes> instead?
    pub fn assign<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        u64s: &[u64],
        u128s: &[u128],
        frs: &[Fr],
    ) {
        let randomness = F::from(0xaa00); // TODOOOOOOO

        let byte_representations = u64s
            .iter()
            .map(u64_to_big_endian)
            .chain(u128s.iter().map(u128_to_big_endian))
            .chain(frs.iter().map(fr_to_big_endian));

        let mut offset = 0;
        for byte_representation in byte_representations {
            let mut value = F::zero();
            let mut rlc = F::zero();
            for (index, byte) in byte_representation.iter().enumerate() {
                let byte = F::from(u64::from(*byte));
                value = value * F::from(256) + byte;
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

fn u64_to_big_endian(x: &u64) -> Vec<u8> {
    x.to_be_bytes().to_vec()
}

fn u128_to_big_endian(x: &u128) -> Vec<u8> {
    x.to_be_bytes().to_vec()
}

fn address_to_big_endian(x: &Address) -> Vec<u8> {
    x.0.to_vec()
}

fn h256_to_big_endian(x: &H256) -> Vec<u8> {
    x.0.to_vec()
}

fn fr_to_big_endian(x: &Fr) -> Vec<u8> {
    let mut bytes = x.to_bytes();
    bytes.reverse();
    bytes.to_vec()
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
        u64s: Vec<u64>,
        u128s: Vec<u128>,
        frs: Vec<Fr>,
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
                        .assign(&mut region, &self.u64s, &self.u128s, &self.frs);
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn test_byte_representation() {
        let circuit = TestCircuit {
            u64s: vec![u64::MAX],
            u128s: vec![0, 1, u128::MAX],
            frs: vec![Fr::zero() - Fr::one()],
        };
        let prover = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));

        // TODO test that intermediate values are in here....
    }

    #[test]
    fn test_helpers() {
        let mut x = vec![0; 8];
        x[7] = 1;
        assert_eq!(u64_to_big_endian(&1), x);

        let mut y = vec![0; 16];
        y[15] = 1;
        assert_eq!(u128_to_big_endian(&1), y);

        let mut z = vec![0; 32];
        z[31] = 1;
        assert_eq!(fr_to_big_endian(&Fr::one()), z);
    }
}
