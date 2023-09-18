use super::{byte_bit::RangeCheck256Lookup, is_zero::IsZeroGadget, rlc_randomness::RlcRandomness};
use crate::constraint_builder::{
    AdviceColumn, ConstraintBuilder, Query, SecondPhaseAdviceColumn, SelectorColumn,
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    halo2curves::bn256::Fr,
    plonk::ConstraintSystem,
};

pub trait RlcLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3];
}

pub trait BytesLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 2];
}

// Right the byte order is big endian, which means that e.g. proving that 0x01 fits into 3
// bytes doesn't prove that it fits into 2 or 1 bytes. If we switch to little endian, we
// could get the intermediate values for free.
#[derive(Clone)]
pub struct ByteRepresentationConfig {
    // lookup columns
    value: AdviceColumn,
    rlc: SecondPhaseAdviceColumn,
    index: AdviceColumn,

    // internal columns
    is_first: SelectorColumn,
    byte: AdviceColumn,
    index_is_zero: IsZeroGadget,
}

// WARNING: it is a soundness issue if the index lookup is >= 31 (i.e. the value can
// overflow in the field if it has 32 or more bytes).
impl RlcLookup for ByteRepresentationConfig {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3] {
        [
            self.value.current(),
            self.index.current(),
            self.rlc.current(),
        ]
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
        randomness: &RlcRandomness,
    ) -> Self {
        let is_first = SelectorColumn(cs.fixed_column());
        let [value, index, byte] = cb.advice_columns(cs);
        let [rlc] = cb.second_phase_advice_columns(cs);
        let index_is_zero = IsZeroGadget::configure(cs, cb, index);

        cb.condition(is_first.current(), |cb| {
            cb.assert_zero("index is 0 for first row", index.current())
        });
        cb.assert_zero(
            "index is 0 or increases by 1",
            index.current() * (index.current() - index.previous() - 1),
        );
        cb.assert_equal(
            "current value = previous value * 256 * (index != 0) + byte",
            value.current(),
            value.previous() * 256 * !index_is_zero.current() + byte.current(),
        );
        cb.assert_equal(
            "current rlc = previous rlc * randomness * (index != 0) + byte",
            rlc.current(),
            rlc.previous() * randomness.query() * !index_is_zero.current() + byte.current(),
        );
        cb.add_lookup("0 <= byte < 256", [byte.current()], range_check.lookup());

        Self {
            value,
            rlc,
            index,
            index_is_zero,
            byte,
            is_first,
        }
    }

    // can this we done with an Iterator<Item: impl ToBigEndianBytes> instead?
    pub fn assign<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        u32s: &[u32],
        u64s: &[u64],
        u128s: &[u128],
        frs: &[Fr],
        randomness: Value<F>,
    ) {
        self.is_first.enable(region, 0);
        let byte_representations = u32s
            .iter()
            .map(u32_to_big_endian)
            .chain(u64s.iter().map(u64_to_big_endian))
            .chain(u128s.iter().map(u128_to_big_endian))
            .chain(frs.iter().map(fr_to_big_endian));

        let mut offset = 0;
        for byte_representation in byte_representations {
            let mut value = F::zero();
            let mut rlc = Value::known(F::zero());
            for (index, byte) in byte_representation.iter().enumerate() {
                let byte = F::from(u64::from(*byte));
                self.byte.assign(region, offset, byte);

                value = value * F::from(256) + byte;
                self.value.assign(region, offset, value);

                rlc = rlc * randomness + Value::known(byte);
                self.rlc.assign(region, offset, rlc);

                let index = u64::try_from(index).unwrap();
                self.index.assign(region, offset, index);
                self.index_is_zero.assign(region, offset, index);

                offset += 1;
            }
        }
    }
}

fn u32_to_big_endian(x: &u32) -> Vec<u8> {
    x.to_be_bytes().to_vec()
}
fn u64_to_big_endian(x: &u64) -> Vec<u8> {
    x.to_be_bytes().to_vec()
}

fn u128_to_big_endian(x: &u128) -> Vec<u8> {
    x.to_be_bytes().to_vec()
}

fn fr_to_big_endian(x: &Fr) -> Vec<u8> {
    let mut bytes = x.to_bytes();
    bytes.reverse();
    // We only the 31 least significant bytes of x so that the value column will not overflow.
    assert_eq!(bytes[0], 0);
    if bytes[0] != 0 {
        log::error!("Fr {:?} does not fit into 31 bytes", x);
    }
    bytes[1..].to_vec()
}

#[cfg(test)]
mod test {
    use super::{super::byte_bit::ByteBitGadget, *};
    use crate::constraint_builder::SelectorColumn;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::{Circuit, Error},
    };

    #[derive(Clone, Default, Debug)]
    struct TestCircuit {
        u32s: Vec<u32>,
        u64s: Vec<u64>,
        u128s: Vec<u128>,
        frs: Vec<Fr>,
    }

    impl Circuit<Fr> for TestCircuit {
        type Config = (
            SelectorColumn,
            ByteBitGadget,
            ByteRepresentationConfig,
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
            let byte_representation =
                ByteRepresentationConfig::configure(cs, &mut cb, &byte_bit, &randomness);
            cb.build(cs);
            (selector, byte_bit, byte_representation, randomness)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let (selector, byte_bit, byte_representation, rlc_randomness) = config;
            let randomness = rlc_randomness.value(&layouter);
            layouter.assign_region(
                || "",
                |mut region| {
                    for offset in 0..1024 {
                        selector.enable(&mut region, offset);
                    }
                    byte_bit.assign(&mut region);
                    byte_representation.assign(
                        &mut region,
                        &self.u32s,
                        &self.u64s,
                        &self.u128s,
                        &self.frs,
                        randomness,
                    );
                    Ok(())
                },
            )
        }
    }

    #[test]
    fn test_byte_representation() {
        let circuit = TestCircuit {
            u32s: vec![0, 1, u32::MAX],
            u64s: vec![u64::MAX],
            u128s: vec![0, 1, u128::MAX],
            frs: vec![Fr::from(2342)],
        };
        let prover = MockProver::<Fr>::run(14, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_helpers() {
        let mut x = vec![0; 8];
        x[7] = 1;
        assert_eq!(u64_to_big_endian(&1), x);

        let mut y = vec![0; 16];
        y[15] = 1;
        assert_eq!(u128_to_big_endian(&1), y);

        let mut z = vec![0; 31];
        z[30] = 1;
        assert_eq!(fr_to_big_endian(&Fr::one()), z);
    }
}
