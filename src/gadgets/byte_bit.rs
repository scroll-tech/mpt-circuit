use super::super::constraint_builder::{
    AdviceColumn, ConstraintBuilder, FixedColumn, IsZeroColumn, Query, SelectorColumn,
};
use ethers_core::types::U256;
use halo2_proofs::circuit::Region;
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use itertools::Itertools;
use num_traits::Zero;

#[derive(Clone)]
pub struct ByteBitGadget {
    byte: FixedColumn, // This lookup table can be used to show that byte[i] = bit in this gadget
    index: FixedColumn, // (0..8).repeat()
    bit: FixedColumn,  // we need to prove that bytes form the canonical representation of value.
}

pub trait RangeCheck8Lookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 1];
}

pub trait RangeCheck256Lookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 1];
}

pub trait ByteBitLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3];
}

impl ByteBitGadget {
    pub fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
    ) -> Self {
        let ([], [byte, index, bit], []) = cb.build_columns(cs);
        Self { byte, index, bit }
    }

    pub fn assign<F: FieldExt>(&self, region: &mut Region<'_, F>) {
        let mut offset = 0;
        for byte in 0..256 {
            for index in 0..8 {
                self.byte.assign(region, offset, byte);
                self.index.assign(region, offset, index);
                self.bit.assign(region, offset, byte & (1 << index) != 0);
                offset += 1
            }
        }
    }
}

impl RangeCheck8Lookup for ByteBitGadget {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 1] {
        [self.index.current()]
    }
}

impl RangeCheck256Lookup for ByteBitGadget {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 1] {
        [self.byte.current()]
    }
}

impl ByteBitLookup for ByteBitGadget {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3] {
        [
            self.byte.current(),
            self.index.current(),
            self.bit.current(),
        ]
    }
}

// impl Circuit<Fr> for ByteBitGadget {
//     type Config = CanonicalRepresentationConfig;
//     type FloorPlanner = SimpleFloorPlanner;

//     fn without_witnesses(&self) -> Self {
//         Self::default()
//     }

//     fn configure(cs: &mut ConstraintSystem<Fr>, &mut cb: ConstraintBuilder<F>) -> Self::Config {
//         let ([], [byte, index, bit], []) = cb.build_columns(cs);

//         Self::Config { byte, index, bit }
//     }

//     fn synthesize(
//         &self,
//         config: Self::Config,
//         mut layouter: impl Layouter<Fr>,
//     ) -> Result<(), Error> {
//         Ok(config.assign()(layouter))
//     }
// }

// #[cfg(test)]
// mod test {
//     use super::*;
//     use halo2_proofs::dev::MockProver;

//     #[test]
//     fn byte_bit() {
//         let circuit = CanonicalRepresentationCircuit {
//             values: vec![Fr::zero(), Fr::one(), Fr::from(256), Fr::zero() - Fr::one()],
//         };
//         let prover = MockProver::<Fr>::run(10, &circuit, vec![]).unwrap();
//         assert_eq!(prover.verify(), Ok(()));
//     }
// }
