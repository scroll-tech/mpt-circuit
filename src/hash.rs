//! The hash circuit base on poseidon.


use crate::poseidon::primitives::{ConstantLengthIden3, Hash, Spec, P128Pow5T3};
use halo2_proofs::{arithmetic::FieldExt, circuit::Chip};
use halo2_proofs::pairing::bn256::Fr;
use std::convert::TryFrom;

trait PoseidonChip<Fp: FieldExt> : Chip<Fp> {
    fn construct(config: &Self::Config) -> Self;
}

/// indicate an field can be hashed in merkle tree (2 Fields to 1 Field)
pub trait Hashable: FieldExt {
    /// the spec type used in circuit for this hashable field
    type SpecType : Spec<Self, 3, 2>;
    /// execute hash for any sequence of fields
    fn hash(inp: [Self; 2]) -> Self;
}

type Poseidon = Hash<Fr, P128Pow5T3<Fr>, ConstantLengthIden3<2>, 3, 2>;

impl Hashable for Fr {
    type SpecType = P128Pow5T3<Self>;
    fn hash(inp: [Self; 2]) -> Self {
        Poseidon::init().hash(inp)
    }
}

use crate::poseidon::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord, Var};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed},
};

/// The config for hash circuit
#[derive(Clone, Debug)]
pub struct HashConfig<Fp: FieldExt> {
    permute_config: Pow5Config<Fp, 3, 2>,
    hash_table: [Column<Advice>; 3],
    constants: [Column<Fixed>; 6],
}

/// Hash circuit
pub struct HashCircuit<Fp, const CALCS: usize> {
    /// the input messages for hashes
    pub inputs: [Option<[Fp; 2]>; CALCS],
    /// the expected hash output for checking
    pub checks: [Option<Fp>; CALCS],
}

impl<'d, Fp: Copy, const CALCS: usize> TryFrom<&[&'d(Fp, Fp, Fp)]> for HashCircuit<Fp, CALCS> {

    type Error = std::array::TryFromSliceError;
    fn try_from(src: &[&'d(Fp, Fp, Fp)]) -> Result<Self, Self::Error> {

        let inputs : Vec<Option<[Fp;2]>> = (0..CALCS).map(|i|{
            if i < src.len() {
                let (a, b, _) = src[i];
                Some([*a, *b])
            } else {
                None
            }
        }).collect();

        let checks : Vec<Option<Fp>> = (0..CALCS).map(|i|{
            if i < src.len() {
                let (_, _, c) = src[i];
                Some(*c)
            } else {
                None
            }
        }).collect();

        Ok(Self {
            inputs: inputs.as_slice().try_into()?,
            checks: checks.as_slice().try_into()?,
        })
    }
}

impl<Fp: Hashable, const CALCS: usize> Circuit<Fp> for HashCircuit<Fp, CALCS> {
    type Config = HashConfig<Fp>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            inputs: [None; CALCS],
            checks: [None; CALCS],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let state = [0; 3].map(|_| meta.advice_column());
        let partial_sbox = meta.advice_column();
        let constants = [0; 6].map(|_| meta.fixed_column());

        let hash_table = [0; 3].map(|_| meta.advice_column());
        for col in hash_table {
            meta.enable_equality(col);
        }
        meta.enable_equality(constants[0]);

        HashConfig {
            permute_config: Pow5Chip::configure::<Fp::SpecType>(
                meta,
                state,
                partial_sbox,
                constants[..3].try_into().unwrap(), //rc_a
                constants[3..].try_into().unwrap(), //rc_b
            ),
            hash_table,
            constants,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let constant_cells = layouter.assign_region(
            || "constant heading",
            |mut region| {
                let c0 = region.assign_fixed(
                    || "constant zero",
                    config.constants[0],
                    0,
                    || Ok(Fp::zero()),
                )?;

                Ok([StateWord::from(c0)])
            },
        )?;

        let zero_cell = &constant_cells[0];

        let (states, hashes) = layouter.assign_region(
            || "hash table",
            |mut region| {
                let mut states = Vec::new();
                let mut hashes = Vec::new();

                // notice our hash table has a (0, 0, 0) at the beginning
                for col in config.hash_table {
                    region.assign_advice(
                        || "dummy inputs",
                        col,
                        0,
                        || Ok(Fp::zero()),
                    )?;                    
                }

                for (i, inp) in self.inputs.into_iter().enumerate() {
                    let inp = inp.unwrap_or_else(|| [Fp::zero(), Fp::zero()]);
                    let offset = i + 1;

                    let c1 = region.assign_advice(
                        || format!("hash input first_{}", i),
                        config.hash_table[0],
                        offset,
                        || Ok(inp[0]),
                    )?;

                    let c2 = region.assign_advice(
                        || format!("hash input second_{}", i),
                        config.hash_table[1],
                        offset,
                        || Ok(inp[1]),
                    )?;

                    let c3 = region.assign_advice(
                        || format!("hash output_{}", i),
                        config.hash_table[2],
                        offset,
                        || Ok(self.checks[i].unwrap_or_else(||Hashable::hash(inp))),
                    )?;

                    //we directly specify the init state of permutation
                    states.push([zero_cell.clone(), StateWord::from(c1), StateWord::from(c2)]);
                    hashes.push(StateWord::from(c3));
                }

                Ok((states, hashes))
            },
        )?;

        let mut chip_finals = Vec::new();

        for state in states {
            let chip = Pow5Chip::construct(config.permute_config.clone());

            let final_state = <Pow5Chip<_, 3, 2> as PoseidonInstructions<
                Fp,
                Fp::SpecType,
                3,
                2,
            >>::permute(&chip, &mut layouter, &state)?;

            chip_finals.push(final_state);
        }

        layouter.assign_region(
            || "final state dummy",
            |mut region| {
                for (hash, final_state) in hashes.iter().zip(chip_finals.iter()) {
                    region.constrain_equal(hash.cell(), final_state[0].cell())?;
                }

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;

    #[test]
    fn poseidon_hash() {
        let b1: Fr = Fr::from_str_vartime("1").unwrap();
        let b2: Fr = Fr::from_str_vartime("2").unwrap();

        let h = Fr::hash([b1, b2]);
        assert_eq!(
            h.to_string(),
            "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a" // "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );
    }

    use halo2_proofs::dev::MockProver;

    #[cfg(feature = "print_layout")]
    #[test]
    fn print_circuit() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("hash-layout.png", (1024, 768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Hash circuit Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = HashCircuit::<1> { inputs: [None] };
        halo2_proofs::dev::CircuitLayout::default()
            .show_equality_constraints(true)
            .render(6, &circuit, &root)
            .unwrap();
    }

    #[test]
    fn poseidon_hash_circuit() {
        let message = [
            Fr::from_str_vartime("1").unwrap(),
            Fr::from_str_vartime("2").unwrap(),
        ];

        let k = 6;
        let circuit = HashCircuit::<Fr, 1> {
            inputs: [Some(message)],
            checks: [None],
        };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
