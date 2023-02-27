use super::super::constraint_builder::{
    AdviceColumn, ConstraintBuilder, FixedColumn, Query, SelectorColumn,
};
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::Layouter,
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};

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
    difference_inverse_or_zero: AdviceColumn, // difference.invert().unwrap_or_default()
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
            [value, byte, difference, difference_inverse_or_zero, differences_are_zero_so_far],
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
            modulus_byte.current() - byte.current(),
        );
        cb.add_constraint(
            "difference * difference_inverse_or_zero is 1 when difference is non-zero",
            selector.current(),
            difference.current()
                * (Query::from(1) - difference.current() * difference_inverse_or_zero.current()),
        );
        cb.add_constraint(
            "bytes represent value",
            index_is_zero.current(),
            value.current()
                - (0..32)
                    .map(|i| byte.rotation(i))
                    .fold(Query::zero(), |acc, x| acc * 256 + x),
        );
        cb.add_constraint(
            "differences_are_zero_so_far = difference is 0 when index = 0",
            index_is_zero.current(),
            differences_are_zero_so_far.current()
                - (Query::one() - difference.current() * difference_inverse_or_zero.current()),
        );
        cb.add_constraint(
            "differences_are_zero_so_far = difference is 0 * differences_are_zero_so_far.previous() when index != 0",
            !index_is_zero.current(),
            differences_are_zero_so_far.current()
                - differences_are_zero_so_far.previous()
                    * (Query::one() - difference.current() * difference_inverse_or_zero.current()),
        );

        cb.build(cs);

        Self::Config {
            selector,
            value,
            index,
            byte,
            index_is_zero,
            modulus_byte,
            difference,
            difference_inverse_or_zero,
            differences_are_zero_so_far,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

// //
// struct CanonicalRepresentationConfig {
//     selector: Selector,

//     // Lookup columns
//     value: Column<Advice>, // We're proving value.to_le_bytes()[i] = byte in this gadget
//     index: Column<Fixed>,  // (0..32).repeat()
//     byte: Column<Advice>, // we need to prove that bytes form the canonical representation of value.

//     // Witness columns
//     index_is_zero: Column<Fixed>, // (0..32).repeat().map(|i| i == 0)
//     modulus_byte: Column<Fixed>,  // (0..32).repeat().map(|i| Fr::MODULUS.to_le_bytes()[i])
//     difference: Column<Advice>,   // modulus_byte - byte
//     difference_inverse_or_zero: Column<Advice>, // difference.invert().unwrap_or_default()
//     differences_are_zero_so_far: Column<Advice>, // difference[0] ... difference[index] are all 0.
// }

// struct ByteLookupTable {}

// impl CanonicalRepresentationConfig {
//     fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>, _lookups: ByteLookupTable) -> Self {
//         let selector = meta.selector();
//         let [value, byte, difference, difference_inverse_or_zero, differences_are_zero_so_far] =
//             [0; 5].map(|_| meta.advice_column());
//         let [index, index_is_zero, modulus_byte] = [0; 3].map(|_| meta.fixed_column());

//         // meta.create_gate("differences_are_zero_so_far is binary", |meta| {
//         //     let selector = meta.query_selector(selector);
//         //     let e = meta.query_advice(differences_are_zero_so_far, Rotation::cur());
//         //     vec![selector * e.clone() * (Expression::Constant(F::one()) - e)]
//         // });

//         // meta.create_gate("difference = modulus_byte - byte", |meta| {
//         //     let selector = meta.query_selector(selector);
//         //     let m = meta.query_fixed(modulus_byte, Rotation::cur());
//         //     let b = meta.query_advice(byte, Rotation::cur());
//         //     vec![selector * (m - b)]
//         // });

//         // meta.create_gate(
//         //     "difference * difference_is_zero is 1 when difference is non-zero",
//         //     |meta| {
//         //         let selector = meta.query_selector(selector);
//         //         let difference = meta.query_advice(difference, Rotation::cur());
//         //         let difference_inverse_or_zero =
//         //             meta.query_advice(difference_inverse_or_zero, Rotation::cur());
//         //         vec![
//         //             selector
//         //                 * difference.clone()
//         //                 * (Expression::Constant(F::one())
//         //                     - difference * difference_inverse_or_zero),
//         //         ]
//         //     },
//         // );

//         // meta.create_gate("bytes represent value", |meta| {
//         //     let selector = meta.query_fixed(index_is_zero, Rotation::cur());
//         //     let mut byte_representation = Expression::Constant(F::zero());
//         //     for i in 0..32 {
//         //         byte_representation = byte_representation * Expression::Constant(256.into())
//         //             + meta.query_advice(byte, Rotation(i32::try_from(i).unwrap()));
//         //     }
//         //     vec![selector * (meta.query_advice(value, Rotation::cur()) - byte_representation)]
//         // });

//         meta.create_gate(
//             "differences_are_zero_so_far is 1 iff previous is 1 and difference is 0",
//             |meta| {
//                 let index_is_zero = meta.query_fixed(index_is_zero, Rotation::cur());
//                 let differences_are_zero_so_far_cur =
//                     meta.query_advice(differences_are_zero_so_far, Rotation::cur());
//                 let differences_are_zero_so_far_prev =
//                     meta.query_advice(differences_are_zero_so_far, Rotation::prev());

//                 let difference = meta.query_advice(difference, Rotation::cur());
//                 let difference_inverse_or_zero =
//                     meta.query_advice(difference_inverse_or_zero, Rotation::cur());
//                 let difference_is_zero =
//                     Expression::Constant(F::one()) - difference * difference_inverse_or_zero;

//                 vec![
//                     index_is_zero.clone()
//                         * (differences_are_zero_so_far_cur.clone() - difference_is_zero.clone()),
//                     (Expression::Constant(F::one()) - index_is_zero)
//                         * (differences_are_zero_so_far_cur
//                             - differences_are_zero_so_far_prev * difference_is_zero),
//                 ]
//             },
//         );

//         Self {
//             selector,
//             value,
//             index,
//             byte,
//             index_is_zero,
//             modulus_byte,
//             difference,
//             difference_inverse_or_zero,
//             differences_are_zero_so_far,
//         }
//     }

//     fn assign<F: Field>(
//         &self,
//         _layouter: &mut impl Layouter<F>,
//         _values: &[Fr],
//     ) -> Result<(), Error> {
//         Ok(())
//     }
// }
