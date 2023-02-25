use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    circuit::Layouter,
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};

//
struct CanonicalRepresentationConfig {
    selector: Selector,

    // Lookup columns
    value: Column<Advice>, // We're proving value.to_le_bytes()[i] = byte in this gadget
    index: Column<Fixed>,  // (0..32).repeat()
    byte: Column<Advice>, // we need to prove that bytes form the canonical representation of value.

    // Witness columns
    index_is_zero: Column<Fixed>, // (0..32).repeat().map(|i| i == 0)
    modulus_byte: Column<Fixed>,  // (0..32).repeat().map(|i| Fr::MODULUS.to_le_bytes()[i])
    difference: Column<Advice>,   // modulus_byte - byte
    difference_inverse_or_zero: Column<Advice>, // difference.invert().unwrap_or_default()
    differences_are_zero_so_far: Column<Advice>, // difference[0] ... difference[index] are all 0.
}

struct ByteLookupTable {}

impl CanonicalRepresentationConfig {
    fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>, _lookups: ByteLookupTable) -> Self {
        let selector = meta.selector();
        let [value, byte, difference, difference_inverse_or_zero, differences_are_zero_so_far] =
            [0; 5].map(|_| meta.advice_column());
        let [index, index_is_zero, modulus_byte] = [0; 3].map(|_| meta.fixed_column());

        meta.create_gate("differences_are_zero_so_far is binary", |meta| {
            let selector = meta.query_selector(selector);
            let e = meta.query_advice(differences_are_zero_so_far, Rotation::cur());
            vec![selector * e.clone() * (Expression::Constant(F::one()) - e)]
        });

        meta.create_gate("difference = modulus_byte - byte", |meta| {
            let selector = meta.query_selector(selector);
            let m = meta.query_fixed(modulus_byte, Rotation::cur());
            let b = meta.query_advice(byte, Rotation::cur());
            vec![selector * (m - b)]
        });

        meta.create_gate(
            "difference * difference_is_zero is 1 when difference is non-zero",
            |meta| {
                let selector = meta.query_selector(selector);
                let difference = meta.query_advice(difference, Rotation::cur());
                let difference_inverse_or_zero =
                    meta.query_advice(difference_inverse_or_zero, Rotation::cur());
                vec![
                    selector
                        * difference.clone()
                        * (Expression::Constant(F::one())
                            - difference * difference_inverse_or_zero),
                ]
            },
        );

        meta.create_gate("bytes represent value", |meta| {
            let selector = meta.query_fixed(index_is_zero, Rotation::cur());
            let mut byte_representation = Expression::Constant(F::zero());
            for i in 0..32 {
                byte_representation = byte_representation * Expression::Constant(256.into())
                    + meta.query_advice(byte, Rotation(i32::try_from(i).unwrap()));
            }
            vec![selector * (meta.query_advice(value, Rotation::cur()) - byte_representation)]
        });

        meta.create_gate(
            "differences_are_zero_so_far is 1 iff previous is 1 and difference is 0",
            |meta| {
                let index_is_zero = meta.query_fixed(index_is_zero, Rotation::cur());
                let differences_are_zero_so_far_cur =
                    meta.query_advice(differences_are_zero_so_far, Rotation::cur());
                let differences_are_zero_so_far_prev =
                    meta.query_advice(differences_are_zero_so_far, Rotation::prev());

                let difference = meta.query_advice(difference, Rotation::cur());
                let difference_inverse_or_zero =
                    meta.query_advice(difference_inverse_or_zero, Rotation::cur());
                let difference_is_zero =
                    Expression::Constant(F::one()) - difference * difference_inverse_or_zero;

                vec![
                    index_is_zero.clone()
                        * (differences_are_zero_so_far_cur.clone() - difference_is_zero.clone()),
                    (Expression::Constant(F::one()) - index_is_zero)
                        * (differences_are_zero_so_far_cur
                            - differences_are_zero_so_far_prev * difference_is_zero),
                ]
            },
        );

        Self {
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

    fn assign<F: Field>(
        &self,
        _layouter: &mut impl Layouter<F>,
        _values: &[Fr],
    ) -> Result<(), Error> {
        Ok(())
    }
}
