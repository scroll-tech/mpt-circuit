use super::{BinaryQuery, ConstraintBuilder, Query};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::ConstraintSystem,
    plonk::{Advice, Column},
    poly::Rotation,
};

#[derive(Clone, Copy)]
pub struct BinaryColumn(pub Column<Advice>);

impl BinaryColumn {
    pub fn rotation<F: FieldExt>(self, i: i32) -> BinaryQuery<F> {
        BinaryQuery(Query(Box::new(move |meta| {
            meta.query_advice(self.0, Rotation(i))
        })))
    }

    pub fn current<F: FieldExt>(self) -> BinaryQuery<F> {
        self.rotation(0)
    }

    pub fn previous<F: FieldExt>(self) -> BinaryQuery<F> {
        self.rotation(-1)
    }

    pub fn configure<F: FieldExt>(
        cs: &mut ConstraintSystem<F>,
        _cb: &mut ConstraintBuilder<F>,
    ) -> Self {
        let advice_column = cs.advice_column();
        // cb.add_constraint()
        Self(advice_column)
    }

    pub fn assign<F: FieldExt>(&self, region: &mut Region<'_, F>, offset: usize, value: bool) {
        region
            .assign_advice(|| "", self.0, offset, || Value::known(F::from(value)))
            .expect("failed assign_advice");
    }
}
