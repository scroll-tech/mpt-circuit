use super::{BinaryQuery, ConstraintBuilder, Query};
use halo2_proofs::{
    circuit::{Region, Value},
    halo2curves::ff::FromUniformBytes,
    plonk::ConstraintSystem,
    plonk::{Advice, Column},
};

#[derive(Clone, Copy)]
pub struct BinaryColumn(pub Column<Advice>);

impl BinaryColumn {
    pub fn rotation<F: FromUniformBytes<64> + Ord>(&self, i: i32) -> BinaryQuery<F> {
        BinaryQuery(Query::Advice(self.0, i))
    }

    pub fn current<F: FromUniformBytes<64> + Ord>(&self) -> BinaryQuery<F> {
        self.rotation(0)
    }

    pub fn previous<F: FromUniformBytes<64> + Ord>(&self) -> BinaryQuery<F> {
        self.rotation(-1)
    }

    pub fn next<F: FromUniformBytes<64> + Ord>(&self) -> BinaryQuery<F> {
        self.rotation(1)
    }

    pub fn configure<F: FromUniformBytes<64> + Ord>(
        cs: &mut ConstraintSystem<F>,
        cb: &mut ConstraintBuilder<F>,
    ) -> Self {
        let binary_column = Self(cs.advice_column());
        cb.assert(
            "binary column is 0 or 1",
            binary_column.current().or(!binary_column.current()),
        );
        binary_column
    }

    pub fn assign<F: FromUniformBytes<64> + Ord>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: bool,
    ) {
        region
            .assign_advice(
                || "binary",
                self.0,
                offset,
                || Value::known(F::from(value as u64)),
            )
            .expect("failed assign_advice");
    }
}
