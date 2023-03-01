#[derive(Clone, Copy)]
pub struct IsZeroColumn {
    pub value: AdviceColumn,
    pub inverse_or_zero: AdviceColumn,
}

// probably a better name for this is IsZeroConfig
impl IsZeroColumn {
    pub fn current<F: FieldExt>(self) -> BinaryQuery<F> {
        BinaryQuery(Query::one() - self.value.current() * self.inverse_or_zero.current())
    }

    pub fn previous<F: FieldExt>(self) -> BinaryQuery<F> {
        BinaryQuery(Query::one() - self.value.previous() * self.inverse_or_zero.previous())
    }

    pub fn assign<F: FieldExt, T: Copy + TryInto<F>>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: T,
    ) where
        <T as TryInto<F>>::Error: Debug,
    {
        self.inverse_or_zero.assign(
            region,
            offset,
            value.try_into().unwrap().invert().unwrap_or(F::zero()),
        );
    }
}
