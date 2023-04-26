use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Value},
    plonk::{Challenge, ConstraintSystem, Expression, FirstPhase, VirtualCells},
};

#[derive(Clone, Copy, Debug)]
pub struct Challenges<T = Challenge> {
    mpt_word: T,
}

impl Challenges {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            mpt_word: meta.challenge_usable_after(FirstPhase),
        }
    }

    /// Return `Expression` of challenges from `ConstraintSystem`.
    pub fn exprs<F: FieldExt>(&self, meta: &mut ConstraintSystem<F>) -> Challenges<Expression<F>> {
        let [mpt_word] = query_expression(meta, |meta| {
            [self.mpt_word].map(|challenge| meta.query_challenge(challenge))
        });

        Challenges { mpt_word }
    }

    /// Return `Value` of challenges from `Layouter`.
    pub fn values<F: FieldExt>(&self, layouter: &impl Layouter<F>) -> Challenges<Value<F>> {
        Challenges {
            mpt_word: layouter.get_challenge(self.mpt_word),
        }
    }
}

impl<T: Clone> Challenges<T> {
    pub fn mpt_word(&self) -> T {
        self.mpt_word.clone()
    }
}

fn query_expression<F: FieldExt, T>(
    meta: &mut ConstraintSystem<F>,
    mut f: impl FnMut(&mut VirtualCells<F>) -> T,
) -> T {
    let mut expr = None;
    meta.create_gate("Query expression", |meta| {
        expr = Some(f(meta));
        Some(Expression::Constant(F::from(0)))
    });
    expr.unwrap()
}
