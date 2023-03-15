use crate::constraint_builder::Query;
use halo2_proofs::arithmetic::FieldExt;

pub trait AccountUpdateLookup {
    fn lookup<F: FieldExt>(&self) -> [Query<F>; 3];
}
