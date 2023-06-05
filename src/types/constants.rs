use crate::util::hash;
use halo2_proofs::halo2curves::bn256::Fr;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref HASH_ZERO_ZERO: Fr = hash(Fr::zero(), Fr::zero());
}
