use ff::PrimeField;
use halo2_proofs::pairing::bn256::Fr;
use crate::poseidon::primitives::{ConstantLengthIden3, P128Pow5T3, Hash};

/// indicate an field can be hashed in merkle tree (2 Fields to 1 Field)
pub trait Hashable: Sized {
    /// execute hash for any sequence of fields
    fn hash(inp: [Self;2]) -> Self;
}

type Poseidon = Hash<Fr, P128Pow5T3<Fr>, ConstantLengthIden3<2>, 3, 2>;


fn same_fr_convert<A: PrimeField, B: PrimeField>(fr: A) -> B {
    let mut ret = B::Repr::default();
    ret.as_mut().copy_from_slice(fr.to_repr().as_ref());

    B::from_repr(ret).unwrap()
}

impl Hashable for Fr {
    fn hash(inp: [Self;2]) -> Self {
        Poseidon::init().hash(inp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_hash() {
        let b1: Fr = Fr::from_str_vartime("1").unwrap();
        let b2: Fr = Fr::from_str_vartime("2").unwrap();

        let h = Fr::hash([b1, b2]);
        assert_eq!(
            h.to_string(),
            "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a" // "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );
    }
}
