use ff::PrimeField;
use halo2_proofs::pairing::bn256::Fr;
use lazy_static::lazy_static;
use poseidon_rs::Poseidon;

/// indicate an field can be hashed
pub trait Hashable: Sized {
    /// execute hash for any sequence of fields
    fn hash(inp: Vec<Self>) -> Result<Self, String>;
}

lazy_static! {
    static ref POSEIDON_HASHER: Poseidon = Poseidon::new();
}

fn same_fr_convert<A: PrimeField, B: PrimeField>(fr: A) -> B {
    let mut ret = B::Repr::default();
    ret.as_mut().copy_from_slice(fr.to_repr().as_ref());

    B::from_repr(ret).unwrap()
}

impl Hashable for Fr {
    fn hash(inp: Vec<Self>) -> Result<Self, String> {
        let inp_in_pfr = inp.into_iter().map(same_fr_convert).collect();
        POSEIDON_HASHER.hash(inp_in_pfr).map(same_fr_convert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_hash() {
        let b0: Fr = Fr::from_str_vartime("0").unwrap();
        let b1: Fr = Fr::from_str_vartime("1").unwrap();
        let b2: Fr = Fr::from_str_vartime("2").unwrap();
        let b3: Fr = Fr::from_str_vartime("3").unwrap();
        let b4: Fr = Fr::from_str_vartime("4").unwrap();
        let b5: Fr = Fr::from_str_vartime("5").unwrap();
        let b6: Fr = Fr::from_str_vartime("6").unwrap();

        let mut big_arr: Vec<Fr> = Vec::new();
        big_arr.push(b1.clone());
        let h = Fr::hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "0x29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133" // "18586133768512220936620570745912940619677854269274689475585506675881198879027"
        );

        let mut big_arr: Vec<Fr> = Vec::new();
        big_arr.push(b1.clone());
        big_arr.push(b2.clone());
        let h = Fr::hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a" // "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        );

        let mut big_arr: Vec<Fr> = Vec::new();
        big_arr.push(b1.clone());
        big_arr.push(b2.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        let h = Fr::hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "0x024058dd1e168f34bac462b6fffe58fd69982807e9884c1c6148182319cee427" // "1018317224307729531995786483840663576608797660851238720571059489595066344487"
        );

        let mut big_arr: Vec<Fr> = Vec::new();
        big_arr.push(b1.clone());
        big_arr.push(b2.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        let h = Fr::hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "0x21e82f465e00a15965e97a44fe3c30f3bf5279d8bf37d4e65765b6c2550f42a1" // "15336558801450556532856248569924170992202208561737609669134139141992924267169"
        );

        let mut big_arr: Vec<Fr> = Vec::new();
        big_arr.push(b3.clone());
        big_arr.push(b4.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        let h = Fr::hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "0x0cd93f1bab9e8c9166ef00f2a1b0e1d66d6a4145e596abe0526247747cc71214" // "5811595552068139067952687508729883632420015185677766880877743348592482390548"
        );

        let mut big_arr: Vec<Fr> = Vec::new();
        big_arr.push(b3.clone());
        big_arr.push(b4.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        big_arr.push(b0.clone());
        let h = Fr::hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "0x1b1caddfc5ea47e09bb445a7447eb9694b8d1b75a97fff58e884398c6b22825a" // "12263118664590987767234828103155242843640892839966517009184493198782366909018"
        );

        let mut big_arr: Vec<Fr> = Vec::new();
        big_arr.push(b1.clone());
        big_arr.push(b2.clone());
        big_arr.push(b3.clone());
        big_arr.push(b4.clone());
        big_arr.push(b5.clone());
        big_arr.push(b6.clone());
        let h = Fr::hash(big_arr.clone()).unwrap();
        assert_eq!(
            h.to_string(),
            "0x2d1a03850084442813c8ebf094dea47538490a68b05f2239134a4cca2f6302e1" // "20400040500897583745843009878988256314335038853985262692600694741116813247201"
        );
    }
}
