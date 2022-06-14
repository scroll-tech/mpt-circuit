pub(crate) mod fp;
pub(crate) use halo2_proofs::pairing::bn256::Fr as Fp;

use super::Mds;

impl super::p128pow5t3::P128Pow5T3Constants for Fp {
    type Fp = Fp;

    fn partial_rounds() -> usize {
        57
    }

    fn round_constants() -> Vec<[Self::Fp; 3]> {
        fp::ROUND_CONSTANTS.to_vec()
    }
    fn mds() -> Mds<Self::Fp, 3> {
        *fp::MDS
    }
    fn mds_inv() -> Mds<Self::Fp, 3> {
        *fp::MDS_INV
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn verify_constants() {
        let c = fp::ROUND_CONSTANTS.to_vec();
        let m = *fp::MDS;

        assert_eq!(
            c[0][0].to_string(),
            "0x0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e"
        );
        assert_eq!(
            c[c.len() - 1][2].to_string(),
            "0x1da55cc900f0d21f4a3e694391918a1b3c23b2ac773c6b3ef88e2e4228325161"
        );
        assert_eq!(
            m[0][0].to_string(),
            "0x109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b"
        );
        assert_eq!(
            m[m.len() - 1][0].to_string(),
            "0x143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7"
        );
    }
}
