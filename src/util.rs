use crate::serde::HexBytes;
use crate::types::HashDomain;
use ethers_core::{
    k256::elliptic_curve::PrimeField,
    types::{Address, U256},
};
use halo2_proofs::{arithmetic::FieldExt, halo2curves::bn256::Fr};
use hash_circuit::hash::Hashable;
use num_bigint::BigUint;

pub(crate) fn fr(x: HexBytes<32>) -> Fr {
    Fr::from_bytes(&x.0).unwrap()
}

pub(crate) fn hash(x: Fr, y: Fr) -> Fr {
    panic!("migrating away from thisssss")
}

pub fn domain_hash(x: Fr, y: Fr, domain: HashDomain) -> Fr {
    Hashable::hash_with_domain([x, y], Fr::from(Into::<u64>::into(domain)))
    // Hashable::hash_with_domain([x, y], domain)
}

pub fn temp_hash(x: Fr, y: Fr, domain: Fr) -> Fr {
    Hashable::hash_with_domain([x, y], domain)
}

pub(crate) trait Bit {
    fn bit(&self, i: usize) -> bool;
}

impl Bit for Fr {
    fn bit(&self, i: usize) -> bool {
        let mut bytes = self.to_bytes();
        bytes.reverse();
        bytes
            .get(31 - i / 8)
            .map_or_else(|| false, |&byte| byte & (1 << (i % 8)) != 0)
    }
}

pub(crate) fn u256_from_hex(x: HexBytes<32>) -> U256 {
    U256::from_big_endian(&x.0)
}

pub(crate) fn split_word(x: U256) -> (Fr, Fr) {
    let mut bytes = [0; 32];
    x.to_big_endian(&mut bytes);
    let high_bytes: [u8; 16] = bytes[..16].try_into().unwrap();
    let low_bytes: [u8; 16] = bytes[16..].try_into().unwrap();

    let high = Fr::from_u128(u128::from_be_bytes(high_bytes));
    let low = Fr::from_u128(u128::from_be_bytes(low_bytes));
    (high, low)

    // TODO: what's wrong with this?
    // let [limb_0, limb_1, limb_2, limb_3] = key.0;
    // let key_high = Fr::from_u128(u128::from(limb_2) + u128::from(limb_3) << 64);
    // let key_low = Fr::from_u128(u128::from(limb_0) + u128::from(limb_1) << 64);
    // hash(key_high, key_low)
}

pub(crate) fn hi_lo(x: &BigUint) -> (Fr, Fr) {
    let mut u64_digits = x.to_u64_digits();
    u64_digits.resize(4, 0);
    (
        Fr::from_u128((u128::from(u64_digits[3]) << 64) + u128::from(u64_digits[2])),
        Fr::from_u128((u128::from(u64_digits[1]) << 64) + u128::from(u64_digits[0])),
    )
}

pub(crate) fn u256_hi_lo(x: &U256) -> (u128, u128) {
    let u64_digits = x.0;
    (
        (u128::from(u64_digits[3]) << 64) + u128::from(u64_digits[2]),
        (u128::from(u64_digits[1]) << 64) + u128::from(u64_digits[0]),
    )
}
pub(crate) fn fr_from_biguint(b: &BigUint) -> Fr {
    b.to_u64_digits()
        .iter()
        .rev() // to_u64_digits has least significant digit first
        .fold(Fr::zero(), |a, b| {
            a * Fr::from(1 << 32).square() + Fr::from(*b)
        })
}

pub fn rlc(be_bytes: &[u8], randomness: Fr) -> Fr {
    let x = be_bytes.iter().fold(Fr::zero(), |acc, byte| {
        randomness * acc + Fr::from(u64::from(*byte))
    });
    // dbg!(x);
    x
}

pub fn u256_from_biguint(x: &BigUint) -> U256 {
    U256::from_big_endian(&x.to_bytes_be())
}

pub fn u256_to_fr(x: U256) -> Fr {
    let mut bytes = [0u8; 32];
    x.to_little_endian(&mut bytes);
    Fr::from_repr(bytes).unwrap()
}

pub fn u256_to_big_endian(x: &U256) -> Vec<u8> {
    let mut bytes = [0; 32];
    x.to_big_endian(&mut bytes);
    bytes.to_vec()
}

pub fn storage_key_hash(key: U256) -> Fr {
    let (high, low) = split_word(key);
    domain_hash(high, low, HashDomain::NodeTypeLeaf)
}

pub fn account_key(address: Address) -> Fr {
    let high_bytes: [u8; 16] = address.0[..16].try_into().unwrap();
    let low_bytes: [u8; 4] = address.0[16..].try_into().unwrap();

    let address_high = Fr::from_u128(u128::from_be_bytes(high_bytes));
    let address_low = Fr::from_u128(u128::from(u32::from_be_bytes(low_bytes)) << 96);
    // dbg!(domain_hash(address_high, address_low, HashDomain::Pair));
    domain_hash(address_high, address_low, HashDomain::Pair)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_u256_hi_lo() {
        assert_eq!(u256_hi_lo(&U256::one()), (0, 1));
    }
}
