use crate::{
    constraint_builder::{AdviceColumn, ConstraintBuilder, Query, SecondPhaseAdviceColumn},
    gadgets::{
        byte_representation::{BytesLookup, RlcLookup},
        poseidon::PoseidonLookup,
    },
    types::HashDomain,
    util::{rlc, u256_hi_lo},
};
use ethers_core::types::U256;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    halo2curves::bn256::Fr,
};

pub fn configure<F: FieldExt>(
    cb: &mut ConstraintBuilder<F>,
    [word_hash, high, low]: [AdviceColumn; 3],
    [rlc_word, rlc_high, rlc_low]: [SecondPhaseAdviceColumn; 3],
    poseidon: &impl PoseidonLookup,
    bytes: &impl BytesLookup,
    rlc: &impl RlcLookup,
    randomness: Query<F>,
) {
    cb.add_lookup(
        "old_high is 16 bytes",
        [high.current(), Query::from(15)],
        bytes.lookup(),
    );
    cb.add_lookup(
        "old_low is 16 bytes",
        [low.current(), Query::from(15)],
        bytes.lookup(),
    );
    cb.poseidon_lookup(
        "word_hash = poseidon(high, low)",
        [
            high.current(),
            low.current(),
            HashDomain::Pair.into(),
            word_hash.current(),
        ],
        poseidon,
    );

    cb.add_lookup(
        "rlc_high = rlc(high) and high is 16 bytes",
        [high.current(), Query::from(15), rlc_high.current()],
        rlc.lookup(),
    );
    cb.add_lookup(
        "rlc_low = rlc(low) and low is 16 bytes",
        [low.current(), Query::from(15), rlc_low.current()],
        rlc.lookup(),
    );
    let randomness_raised_to_16 = randomness.square().square().square().square();
    cb.assert_equal(
        "word_rlc = rlc(high) * randomness ^ 16 + rlc(low)",
        rlc_word.current(),
        rlc_high.current() * randomness_raised_to_16 + rlc_low.current(),
    );
}

pub fn assign(
    region: &mut Region<'_, Fr>,
    offset: usize,
    word: U256,
    [high_column, low_column]: [AdviceColumn; 2],
    [rlc_high, rlc_low]: [SecondPhaseAdviceColumn; 2],
    randomness: Value<Fr>,
) {
    let (high, low) = u256_hi_lo(&word);
    high_column.assign(region, offset, Fr::from_u128(high));
    low_column.assign(region, offset, Fr::from_u128(low));
    rlc_high.assign(
        region,
        offset,
        randomness.map(|r| rlc(&high.to_be_bytes(), r)),
    );
    rlc_low.assign(
        region,
        offset,
        randomness.map(|r| rlc(&low.to_be_bytes(), r)),
    );
}
